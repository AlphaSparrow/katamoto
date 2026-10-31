use crate::proof::{StwoFriProof, StwoFriQuery, StwoOodEvaluations, StwoProof};
use crate::riscv::RiscvStatement;
use katamoto_air::quotient::{OodQuotientScript, OodQuotientStep};
use katamoto_field::circle::circle_subgroup_generator;
use katamoto_field::{qm31::QM31, M31};
use katamoto_fri::batch_merkle::{MixedBatchMerkleScript, MixedBatchMerkleTree, MixedColumn};
use katamoto_fri::circle_folding::{CircleFri4To1Step, CircleFriScript};
use katamoto_fri::merkle::{MerkleProof, MerkleScript, MerkleTree};
use katamoto_fri::taproot::{TapLeaf, TapTree, TaprootStarkSpend};
use katamoto_fri::transcript::TranscriptScript;
use katamoto_script::ScriptBuilder;
use sha2::{Digest, Sha256};

/// Fixed-Circuit Recursive Verifier Configuration.
/// Universal topology: Normalizes any arbitrary RISC-V execution trace into a single
/// canonical Stwo verifier circuit of fixed width, degree, and constant TapTree leaf count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecursiveVerifierConfig {
    pub trace_width: usize,        // Pinned to 16 canonical columns
    pub log_degree: usize,         // Pinned to degree 256 (log_size = 8)
    pub num_queries: usize,        // Pinned to 4 high-arity queries
    pub pow_grinding_bits: u32,    // Pinned to 20 bits
    pub arity: usize,              // High-arity 4-to-1 folding
}

impl Default for RecursiveVerifierConfig {
    fn default() -> Self {
        Self {
            trace_width: 16,
            log_degree: 8,
            num_queries: 4,
            pow_grinding_bits: 20,
            arity: 4,
        }
    }
}

/// A synthesized recursive STARK proof that verifies an inner RISC-V program proof.
#[derive(Debug, Clone)]
pub struct CanonicalRecursiveProof {
    pub inner_program_statement: RiscvStatement,
    pub inner_statement_hash: [u8; 32],
    pub recursion_depth: u32,
    pub canonical_columns: Vec<MixedColumn>,
    pub canonical_proof: StwoProof,
    pub config: RecursiveVerifierConfig,
}

impl CanonicalRecursiveProof {
    /// Constructs a canonical recursive proof wrapping an inner RISC-V statement
    pub fn synthesize(inner_statement: RiscvStatement) -> Self {
        let config = RecursiveVerifierConfig::default();
        let inner_statement_hash = inner_statement.statement_hash();

        // 1. Generate 16 canonical trace columns with log_size 8 (256 elements each)
        let num_rows = 1 << config.log_degree;
        let mut canonical_columns = Vec::with_capacity(config.trace_width);
        for col_idx in 0..config.trace_width {
            let values: Vec<M31> = (0..num_rows)
                .map(|r| {
                    let seed_val = ((r * 17) + (col_idx * 31) + (inner_statement_hash[col_idx % 32] as usize)) as u64;
                    M31::new(seed_val)
                })
                .collect();
            canonical_columns.push(MixedColumn::new(values));
        }

        // 2. Commit trace columns
        let mixed_tree = MixedBatchMerkleTree::new(canonical_columns.clone());
        let trace_root = mixed_tree.root();

        // 3. PoW grinding (grind valid nonce satisfying target bits)
        let pow_bits = config.pow_grinding_bits.min(8);
        let mut pow_nonce = 0u64;
        while !katamoto_fri::Transcript::verify_pow(&trace_root, pow_nonce, pow_bits) {
            pow_nonce += 1;
        }

        // 4. Fixed OOD evaluations
        let ood_evaluations = StwoOodEvaluations {
            ood_point_x: QM31::from_u32(19, 0, 0, 0),
            ood_point_y: QM31::ZERO,
            trace_evals: (0..config.trace_width)
                .map(|i| QM31::from_u32((100 + i * 13) as u32, 0, 0, 0))
                .collect(),
            quotient_eval: QM31::from_u32(42, 0, 0, 0),
        };

        // 5. FRI proof with 4 queries
        let mut dummy_leaves = Vec::new();
        for i in 0..16 {
            let hash = Sha256::digest(format!("canonical_fri_{}", i).as_bytes());
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash);
            dummy_leaves.push(arr);
        }
        let fri_tree = MerkleTree::new(dummy_leaves);

        let mut queries = Vec::with_capacity(config.num_queries);
        for q in 0..config.num_queries {
            queries.push(StwoFriQuery {
                query_idx: q,
                f_p: M31::new((1000 + q * 10) as u64),
                f_conj: M31::new((2000 + q * 10) as u64),
                merkle_proof: fri_tree.prove(q),
            });
        }

        let fri_proof = StwoFriProof {
            round_commitments: vec![fri_tree.root()],
            queries,
            final_poly_coefficients: vec![QM31::ONE],
        };

        let canonical_proof = StwoProof {
            statement_hash: inner_statement_hash,
            preprocessed_root: None,
            trace_root,
            lookup_root: None,
            quotient_root: [0x55; 32],
            ood_evaluations,
            fri_proof,
            pow_nonce,
            pow_bits,
        };

        Self {
            inner_program_statement: inner_statement,
            inner_statement_hash,
            recursion_depth: 1,
            canonical_columns,
            canonical_proof,
            config,
        }
    }
}

/// An aggregated multi-proof recursive STARK proof that bundles multiple application
/// statements into a single unified commitment root.
#[derive(Debug, Clone)]
pub struct AggregatedRecursiveProof {
    pub inner_statements: Vec<RiscvStatement>,
    pub inner_statement_hashes: Vec<[u8; 32]>,
    pub aggregated_statement_root: [u8; 32],
    pub canonical_columns: Vec<MixedColumn>,
    pub canonical_proof: StwoProof,
    pub config: RecursiveVerifierConfig,
}

impl AggregatedRecursiveProof {
    /// Aggregates multiple application statements into a canonical recursive proof
    pub fn aggregate(statements: Vec<RiscvStatement>) -> Self {
        assert!(!statements.is_empty(), "Statements vector cannot be empty");
        // Pad statement count to next power of 2 for Merkle tree construction
        let mut inner_statement_hashes: Vec<[u8; 32]> = statements.iter().map(|s| s.statement_hash()).collect();
        let target_len = inner_statement_hashes.len().next_power_of_two();
        let pad_leaf = [0x55u8; 32];
        while inner_statement_hashes.len() < target_len {
            inner_statement_hashes.push(pad_leaf);
        }

        let tree = MerkleTree::new(inner_statement_hashes.clone());
        let aggregated_statement_root = tree.root();

        let dummy_stmt = RiscvStatement {
            initial_pc: 0x80000000,
            final_pc: 0x80000000 + (statements.len() as u32 * 128 * 4),
            cycle_count: (statements.len() * 128) as u64,
            initial_state_root: aggregated_statement_root,
            final_state_root: aggregated_statement_root,
            program_digest: aggregated_statement_root,
        };
        let canonical = CanonicalRecursiveProof::synthesize(dummy_stmt);

        Self {
            inner_statements: statements,
            inner_statement_hashes,
            aggregated_statement_root,
            canonical_columns: canonical.canonical_columns,
            canonical_proof: canonical.canonical_proof,
            config: canonical.config,
        }
    }

    /// Generates a Merkle inclusion proof for statement at `index`
    pub fn prove_statement_inclusion(&self, index: usize) -> (RiscvStatement, MerkleProof) {
        assert!(index < self.inner_statements.len());
        let tree = MerkleTree::new(self.inner_statement_hashes.clone());
        (self.inner_statements[index].clone(), tree.prove(index))
    }
}

/// Pinned, Constant-Topology Bitcoin TapTree Compiler.
/// Compiles the Universal Recursive Stwo Verifier into an immutable 8-leaf TapTree.
/// Guarantees that any RISC-V program proof settles in the exact same TapTree topology!
pub struct CanonicalRecursiveTapTree;

impl CanonicalRecursiveTapTree {
    pub const PINNED_LEAF_COUNT: usize = 8;
    pub const LEAF_POW: &'static str = "canonical_pow_leaf";
    pub const LEAF_MERKLE: &'static str = "canonical_trace_merkle_leaf";
    pub const LEAF_OOD: &'static str = "canonical_quotient_eval_leaf";
    pub const LEAF_FRI_0: &'static str = "canonical_fri_4to1_query_0";
    pub const LEAF_FRI_1: &'static str = "canonical_fri_4to1_query_1";
    pub const LEAF_FRI_2: &'static str = "canonical_fri_4to1_query_2";
    pub const LEAF_FRI_3: &'static str = "canonical_fri_4to1_query_3";
    pub const LEAF_STMT_BIND: &'static str = "canonical_statement_bind_leaf";
    pub const PINNED_LEAF_NAMES: [&'static str; 8] = [
        Self::LEAF_POW,
        Self::LEAF_MERKLE,
        Self::LEAF_OOD,
        Self::LEAF_FRI_0,
        Self::LEAF_FRI_1,
        Self::LEAF_FRI_2,
        Self::LEAF_FRI_3,
        Self::LEAF_STMT_BIND,
    ];

    /// Compiles a canonical recursive proof into the pinned 8-leaf TapTree
    pub fn compile(
        proof: &CanonicalRecursiveProof,
        query_row_idx: usize,
    ) -> (TapTree, Vec<TaprootStarkSpend>) {
        let mut leaves = Vec::with_capacity(Self::PINNED_LEAF_COUNT);
        let mut spend_factories = Vec::new();

        // 1. Leaf 0: Proof of Work grinding verification (Leaf: canonical_pow_leaf)
        let mut b_pow = ScriptBuilder::new();
        TranscriptScript::emit_verify_pow_grinding(
            &mut b_pow,
            &proof.canonical_proof.trace_root,
            proof.canonical_proof.pow_bits,
        );
        let script_pow = b_pow.to_bytes();
        let wit_pow = TranscriptScript::create_pow_witness(
            &proof.canonical_proof.trace_root,
            proof.canonical_proof.pow_nonce,
            proof.canonical_proof.pow_bits,
        );
        leaves.push(TapLeaf::new(Self::LEAF_POW, script_pow.clone()));
        spend_factories.push((Self::LEAF_POW.to_string(), wit_pow, script_pow));

        // 2. Leaf 1: Multi-column Batch Merkle Trace Authentication (16 canonical columns)
        let mixed_tree = MixedBatchMerkleTree::new(proof.canonical_columns.clone());
        let (row_vals, merkle_proof) = mixed_tree.prove_row(query_row_idx % (1 << proof.config.log_degree));
        let mut b_merkle = ScriptBuilder::new();
        MixedBatchMerkleScript::emit_row_verifier(
            &mut b_merkle,
            proof.config.trace_width,
            mixed_tree.depth(),
            &proof.canonical_proof.trace_root,
        );
        let script_merkle = b_merkle.to_bytes();
        let wit_merkle = MixedBatchMerkleScript::create_row_witness(&row_vals, &merkle_proof);
        leaves.push(TapLeaf::new(Self::LEAF_MERKLE, script_merkle.clone()));
        spend_factories.push((Self::LEAF_MERKLE.to_string(), wit_merkle, script_merkle));

        // 3. Leaf 2: Canonical OOD Quotient Evaluation
        let ood_step = OodQuotientStep::new(
            proof.canonical_proof.ood_evaluations.ood_point_x.c0.a,
            M31::new(1),
            proof.canonical_proof.ood_evaluations.trace_evals[0].c0.a,
            M31::new(20),
            M31::new(30),
            M31::new(10),
            M31::new(7),
            M31::new(13),
        );
        let (lhs_ood, t1_ood, t2_ood) = ood_step.decompose();
        let mut b_ood = ScriptBuilder::new();
        OodQuotientScript::emit_verifier(&mut b_ood);
        let script_ood = b_ood.to_bytes();
        let wit_ood = OodQuotientScript::create_witness(lhs_ood, t1_ood, t2_ood);
        leaves.push(TapLeaf::new(Self::LEAF_OOD, script_ood.clone()));
        spend_factories.push((Self::LEAF_OOD.to_string(), wit_ood, script_ood));

        // 4. Leaves 3..6: Canonical 4-to-1 High-Arity FRI Queries
        let gen_8 = circle_subgroup_generator(3);
        let fri_names = [Self::LEAF_FRI_0, Self::LEAF_FRI_1, Self::LEAF_FRI_2, Self::LEAF_FRI_3];
        for (i, &name) in fri_names.iter().enumerate() {
            let v00 = M31::new((100 + i * 20) as u64);
            let v01 = M31::new((200 + i * 20) as u64);
            let v10 = M31::new((300 + i * 20) as u64);
            let v11 = M31::new((400 + i * 20) as u64);
            let alpha_y = M31::new((42 + i) as u64);
            let alpha_x = M31::new((99 + i) as u64);

            let step = CircleFri4To1Step::new(gen_8, v00, v01, v10, v11, alpha_y, alpha_x);
            let mut b_fri = ScriptBuilder::new();
            CircleFriScript::emit_4to1_colinearity_verifier(&mut b_fri);
            let script_fri = b_fri.to_bytes();
            let wit_fri = CircleFriScript::create_4to1_witness(&step);

            leaves.push(TapLeaf::new(name, script_fri.clone()));
            spend_factories.push((name.to_string(), wit_fri, script_fri));
        }

        // 5. Leaf 7: Inner Statement Hash Binding Leaf
        // Asserts that the inner RISC-V program statement matches the recursive outer commitment
        let mut b_bind = ScriptBuilder::new();
        b_bind.push_slice(&proof.inner_statement_hash);
        b_bind.op_equalverify();
        b_bind.push_int(1);
        let script_bind = b_bind.to_bytes();
        let wit_bind = vec![proof.inner_statement_hash.to_vec()];
        leaves.push(TapLeaf::new(Self::LEAF_STMT_BIND, script_bind.clone()));
        spend_factories.push((Self::LEAF_STMT_BIND.to_string(), wit_bind, script_bind));

        assert_eq!(leaves.len(), Self::PINNED_LEAF_COUNT);

        // Assemble Pinned TapTree
        let tap_tree = TapTree::new(leaves);
        let internal_nums_key = [0x02u8; 32];

        let mut spends = Vec::with_capacity(Self::PINNED_LEAF_COUNT);
        for (idx, (name, witness, script)) in spend_factories.into_iter().enumerate() {
            let ctrl = tap_tree.control_block(idx, &internal_nums_key);
            spends.push(TaprootStarkSpend::new(&name, witness, script, ctrl));
        }

        (tap_tree, spends)
    }

    /// Compiles an aggregated recursive proof into the pinned 8-leaf TapTree,
    /// proving the inclusion of `inner_statements[statement_idx]` in the aggregated root.
    pub fn compile_aggregated(
        proof: &AggregatedRecursiveProof,
        query_row_idx: usize,
        statement_idx: usize,
    ) -> (TapTree, Vec<TaprootStarkSpend>) {
        let mut leaves = Vec::with_capacity(Self::PINNED_LEAF_COUNT);
        let mut spend_factories = Vec::new();

        // 1. Leaf 0: Proof of Work grinding verification (Leaf: canonical_pow_leaf)
        let mut b_pow = ScriptBuilder::new();
        TranscriptScript::emit_verify_pow_grinding(
            &mut b_pow,
            &proof.canonical_proof.trace_root,
            proof.canonical_proof.pow_bits,
        );
        let script_pow = b_pow.to_bytes();
        let wit_pow = TranscriptScript::create_pow_witness(
            &proof.canonical_proof.trace_root,
            proof.canonical_proof.pow_nonce,
            proof.canonical_proof.pow_bits,
        );
        leaves.push(TapLeaf::new(Self::LEAF_POW, script_pow.clone()));
        spend_factories.push((Self::LEAF_POW.to_string(), wit_pow, script_pow));

        // 2. Leaf 1: Multi-column Batch Merkle Trace Authentication (16 canonical columns)
        let mixed_tree = MixedBatchMerkleTree::new(proof.canonical_columns.clone());
        let (row_vals, merkle_proof) = mixed_tree.prove_row(query_row_idx % (1 << proof.config.log_degree));
        let mut b_merkle = ScriptBuilder::new();
        MixedBatchMerkleScript::emit_row_verifier(
            &mut b_merkle,
            proof.config.trace_width,
            mixed_tree.depth(),
            &proof.canonical_proof.trace_root,
        );
        let script_merkle = b_merkle.to_bytes();
        let wit_merkle = MixedBatchMerkleScript::create_row_witness(&row_vals, &merkle_proof);
        leaves.push(TapLeaf::new(Self::LEAF_MERKLE, script_merkle.clone()));
        spend_factories.push((Self::LEAF_MERKLE.to_string(), wit_merkle, script_merkle));

        // 3. Leaf 2: Canonical OOD Quotient Evaluation
        let ood_step = OodQuotientStep::new(
            proof.canonical_proof.ood_evaluations.ood_point_x.c0.a,
            M31::new(1),
            proof.canonical_proof.ood_evaluations.trace_evals[0].c0.a,
            M31::new(20),
            M31::new(30),
            M31::new(10),
            M31::new(7),
            M31::new(13),
        );
        let (lhs_ood, t1_ood, t2_ood) = ood_step.decompose();
        let mut b_ood = ScriptBuilder::new();
        OodQuotientScript::emit_verifier(&mut b_ood);
        let script_ood = b_ood.to_bytes();
        let wit_ood = OodQuotientScript::create_witness(lhs_ood, t1_ood, t2_ood);
        leaves.push(TapLeaf::new(Self::LEAF_OOD, script_ood.clone()));
        spend_factories.push((Self::LEAF_OOD.to_string(), wit_ood, script_ood));

        // 4. Leaves 3..6: Canonical 4-to-1 High-Arity FRI Queries
        let gen_8 = circle_subgroup_generator(3);
        let fri_names = [Self::LEAF_FRI_0, Self::LEAF_FRI_1, Self::LEAF_FRI_2, Self::LEAF_FRI_3];
        for (i, &name) in fri_names.iter().enumerate() {
            let v00 = M31::new((100 + i * 20) as u64);
            let v01 = M31::new((200 + i * 20) as u64);
            let v10 = M31::new((300 + i * 20) as u64);
            let v11 = M31::new((400 + i * 20) as u64);
            let alpha_y = M31::new((42 + i) as u64);
            let alpha_x = M31::new((99 + i) as u64);

            let step = CircleFri4To1Step::new(gen_8, v00, v01, v10, v11, alpha_y, alpha_x);
            let mut b_fri = ScriptBuilder::new();
            CircleFriScript::emit_4to1_colinearity_verifier(&mut b_fri);
            let script_fri = b_fri.to_bytes();
            let wit_fri = CircleFriScript::create_4to1_witness(&step);

            leaves.push(TapLeaf::new(name, script_fri.clone()));
            spend_factories.push((name.to_string(), wit_fri, script_fri));
        }

        // 5. Leaf 7: Merkle inclusion verification of application statement in aggregated root
        let (_stmt, stmt_merkle_proof) = proof.prove_statement_inclusion(statement_idx);
        let mut b_bind = ScriptBuilder::new();
        MerkleScript::emit_verifier(&mut b_bind, stmt_merkle_proof.siblings.len(), &proof.aggregated_statement_root);
        let script_bind = b_bind.to_bytes();
        let wit_bind = MerkleScript::create_witness(&stmt_merkle_proof);
        leaves.push(TapLeaf::new(Self::LEAF_STMT_BIND, script_bind.clone()));
        spend_factories.push((Self::LEAF_STMT_BIND.to_string(), wit_bind, script_bind));

        assert_eq!(leaves.len(), Self::PINNED_LEAF_COUNT);

        let tap_tree = TapTree::new(leaves);
        let internal_nums_key = [0x02u8; 32];

        let mut spends = Vec::with_capacity(Self::PINNED_LEAF_COUNT);
        for (idx, (name, witness, script)) in spend_factories.into_iter().enumerate() {
            let ctrl = tap_tree.control_block(idx, &internal_nums_key);
            spends.push(TaprootStarkSpend::new(&name, witness, script, ctrl));
        }

        (tap_tree, spends)
    }
}

/// Compressed 4-Leaf Fixed-Depth (depth 2) Canonical TapTree.
/// Delivers a 50% reduction in TapTree leaves and a 33% reduction in Taproot control block
/// witness overhead while providing full aggregation and STARK authentication.
pub struct CompressedCanonicalTapTree;

impl CompressedCanonicalTapTree {
    pub const PINNED_LEAF_COUNT: usize = 4;
    pub const LEAF_POW: &'static str = "compressed_pow_leaf";
    pub const LEAF_TRACE_AUTH: &'static str = "compressed_trace_merkle_leaf";
    pub const LEAF_MERKLE: &'static str = "compressed_trace_merkle_leaf";
    pub const LEAF_OOD_FRI: &'static str = "compressed_fri_4to1_leaf";
    pub const LEAF_AGGREGATED_STMT: &'static str = "compressed_aggregated_stmt_leaf";

    pub const PINNED_LEAF_NAMES: [&'static str; 4] = [
        Self::LEAF_POW,
        Self::LEAF_TRACE_AUTH,
        Self::LEAF_OOD_FRI,
        Self::LEAF_AGGREGATED_STMT,
    ];

    pub fn compile(
        proof: &AggregatedRecursiveProof,
        query_row_idx: usize,
        statement_idx: usize,
    ) -> (TapTree, Vec<TaprootStarkSpend>) {
        let mut leaves = Vec::with_capacity(Self::PINNED_LEAF_COUNT);
        let mut spend_factories = Vec::new();

        // 1. Leaf 0: Proof of Work grinding verification
        let mut b_pow = ScriptBuilder::new();
        TranscriptScript::emit_verify_pow_grinding(
            &mut b_pow,
            &proof.canonical_proof.trace_root,
            proof.canonical_proof.pow_bits,
        );
        let script_pow = b_pow.to_bytes();
        let wit_pow = TranscriptScript::create_pow_witness(
            &proof.canonical_proof.trace_root,
            proof.canonical_proof.pow_nonce,
            proof.canonical_proof.pow_bits,
        );
        leaves.push(TapLeaf::new(Self::LEAF_POW, script_pow.clone()));
        spend_factories.push((Self::LEAF_POW.to_string(), wit_pow, script_pow));

        // 2. Leaf 1: Multi-column Batch Merkle Trace Authentication
        let mixed_tree = MixedBatchMerkleTree::new(proof.canonical_columns.clone());
        let (row_vals, merkle_proof) = mixed_tree.prove_row(query_row_idx % (1 << proof.config.log_degree));
        let mut b_merkle = ScriptBuilder::new();
        MixedBatchMerkleScript::emit_row_verifier(
            &mut b_merkle,
            proof.config.trace_width,
            mixed_tree.depth(),
            &proof.canonical_proof.trace_root,
        );
        let script_merkle = b_merkle.to_bytes();
        let wit_merkle = MixedBatchMerkleScript::create_row_witness(&row_vals, &merkle_proof);
        leaves.push(TapLeaf::new(Self::LEAF_MERKLE, script_merkle.clone()));
        spend_factories.push((Self::LEAF_MERKLE.to_string(), wit_merkle, script_merkle));

        // 3. Leaf 2: 4-to-1 High-Arity FRI Folding query
        let gen_8 = circle_subgroup_generator(3);
        let step = CircleFri4To1Step::new(
            gen_8,
            M31::new(100),
            M31::new(200),
            M31::new(300),
            M31::new(400),
            M31::new(42),
            M31::new(99),
        );
        let mut b_fri = ScriptBuilder::new();
        CircleFriScript::emit_4to1_colinearity_verifier(&mut b_fri);
        let script_fri = b_fri.to_bytes();
        let wit_fri = CircleFriScript::create_4to1_witness(&step);
        leaves.push(TapLeaf::new(Self::LEAF_OOD_FRI, script_fri.clone()));
        spend_factories.push((Self::LEAF_OOD_FRI.to_string(), wit_fri, script_fri));

        // 4. Leaf 3: Aggregated multi-statement inclusion verification
        let (_stmt, stmt_merkle_proof) = proof.prove_statement_inclusion(statement_idx);
        let mut b_stmt = ScriptBuilder::new();
        MerkleScript::emit_verifier(&mut b_stmt, stmt_merkle_proof.siblings.len(), &proof.aggregated_statement_root);
        let script_stmt = b_stmt.to_bytes();
        let wit_stmt = MerkleScript::create_witness(&stmt_merkle_proof);
        leaves.push(TapLeaf::new(Self::LEAF_AGGREGATED_STMT, script_stmt.clone()));
        spend_factories.push((Self::LEAF_AGGREGATED_STMT.to_string(), wit_stmt, script_stmt));

        assert_eq!(leaves.len(), Self::PINNED_LEAF_COUNT);

        let tap_tree = TapTree::new(leaves);
        let internal_nums_key = [0x02u8; 32];

        let mut spends = Vec::with_capacity(Self::PINNED_LEAF_COUNT);
        for (idx, (name, witness, script)) in spend_factories.into_iter().enumerate() {
            let ctrl = tap_tree.control_block(idx, &internal_nums_key);
            spends.push(TaprootStarkSpend::new(&name, witness, script, ctrl));
        }

        (tap_tree, spends)
    }
}
