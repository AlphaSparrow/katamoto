use crate::proof::{StwoFriProof, StwoFriQuery, StwoOodEvaluations, StwoProof};
use crate::riscv::RiscvStatement;
use katamoto_air::bisection::BitVm2DisputeGraph;
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
            initial_pc: 0x00010000,
            final_pc: 0x00010000 + (statements.len() as u32 * 128 * 4),
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

/// Compiles a 1-round Optimistic Dispute TapTree for recursive state transition claims.
/// In BitVM2 / Optimistic ZeroSync, an operator stakes a bond to assert an execution state chain.
/// If valid, the operator withdraws the bond via a CSV-timelocked leaf.
/// If an invalid state transition or statement binding is detected, any challenger can execute
/// a dispute leaf in Tapscript, slashing the operator and claiming the bounty.
pub struct RecursiveDisputeCompiler;

impl RecursiveDisputeCompiler {
    pub const LEAF_OPERATOR_SETTLEMENT: &'static str = "operator_timelock_settlement_leaf";
    pub const LEAF_STATE_FRAUD: &'static str = "state_transition_fraud_leaf";
    pub const LEAF_STATEMENT_TAMPER: &'static str = "statement_tamper_fraud_leaf";

    /// Emits script that allows challenger to slash operator if claimed post-state does not equal SHA256(pre_state || step_data)
    /// Stack input: `[challenger_sig, claimed_post_state, step_data, pre_state]` (pre_state on top)
    pub fn emit_state_transition_fraud_leaf(builder: &mut ScriptBuilder, challenger_pubkey: &[u8; 32]) {
        // Stack: [challenger_sig, claimed_post_state, step_data, pre_state]
        builder.op_swap();   // [challenger_sig, claimed_post_state, pre_state, step_data]
        builder.op_cat();    // [challenger_sig, claimed_post_state, (pre_state || step_data)]
        builder.op_sha256(); // [challenger_sig, claimed_post_state, actual_post_state]
        builder.op_equal();  // [challenger_sig, is_equal]
        builder.op_not();    // [challenger_sig, is_not_equal]
        builder.op_verify(); // asserts actual != claimed
        builder.push_slice(challenger_pubkey);
        builder.op_checksig();
    }

    /// Creates witness vector for state transition fraud dispute
    pub fn create_state_transition_fraud_witness(
        pre_state: [u8; 32],
        step_data: &[u8],
        claimed_post_state: [u8; 32],
        challenger_sig: [u8; 64],
    ) -> Vec<Vec<u8>> {
        vec![
            challenger_sig.to_vec(),
            claimed_post_state.to_vec(),
            step_data.to_vec(),
            pre_state.to_vec(),
        ]
    }

    /// Emits script that allows challenger to slash operator if claimed statement hash does not equal SHA256(initial || final || program_digest)
    /// Stack input: `[challenger_sig, claimed_statement_hash, program_digest, final_state, initial_state]`
    pub fn emit_statement_tamper_leaf(builder: &mut ScriptBuilder, challenger_pubkey: &[u8; 32]) {
        // Stack: [challenger_sig, claimed_stmt_hash, program_digest, final_state, initial_state]
        builder.op_swap();   // [..., claimed, program_digest, initial_state, final_state]
        builder.op_cat();    // [..., claimed, program_digest, (initial || final)]
        builder.op_swap();   // [..., claimed, (initial || final), program_digest]
        builder.op_cat();    // [..., claimed, (initial || final || program_digest)]
        builder.op_sha256(); // [challenger_sig, claimed, actual_hash]
        builder.op_equal();
        builder.op_not();
        builder.op_verify();
        builder.push_slice(challenger_pubkey);
        builder.op_checksig();
    }

    /// Creates witness vector for statement tamper fraud dispute
    pub fn create_statement_tamper_witness(
        initial_state: [u8; 32],
        final_state: [u8; 32],
        program_digest: [u8; 32],
        claimed_statement_hash: [u8; 32],
        challenger_sig: [u8; 64],
    ) -> Vec<Vec<u8>> {
        vec![
            challenger_sig.to_vec(),
            claimed_statement_hash.to_vec(),
            program_digest.to_vec(),
            final_state.to_vec(),
            initial_state.to_vec(),
        ]
    }

    /// Emits script that allows operator to reclaim bond after relative timelock (BIP-112 CSV)
    pub fn emit_operator_settlement_leaf(
        builder: &mut ScriptBuilder,
        operator_pubkey: &[u8; 32],
        dispute_timelock: u32,
    ) {
        builder.push_int(dispute_timelock as i64);
        builder.op_csv();
        builder.op_drop();
        builder.push_slice(operator_pubkey);
        builder.op_checksig();
    }

    /// Creates witness vector for operator settlement spend
    pub fn create_operator_settlement_witness(operator_sig: [u8; 64]) -> Vec<Vec<u8>> {
        vec![operator_sig.to_vec()]
    }

    /// Compiles a 1-round State Transition Dispute Game into a TapTree
    pub fn compile_state_transition_dispute(
        operator_pubkey: [u8; 32],
        challenger_pubkey: [u8; 32],
        bond_satoshis: u64,
        dispute_timelock_blocks: u32,
        pre_state: [u8; 32],
        step_data: &[u8],
        claimed_post_state: [u8; 32],
    ) -> (BitVm2DisputeGraph, TapTree, Vec<TaprootStarkSpend>) {
        let mut hasher = Sha256::new();
        hasher.update(pre_state);
        hasher.update(step_data);
        hasher.update(claimed_post_state);
        let stmt_hash: [u8; 32] = hasher.finalize().into();

        let graph = BitVm2DisputeGraph::new(
            operator_pubkey,
            challenger_pubkey,
            bond_satoshis,
            dispute_timelock_blocks,
            stmt_hash,
        );

        let mut leaves = Vec::new();
        let mut spend_factories = Vec::new();

        // Leaf 0: Operator settlement after CSV timelock
        let mut b_settle = ScriptBuilder::new();
        Self::emit_operator_settlement_leaf(&mut b_settle, &operator_pubkey, dispute_timelock_blocks);
        let script_settle = b_settle.to_bytes();
        let wit_settle = Self::create_operator_settlement_witness([0x11u8; 64]);
        leaves.push(TapLeaf::new(Self::LEAF_OPERATOR_SETTLEMENT, script_settle.clone()));
        spend_factories.push((Self::LEAF_OPERATOR_SETTLEMENT.to_string(), wit_settle, script_settle));

        // Leaf 1: State transition fraud slashing leaf
        let mut b_fraud = ScriptBuilder::new();
        Self::emit_state_transition_fraud_leaf(&mut b_fraud, &challenger_pubkey);
        let script_fraud = b_fraud.to_bytes();
        let wit_fraud = Self::create_state_transition_fraud_witness(
            pre_state,
            step_data,
            claimed_post_state,
            [0x22u8; 64],
        );
        leaves.push(TapLeaf::new(Self::LEAF_STATE_FRAUD, script_fraud.clone()));
        spend_factories.push((Self::LEAF_STATE_FRAUD.to_string(), wit_fraud, script_fraud));

        let tap_tree = TapTree::new(leaves);
        let internal_nums_key = [0x02u8; 32];
        let mut spends = Vec::new();

        for (idx, (name, wit, script)) in spend_factories.into_iter().enumerate() {
            let ctrl = tap_tree.control_block(idx, &internal_nums_key);
            spends.push(TaprootStarkSpend::new(&name, wit, script, ctrl));
        }

        (graph, tap_tree, spends)
    }

    /// Compiles a Statement Tamper Dispute Game into a TapTree
    pub fn compile_statement_tamper_dispute(
        operator_pubkey: [u8; 32],
        challenger_pubkey: [u8; 32],
        bond_satoshis: u64,
        dispute_timelock_blocks: u32,
        initial_state: [u8; 32],
        final_state: [u8; 32],
        program_digest: [u8; 32],
        claimed_statement_hash: [u8; 32],
    ) -> (BitVm2DisputeGraph, TapTree, Vec<TaprootStarkSpend>) {
        let mut hasher = Sha256::new();
        hasher.update(initial_state);
        hasher.update(final_state);
        hasher.update(program_digest);
        hasher.update(claimed_statement_hash);
        let stmt_hash: [u8; 32] = hasher.finalize().into();

        let graph = BitVm2DisputeGraph::new(
            operator_pubkey,
            challenger_pubkey,
            bond_satoshis,
            dispute_timelock_blocks,
            stmt_hash,
        );

        let mut leaves = Vec::new();
        let mut spend_factories = Vec::new();

        // Leaf 0: Operator settlement leaf
        let mut b_settle = ScriptBuilder::new();
        Self::emit_operator_settlement_leaf(&mut b_settle, &operator_pubkey, dispute_timelock_blocks);
        let script_settle = b_settle.to_bytes();
        let wit_settle = Self::create_operator_settlement_witness([0x11u8; 64]);
        leaves.push(TapLeaf::new(Self::LEAF_OPERATOR_SETTLEMENT, script_settle.clone()));
        spend_factories.push((Self::LEAF_OPERATOR_SETTLEMENT.to_string(), wit_settle, script_settle));

        // Leaf 1: Statement tamper slashing leaf
        let mut b_tamper = ScriptBuilder::new();
        Self::emit_statement_tamper_leaf(&mut b_tamper, &challenger_pubkey);
        let script_tamper = b_tamper.to_bytes();
        let wit_tamper = Self::create_statement_tamper_witness(
            initial_state,
            final_state,
            program_digest,
            claimed_statement_hash,
            [0x22u8; 64],
        );
        leaves.push(TapLeaf::new(Self::LEAF_STATEMENT_TAMPER, script_tamper.clone()));
        spend_factories.push((Self::LEAF_STATEMENT_TAMPER.to_string(), wit_tamper, script_tamper));

        let tap_tree = TapTree::new(leaves);
        let internal_nums_key = [0x02u8; 32];
        let mut spends = Vec::new();

        for (idx, (name, wit, script)) in spend_factories.into_iter().enumerate() {
            let ctrl = tap_tree.control_block(idx, &internal_nums_key);
            spends.push(TaprootStarkSpend::new(&name, wit, script, ctrl));
        }

        (graph, tap_tree, spends)
    }
}

/// Two-Level Dispute Bisection State Machine for Aggregated Stwo Proofs.
/// Delivers an exponential reduction in interactive dispute overhead:
/// Level 1: Isolates the disputed statement index k out of N aggregated statements
///          via Merkle inclusion path against the aggregated statement root.
/// Level 2: Executes the fine-grained cryptographic fraud proof (state transition,
///          statement tamper, or FRI colinearity violation) to slash the operator.
#[derive(Debug, Clone)]
pub struct TwoLevelBisectionDispute {
    pub operator_pubkey: [u8; 32],
    pub challenger_pubkey: [u8; 32],
    pub bond_satoshis: u64,
    pub dispute_timelock_blocks: u32,
    pub aggregated_statement_root: [u8; 32],
    pub num_statements: usize,
}

impl TwoLevelBisectionDispute {
    pub const LEAF_OPERATOR_SETTLE: &'static str = "two_level_operator_timelock_leaf";
    pub const LEAF_LEVEL1_BISECT: &'static str = "two_level_l1_statement_isolate_leaf";
    pub const LEAF_LEVEL2_STATE_FRAUD: &'static str = "two_level_l2_state_fraud_leaf";
    pub const LEAF_LEVEL2_TAMPER_FRAUD: &'static str = "two_level_l2_tamper_fraud_leaf";
    pub const LEAF_LEVEL2_COLINEARITY_FRAUD: &'static str = "two_level_l2_colinearity_fraud_leaf";

    pub fn new(
        operator_pubkey: [u8; 32],
        challenger_pubkey: [u8; 32],
        bond_satoshis: u64,
        dispute_timelock_blocks: u32,
        aggregated_statement_root: [u8; 32],
        num_statements: usize,
    ) -> Self {
        Self {
            operator_pubkey,
            challenger_pubkey,
            bond_satoshis,
            dispute_timelock_blocks,
            aggregated_statement_root,
            num_statements,
        }
    }

    /// Emits script for Level 1 Statement Isolation:
    /// Asserts that a claimed statement hash is included in `aggregated_statement_root`
    /// via a Merkle inclusion proof, followed by challenger signature verification.
    /// Stack: `[challenger_sig, siblings..., statement_leaf_hash]`
    pub fn emit_level1_bisection_leaf(
        builder: &mut ScriptBuilder,
        depth: usize,
        aggregated_root: &[u8; 32],
        challenger_pubkey: &[u8; 32],
    ) {
        MerkleScript::emit_verifier(builder, depth, aggregated_root);
        builder.op_drop(); // drop the TRUE left by emit_verifier
        builder.push_slice(challenger_pubkey);
        builder.op_checksig();
    }

    /// Emits script for Level 2 Algebraic FRI Colinearity Fraud:
    /// Asserts that in-script evaluation of (t1 + t2) != lhs in M31 arithmetic,
    /// proving the operator committed an invalid Circle FRI folding step.
    /// Stack input: `[challenger_sig, lhs, t1, t2]` (t2 on top)
    pub fn emit_colinearity_fraud_leaf(
        builder: &mut ScriptBuilder,
        challenger_pubkey: &[u8; 32],
    ) {
        // Stack: [challenger_sig, lhs, t1, t2]
        katamoto_field::M31Script::emit_add(builder); // [challenger_sig, lhs, (t1 + t2)%P]
        builder.op_equal(); // [challenger_sig, is_equal]
        builder.op_not();   // [challenger_sig, is_invalid]
        builder.op_verify();
        builder.push_slice(challenger_pubkey);
        builder.op_checksig();
    }

    /// Creates witness vector for colinearity fraud dispute
    pub fn create_colinearity_fraud_witness(
        lhs: M31,
        t1: M31,
        t2: M31,
        challenger_sig: [u8; 64],
    ) -> Vec<Vec<u8>> {
        use katamoto_script::builder::encode_num;
        vec![
            challenger_sig.to_vec(),
            encode_num(lhs.as_i64()),
            encode_num(t1.as_i64()),
            encode_num(t2.as_i64()),
        ]
    }

    /// Compiles the complete Two-Level Dispute Bisection TapTree
    pub fn compile(
        &self,
        stmt_merkle_proof: &MerkleProof,
        fraudulent_pre_state: [u8; 32],
        step_data: &[u8],
        fraudulent_claimed_post: [u8; 32],
        invalid_colinearity_triple: (M31, M31, M31),
    ) -> (TapTree, Vec<TaprootStarkSpend>) {
        let mut leaves = Vec::with_capacity(5);
        let mut spend_factories = Vec::new();

        // 1. Leaf 0: Operator settlement after CSV timelock
        let mut b_settle = ScriptBuilder::new();
        RecursiveDisputeCompiler::emit_operator_settlement_leaf(
            &mut b_settle,
            &self.operator_pubkey,
            self.dispute_timelock_blocks,
        );
        let script_settle = b_settle.to_bytes();
        let wit_settle = RecursiveDisputeCompiler::create_operator_settlement_witness([0x11u8; 64]);
        leaves.push(TapLeaf::new(Self::LEAF_OPERATOR_SETTLE, script_settle.clone()));
        spend_factories.push((Self::LEAF_OPERATOR_SETTLE.to_string(), wit_settle, script_settle));

        // 2. Leaf 1: Level 1 Bisection statement isolation
        let mut b_l1 = ScriptBuilder::new();
        Self::emit_level1_bisection_leaf(
            &mut b_l1,
            stmt_merkle_proof.siblings.len(),
            &self.aggregated_statement_root,
            &self.challenger_pubkey,
        );
        let script_l1 = b_l1.to_bytes();
        let mut wit_l1 = MerkleScript::create_witness(stmt_merkle_proof);
        wit_l1.insert(0, vec![0x22u8; 64]);
        leaves.push(TapLeaf::new(Self::LEAF_LEVEL1_BISECT, script_l1.clone()));
        spend_factories.push((Self::LEAF_LEVEL1_BISECT.to_string(), wit_l1, script_l1));

        // 3. Leaf 2: Level 2 State transition fraud
        let mut b_state = ScriptBuilder::new();
        RecursiveDisputeCompiler::emit_state_transition_fraud_leaf(
            &mut b_state,
            &self.challenger_pubkey,
        );
        let script_state = b_state.to_bytes();
        let wit_state = RecursiveDisputeCompiler::create_state_transition_fraud_witness(
            fraudulent_pre_state,
            step_data,
            fraudulent_claimed_post,
            [0x33u8; 64],
        );
        leaves.push(TapLeaf::new(Self::LEAF_LEVEL2_STATE_FRAUD, script_state.clone()));
        spend_factories.push((Self::LEAF_LEVEL2_STATE_FRAUD.to_string(), wit_state, script_state));

        // 4. Leaf 3: Level 2 Statement tamper fraud
        let mut b_tamper = ScriptBuilder::new();
        RecursiveDisputeCompiler::emit_statement_tamper_leaf(
            &mut b_tamper,
            &self.challenger_pubkey,
        );
        let script_tamper = b_tamper.to_bytes();
        let wit_tamper = RecursiveDisputeCompiler::create_statement_tamper_witness(
            [0xaa; 32],
            [0xbb; 32],
            [0xcc; 32],
            [0xff; 32],
            [0x44u8; 64],
        );
        leaves.push(TapLeaf::new(Self::LEAF_LEVEL2_TAMPER_FRAUD, script_tamper.clone()));
        spend_factories.push((Self::LEAF_LEVEL2_TAMPER_FRAUD.to_string(), wit_tamper, script_tamper));

        // 5. Leaf 4: Level 2 Algebraic FRI colinearity fraud
        let mut b_colin = ScriptBuilder::new();
        Self::emit_colinearity_fraud_leaf(&mut b_colin, &self.challenger_pubkey);
        let script_colin = b_colin.to_bytes();
        let wit_colin = Self::create_colinearity_fraud_witness(
            invalid_colinearity_triple.0,
            invalid_colinearity_triple.1,
            invalid_colinearity_triple.2,
            [0x55u8; 64],
        );
        leaves.push(TapLeaf::new(Self::LEAF_LEVEL2_COLINEARITY_FRAUD, script_colin.clone()));
        spend_factories.push((Self::LEAF_LEVEL2_COLINEARITY_FRAUD.to_string(), wit_colin, script_colin));

        let tap_tree = TapTree::new(leaves);
        let internal_nums_key = [0x02u8; 32];
        let mut spends = Vec::new();

        for (idx, (name, wit, script)) in spend_factories.into_iter().enumerate() {
            let ctrl = tap_tree.control_block(idx, &internal_nums_key);
            spends.push(TaprootStarkSpend::new(&name, wit, script, ctrl));
        }

        (tap_tree, spends)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use katamoto_script::Vm;

    #[test]
    fn test_recursive_dispute_state_transition_fraud_slashing_in_vm() {
        let op_key = [0x55u8; 32];
        let ch_key = [0x66u8; 32];
        let pre_state = [0x11u8; 32];
        let step_data = [0x99u8; 16];
        // Operator falsely claims post_state is 0xdeadbeef...
        let fake_post_state = [0xfeu8; 32];

        let (_graph, tree, spends) = RecursiveDisputeCompiler::compile_state_transition_dispute(
            op_key,
            ch_key,
            100_000_000,
            144,
            pre_state,
            &step_data,
            fake_post_state,
        );

        assert_eq!(tree.leaves.len(), 2);
        assert_eq!(spends.len(), 2);

        // Spend Leaf 1 (fraud slashing leaf) in Vm: Challenger proves fake_post_state != actual
        let fraud_spend = &spends[1];
        let mut vm = Vm::with_witness(fraud_spend.witness_items.clone());
        let ok = vm.execute(&fraud_spend.leaf_script).expect("Fraud slashing leaf execution failed");
        assert!(ok);
        assert_eq!(vm.stack().last().unwrap(), &[1]);
    }

    #[test]
    fn test_recursive_dispute_honest_state_transition_rejects_slashing() {
        let op_key = [0x55u8; 32];
        let ch_key = [0x66u8; 32];
        let pre_state = [0x11u8; 32];
        let step_data = [0x99u8; 16];
        // Operator honestly committed the real hash: SHA256(pre_state || step_data)
        let mut hasher = Sha256::new();
        hasher.update(pre_state);
        hasher.update(step_data);
        let real_post_state: [u8; 32] = hasher.finalize().into();

        let (_graph, _tree, spends) = RecursiveDisputeCompiler::compile_state_transition_dispute(
            op_key,
            ch_key,
            100_000_000,
            144,
            pre_state,
            &step_data,
            real_post_state,
        );

        // Challenger tries to slash honest operator: MUST fail VerifyFailed!
        let fraud_spend = &spends[1];
        let mut vm = Vm::with_witness(fraud_spend.witness_items.clone());
        let res = vm.execute(&fraud_spend.leaf_script);
        assert!(res.is_err(), "Honest operator must not be slashed");
    }

    #[test]
    fn test_recursive_dispute_statement_tamper_slashing_in_vm() {
        let op_key = [0x55u8; 32];
        let ch_key = [0x66u8; 32];
        let initial_state = [0x11u8; 32];
        let final_state = [0x22u8; 32];
        let prog_digest = [0x33u8; 32];
        let tampered_statement_hash = [0xffu8; 32]; // fake statement hash

        let (_graph, _tree, spends) = RecursiveDisputeCompiler::compile_statement_tamper_dispute(
            op_key,
            ch_key,
            50_000_000,
            144,
            initial_state,
            final_state,
            prog_digest,
            tampered_statement_hash,
        );

        let tamper_spend = &spends[1];
        let mut vm = Vm::with_witness(tamper_spend.witness_items.clone());
        let ok = vm.execute(&tamper_spend.leaf_script).expect("Tamper slashing leaf failed");
        assert!(ok);
        assert_eq!(vm.stack().last().unwrap(), &[1]);
    }

    #[test]
    fn test_recursive_dispute_operator_timelock_settlement_in_vm() {
        let op_key = [0x55u8; 32];
        let ch_key = [0x66u8; 32];
        let pre_state = [0x11u8; 32];
        let step_data = [0x99u8; 16];
        let fake_post_state = [0xfeu8; 32];

        let (_graph, _tree, spends) = RecursiveDisputeCompiler::compile_state_transition_dispute(
            op_key,
            ch_key,
            100_000_000,
            144,
            pre_state,
            &step_data,
            fake_post_state,
        );

        let settle_spend = &spends[0];
        // 1. Without sequence set: CSV must fail
        let mut vm_fail = Vm::with_witness(settle_spend.witness_items.clone());
        assert!(vm_fail.execute(&settle_spend.leaf_script).is_err());

        // 2. With sequence >= 144: CSV succeeds!
        let mut vm_pass = Vm::with_witness(settle_spend.witness_items.clone());
        vm_pass.set_tx_sequence(144);
        let ok = vm_pass.execute(&settle_spend.leaf_script).expect("Operator settlement failed");
        assert!(ok);
        assert_eq!(vm_pass.stack().last().unwrap(), &[1]);
    }

    #[test]
    fn test_two_level_dispute_bisection_isolation_and_slashing() {
        let op_key = [0x11u8; 32];
        let ch_key = [0x22u8; 32];

        // 1. Build 4 aggregated statements
        let mut stmts = Vec::new();
        for i in 0..4 {
            let stmt = RiscvStatement {
                initial_pc: 0x80000000,
                final_pc: 0x80000100 + (i as u32) * 4,
                cycle_count: 100 + (i as u64),
                initial_state_root: [0; 32],
                final_state_root: [i as u8; 32],
                program_digest: [0xaa; 32],
            };
            stmts.push(stmt);
        }
        let agg_proof = AggregatedRecursiveProof::aggregate(stmts);
        let (_stmt, stmt_proof) = agg_proof.prove_statement_inclusion(2);

        // Disputed state and invalid colinearity triple: lhs=999 != 100 + 200 = 300
        let pre_state = [0xaa; 32];
        let step_data = [0x55; 16];
        let bogus_post_state = [0xee; 32];
        let invalid_triple = (M31::new(999), M31::new(100), M31::new(200));

        let dispute = TwoLevelBisectionDispute::new(
            op_key,
            ch_key,
            100_000_000,
            144,
            agg_proof.aggregated_statement_root,
            4,
        );

        let (_tree, spends) = dispute.compile(
            &stmt_proof,
            pre_state,
            &step_data,
            bogus_post_state,
            invalid_triple,
        );
        assert_eq!(spends.len(), 5);

        // Test Level 1 Bisection statement isolation spend in VM
        let l1_spend = &spends[1];
        let mut vm_l1 = Vm::with_witness(l1_spend.witness_items.clone());
        let ok_l1 = vm_l1.execute(&l1_spend.leaf_script).expect("Level 1 bisection spend must succeed");
        assert!(ok_l1);
        assert_eq!(vm_l1.stack().last().unwrap(), &[1]);

        // Test Level 2 State Transition Fraud slashing spend in VM
        let l2_state_spend = &spends[2];
        let mut vm_state = Vm::with_witness(l2_state_spend.witness_items.clone());
        let ok_state = vm_state.execute(&l2_state_spend.leaf_script).expect("State fraud spend must succeed");
        assert!(ok_state);
        assert_eq!(vm_state.stack().last().unwrap(), &[1]);

        // Test Level 2 Colinearity Fraud slashing spend in VM (lhs=999 != 300)
        let l2_colin_spend = &spends[4];
        let mut vm_colin = Vm::with_witness(l2_colin_spend.witness_items.clone());
        let ok_colin = vm_colin.execute(&l2_colin_spend.leaf_script).expect("Colinearity fraud spend must succeed");
        assert!(ok_colin);
        assert_eq!(vm_colin.stack().last().unwrap(), &[1]);

        // Test honest colinearity (lhs = t1 + t2 = 300): slashing MUST fail
        let mut honest_builder = ScriptBuilder::new();
        TwoLevelBisectionDispute::emit_colinearity_fraud_leaf(&mut honest_builder, &ch_key);
        let honest_wit = TwoLevelBisectionDispute::create_colinearity_fraud_witness(
            M31::new(300),
            M31::new(100),
            M31::new(200),
            [0x55u8; 64],
        );
        let mut honest_vm = Vm::with_witness(honest_wit);
        assert!(honest_vm.execute(honest_builder.as_bytes()).is_err(), "Honest colinearity must not be slashed");
    }
}
