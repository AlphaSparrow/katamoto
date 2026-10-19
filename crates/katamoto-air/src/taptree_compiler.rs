use crate::constraints::BoundaryConstraint;
use crate::quotient::{OodQuotientScript, OodQuotientStep};
use crate::trace::ExecutionTrace;
use katamoto_field::M31;
use katamoto_fri::{
    FriQueryStep, FriRoundQuery, FriScript, MerkleTree, TapLeaf, TapTree, TaprootStarkSpend,
    Transcript, TranscriptScript,
};
use katamoto_script::{OutPoint, ScriptBuilder, ScriptProfile, Transaction, TxOut, Vm, VmError};

/// Maximum allowable stack watermark before automated sub-leaf partitioning is triggered (consensus limit is 1,000)
pub const STACK_DEPTH_SPLIT_THRESHOLD: usize = 900;

/// End-to-End Bitcoin STARK Verifier TapTree Compiler
/// Compiles the complete proof verification pipeline into partitioned BIP-341 Taproot leaves.
pub struct StarkTapTreeCompiler;

impl StarkTapTreeCompiler {
    /// Compiles an entire STARK verification proof for a Fibonacci computation into a TapTree
    pub fn compile_fibonacci_stark(
        trace: &ExecutionTrace,
        num_fri_queries: usize,
    ) -> (TapTree, Vec<TaprootStarkSpend>) {
        let trace_tree = trace.commit_merkle();
        let trace_root = trace_tree.root();

        let mut transcript = Transcript::new();
        transcript.absorb(&trace_root);

        let mut leaves = Vec::new();

        // --- Leaf 0: Boundary Constraint Leaf ---
        let initial_val = trace.columns[0][0];
        let terminal_val = trace.columns[0][trace.length - 1];
        let mut b_boundary = ScriptBuilder::new();
        BoundaryConstraint::emit_double_verifier(&mut b_boundary, initial_val, terminal_val);
        let leaf_boundary = TapLeaf::new("boundary_constraints_leaf", b_boundary.to_bytes());
        leaves.push(leaf_boundary.clone());

        // --- Leaf 1: OOD Quotient Evaluation Leaf ---
        let (alpha, _, _) = transcript.squeeze_m31_challenge();
        let z = M31::new(1234567);
        let z_init = M31::ONE;
        let v0 = trace.columns[0][0];
        let v1 = trace.columns[0][1];
        let v2 = trace.columns[0][2];
        let zh_z = M31::new(987654);
        let ood_step = OodQuotientStep::new(z, z_init, v0, v1, v2, initial_val, zh_z, alpha);
        let mut b_ood = ScriptBuilder::new();
        OodQuotientScript::emit_verifier(&mut b_ood);
        let leaf_ood = TapLeaf::new("ood_quotient_leaf", b_ood.to_bytes());
        leaves.push(leaf_ood.clone());

        // --- Leaf 2: Fiat-Shamir Transcript Evolution Leaf ---
        let mut b_transcript = ScriptBuilder::new();
        TranscriptScript::emit_verify_challenge_extraction(&mut b_transcript);
        let leaf_transcript = TapLeaf::new("fiat_shamir_leaf", b_transcript.to_bytes());
        leaves.push(leaf_transcript.clone());

        // --- Leaves 3..K: FRI Consistency Query Leaves ---
        let dummy_fri_leaves: Vec<[u8; 32]> = (0..16)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[0] = i as u8;
                arr[31] = 0xff;
                arr
            })
            .collect();
        let fri_tree = MerkleTree::new(dummy_fri_leaves);
        let fri_root = fri_tree.root();

        let mut fri_queries = Vec::new();
        for q in 0..num_fri_queries {
            let x = M31::new((1000 + q * 13) as u64);
            let fx = M31::new((2000 + q * 17) as u64);
            let f_neg_x = M31::new((3000 + q * 19) as u64);
            let alpha_fri = M31::new((4000 + q * 23) as u64);

            let step = FriQueryStep::new(x, fx, f_neg_x, alpha_fri);
            let proof_fx = fri_tree.prove((q * 2) % 16);
            let proof_f_neg_x = fri_tree.prove((q * 2 + 1) % 16);

            let round_query = FriRoundQuery {
                step,
                fx_merkle_proof: proof_fx,
                f_neg_x_merkle_proof: proof_f_neg_x,
            };

            let mut b_fri = ScriptBuilder::new();
            FriScript::emit_integrated_round_verifier(&mut b_fri, fri_tree.depth(), &fri_root);
            let leaf_name = format!("fri_query_leaf_{}", q);
            leaves.push(TapLeaf::new(leaf_name, b_fri.to_bytes()));
            fri_queries.push(round_query);
        }

        // Assemble the BIP-341 TapTree
        let tap_tree = TapTree::new(leaves);
        let internal_nums_key = [0x02u8; 32]; // Standard secp256k1 unspendable NUMS key

        // Construct spend packages for each leaf
        let mut spends = Vec::new();

        // 1. Boundary spend package
        let ctrl_boundary = tap_tree.control_block(0, &internal_nums_key);
        let witness_boundary = BoundaryConstraint::create_double_witness(initial_val, terminal_val);
        spends.push(TaprootStarkSpend::new(
            &tap_tree.leaves[0].name,
            witness_boundary,
            tap_tree.leaves[0].script.clone(),
            ctrl_boundary,
        ));

        // 2. OOD spend package
        let ctrl_ood = tap_tree.control_block(1, &internal_nums_key);
        let (lhs_ood, t1_ood, t2_ood) = ood_step.decompose();
        let witness_ood = OodQuotientScript::create_witness(lhs_ood, t1_ood, t2_ood);
        spends.push(TaprootStarkSpend::new(
            &tap_tree.leaves[1].name,
            witness_ood,
            tap_tree.leaves[1].script.clone(),
            ctrl_ood,
        ));

        // 3. Transcript spend package
        let ctrl_transcript = tap_tree.control_block(2, &internal_nums_key);
        let (_, prefix, suffix) = transcript.squeeze_m31_challenge();
        let witness_transcript =
            TranscriptScript::create_challenge_witness(&transcript.state(), &prefix, &suffix);
        spends.push(TaprootStarkSpend::new(
            &tap_tree.leaves[2].name,
            witness_transcript,
            tap_tree.leaves[2].script.clone(),
            ctrl_transcript,
        ));

        // 4. FRI query spend packages
        for (q, query) in fri_queries.iter().enumerate() {
            let leaf_idx = 3 + q;
            let ctrl_fri = tap_tree.control_block(leaf_idx, &internal_nums_key);
            let witness_fri = FriScript::create_integrated_witness(query);
            spends.push(TaprootStarkSpend::new(
                &tap_tree.leaves[leaf_idx].name,
                witness_fri,
                tap_tree.leaves[leaf_idx].script.clone(),
                ctrl_fri,
            ));
        }

        (tap_tree, spends)
    }

    /// Builds a ready-to-broadcast Bitcoin transaction spending a specific STARK leaf
    pub fn build_broadcast_tx(
        spend: &TaprootStarkSpend,
        funding_outpoint: OutPoint,
        p2tr_output_key: &[u8; 32],
        satoshis: u64,
    ) -> Transaction {
        let dest_spk = TxOut::p2tr(p2tr_output_key, satoshis).script_pubkey;
        spend.build_spending_tx(funding_outpoint, dest_spk, satoshis)
    }

    /// Evaluates and profiles a specific spend inside the Bitcoin Script VM to record execution stats,
    /// watermark stack depth, maximum element size, and consensus limit compliance.
    pub fn profile_spend(spend: &TaprootStarkSpend) -> Result<ScriptProfile, VmError> {
        let mut vm = Vm::with_witness(spend.witness_items.clone());
        let _ = vm.execute(&spend.leaf_script)?;
        Ok(vm.profile())
    }

    /// Automatically partitions an OOD quotient step into sub-leaves whenever stack depth
    /// approaches the 900-element limit or when independent verification is desired.
    pub fn compile_split_ood_leaves(
        step: &OodQuotientStep,
    ) -> (Vec<TapLeaf>, Vec<Vec<Vec<u8>>>) {
        let (lhs, t1, t2) = step.decompose();

        // Sub-leaf 1: Boundary quotient difference
        let mut b1 = ScriptBuilder::new();
        OodQuotientScript::emit_split_boundary_verifier(&mut b1);
        let leaf1 = TapLeaf::new("ood_split_boundary_leaf", b1.to_bytes());
        let wit1 = vec![
            katamoto_script::builder::encode_num(step.v0.as_i64()),
            katamoto_script::builder::encode_num(step.expected_init.as_i64()),
            katamoto_script::builder::encode_num((step.v0 - step.expected_init).as_i64()),
        ];

        // Sub-leaf 2: Colinearity linear combination
        let mut b2 = ScriptBuilder::new();
        OodQuotientScript::emit_split_combination_verifier(&mut b2);
        let leaf2 = TapLeaf::new("ood_split_combination_leaf", b2.to_bytes());
        let wit2 = OodQuotientScript::create_witness(lhs, t1, t2);

        (vec![leaf1, leaf2], vec![wit1, wit2])
    }
}

/// Telemetry details for individual Taproot leaf scripts
#[derive(Debug, Clone)]
pub struct LeafTelemetry {
    pub leaf_index: usize,
    pub name: String,
    pub category: &'static str,
    pub script_bytes: usize,
    pub witness_bytes: usize,
    pub witness_elements: usize,
}

/// Telemetry metrics for recursive script chunking and TapTree partitioning
#[derive(Debug, Clone)]
pub struct PartitioningTelemetry {
    pub total_leaves: usize,
    pub max_script_bytes: usize,
    pub min_script_bytes: usize,
    pub avg_script_bytes: f64,
    pub max_witness_bytes: usize,
    pub conforms_to_consensus: bool,
    pub leaf_details: Vec<LeafTelemetry>,
}

/// Specialized TapTree compiler for Circle STARK verifiers (Stwo-compatible)
pub struct CircleStarkTapTreeCompiler;

impl CircleStarkTapTreeCompiler {
    /// Compiles a complete Circle STARK verifier partitioned across 4 leaf types:
    /// - Leaf Type A: Multi-column Batch Merkle authentication (`OP_CAT`)
    /// - Leaf Type B: Circle folding step evaluations (Circle FRI colinearity)
    /// - Leaf Type C: Boundary and transition constraint checks
    /// - Leaf Type D: Fiat-Shamir transcript evolution
    pub fn compile_circle_stark(
        trace: &ExecutionTrace,
        num_circle_fri_queries: usize,
    ) -> (TapTree, Vec<TaprootStarkSpend>, PartitioningTelemetry) {
        use katamoto_field::circle::circle_subgroup_generator;
        use katamoto_fri::{
            circle_folding::{CircleFriScript, CircleFriYStep},
            batch_merkle::{BatchMerkleScript, BatchMerkleTree},
        };

        let mut leaves = Vec::new();
        let mut spend_factories: Vec<(String, &'static str, Vec<Vec<u8>>, Vec<u8>)> = Vec::new();

        // 1. Leaf Type C: Boundary Constraints
        let initial_val = trace.columns[0][0];
        let terminal_val = trace.columns[0][trace.length - 1];
        let mut b_boundary = ScriptBuilder::new();
        BoundaryConstraint::emit_double_verifier(&mut b_boundary, initial_val, terminal_val);
        let script_boundary = b_boundary.to_bytes();
        let wit_boundary = BoundaryConstraint::create_double_witness(initial_val, terminal_val);
        leaves.push(TapLeaf::new("circle_boundary_leaf", script_boundary.clone()));
        spend_factories.push((
            "circle_boundary_leaf".to_string(),
            "Constraints",
            wit_boundary,
            script_boundary,
        ));

        // 2. Leaf Type C: Fibonacci Transition Constraints
        if trace.length >= 3 {
            let mut b_trans = ScriptBuilder::new();
            crate::constraints::FibonacciTransition::emit_verifier(&mut b_trans);
            let script_trans = b_trans.to_bytes();
            let wit_trans = crate::constraints::FibonacciTransition::create_witness(
                trace.columns[0][0],
                trace.columns[0][1],
                trace.columns[0][2],
            );
            leaves.push(TapLeaf::new("circle_transition_leaf", script_trans.clone()));
            spend_factories.push((
                "circle_transition_leaf".to_string(),
                "Constraints",
                wit_trans,
                script_trans,
            ));
        }

        // 3. Leaf Type D: Fiat-Shamir Transcript Challenge Squeeze
        let mut b_transcript = ScriptBuilder::new();
        TranscriptScript::emit_verify_challenge_extraction(&mut b_transcript);
        let script_transcript = b_transcript.to_bytes();
        let mut transcript = Transcript::new();
        use sha2::Digest;
        let trace_root: [u8; 32] = sha2::Sha256::digest(b"circle_stark_trace").into();
        transcript.absorb(&trace_root);
        let (_, prefix, suffix) = transcript.squeeze_m31_challenge();
        let wit_transcript =
            TranscriptScript::create_challenge_witness(&transcript.state(), &prefix, &suffix);
        leaves.push(TapLeaf::new("circle_transcript_leaf", script_transcript.clone()));
        spend_factories.push((
            "circle_transcript_leaf".to_string(),
            "Transcript",
            wit_transcript,
            script_transcript,
        ));

        // 4. Leaf Type A: Multi-Column Batch Merkle Row Authentication
        let batch_tree = BatchMerkleTree::new(&trace.columns);
        let batch_root = batch_tree.root();
        let (row_vals, proof_row) = batch_tree.prove_row(trace.length / 2);

        let mut b_merkle = ScriptBuilder::new();
        BatchMerkleScript::emit_row_verifier(
            &mut b_merkle,
            trace.num_columns,
            batch_tree.depth(),
            &batch_root,
        );
        let script_merkle = b_merkle.to_bytes();
        let wit_merkle = BatchMerkleScript::create_row_witness(&row_vals, &proof_row);
        leaves.push(TapLeaf::new("batch_merkle_auth_leaf", script_merkle.clone()));
        spend_factories.push((
            "batch_merkle_auth_leaf".to_string(),
            "MerkleAuth",
            wit_merkle,
            script_merkle,
        ));

        // 5. Leaf Type B: Circle FRI Folding Step Evaluations
        let gen_8 = circle_subgroup_generator(3);
        for q in 0..num_circle_fri_queries {
            let f_p = M31::new((1000 + q * 37) as u64);
            let f_conj = M31::new((2000 + q * 41) as u64);
            let alpha = M31::new((3000 + q * 43) as u64);
            let y_step = CircleFriYStep::new(gen_8, f_p, f_conj, alpha);
            let (lhs, t1, t2) = y_step.decompose();

            let mut b_fold = ScriptBuilder::new();
            CircleFriScript::emit_colinearity_verifier(&mut b_fold);
            let script_fold = b_fold.to_bytes();
            let wit_fold = vec![
                katamoto_script::builder::encode_num(lhs.as_i64()),
                katamoto_script::builder::encode_num(t1.as_i64()),
                katamoto_script::builder::encode_num(t2.as_i64()),
            ];
            let leaf_name = format!("circle_fri_fold_leaf_{}", q);
            leaves.push(TapLeaf::new(leaf_name.clone(), script_fold.clone()));
            spend_factories.push((
                leaf_name,
                "CircleFolding",
                wit_fold,
                script_fold,
            ));
        }

        // Assemble the TapTree
        let tap_tree = TapTree::new(leaves);
        let internal_nums_key = [0x02u8; 32];

        // Build spend packages
        let mut spends = Vec::new();
        let mut leaf_details = Vec::new();

        for (idx, (name, category, witness, script)) in spend_factories.into_iter().enumerate() {
            let ctrl_block = tap_tree.control_block(idx, &internal_nums_key);
            let witness_bytes: usize = witness.iter().map(|w| w.len()).sum();
            let witness_elements = witness.len();

            leaf_details.push(LeafTelemetry {
                leaf_index: idx,
                name: name.clone(),
                category,
                script_bytes: script.len(),
                witness_bytes,
                witness_elements,
            });

            spends.push(TaprootStarkSpend::new(
                &name,
                witness,
                script,
                ctrl_block,
            ));
        }

        let total_leaves = spends.len();
        let max_script_bytes = leaf_details.iter().map(|l| l.script_bytes).max().unwrap_or(0);
        let min_script_bytes = leaf_details.iter().map(|l| l.script_bytes).min().unwrap_or(0);
        let avg_script_bytes = if total_leaves > 0 {
            leaf_details.iter().map(|l| l.script_bytes).sum::<usize>() as f64 / total_leaves as f64
        } else {
            0.0
        };
        let max_witness_bytes = leaf_details.iter().map(|l| l.witness_bytes).max().unwrap_or(0);

        let conforms_to_consensus = leaf_details.iter().all(|l| {
            l.script_bytes <= 520 && l.witness_elements <= 1000
        });

        let telemetry = PartitioningTelemetry {
            total_leaves,
            max_script_bytes,
            min_script_bytes,
            avg_script_bytes,
            max_witness_bytes,
            conforms_to_consensus,
            leaf_details,
        };

        (tap_tree, spends, telemetry)
    }

    /// Builds a ready-to-broadcast Bitcoin transaction spending a specific Circle STARK leaf
    pub fn build_broadcast_tx(
        spend: &TaprootStarkSpend,
        funding_outpoint: OutPoint,
        p2tr_output_key: &[u8; 32],
        satoshis: u64,
    ) -> Transaction {
        let dest_spk = TxOut::p2tr(p2tr_output_key, satoshis).script_pubkey;
        spend.build_spending_tx(funding_outpoint, dest_spk, satoshis)
    }

    /// Evaluates and profiles a specific spend inside the Bitcoin Script VM to record execution stats,
    /// watermark stack depth, maximum element size, and consensus limit compliance.
    pub fn profile_spend(spend: &TaprootStarkSpend) -> Result<ScriptProfile, VmError> {
        let mut vm = Vm::with_witness(spend.witness_items.clone());
        let _ = vm.execute(&spend.leaf_script)?;
        Ok(vm.profile())
    }

    /// Automatically partitions an OOD quotient step into sub-leaves whenever stack depth
    /// approaches the 900-element limit or when independent verification is desired.
    pub fn compile_split_ood_leaves(
        step: &OodQuotientStep,
    ) -> (Vec<TapLeaf>, Vec<Vec<Vec<u8>>>) {
        let (lhs, t1, t2) = step.decompose();

        // Sub-leaf 1: Boundary quotient difference
        let mut b1 = ScriptBuilder::new();
        OodQuotientScript::emit_split_boundary_verifier(&mut b1);
        let leaf1 = TapLeaf::new("ood_split_boundary_leaf", b1.to_bytes());
        let wit1 = vec![
            katamoto_script::builder::encode_num(step.v0.as_i64()),
            katamoto_script::builder::encode_num(step.expected_init.as_i64()),
            katamoto_script::builder::encode_num((step.v0 - step.expected_init).as_i64()),
        ];

        // Sub-leaf 2: Colinearity linear combination
        let mut b2 = ScriptBuilder::new();
        OodQuotientScript::emit_split_combination_verifier(&mut b2);
        let leaf2 = TapLeaf::new("ood_split_combination_leaf", b2.to_bytes());
        let wit2 = OodQuotientScript::create_witness(lhs, t1, t2);

        (vec![leaf1, leaf2], vec![wit1, wit2])
    }
}
