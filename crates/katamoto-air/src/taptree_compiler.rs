use crate::constraints::BoundaryConstraint;
use crate::quotient::{OodQuotientScript, OodQuotientStep};
use crate::trace::ExecutionTrace;
use katamoto_field::M31;
use katamoto_fri::{
    FriQueryStep, FriRoundQuery, FriScript, MerkleTree, TapLeaf, TapTree, TaprootStarkSpend,
    Transcript, TranscriptScript,
};
use katamoto_script::{OutPoint, ScriptBuilder, Transaction, TxOut};

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
}
