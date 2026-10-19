pub mod batch_merkle;
pub mod circle_folding;
pub mod folding;
pub mod merkle;
pub mod taproot;
pub mod transcript;

pub use batch_merkle::{
    BatchMerkleScript, BatchMerkleTree, MixedBatchMerkleScript, MixedBatchMerkleTree, MixedColumn,
};
pub use circle_folding::{
    CircleFriRoundQuery, CircleFriScript, CircleFriXStep, CircleFriYStep,
};
pub use folding::{FriQueryStep, FriRoundQuery, FriScript};
pub use merkle::{hash_node, MerkleProof, MerkleScript, MerkleTree};
pub use taproot::{tagged_hash, TapLeaf, TapTree, TaprootStarkSpend, TAPSCRIPT_LEAF_VERSION};
pub use transcript::{Transcript, TranscriptScript, TRANSCRIPT_INIT_SEED};

#[cfg(test)]
mod tests {
    use super::*;
    use katamoto_script::{ScriptBuilder, Vm};
    use sha2::{Digest, Sha256};

    #[test]
    fn test_merkle_tree_proof_verification_with_op_cat() {
        let mut leaves = Vec::new();
        for i in 0..16 {
            let hash = Sha256::digest(format!("execution_trace_row_{}", i).as_bytes());
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash);
            leaves.push(arr);
        }

        let tree = MerkleTree::new(leaves);
        let root = tree.root();
        assert_eq!(tree.depth(), 4);

        // Prove leaf 7
        let proof = tree.prove(7);
        assert_eq!(proof.siblings.len(), 4);

        // Build Bitcoin Script verifier with BIP-347 OP_CAT
        let mut builder = ScriptBuilder::new();
        MerkleScript::emit_verifier(&mut builder, tree.depth(), &root);

        // Setup witness stack
        let witness = MerkleScript::create_witness(&proof);

        let mut vm = Vm::with_witness(witness);
        let ok = vm.execute(builder.as_bytes()).expect("Merkle verification script failed");
        assert!(ok);
        assert_eq!(vm.stack().last().unwrap(), &[1]);

        println!(
            "Depth 4 Merkle Verification Stats: opcodes={}, max_stack_depth={}",
            vm.stats().opcodes_executed,
            vm.stats().max_stack_depth
        );
    }

    #[test]
    fn test_large_merkle_tree_depth_8() {
        let mut leaves = Vec::new();
        for i in 0..256 {
            let hash = Sha256::digest(format!("trace_{}", i).as_bytes());
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash);
            leaves.push(arr);
        }

        let tree = MerkleTree::new(leaves);
        let root = tree.root();
        assert_eq!(tree.depth(), 8);

        // Prove leaf 189
        let proof = tree.prove(189);

        let mut builder = ScriptBuilder::new();
        MerkleScript::emit_verifier(&mut builder, tree.depth(), &root);

        let witness = MerkleScript::create_witness(&proof);
        let mut vm = Vm::with_witness(witness);
        let ok = vm.execute(builder.as_bytes()).expect("Depth 8 verification failed");
        assert!(ok);

        println!(
            "Depth 8 (256 leaves) Merkle Verification Stats: opcodes={}, max_stack_depth={}",
            vm.stats().opcodes_executed,
            vm.stats().max_stack_depth
        );
    }

    #[test]
    fn test_fiat_shamir_transcript_verification_in_script() {
        let mut transcript = Transcript::new();
        let trace_root = [0x42u8; 32];
        transcript.absorb(&trace_root);

        let (challenge, prefix, suffix) = transcript.squeeze_m31_challenge();
        assert!(challenge.value() < (katamoto_field::M31_P as u32));

        // Test in Bitcoin Script:
        // 1. Absorb gadget verification:
        let initial_state = Transcript::new().state();
        let mut b1 = ScriptBuilder::new();
        b1.push_slice(&initial_state);
        b1.push_slice(&trace_root);
        TranscriptScript::emit_absorb(&mut b1);

        let mut vm1 = Vm::new();
        let ok1 = vm1.execute(b1.as_bytes()).unwrap();
        assert!(ok1);
        // After absorbing trace_root, stack has new state
        let mut expected_after_absorb = Sha256::new();
        expected_after_absorb.update(&initial_state);
        expected_after_absorb.update(&trace_root);
        assert_eq!(vm1.stack()[0], expected_after_absorb.finalize().to_vec());

        // 2. Challenge extraction verification:
        let current_state = transcript.state();
        let witness = TranscriptScript::create_challenge_witness(&current_state, &prefix, &suffix);

        let mut b2 = ScriptBuilder::new();
        TranscriptScript::emit_verify_challenge_extraction(&mut b2);

        let mut vm2 = Vm::with_witness(witness);
        let ok2 = vm2.execute(b2.as_bytes()).expect("Challenge extraction script failed");
        assert!(ok2);
        assert_eq!(vm2.stack().last().unwrap(), &[1]);
    }

    #[test]
    fn test_integrated_fri_round_verification() {
        use katamoto_field::M31;

        // Build a layer tree of 8 evaluations
        let mut leaves = Vec::new();
        for i in 0..8 {
            let hash = Sha256::digest(format!("eval_layer_{}", i).as_bytes());
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash);
            leaves.push(arr);
        }
        let tree = MerkleTree::new(leaves);
        let root = tree.root();

        // Query point: x = 12345, -x = M31_P - 12345
        let x = M31::new(12345);
        let fx = M31::new(6789);
        let f_neg_x = M31::new(4321);
        let alpha = M31::new(999);

        let step = FriQueryStep::new(x, fx, f_neg_x, alpha);

        // Prove leaf 2 (for fx) and leaf 5 (for f_neg_x)
        let proof_fx = tree.prove(2);
        let proof_f_neg_x = tree.prove(5);

        let query = FriRoundQuery {
            step,
            fx_merkle_proof: proof_fx,
            f_neg_x_merkle_proof: proof_f_neg_x,
        };

        let mut builder = ScriptBuilder::new();
        FriScript::emit_integrated_round_verifier(&mut builder, tree.depth(), &root);

        let witness = FriScript::create_integrated_witness(&query);
        let mut vm = Vm::with_witness(witness);
        let ok = vm.execute(builder.as_bytes()).expect("Integrated FRI round verification failed");
        assert!(ok);
        assert_eq!(vm.stack().last().unwrap(), &[1]);

        println!(
            "Integrated FRI Round Verifier Stats: opcodes={}, max_stack_depth={}, script_size={} B",
            vm.stats().opcodes_executed,
            vm.stats().max_stack_depth,
            builder.len()
        );
    }

    #[test]
    fn test_taproot_stark_tree_and_leaf_spend() {
        use katamoto_field::M31;

        // Leaf 0: Fiat-Shamir Transcript Leaf
        let mut transcript = Transcript::new();
        let dummy_trace_root = [0x77u8; 32];
        transcript.absorb(&dummy_trace_root);
        let (_challenge, _prefix, _suffix) = transcript.squeeze_m31_challenge();
        let mut b0 = ScriptBuilder::new();
        TranscriptScript::emit_verify_challenge_extraction(&mut b0);
        let leaf_0 = TapLeaf::new("fiat_shamir_leaf", b0.to_bytes());

        // Leaf 1: FRI Colinearity Leaf
        let x = M31::new(12345);
        let fx = M31::new(6789);
        let f_neg_x = M31::new(4321);
        let alpha = M31::new(999);
        let step = FriQueryStep::new(x, fx, f_neg_x, alpha);
        let (lhs, t1, t2) = step.decompose();
        let mut b1 = ScriptBuilder::new();
        FriScript::emit_colinearity_verifier(&mut b1);
        let leaf_1 = TapLeaf::new("fri_colinearity_leaf", b1.to_bytes());

        // Assemble TapTree containing both leaves
        let tap_tree = TapTree::new(vec![leaf_0.clone(), leaf_1.clone()]);
        let tree_root = tap_tree.root();
        assert_ne!(tree_root, [0u8; 32]);

        // Simulated internal NUMS key (H point on secp256k1)
        let internal_key = [0x02u8; 32];
        let tweak = tap_tree.tweak(&internal_key);
        assert_ne!(tweak, [0u8; 32]);

        // Generate control block for Leaf 1 (FRI Colinearity)
        let ctrl_block_1 = tap_tree.control_block(1, &internal_key);
        assert_eq!(ctrl_block_1.len(), 33 + 32); // version (1) + internal_key (32) + 1 sibling (32)

        // Generate full witness spend package
        let witness_items = FriScript::create_colinearity_witness(lhs, t1, t2);
        let spend = TaprootStarkSpend::new(
            &leaf_1.name,
            witness_items.clone(),
            leaf_1.script.clone(),
            ctrl_block_1,
        );
        assert!(spend.total_witness_size() > 0);

        // Execute Leaf 1 in the Bitcoin Script VM with its witness items
        let mut vm = Vm::with_witness(witness_items);
        let ok = vm.execute(&leaf_1.script).expect("Taproot leaf 1 execution failed");
        assert!(ok);
        assert_eq!(vm.stack().last().unwrap(), &[1]);

        println!(
            "Taproot STARK Tree Verified: TapTreeRoot={}, Witness Size={} B",
            hex::encode(tree_root),
            spend.total_witness_size()
        );

        // Build complete Bitcoin transaction spending this STARK leaf
        let funding_outpoint = katamoto_script::OutPoint::new([0x33u8; 32], 0);
        let dest_spk = katamoto_script::TxOut::op_return(b"KATAMOTO_STARK_SETTLED", 0).script_pubkey;
        let tx = spend.build_spending_tx(funding_outpoint, dest_spk, 50_000);

        assert!(tx.has_witness());
        assert!(tx.validate_consensus_limits().is_ok());
        let raw_tx_hex = tx.to_hex();
        assert!(!raw_tx_hex.is_empty());
        let rpc_req = katamoto_script::TestMempoolAccept::format_rpc_request(&raw_tx_hex);
        assert!(rpc_req.contains("testmempoolaccept"));
    }

    #[test]
    fn test_circle_fri_two_stage_folding_verification() {
        use katamoto_field::circle::circle_subgroup_generator;
        use katamoto_field::M31;

        // Domain generator of order 8
        let gen = circle_subgroup_generator(3);
        let p = gen;
        let _p_conj = p.conjugate();

        let f_p = M31::new(112233);
        let f_conj = M31::new(445566);
        let alpha = M31::new(778899);

        // 1. Stage 1: y-folding
        let y_step = CircleFriYStep::new(p, f_p, f_conj, alpha);
        let (lhs_y, t1_y, t2_y) = y_step.decompose();
        assert_eq!(lhs_y, t1_y + t2_y);

        // 2. Stage 2: x-folding
        let f_neg_x = M31::new(998877);
        let alpha_x = M31::new(332211);
        let x_step = CircleFriXStep::new(p.x, y_step.next_f, f_neg_x, alpha_x);
        let (lhs_x, t1_x, t2_x) = x_step.decompose();
        assert_eq!(lhs_x, t1_x + t2_x);

        // 3. Merkle commitments for Circle Domain evaluations
        let mut leaves = Vec::new();
        for i in 0..8 {
            let hash = Sha256::digest(format!("circle_eval_{}", i).as_bytes());
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash);
            leaves.push(arr);
        }
        let tree = MerkleTree::new(leaves);
        let root = tree.root();

        let proof_p = tree.prove(1);
        let proof_conj = tree.prove(7);

        let query = CircleFriRoundQuery {
            y_step,
            proof_p,
            proof_conj,
        };

        let mut builder = ScriptBuilder::new();
        CircleFriScript::emit_integrated_circle_round_verifier(&mut builder, tree.depth(), &root);

        let witness = CircleFriScript::create_integrated_witness(&query);
        let mut vm = Vm::with_witness(witness);
        let ok = vm.execute(builder.as_bytes()).expect("Circle FRI round execution failed");
        assert!(ok);
        assert_eq!(vm.stack().last().unwrap(), &[1]);

        println!(
            "Circle FRI Verifier: Depth={}, Script Size={} B, Opcodes={}, Max Stack={}",
            tree.depth(),
            builder.len(),
            builder.opcode_count(),
            vm.stats().max_stack_depth
        );
    }

    #[test]
    fn test_batch_merkle_tree_multi_column_verification() {
        use katamoto_field::M31;

        // 3 trace columns of length 8
        let col0: Vec<M31> = (0..8).map(|i| M31::new(i * 10)).collect();
        let col1: Vec<M31> = (0..8).map(|i| M31::new(i * 20 + 1)).collect();
        let col2: Vec<M31> = (0..8).map(|i| M31::new(i * 30 + 2)).collect();

        let batch_tree = BatchMerkleTree::new(&[col0, col1, col2]);
        assert_eq!(batch_tree.depth(), 3);
        let root = batch_tree.root();

        // Prove row 5
        let (row_vals, proof) = batch_tree.prove_row(5);
        assert_eq!(row_vals.len(), 3);
        assert_eq!(row_vals[0].value(), 50);
        assert_eq!(row_vals[1].value(), 101);
        assert_eq!(row_vals[2].value(), 152);

        // Build Bitcoin Script verifier that reconstructs leaf from 3 columns and verifies path
        let mut builder = ScriptBuilder::new();
        BatchMerkleScript::emit_row_verifier(&mut builder, 3, batch_tree.depth(), &root);

        let witness = BatchMerkleScript::create_row_witness(&row_vals, &proof);
        let mut vm = Vm::with_witness(witness);
        let ok = vm.execute(builder.as_bytes()).expect("Batch Merkle verification failed");
        assert!(ok);
        assert_eq!(vm.stack().last().unwrap(), &[1]);
    }

    #[test]
    fn test_pow_grinding_verification() {
        let transcript = Transcript::new();
        let state = transcript.state();

        // 1. Byte-aligned difficulty (8 bits = 1 leading 0x00 byte)
        let pow_bits_8 = 8;
        let nonce_8 = transcript.grind_pow(pow_bits_8);
        assert!(Transcript::verify_pow(&state, nonce_8, pow_bits_8));

        let mut builder_8 = ScriptBuilder::new();
        TranscriptScript::emit_verify_pow_grinding(&mut builder_8, &state, pow_bits_8);
        let witness_8 = TranscriptScript::create_pow_witness(&state, nonce_8, pow_bits_8);

        let mut vm_8 = Vm::with_witness(witness_8);
        let ok_8 = vm_8.execute(builder_8.as_bytes()).expect("PoW 8-bit verification failed");
        assert!(ok_8);

        // 2. Sub-byte difficulty (12 bits = 1 byte zero + high nibble zero)
        let pow_bits_12 = 12;
        let nonce_12 = transcript.grind_pow(pow_bits_12);
        assert!(Transcript::verify_pow(&state, nonce_12, pow_bits_12));

        let mut builder_12 = ScriptBuilder::new();
        TranscriptScript::emit_verify_pow_grinding(&mut builder_12, &state, pow_bits_12);
        let witness_12 = TranscriptScript::create_pow_witness(&state, nonce_12, pow_bits_12);

        let mut vm_12 = Vm::with_witness(witness_12);
        let ok_12 = vm_12.execute(builder_12.as_bytes()).expect("PoW 12-bit verification failed");
        assert!(ok_12);
    }

    #[test]
    fn test_mixed_batch_merkle_tree_multi_column_verification() {
        use katamoto_field::M31;

        // 3 columns of different lengths:
        // Col 0: log_size 4 (16 elements)
        // Col 1: log_size 3 (8 elements)
        // Col 2: log_size 2 (4 elements)
        let col0 = MixedColumn::new((0..16).map(|i| M31::new(i * 10)).collect());
        let col1 = MixedColumn::new((0..8).map(|i| M31::new(i * 20 + 1)).collect());
        let col2 = MixedColumn::new((0..4).map(|i| M31::new(i * 30 + 2)).collect());

        let mixed_tree = MixedBatchMerkleTree::new(vec![col0, col1, col2]);
        assert_eq!(mixed_tree.depth(), 4);
        assert_eq!(mixed_tree.max_log_size, 4);
        let root = mixed_tree.root();

        // Prove row index 11 (binary 1011):
        // Col 0 at: 11 >> (4 - 4) = 11 -> 110
        // Col 1 at: 11 >> (4 - 3) = 5  -> 101
        // Col 2 at: 11 >> (4 - 2) = 2  -> 62
        let (row_vals, proof) = mixed_tree.prove_row(11);
        assert_eq!(row_vals.len(), 3);
        assert_eq!(row_vals[0].value(), 110);
        assert_eq!(row_vals[1].value(), 101);
        assert_eq!(row_vals[2].value(), 62);

        let mut builder = ScriptBuilder::new();
        MixedBatchMerkleScript::emit_row_verifier(&mut builder, 3, mixed_tree.depth(), &root);

        let witness = MixedBatchMerkleScript::create_row_witness(&row_vals, &proof);
        let mut vm = Vm::with_witness(witness);
        let ok = vm.execute(builder.as_bytes()).expect("Mixed Batch Merkle verification failed");
        assert!(ok);
        assert_eq!(vm.stack().last().unwrap(), &[1]);
    }
}


