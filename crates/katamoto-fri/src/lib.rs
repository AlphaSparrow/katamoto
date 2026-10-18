pub mod folding;
pub mod merkle;
pub mod taproot;
pub mod transcript;

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
    }
}
