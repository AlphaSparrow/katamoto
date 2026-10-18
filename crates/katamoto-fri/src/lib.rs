pub mod folding;
pub mod merkle;
pub mod transcript;

pub use folding::{FriQueryStep, FriScript};
pub use merkle::{hash_node, MerkleProof, MerkleScript, MerkleTree};
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
}
