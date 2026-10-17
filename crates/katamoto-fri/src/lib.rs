pub mod folding;
pub mod merkle;

pub use folding::{FriQueryStep, FriScript};
pub use merkle::{hash_node, MerkleProof, MerkleScript, MerkleTree};

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
}
