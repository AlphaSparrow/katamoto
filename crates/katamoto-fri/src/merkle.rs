use katamoto_script::{Opcode, ScriptBuilder};
use sha2::{Digest, Sha256};

pub fn hash_node(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub leaf: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
    pub directions: Vec<bool>, // false = leaf is left, true = leaf is right
}

#[derive(Debug, Clone)]
pub struct MerkleTree {
    pub leaves: Vec<[u8; 32]>,
    pub layers: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    pub fn new(leaves: Vec<[u8; 32]>) -> Self {
        assert!(!leaves.is_empty(), "Leaves cannot be empty");
        assert!(leaves.len().is_power_of_two(), "Leaf count must be power of 2");

        let mut layers = Vec::new();
        layers.push(leaves.clone());

        let mut current = leaves.clone();
        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len() / 2);
            for chunk in current.chunks_exact(2) {
                next.push(hash_node(&chunk[0], &chunk[1]));
            }
            layers.push(next.clone());
            current = next;
        }

        Self { leaves, layers }
    }

    pub fn root(&self) -> [u8; 32] {
        self.layers.last().unwrap()[0]
    }

    pub fn depth(&self) -> usize {
        self.layers.len() - 1
    }

    pub fn prove(&self, mut index: usize) -> MerkleProof {
        let leaf = self.leaves[index];
        let mut siblings = Vec::new();
        let mut directions = Vec::new();

        for layer in &self.layers[..self.layers.len() - 1] {
            let is_right = (index % 2) == 1;
            let sibling_idx = if is_right { index - 1 } else { index + 1 };
            siblings.push(layer[sibling_idx]);
            directions.push(is_right);
            index /= 2;
        }

        MerkleProof {
            leaf,
            siblings,
            directions,
        }
    }
}

pub struct MerkleScript;

impl MerkleScript {
    /// Compiles a Bitcoin Script verifier that authenticates a Merkle membership path using BIP-347 OP_CAT.
    ///
    /// Expected Witness Stack:
    /// `[leaf_hash, sibling_0, dir_0, sibling_1, dir_1, ..., sibling_{D-1}, dir_{D-1}]`
    ///
    /// Script checks the path against the expected root hardcoded or on stack, and leaves TRUE if valid.
    pub fn emit_verifier(builder: &mut ScriptBuilder, depth: usize, expected_root: &[u8; 32]) {
        for _ in 0..depth {
            // Stack top has: `[..., current_hash, sibling, dir]`
            builder.op_if();
            // dir == 1: current is right child -> parent = SHA256(sibling || current)
            builder.op_swap();
            builder.op_cat();
            builder.op_sha256();
            builder.op_else();
            // dir == 0: current is left child -> parent = SHA256(current || sibling)
            builder.op_cat();
            builder.op_sha256();
            builder.op_endif();
        }

        // Stack now has: `[computed_root]`
        builder.push_slice(expected_root);
        builder.op_equalverify();
        builder.push_int(1); // leaves TRUE on stack
    }

    /// Prepares the witness vector for execution in the VM
    pub fn create_witness(proof: &MerkleProof) -> Vec<Vec<u8>> {
        use katamoto_script::builder::encode_num;
        let mut witness = Vec::new();
        witness.push(proof.leaf.to_vec());
        for i in 0..proof.siblings.len() {
            witness.push(proof.siblings[i].to_vec());
            witness.push(encode_num(if proof.directions[i] { 1 } else { 0 }));
        }
        witness
    }
}
