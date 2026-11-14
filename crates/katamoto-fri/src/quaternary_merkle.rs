use katamoto_script::{builder::encode_num, ScriptBuilder};
use sha2::{Digest, Sha256};

/// Computes the parent hash of 4 children in a Quaternary Merkle Tree:
/// SHA256(c0 || c1 || c2 || c3)
pub fn hash_4_nodes(
    c0: &[u8; 32],
    c1: &[u8; 32],
    c2: &[u8; 32],
    c3: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(c0);
    hasher.update(c1);
    hasher.update(c2);
    hasher.update(c3);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// A single step in a Quaternary Merkle authentication path
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuaternaryMerkleStep {
    pub children: [[u8; 32]; 4],
    pub selector: u8, // 0..=3 indicating which child is the target node
}

/// Quaternary Merkle membership proof
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuaternaryMerkleProof {
    pub leaf: [u8; 32],
    pub steps: Vec<QuaternaryMerkleStep>,
}

/// Quaternary (4-ary) Merkle Tree.
/// Halves the tree depth compared to standard binary Merkle trees (depth = log_4(N) = log_2(N)/2),
/// cutting SHA-256 evaluation rounds in half for Circle FRI commitments.
#[derive(Debug, Clone)]
pub struct QuaternaryMerkleTree {
    pub leaves: Vec<[u8; 32]>,
    pub layers: Vec<Vec<[u8; 32]>>,
}

impl QuaternaryMerkleTree {
    /// Constructs a quaternary Merkle tree from leaves.
    /// Number of leaves must be a power of 4 (e.g. 4, 16, 64, 256, 1024, ...).
    pub fn new(leaves: Vec<[u8; 32]>) -> Self {
        assert!(leaves.len() >= 4, "Quaternary tree requires at least 4 leaves");
        assert!(
            leaves.len().is_power_of_two() && leaves.len().trailing_zeros().is_multiple_of(2),
            "Leaf count must be a power of 4 (4, 16, 64, 256, ...)"
        );

        let mut layers = Vec::new();
        layers.push(leaves.clone());

        let mut current = leaves.clone();
        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len() / 4);
            for chunk in current.as_chunks::<4>().0 {
                next.push(hash_4_nodes(&chunk[0], &chunk[1], &chunk[2], &chunk[3]));
            }
            layers.push(next.clone());
            current = next;
        }

        Self { leaves, layers }
    }

    /// Root hash of the quaternary tree
    pub fn root(&self) -> [u8; 32] {
        self.layers.last().unwrap()[0]
    }

    /// Depth of the quaternary tree (number of quaternary layers)
    pub fn depth(&self) -> usize {
        self.layers.len() - 1
    }

    /// Generates a membership proof for leaf at `index`
    pub fn prove(&self, mut index: usize) -> QuaternaryMerkleProof {
        let leaf = self.leaves[index];
        let mut steps = Vec::with_capacity(self.depth());

        for layer in &self.layers[..self.layers.len() - 1] {
            let group_start = (index / 4) * 4;
            let selector = (index % 4) as u8;
            let children = [
                layer[group_start],
                layer[group_start + 1],
                layer[group_start + 2],
                layer[group_start + 3],
            ];
            steps.push(QuaternaryMerkleStep { children, selector });
            index /= 4;
        }

        QuaternaryMerkleProof { leaf, steps }
    }
}

/// Bitcoin Script Gadget for Quaternary Merkle Tree Verification using BIP-347 OP_CAT
pub struct QuaternaryMerkleScript;

impl QuaternaryMerkleScript {
    /// Compiles Bitcoin Script verifier that authenticates a 4-ary Merkle membership path.
    ///
    /// For each layer:
    ///   Stack on entry: `[..., c_0, c_1, c_2, c_3, sel, current_hash]`
    ///   1. Swaps sel and current_hash, verifies 0 <= sel < 4 via OP_WITHIN
    ///   2. Picks c_{sel} and verifies it equals current_hash via OP_EQUALVERIFY
    ///   3. Concatenates c_0 || c_1 || c_2 || c_3 with 3 OP_CATs
    ///   4. Computes SHA256 to produce the parent hash
    ///
    /// Finally asserts computed root matches expected_root, leaving 1 (TRUE).
    pub fn emit_verifier(builder: &mut ScriptBuilder, depth: usize, expected_root: &[u8; 32]) {
        for _ in 0..depth {
            // Stack top: [..., c_0, c_1, c_2, c_3, sel, current_hash]
            builder.op_swap(); // [..., c_0, c_1, c_2, c_3, current_hash, sel]

            // Assert 0 <= sel < 4
            builder.op_dup();
            builder.push_int(0);
            builder.push_int(4);
            builder.op_within();
            builder.op_verify();

            // Depth of c_{sel} from stack top after popping pick depth is (4 - sel)
            builder.push_int(4);
            builder.op_swap();
            builder.op_sub();
            builder.push_opcode(katamoto_script::Opcode::OpPick); // [..., c_0, c_1, c_2, c_3, current_hash, c_{sel}]

            // Verify picked child equals current_hash
            builder.op_equalverify(); // [..., c_0, c_1, c_2, c_3]

            // Concatenate 4 children: (c_0 || c_1 || c_2 || c_3)
            builder.op_cat(); // c_2 || c_3
            builder.op_cat(); // c_1 || c_2 || c_3
            builder.op_cat(); // c_0 || c_1 || c_2 || c_3

            // Hash to parent
            builder.op_sha256(); // [..., parent_hash]
        }

        // Assert root matches expected_root
        builder.push_slice(expected_root);
        builder.op_equalverify();
        builder.push_int(1);
    }

    /// Prepares witness vector for execution in the Bitcoin Script VM.
    /// Pushes from depth-1 down to 0, followed by leaf hash on top.
    pub fn create_witness(proof: &QuaternaryMerkleProof) -> Vec<Vec<u8>> {
        let mut witness = Vec::new();

        // Push layers in reverse order (D-1 down to 0) so layer 0 is right under leaf
        for step in proof.steps.iter().rev() {
            witness.push(step.children[0].to_vec());
            witness.push(step.children[1].to_vec());
            witness.push(step.children[2].to_vec());
            witness.push(step.children[3].to_vec());
            witness.push(encode_num(step.selector as i64));
        }

        witness.push(proof.leaf.to_vec());
        witness
    }
}
