use crate::merkle::{MerkleProof, MerkleScript, MerkleTree};
use katamoto_field::M31;
use katamoto_script::ScriptBuilder;
use sha2::{Digest, Sha256};

/// Multi-column Batched Merkle Tree:
/// Commits to multiple trace columns with a single Merkle Tree.
/// Each leaf is SHA256(col_0 || col_1 || ... || col_{W-1})
#[derive(Debug, Clone)]
pub struct BatchMerkleTree {
    pub num_columns: usize,
    pub num_rows: usize,
    pub rows: Vec<Vec<M31>>,
    pub tree: MerkleTree,
}

impl BatchMerkleTree {
    /// Constructs a multi-column batched Merkle Tree from columns
    pub fn new(columns: &[Vec<M31>]) -> Self {
        assert!(!columns.is_empty(), "Columns cannot be empty");
        let num_rows = columns[0].len();
        let num_columns = columns.len();
        assert!(num_rows.is_power_of_two(), "Row count must be power of 2");

        for col in columns {
            assert_eq!(col.len(), num_rows, "All columns must have the same length");
        }

        let mut leaves = Vec::with_capacity(num_rows);
        let mut rows = Vec::with_capacity(num_rows);

        for row_idx in 0..num_rows {
            let mut row = Vec::with_capacity(num_columns);
            let mut hasher = Sha256::new();

            for col in columns {
                let elem = col[row_idx];
                row.push(elem);
                hasher.update(&elem.value().to_le_bytes());
            }

            let hash = hasher.finalize();
            let mut leaf = [0u8; 32];
            leaf.copy_from_slice(&hash);
            leaves.push(leaf);
            rows.push(row);
        }

        let tree = MerkleTree::new(leaves);

        Self {
            num_columns,
            num_rows,
            rows,
            tree,
        }
    }

    pub fn root(&self) -> [u8; 32] {
        self.tree.root()
    }

    pub fn depth(&self) -> usize {
        self.tree.depth()
    }

    /// Generates a batched row proof at given row index
    pub fn prove_row(&self, row_idx: usize) -> (Vec<M31>, MerkleProof) {
        let row_values = self.rows[row_idx].clone();
        let proof = self.tree.prove(row_idx);
        (row_values, proof)
    }
}

/// Bitcoin Script Gadget for Batched Multi-Column Merkle Authentication
pub struct BatchMerkleScript;

impl BatchMerkleScript {
    /// Emits script that:
    /// 1. Hashes the row elements via OP_CAT + OP_SHA256 to reconstruct the leaf hash
    /// 2. Verifies the Merkle inclusion path against the expected tree root
    ///
    /// Expected Witness Stack:
    /// `[merkle_siblings..., leaf_preimages (W items, 4 bytes each)]`
    pub fn emit_row_verifier(
        builder: &mut ScriptBuilder,
        num_columns: usize,
        depth: usize,
        expected_root: &[u8; 32],
    ) {
        assert!(num_columns >= 1, "Must have at least one column");

        // 1. Reconstruct leaf hash: col_0 || col_1 || ... || col_{W-1} -> OP_SHA256
        // Stack top: [col_0, col_1, ..., col_{W-1}]
        for _ in 1..num_columns {
            // Stack has items to concatenate
            builder.op_cat();
        }
        builder.op_sha256(); // leaves computed leaf_hash on stack

        // 2. Authenticate Merkle path
        MerkleScript::emit_verifier(builder, depth, expected_root);
    }

    /// Prepares witness for batched row authentication
    pub fn create_row_witness(row: &[M31], proof: &MerkleProof) -> Vec<Vec<u8>> {
        let mut witness = Vec::new();

        // 1. Merkle path siblings (pushed first, evaluated after leaf reconstruction)
        let merkle_wit = MerkleScript::create_witness(proof);
        // Note: create_witness includes proof.leaf at top; we replace it with raw column byte chunks
        for item in &merkle_wit[..merkle_wit.len() - 1] {
            witness.push(item.clone());
        }

        // 2. Row column preimages (4 bytes each, col_0 at bottom, col_{W-1} on top)
        for col in row {
            witness.push(col.value().to_le_bytes().to_vec());
        }

        witness
    }
}

/// A column with arbitrary power-of-2 length (log-size)
#[derive(Debug, Clone)]
pub struct MixedColumn {
    pub log_size: usize,
    pub values: Vec<M31>,
}

impl MixedColumn {
    pub fn new(values: Vec<M31>) -> Self {
        assert!(values.len().is_power_of_two(), "Column length must be power of 2");
        let log_size = values.len().trailing_zeros() as usize;
        Self { log_size, values }
    }
}

/// Mixed-Degree Multi-Column Merkle Tree:
/// Commits to multiple columns with potentially different log sizes (matching Stwo's mixed-degree commitments).
/// The tree depth is D_max = max(col.log_size).
/// For query index j in [0, 2^{D_max} - 1], the value of column i is col_i.values[j >> (D_max - col_i.log_size)].
#[derive(Debug, Clone)]
pub struct MixedBatchMerkleTree {
    pub columns: Vec<MixedColumn>,
    pub max_log_size: usize,
    pub tree: MerkleTree,
}

impl MixedBatchMerkleTree {
    pub fn new(columns: Vec<MixedColumn>) -> Self {
        assert!(!columns.is_empty(), "Columns cannot be empty");
        let max_log_size = columns.iter().map(|c| c.log_size).max().unwrap();
        let num_leaves = 1 << max_log_size;

        let mut leaves = Vec::with_capacity(num_leaves);
        for row_idx in 0..num_leaves {
            let mut hasher = Sha256::new();
            for col in &columns {
                let shift = max_log_size - col.log_size;
                let col_idx = row_idx >> shift;
                let elem = col.values[col_idx];
                hasher.update(&elem.value().to_le_bytes());
            }
            let hash = hasher.finalize();
            let mut leaf = [0u8; 32];
            leaf.copy_from_slice(&hash);
            leaves.push(leaf);
        }

        let tree = MerkleTree::new(leaves);
        Self {
            columns,
            max_log_size,
            tree,
        }
    }

    pub fn root(&self) -> [u8; 32] {
        self.tree.root()
    }

    pub fn depth(&self) -> usize {
        self.max_log_size
    }

    /// Evaluates row values for each column at leaf index `row_idx`
    pub fn query_row(&self, row_idx: usize) -> Vec<M31> {
        self.columns
            .iter()
            .map(|col| {
                let shift = self.max_log_size - col.log_size;
                col.values[row_idx >> shift]
            })
            .collect()
    }

    /// Generates proof for row at `row_idx` (leaf index in [0, 2^{max_log_size} - 1])
    pub fn prove_row(&self, row_idx: usize) -> (Vec<M31>, MerkleProof) {
        let row_values = self.query_row(row_idx);
        let proof = self.tree.prove(row_idx);
        (row_values, proof)
    }
}

/// Bitcoin Script Gadget for Mixed-Degree Batched Merkle Authentication
pub struct MixedBatchMerkleScript;

impl MixedBatchMerkleScript {
    pub fn emit_row_verifier(
        builder: &mut ScriptBuilder,
        num_columns: usize,
        depth: usize,
        expected_root: &[u8; 32],
    ) {
        BatchMerkleScript::emit_row_verifier(builder, num_columns, depth, expected_root);
    }

    pub fn create_row_witness(row: &[M31], proof: &MerkleProof) -> Vec<Vec<u8>> {
        BatchMerkleScript::create_row_witness(row, proof)
    }
}

