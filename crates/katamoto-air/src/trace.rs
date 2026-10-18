use katamoto_field::M31;
use katamoto_fri::MerkleTree;
use sha2::{Digest, Sha256};

/// Execution Trace matrix for an Algebraic Intermediate Representation (AIR)
#[derive(Debug, Clone)]
pub struct ExecutionTrace {
    pub num_columns: usize,
    pub length: usize, // Must be power of 2
    pub columns: Vec<Vec<M31>>,
}

impl ExecutionTrace {
    pub fn new(columns: Vec<Vec<M31>>) -> Self {
        assert!(!columns.is_empty(), "Trace must contain at least one column");
        let len = columns[0].len();
        assert!(len.is_power_of_two(), "Trace length must be a power of 2");
        for col in &columns {
            assert_eq!(col.len(), len, "All columns must have the same length");
        }
        Self {
            num_columns: columns.len(),
            length: len,
            columns,
        }
    }

    /// Generates a valid Fibonacci state machine trace of length N:
    ///   row 0: F_0 = a0
    ///   row 1: F_1 = a1
    ///   row i: F_i = F_{i-1} + F_{i-2} mod M31_P
    pub fn generate_fibonacci(length: usize, a0: u32, a1: u32) -> Self {
        assert!(length.is_power_of_two(), "Length must be a power of 2");
        assert!(length >= 4, "Length must be at least 4");

        let mut row = Vec::with_capacity(length);
        row.push(M31::new(a0 as u64));
        row.push(M31::new(a1 as u64));

        for i in 2..length {
            let next = row[i - 1] + row[i - 2];
            row.push(next);
        }

        Self::new(vec![row])
    }

    /// Returns row slice at given index
    pub fn get_row(&self, index: usize) -> Vec<M31> {
        self.columns.iter().map(|col| col[index]).collect()
    }

    /// Computes Merkle Tree commitment to the trace:
    /// Each leaf is SHA256(column_0 || column_1 || ...)
    pub fn commit_merkle(&self) -> MerkleTree {
        let mut leaves = Vec::with_capacity(self.length);
        for row_idx in 0..self.length {
            let mut hasher = Sha256::new();
            for col in &self.columns {
                hasher.update(&col[row_idx].value().to_le_bytes());
            }
            let hash = hasher.finalize();
            let mut leaf = [0u8; 32];
            leaf.copy_from_slice(&hash);
            leaves.push(leaf);
        }
        MerkleTree::new(leaves)
    }
}
