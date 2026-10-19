use katamoto_field::{qm31::QM31, M31};
use katamoto_fri::merkle::MerkleProof;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StwoProofError {
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Invalid proof format: {0}")]
    InvalidFormat(String),
    #[error("Hex decode error: {0}")]
    HexDecodeError(#[from] hex::FromHexError),
}

/// Out-of-domain (OOD) evaluations of trace and quotient polynomials
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StwoOodEvaluations {
    pub ood_point_x: QM31,
    pub ood_point_y: QM31,
    pub trace_evals: Vec<QM31>,
    pub quotient_eval: QM31,
}

/// Circle FRI query opening across rounds
#[derive(Debug, Clone)]
pub struct StwoFriQuery {
    pub query_idx: usize,
    pub f_p: M31,
    pub f_conj: M31,
    pub merkle_proof: MerkleProof,
}

/// Circle FRI proof components matching Stwo protocol
#[derive(Debug, Clone)]
pub struct StwoFriProof {
    pub round_commitments: Vec<[u8; 32]>,
    pub queries: Vec<StwoFriQuery>,
    pub final_poly_coefficients: Vec<QM31>,
}

/// Native Stwo Circle STARK proof representation for Katamoto on-chain verification
#[derive(Debug, Clone)]
pub struct StwoProof {
    pub statement_hash: [u8; 32],
    pub preprocessed_root: Option<[u8; 32]>,
    pub trace_root: [u8; 32],
    pub lookup_root: Option<[u8; 32]>,
    pub quotient_root: [u8; 32],
    pub ood_evaluations: StwoOodEvaluations,
    pub fri_proof: StwoFriProof,
    pub pow_nonce: u64,
    pub pow_bits: u32,
}

impl StwoProof {
    /// Serializes proof into compact binary format
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.statement_hash);
        
        // Flags for optionals
        let flags = (self.preprocessed_root.is_some() as u8) | ((self.lookup_root.is_some() as u8) << 1);
        buf.push(flags);

        if let Some(root) = self.preprocessed_root {
            buf.extend_from_slice(&root);
        }
        buf.extend_from_slice(&self.trace_root);
        if let Some(root) = self.lookup_root {
            buf.extend_from_slice(&root);
        }
        buf.extend_from_slice(&self.quotient_root);

        // PoW
        buf.extend_from_slice(&self.pow_nonce.to_le_bytes());
        buf.extend_from_slice(&self.pow_bits.to_le_bytes());

        // FRI round commitments count
        buf.extend_from_slice(&(self.fri_proof.round_commitments.len() as u32).to_le_bytes());
        for comm in &self.fri_proof.round_commitments {
            buf.extend_from_slice(comm);
        }

        buf
    }

    /// Encodes proof to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}
