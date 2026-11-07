use katamoto_field::{qm31::QM31, M31};
use katamoto_fri::merkle::MerkleProof;
use thiserror::Error;

pub const STWO_PROOF_MAGIC: &[u8; 5] = b"STWO\x01";

#[derive(Error, Debug)]
pub enum StwoProofError {
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Invalid proof format: {0}")]
    InvalidFormat(String),
    #[error("Unexpected end of file while reading {0}")]
    UnexpectedEof(&'static str),
    #[error("Hex decode error: {0}")]
    HexDecodeError(#[from] hex::FromHexError),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Out-of-domain (OOD) evaluations of trace and quotient polynomials
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StwoOodEvaluations {
    pub ood_point_x: QM31,
    pub ood_point_y: QM31,
    pub trace_evals: Vec<QM31>,
    pub quotient_eval: QM31,
}

impl StwoOodEvaluations {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_qm31(&self.ood_point_x, &mut buf);
        encode_qm31(&self.ood_point_y, &mut buf);
        buf.extend_from_slice(&(self.trace_evals.len() as u32).to_le_bytes());
        for eval in &self.trace_evals {
            encode_qm31(eval, &mut buf);
        }
        encode_qm31(&self.quotient_eval, &mut buf);
        buf
    }

    pub fn from_bytes(reader: &mut &[u8]) -> Result<Self, StwoProofError> {
        let ood_point_x = decode_qm31(reader, "ood_point_x")?;
        let ood_point_y = decode_qm31(reader, "ood_point_y")?;
        let evals_len = read_u32(reader, "trace_evals_count")? as usize;
        let mut trace_evals = Vec::with_capacity(evals_len);
        for _ in 0..evals_len {
            trace_evals.push(decode_qm31(reader, "trace_eval")?);
        }
        let quotient_eval = decode_qm31(reader, "quotient_eval")?;
        Ok(Self {
            ood_point_x,
            ood_point_y,
            trace_evals,
            quotient_eval,
        })
    }
}

/// Circle FRI query opening across rounds
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StwoFriQuery {
    pub query_idx: usize,
    pub f_p: M31,
    pub f_conj: M31,
    pub merkle_proof: MerkleProof,
}

impl StwoFriQuery {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.query_idx as u32).to_le_bytes());
        buf.extend_from_slice(&self.f_p.value().to_le_bytes());
        buf.extend_from_slice(&self.f_conj.value().to_le_bytes());
        encode_merkle_proof(&self.merkle_proof, &mut buf);
        buf
    }

    pub fn from_bytes(reader: &mut &[u8]) -> Result<Self, StwoProofError> {
        let query_idx = read_u32(reader, "query_idx")? as usize;
        let f_p = decode_m31(reader, "f_p")?;
        let f_conj = decode_m31(reader, "f_conj")?;
        let merkle_proof = decode_merkle_proof(reader)?;
        Ok(Self {
            query_idx,
            f_p,
            f_conj,
            merkle_proof,
        })
    }
}

/// Circle FRI proof components matching Stwo protocol
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StwoFriProof {
    pub round_commitments: Vec<[u8; 32]>,
    pub queries: Vec<StwoFriQuery>,
    pub final_poly_coefficients: Vec<QM31>,
}

impl StwoFriProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.round_commitments.len() as u32).to_le_bytes());
        for comm in &self.round_commitments {
            buf.extend_from_slice(comm);
        }
        buf.extend_from_slice(&(self.final_poly_coefficients.len() as u32).to_le_bytes());
        for coef in &self.final_poly_coefficients {
            encode_qm31(coef, &mut buf);
        }
        buf.extend_from_slice(&(self.queries.len() as u32).to_le_bytes());
        for q in &self.queries {
            buf.extend_from_slice(&q.to_bytes());
        }
        buf
    }

    pub fn from_bytes(reader: &mut &[u8]) -> Result<Self, StwoProofError> {
        let comm_len = read_u32(reader, "round_commitments_count")? as usize;
        let mut round_commitments = Vec::with_capacity(comm_len);
        for _ in 0..comm_len {
            round_commitments.push(read_array_32(reader, "round_commitment")?);
        }

        let coef_len = read_u32(reader, "final_poly_coefficients_count")? as usize;
        let mut final_poly_coefficients = Vec::with_capacity(coef_len);
        for _ in 0..coef_len {
            final_poly_coefficients.push(decode_qm31(reader, "final_poly_coefficient")?);
        }

        let query_len = read_u32(reader, "queries_count")? as usize;
        let mut queries = Vec::with_capacity(query_len);
        for _ in 0..query_len {
            queries.push(StwoFriQuery::from_bytes(reader)?);
        }

        Ok(Self {
            round_commitments,
            queries,
            final_poly_coefficients,
        })
    }
}

/// Native Stwo Circle STARK proof representation for Katamoto on-chain verification
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Serializes proof into Stwo binary format with magic header
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Magic header
        buf.extend_from_slice(STWO_PROOF_MAGIC);
        buf.extend_from_slice(&self.statement_hash);

        // Optional presence flags
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

        // Proof of Work
        buf.extend_from_slice(&self.pow_nonce.to_le_bytes());
        buf.extend_from_slice(&self.pow_bits.to_le_bytes());

        // OOD evaluations
        buf.extend_from_slice(&self.ood_evaluations.to_bytes());

        // FRI Proof
        buf.extend_from_slice(&self.fri_proof.to_bytes());

        buf
    }

    /// Deserializes proof from Stwo binary format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StwoProofError> {
        let mut reader = bytes;

        if reader.len() < STWO_PROOF_MAGIC.len() {
            return Err(StwoProofError::UnexpectedEof("magic_header"));
        }
        if &reader[..STWO_PROOF_MAGIC.len()] != STWO_PROOF_MAGIC {
            return Err(StwoProofError::InvalidFormat(
                "Invalid Stwo proof magic header".to_string(),
            ));
        }
        reader = &reader[STWO_PROOF_MAGIC.len()..];

        let statement_hash = read_array_32(&mut reader, "statement_hash")?;
        let flags = read_u8(&mut reader, "optional_flags")?;
        let has_preprocessed = (flags & 0x01) != 0;
        let has_lookup = (flags & 0x02) != 0;

        let preprocessed_root = if has_preprocessed {
            Some(read_array_32(&mut reader, "preprocessed_root")?)
        } else {
            None
        };

        let trace_root = read_array_32(&mut reader, "trace_root")?;

        let lookup_root = if has_lookup {
            Some(read_array_32(&mut reader, "lookup_root")?)
        } else {
            None
        };

        let quotient_root = read_array_32(&mut reader, "quotient_root")?;

        let pow_nonce = read_u64(&mut reader, "pow_nonce")?;
        let pow_bits = read_u32(&mut reader, "pow_bits")?;

        let ood_evaluations = StwoOodEvaluations::from_bytes(&mut reader)?;
        let fri_proof = StwoFriProof::from_bytes(&mut reader)?;

        Ok(Self {
            statement_hash,
            preprocessed_root,
            trace_root,
            lookup_root,
            quotient_root,
            ood_evaluations,
            fri_proof,
            pow_nonce,
            pow_bits,
        })
    }

    /// Encodes proof to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decodes proof from hex string
    pub fn from_hex(s: &str) -> Result<Self, StwoProofError> {
        let raw = hex::decode(s)?;
        Self::from_bytes(&raw)
    }

    /// Saves binary proof artifact to disk
    pub fn save_to_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<(), StwoProofError> {
        std::fs::write(path, self.to_bytes())?;
        Ok(())
    }

    /// Ingests binary proof artifact from disk
    pub fn load_from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, StwoProofError> {
        let raw = std::fs::read(path)?;
        Self::from_bytes(&raw)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal serialization helpers
// ─────────────────────────────────────────────────────────────────────────────

fn read_u8(reader: &mut &[u8], field: &'static str) -> Result<u8, StwoProofError> {
    if reader.is_empty() {
        return Err(StwoProofError::UnexpectedEof(field));
    }
    let b = reader[0];
    *reader = &reader[1..];
    Ok(b)
}

fn read_u32(reader: &mut &[u8], field: &'static str) -> Result<u32, StwoProofError> {
    if reader.len() < 4 {
        return Err(StwoProofError::UnexpectedEof(field));
    }
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&reader[..4]);
    *reader = &reader[4..];
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(reader: &mut &[u8], field: &'static str) -> Result<u64, StwoProofError> {
    if reader.len() < 8 {
        return Err(StwoProofError::UnexpectedEof(field));
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&reader[..8]);
    *reader = &reader[8..];
    Ok(u64::from_le_bytes(bytes))
}

fn read_array_32(reader: &mut &[u8], field: &'static str) -> Result<[u8; 32], StwoProofError> {
    if reader.len() < 32 {
        return Err(StwoProofError::UnexpectedEof(field));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&reader[..32]);
    *reader = &reader[32..];
    Ok(arr)
}

fn encode_qm31(val: &QM31, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&val.c0.a.value().to_le_bytes());
    buf.extend_from_slice(&val.c0.b.value().to_le_bytes());
    buf.extend_from_slice(&val.c1.a.value().to_le_bytes());
    buf.extend_from_slice(&val.c1.b.value().to_le_bytes());
}

fn decode_qm31(reader: &mut &[u8], field: &'static str) -> Result<QM31, StwoProofError> {
    let a = decode_m31(reader, field)?;
    let b = decode_m31(reader, field)?;
    let c = decode_m31(reader, field)?;
    let d = decode_m31(reader, field)?;
    Ok(QM31::from_m31(a, b, c, d))
}

fn decode_m31(reader: &mut &[u8], field: &'static str) -> Result<M31, StwoProofError> {
    let val = read_u32(reader, field)?;
    Ok(M31::new(val as u64))
}

fn encode_merkle_proof(proof: &MerkleProof, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&proof.leaf);
    buf.extend_from_slice(&(proof.siblings.len() as u32).to_le_bytes());
    for sib in &proof.siblings {
        buf.extend_from_slice(sib);
    }
    for dir in &proof.directions {
        buf.push(if *dir { 1 } else { 0 });
    }
}

fn decode_merkle_proof(reader: &mut &[u8]) -> Result<MerkleProof, StwoProofError> {
    let leaf = read_array_32(reader, "merkle_leaf")?;
    let sib_len = read_u32(reader, "merkle_siblings_count")? as usize;
    let mut siblings = Vec::with_capacity(sib_len);
    for _ in 0..sib_len {
        siblings.push(read_array_32(reader, "merkle_sibling")?);
    }
    let mut directions = Vec::with_capacity(sib_len);
    for _ in 0..sib_len {
        let d = read_u8(reader, "merkle_direction")?;
        directions.push(d != 0);
    }
    Ok(MerkleProof {
        leaf,
        siblings,
        directions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stwo_proof_binary_and_hex_roundtrip() {
        let ood_evaluations = StwoOodEvaluations {
            ood_point_x: QM31::from_u32(11, 22, 33, 44),
            ood_point_y: QM31::from_u32(55, 66, 77, 88),
            trace_evals: vec![
                QM31::from_u32(1, 2, 3, 4),
                QM31::from_u32(5, 6, 7, 8),
            ],
            quotient_eval: QM31::from_u32(100, 200, 300, 400),
        };

        let merkle_proof = MerkleProof {
            leaf: [0xaa; 32],
            siblings: vec![[0x11; 32], [0x22; 32], [0x33; 32]],
            directions: vec![false, true, false],
        };

        let queries = vec![
            StwoFriQuery {
                query_idx: 0,
                f_p: M31::new(12345),
                f_conj: M31::new(67890),
                merkle_proof: merkle_proof.clone(),
            },
            StwoFriQuery {
                query_idx: 1,
                f_p: M31::new(54321),
                f_conj: M31::new(9876),
                merkle_proof,
            },
        ];

        let fri_proof = StwoFriProof {
            round_commitments: vec![[0xbb; 32], [0xcc; 32]],
            queries,
            final_poly_coefficients: vec![QM31::from_u32(9, 9, 9, 9)],
        };

        let original_proof = StwoProof {
            statement_hash: [0x55; 32],
            preprocessed_root: Some([0x66; 32]),
            trace_root: [0x77; 32],
            lookup_root: Some([0x88; 32]),
            quotient_root: [0x99; 32],
            ood_evaluations,
            fri_proof,
            pow_nonce: 0xDEADBEEFCAFE,
            pow_bits: 16,
        };

        // Binary roundtrip
        let bytes = original_proof.to_bytes();
        assert!(bytes.starts_with(STWO_PROOF_MAGIC));
        let decoded = StwoProof::from_bytes(&bytes).expect("Binary decoding should succeed");
        assert_eq!(original_proof, decoded);

        // Hex roundtrip
        let hex_str = original_proof.to_hex();
        let decoded_hex = StwoProof::from_hex(&hex_str).expect("Hex decoding should succeed");
        assert_eq!(original_proof, decoded_hex);

        // File I/O roundtrip in tempdir
        let temp_path = std::env::temp_dir().join("katamoto_test_proof.bin");
        original_proof.save_to_file(&temp_path).expect("File saving should succeed");
        let loaded = StwoProof::load_from_file(&temp_path).expect("File loading should succeed");
        assert_eq!(original_proof, loaded);
        let _ = std::fs::remove_file(temp_path);
    }
}
