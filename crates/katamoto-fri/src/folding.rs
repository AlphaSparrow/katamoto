use crate::merkle::{MerkleProof, MerkleScript};
use katamoto_field::{M31Script, M31};
use katamoto_script::{builder::encode_num, ScriptBuilder};

/// FRI Folding Proof data for a single query step
#[derive(Debug, Clone)]
pub struct FriQueryStep {
    pub x: M31,
    pub fx: M31,
    pub f_neg_x: M31,
    pub alpha: M31,
    pub next_f: M31,
}

impl FriQueryStep {
    pub fn new(x: M31, fx: M31, f_neg_x: M31, alpha: M31) -> Self {
        let next_f = Self::compute_next_f(x, fx, f_neg_x, alpha);
        Self { x, fx, f_neg_x, alpha, next_f }
    }

    /// Computes the expected next-round evaluation f*(x^2) natively:
    /// f*(x^2) = (f(x) + f(-x))/2 + alpha * (f(x) - f(-x)) / (2x)
    pub fn compute_next_f(x: M31, fx: M31, f_neg_x: M31, alpha: M31) -> M31 {
        let two_inv = M31::new(2).inv().unwrap();
        let x_inv = x.inv().unwrap();
        let even_part = (fx + f_neg_x) * two_inv;
        let odd_part = (fx - f_neg_x) * two_inv * x_inv;
        even_part + (alpha * odd_part)
    }

    /// Decomposes the colinearity relation into witness-verifiable components:
    ///   LHS = 2 * x * next_f
    ///   T1  = x * (fx + f_neg_x)
    ///   T2  = alpha * (fx - f_neg_x)
    ///   LHS == T1 + T2 (mod P)
    pub fn decompose(&self) -> (M31, M31, M31) {
        let two_x = M31::new(2) * self.x;
        let lhs = two_x * self.next_f;

        let sum = self.fx + self.f_neg_x;
        let diff = self.fx - self.f_neg_x;

        let t1 = self.x * sum;
        let t2 = self.alpha * diff;

        debug_assert_eq!(lhs, t1 + t2, "Colinearity relation must hold");
        (lhs, t1, t2)
    }
}

/// Complete round verification package combining Merkle proof and FRI fold
#[derive(Debug, Clone)]
pub struct FriRoundQuery {
    pub step: FriQueryStep,
    pub fx_merkle_proof: MerkleProof,
    pub f_neg_x_merkle_proof: MerkleProof,
}

pub struct FriScript;

impl FriScript {
    /// Emits Bitcoin Script that verifies the linear folding equation between round r and round r+1
    ///
    /// Equation:
    ///   LHS == (T1 + T2) mod M31_P
    ///
    /// Expected Witness Stack:
    /// `[lhs, t1, t2]`
    pub fn emit_colinearity_verifier(builder: &mut ScriptBuilder) {
        // Stack: [lhs, t1, t2]
        M31Script::emit_add(builder); // stack: [lhs, (t1 + t2) % P]
        builder.op_equalverify();     // asserts lhs == (t1 + t2) % P
        builder.push_int(1);          // leaves TRUE on stack
    }

    /// Emits an integrated FRI query verification script:
    /// 1. Authenticates f(x) Merkle leaf inclusion against expected layer root
    /// 2. Authenticates f(-x) Merkle leaf inclusion against expected layer root
    /// 3. Validates colinearity relation: LHS == (T1 + T2) mod P
    pub fn emit_integrated_round_verifier(
        builder: &mut ScriptBuilder,
        depth: usize,
        expected_root: &[u8; 32],
    ) {
        // 1. Verify Merkle path for f(x)
        MerkleScript::emit_verifier(builder, depth, expected_root);
        builder.op_verify(); // ensure f(x) Merkle proof succeeded

        // 2. Verify Merkle path for f(-x)
        MerkleScript::emit_verifier(builder, depth, expected_root);
        builder.op_verify(); // ensure f(-x) Merkle proof succeeded

        // 3. Verify colinearity fold
        Self::emit_colinearity_verifier(builder);
    }

    /// Prepares witness for colinearity check
    pub fn create_colinearity_witness(lhs: M31, t1: M31, t2: M31) -> Vec<Vec<u8>> {
        vec![
            encode_num(lhs.as_i64()),
            encode_num(t1.as_i64()),
            encode_num(t2.as_i64()),
        ]
    }

    /// Prepares combined witness for integrated round verification
    pub fn create_integrated_witness(
        query: &FriRoundQuery,
    ) -> Vec<Vec<u8>> {
        let (lhs, t1, t2) = query.step.decompose();
        let mut witness = Vec::new();

        // Witness for colinearity check (at bottom)
        witness.push(encode_num(lhs.as_i64()));
        witness.push(encode_num(t1.as_i64()));
        witness.push(encode_num(t2.as_i64()));

        // Witness for f(-x) Merkle proof
        let neg_witness = MerkleScript::create_witness(&query.f_neg_x_merkle_proof);
        witness.extend(neg_witness);

        // Witness for f(x) Merkle proof (at top, executed first)
        let fx_witness = MerkleScript::create_witness(&query.fx_merkle_proof);
        witness.extend(fx_witness);

        witness
    }
}
