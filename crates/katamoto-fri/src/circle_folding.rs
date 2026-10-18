use crate::merkle::{MerkleProof, MerkleScript};
use katamoto_field::{circle::CirclePoint, M31Script, M31};
use katamoto_script::{builder::encode_num, ScriptBuilder};

/// Stage 1 of Circle FRI: y-folding over conjugate pair (x, y) and (x, -y)
///   f*(x) = (f(P) + f(P_conj))/2 + alpha * (f(P) - f(P_conj)) / (2y)
#[derive(Debug, Clone)]
pub struct CircleFriYStep {
    pub point: CirclePoint,
    pub f_p: M31,
    pub f_conj: M31,
    pub alpha: M31,
    pub next_f: M31,
}

impl CircleFriYStep {
    pub fn new(point: CirclePoint, f_p: M31, f_conj: M31, alpha: M31) -> Self {
        assert!(point.is_on_curve(), "Point must lie on circle");
        assert_ne!(point.y, M31::ZERO, "y coordinate cannot be zero for y-fold");

        let two_inv = M31::new(2).inv().unwrap();
        let y_inv = point.y.inv().unwrap();
        let even_part = (f_p + f_conj) * two_inv;
        let odd_part = (f_p - f_conj) * two_inv * y_inv;
        let next_f = even_part + (alpha * odd_part);

        Self {
            point,
            f_p,
            f_conj,
            alpha,
            next_f,
        }
    }

    /// Decomposes into witness-verifiable linear components:
    ///   LHS = 2 * y * next_f
    ///   T1  = y * (f_p + f_conj)
    ///   T2  = alpha * (f_p - f_conj)
    ///   LHS == T1 + T2 (mod P)
    pub fn decompose(&self) -> (M31, M31, M31) {
        let two_y = M31::new(2) * self.point.y;
        let lhs = two_y * self.next_f;

        let sum = self.f_p + self.f_conj;
        let diff = self.f_p - self.f_conj;

        let t1 = self.point.y * sum;
        let t2 = self.alpha * diff;

        debug_assert_eq!(lhs, t1 + t2, "Circle y-fold colinearity must hold");
        (lhs, t1, t2)
    }
}

/// Stage 2 of Circle FRI: x-folding over x and -x to pi(x) = 2x^2 - 1
///   g*(pi(x)) = (f*(x) + f*(-x))/2 + alpha_x * (f*(x) - f*(-x)) / (2x)
#[derive(Debug, Clone)]
pub struct CircleFriXStep {
    pub x: M31,
    pub f_x: M31,
    pub f_neg_x: M31,
    pub alpha_x: M31,
    pub next_f: M31,
}

impl CircleFriXStep {
    pub fn new(x: M31, f_x: M31, f_neg_x: M31, alpha_x: M31) -> Self {
        assert_ne!(x, M31::ZERO, "x coordinate cannot be zero for x-fold");

        let two_inv = M31::new(2).inv().unwrap();
        let x_inv = x.inv().unwrap();
        let even_part = (f_x + f_neg_x) * two_inv;
        let odd_part = (f_x - f_neg_x) * two_inv * x_inv;
        let next_f = even_part + (alpha_x * odd_part);

        Self {
            x,
            f_x,
            f_neg_x,
            alpha_x,
            next_f,
        }
    }

    /// Decomposes into witness-verifiable linear components:
    ///   LHS = 2 * x * next_f
    ///   T1  = x * (f_x + f_neg_x)
    ///   T2  = alpha_x * (f_x - f_neg_x)
    ///   LHS == T1 + T2 (mod P)
    pub fn decompose(&self) -> (M31, M31, M31) {
        let two_x = M31::new(2) * self.x;
        let lhs = two_x * self.next_f;

        let sum = self.f_x + self.f_neg_x;
        let diff = self.f_x - self.f_neg_x;

        let t1 = self.x * sum;
        let t2 = self.alpha_x * diff;

        debug_assert_eq!(lhs, t1 + t2, "Circle x-fold colinearity must hold");
        (lhs, t1, t2)
    }
}

/// Integrated Circle FRI Query Round containing Merkle inclusion and two-stage fold
#[derive(Debug, Clone)]
pub struct CircleFriRoundQuery {
    pub y_step: CircleFriYStep,
    pub proof_p: MerkleProof,
    pub proof_conj: MerkleProof,
}

/// Bitcoin Script Gadgets for Circle FRI Verifier
pub struct CircleFriScript;

impl CircleFriScript {
    /// Emits script that verifies the linear folding equation:
    ///   LHS == (T1 + T2) mod M31_P
    /// Expected Witness Stack: `[lhs, t1, t2]`
    pub fn emit_colinearity_verifier(builder: &mut ScriptBuilder) {
        // Stack: [lhs, t1, t2]
        M31Script::emit_add(builder);
        builder.op_equalverify();
        builder.push_int(1);
    }

    /// Emits complete Circle FRI query round verifier:
    /// 1. Verifies Merkle path for f(P)
    /// 2. Verifies Merkle path for f(P_conj)
    /// 3. Validates Circle y-fold colinearity: LHS == T1 + T2
    pub fn emit_integrated_circle_round_verifier(
        builder: &mut ScriptBuilder,
        depth: usize,
        expected_root: &[u8; 32],
    ) {
        // 1. Verify Merkle path for f(P)
        MerkleScript::emit_verifier(builder, depth, expected_root);
        builder.op_verify();

        // 2. Verify Merkle path for f(P_conj)
        MerkleScript::emit_verifier(builder, depth, expected_root);
        builder.op_verify();

        // 3. Verify Circle colinearity fold
        Self::emit_colinearity_verifier(builder);
    }

    /// Prepares combined witness for integrated Circle FRI round verification
    pub fn create_integrated_witness(query: &CircleFriRoundQuery) -> Vec<Vec<u8>> {
        let (lhs, t1, t2) = query.y_step.decompose();
        let mut witness = Vec::new();

        // Colinearity witness items (at bottom)
        witness.push(encode_num(lhs.as_i64()));
        witness.push(encode_num(t1.as_i64()));
        witness.push(encode_num(t2.as_i64()));

        // Witness for f(P_conj) Merkle proof
        let conj_witness = MerkleScript::create_witness(&query.proof_conj);
        witness.extend(conj_witness);

        // Witness for f(P) Merkle proof (at top, verified first)
        let p_witness = MerkleScript::create_witness(&query.proof_p);
        witness.extend(p_witness);

        witness
    }
}
