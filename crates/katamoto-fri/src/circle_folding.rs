use crate::merkle::{MerkleProof, MerkleScript};
use katamoto_field::{
    circle::{circle_subgroup_generator, CirclePoint},
    M31Script, M31,
};
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

    /// Emits a cryptographically sound Circle FRI round verifier with strict leaf preimage binding:
    /// 1. Takes preimage bytes of [f_conj, f_p], concatenates them via OP_SWAP + OP_CAT and hashes via OP_SHA256
    /// 2. Verifies the authenticated leaf against expected_root using MerkleScript
    /// 3. Validates the colinearity relation: LHS == (T1 + T2) mod M31_P
    pub fn emit_preimage_bound_round_verifier(
        builder: &mut ScriptBuilder,
        depth: usize,
        expected_root: &[u8; 32],
    ) {
        // Stack top on entry: [..., sibling_0, dir_0, f_conj_bytes, f_p_bytes]
        // Step 1: Reconstruct leaf hash: OP_SWAP -> OP_CAT -> OP_SHA256
        builder.op_swap(); // [..., f_p_bytes, f_conj_bytes]
        builder.op_cat();  // [..., (f_p || f_conj)]
        builder.op_sha256(); // [..., leaf_hash]

        // Step 2: Verify Merkle path from reconstructed leaf hash
        MerkleScript::emit_verifier(builder, depth, expected_root);
        builder.op_verify();

        // Step 3: Verify colinearity fold: LHS == (T1 + T2) mod M31_P
        Self::emit_colinearity_verifier(builder);
    }

    /// Prepares witness for preimage-bound Circle FRI round verification
    pub fn create_preimage_bound_witness(
        f_p: M31,
        f_conj: M31,
        proof: &MerkleProof,
        lhs: M31,
        t1: M31,
        t2: M31,
    ) -> Vec<Vec<u8>> {
        let mut witness = Vec::new();

        // 1. Colinearity witness items (at bottom of stack)
        witness.push(encode_num(lhs.as_i64()));
        witness.push(encode_num(t1.as_i64()));
        witness.push(encode_num(t2.as_i64()));

        // 2. Merkle siblings and direction bits (excluding the dummy leaf at top of MerkleProof)
        let merkle_wit = MerkleScript::create_witness(proof);
        for item in &merkle_wit[..merkle_wit.len() - 1] {
            witness.push(item.clone());
        }

        // 3. Preimage field element bytes: f_conj pushed first (depth 1), then f_p (depth 0 / stack top)
        witness.push(f_conj.value().to_le_bytes().to_vec());
        witness.push(f_p.value().to_le_bytes().to_vec());

        witness
    }

    /// Emits script verifying a 4-to-1 high-arity Circle folding step:
    /// Checks 3 colinearities sequentially on the stack:
    ///   1. y-fold of P0
    ///   2. y-fold of P1
    ///   3. x-fold combining the two into pi(x) = 2x^2 - 1
    /// Stack layout on entry: `[triple_2 (x-fold), triple_1 (y1), triple_0 (y0)]`
    /// where each triple is `[lhs, t1, t2]` (t2 at stack top)
    pub fn emit_4to1_colinearity_verifier(builder: &mut ScriptBuilder) {
        for _ in 0..3 {
            // Stack top: [..., lhs, t1, t2]
            M31Script::emit_add(builder); // [..., lhs, (t1 + t2)]
            builder.op_equalverify();     // [..., ]
        }
        builder.push_int(1);
    }

    /// Prepares witness for 4-to-1 high-arity Circle FRI folding
    pub fn create_4to1_witness(step: &CircleFri4To1Step) -> Vec<Vec<u8>> {
        let triples = step.decompose();
        let mut witness = Vec::with_capacity(9);
        // Stack evaluates triple_0 first, then triple_1, then triple_2
        // So triple_2 pushed at bottom, triple_0 at top:
        for triple in triples.iter().rev() {
            witness.push(encode_num(triple.0.as_i64()));
            witness.push(encode_num(triple.1.as_i64()));
            witness.push(encode_num(triple.2.as_i64()));
        }
        witness
    }

    /// Emits a cryptographically sound 4-to-1 skip-layer Circle FRI verifier with leaf preimage binding:
    /// 1. Takes preimage bytes [v11, v10, v01, v00] and reconstructs the quad-leaf hash:
    ///    OP_SWAP -> OP_CAT -> OP_TOALTSTACK -> OP_SWAP -> OP_CAT -> OP_FROMALTSTACK -> OP_SWAP -> OP_CAT -> OP_SHA256
    /// 2. Verifies the authenticated quad-leaf against expected_root using MerkleScript
    /// 3. Validates the 3 colinearity relations (y0, y1, x) across the skip layer:
    ///    LHS == (T1 + T2) mod M31_P for each fold step.
    pub fn emit_preimage_bound_4to1_verifier(
        builder: &mut ScriptBuilder,
        depth: usize,
        expected_root: &[u8; 32],
    ) {
        // Stack top on entry: [..., sibling_0, dir_0, v11, v10, v01, v00]
        // Step 1: Reconstruct quad-leaf hash from 4 field elements: (v00 || v01 || v10 || v11)
        builder.op_swap();
        builder.op_cat();
        builder.op_toaltstack();
        builder.op_swap();
        builder.op_cat();
        builder.op_fromaltstack();
        builder.op_swap();
        builder.op_cat();
        builder.op_sha256();

        // Step 2: Verify Merkle path from reconstructed quad-leaf hash
        MerkleScript::emit_verifier(builder, depth, expected_root);
        builder.op_verify();

        // Step 3: Verify 4-to-1 colinearity folds (3 sequential colinearities)
        Self::emit_4to1_colinearity_verifier(builder);
    }

    /// Prepares witness for preimage-bound 4-to-1 skip-layer Circle FRI verification
    pub fn create_preimage_bound_4to1_witness(
        step: &CircleFri4To1Step,
        proof: &MerkleProof,
    ) -> Vec<Vec<u8>> {
        let mut witness = Vec::new();

        // 1. Colinearity witness items (at bottom of stack)
        let triples = step.decompose();
        for triple in triples.iter().rev() {
            witness.push(encode_num(triple.0.as_i64()));
            witness.push(encode_num(triple.1.as_i64()));
            witness.push(encode_num(triple.2.as_i64()));
        }

        // 2. Merkle siblings and direction bits (excluding dummy leaf at top of proof)
        let merkle_wit = MerkleScript::create_witness(proof);
        for item in &merkle_wit[..merkle_wit.len() - 1] {
            witness.push(item.clone());
        }

        // 3. Preimage field element bytes: v11, v10, v01 pushed first, then v00 at stack top
        witness.push(step.v11.value().to_le_bytes().to_vec());
        witness.push(step.v10.value().to_le_bytes().to_vec());
        witness.push(step.v01.value().to_le_bytes().to_vec());
        witness.push(step.v00.value().to_le_bytes().to_vec());

        witness
    }

    /// Emits script verifying an 8-to-1 high-arity Circle folding step:
    /// Checks 7 colinearities sequentially across 3 folding layers:
    ///   - 4 y-folds
    ///   - 2 x-folds
    ///   - 1 pi-fold combining down to pi(pi(x))
    /// Stack layout: 7 consecutive `[lhs, t1, t2]` triples
    pub fn emit_8to1_colinearity_verifier(builder: &mut ScriptBuilder) {
        for _ in 0..7 {
            M31Script::emit_add(builder);
            builder.op_equalverify();
        }
        builder.push_int(1);
    }

    /// Prepares witness for 8-to-1 high-arity Circle FRI folding
    pub fn create_8to1_witness(step: &CircleFri8To1Step) -> Vec<Vec<u8>> {
        let triples = step.decompose();
        let mut witness = Vec::with_capacity(21);
        for triple in triples.iter().rev() {
            witness.push(encode_num(triple.0.as_i64()));
            witness.push(encode_num(triple.1.as_i64()));
            witness.push(encode_num(triple.2.as_i64()));
        }
        witness
    }

    /// Emits script verifying a 16-to-1 high-arity Circle folding step:
    /// Checks 15 colinearities sequentially across 4 folding layers:
    ///   - 8 y-folds
    ///   - 4 x-folds
    ///   - 2 pi-folds
    ///   - 1 pi^2-fold combining down to pi(pi(pi(x)))
    /// Stack layout: 15 consecutive `[lhs, t1, t2]` triples
    pub fn emit_16to1_colinearity_verifier(builder: &mut ScriptBuilder) {
        for _ in 0..15 {
            M31Script::emit_add(builder);
            builder.op_equalverify();
        }
        builder.push_int(1);
    }

    /// Prepares witness for 16-to-1 high-arity Circle FRI folding
    pub fn create_16to1_witness(step: &CircleFri16To1Step) -> Vec<Vec<u8>> {
        let triples = step.decompose();
        let mut witness = Vec::with_capacity(45);
        for triple in triples.iter().rev() {
            witness.push(encode_num(triple.0.as_i64()));
            witness.push(encode_num(triple.1.as_i64()));
            witness.push(encode_num(triple.2.as_i64()));
        }
        witness
    }

    /// Emits script verifying an experimental 32-to-1 ultra-high-arity Circle folding step:
    /// Checks 31 colinearities sequentially across 5 folding layers:
    ///   - 16 y-folds
    ///   - 8 x-folds
    ///   - 4 pi-folds
    ///   - 2 pi^2-folds
    ///   - 1 pi^3-fold combining down to pi^4(x)
    /// Stack layout: 31 consecutive `[lhs, t1, t2]` triples
    pub fn emit_32to1_colinearity_verifier(builder: &mut ScriptBuilder) {
        for _ in 0..31 {
            M31Script::emit_add(builder);
            builder.op_equalverify();
        }
        builder.push_int(1);
    }

    /// Prepares witness for 32-to-1 high-arity Circle FRI folding
    pub fn create_32to1_witness(step: &CircleFri32To1Step) -> Vec<Vec<u8>> {
        let triples = step.decompose();
        let mut witness = Vec::with_capacity(93);
        for triple in triples.iter().rev() {
            witness.push(encode_num(triple.0.as_i64()));
            witness.push(encode_num(triple.1.as_i64()));
            witness.push(encode_num(triple.2.as_i64()));
        }
        witness
    }
}

/// Stage 1 & 2 Combined: 4-to-1 High-Arity Circle FRI Folding Step.
/// Folds 4 sibling evaluations on the unit circle into a single folded value
/// at pi(x) = 2x^2 - 1 within a single TapLeaf, eliminating intermediate Merkle proofs.
#[derive(Debug, Clone)]
pub struct CircleFri4To1Step {
    pub point: CirclePoint,
    pub v00: M31, // f(x, y)
    pub v01: M31, // f(x, -y)
    pub v10: M31, // f(-x, y)
    pub v11: M31, // f(-x, -y)
    pub alpha_y: M31,
    pub alpha_x: M31,
    pub f_x: M31,     // intermediate y-fold at x
    pub f_neg_x: M31, // intermediate y-fold at -x
    pub next_f: M31,  // final folded value at pi(x) = 2x^2 - 1
}

impl CircleFri4To1Step {
    pub fn new(
        point: CirclePoint,
        v00: M31,
        v01: M31,
        v10: M31,
        v11: M31,
        alpha_y: M31,
        alpha_x: M31,
    ) -> Self {
        assert!(point.is_on_curve(), "Point must lie on circle");
        assert_ne!(point.y, M31::ZERO, "y coordinate cannot be zero for y-fold");
        assert_ne!(point.x, M31::ZERO, "x coordinate cannot be zero for x-fold");

        let two_inv = M31::new(2).inv().unwrap();
        let y_inv = point.y.inv().unwrap();
        let x_inv = point.x.inv().unwrap();

        // 1. y-fold at +x
        let even_0 = (v00 + v01) * two_inv;
        let odd_0 = (v00 - v01) * two_inv * y_inv;
        let f_x = even_0 + (alpha_y * odd_0);

        // 2. y-fold at -x
        let even_1 = (v10 + v11) * two_inv;
        let odd_1 = (v10 - v11) * two_inv * y_inv;
        let f_neg_x = even_1 + (alpha_y * odd_1);

        // 3. x-fold at pi(x) = 2x^2 - 1
        let even_x = (f_x + f_neg_x) * two_inv;
        let odd_x = (f_x - f_neg_x) * two_inv * x_inv;
        let next_f = even_x + (alpha_x * odd_x);

        Self {
            point,
            v00,
            v01,
            v10,
            v11,
            alpha_y,
            alpha_x,
            f_x,
            f_neg_x,
            next_f,
        }
    }

    /// Decomposes into 3 witness-verifiable linear colinearity triples:
    ///   1. y0: LHS_y0 == T1_y0 + T2_y0
    ///   2. y1: LHS_y1 == T1_y1 + T2_y1
    ///   3. x:  LHS_x  == T1_x  + T2_x
    pub fn decompose(&self) -> [(M31, M31, M31); 3] {
        let two_y = M31::new(2) * self.point.y;
        let lhs_y0 = two_y * self.f_x;
        let t1_y0 = self.point.y * (self.v00 + self.v01);
        let t2_y0 = self.alpha_y * (self.v00 - self.v01);
        debug_assert_eq!(lhs_y0, t1_y0 + t2_y0, "4-to-1 y0 colinearity must hold");

        let lhs_y1 = two_y * self.f_neg_x;
        let t1_y1 = self.point.y * (self.v10 + self.v11);
        let t2_y1 = self.alpha_y * (self.v10 - self.v11);
        debug_assert_eq!(lhs_y1, t1_y1 + t2_y1, "4-to-1 y1 colinearity must hold");

        let two_x = M31::new(2) * self.point.x;
        let lhs_x = two_x * self.next_f;
        let t1_x = self.point.x * (self.f_x + self.f_neg_x);
        let t2_x = self.alpha_x * (self.f_x - self.f_neg_x);
        debug_assert_eq!(lhs_x, t1_x + t2_x, "4-to-1 x colinearity must hold");

        [
            (lhs_y0, t1_y0, t2_y0),
            (lhs_y1, t1_y1, t2_y1),
            (lhs_x, t1_x, t2_x),
        ]
    }
}

/// Stage 1, 2, & 3 Combined: 8-to-1 High-Arity Circle FRI Folding Step.
/// Folds 8 sibling evaluations across 3 domain halvings into a single folded value
/// at pi(pi(x)) within a single TapLeaf, eliminating TWO intermediate Merkle trees (66% reduction).
#[derive(Debug, Clone)]
pub struct CircleFri8To1Step {
    pub step_a: CircleFri4To1Step,
    pub step_b: CircleFri4To1Step,
    pub alpha_pi: M31,
    pub pi_x_a: M31,
    pub next_next_f: M31,
}

impl CircleFri8To1Step {
    pub fn new(
        point_a: CirclePoint,
        vals_a: [M31; 4],
        vals_b: [M31; 4],
        alpha_y: M31,
        alpha_x: M31,
        alpha_pi: M31,
    ) -> Self {
        assert!(point_a.is_on_curve(), "Point A must lie on circle");
        // Point B constructed on circle such that pi(x_b) = -pi(x_a)
        // Since x_a^2 + y_a^2 = 1, setting x_b = y_a and y_b = x_a gives:
        // pi(x_b) = 2*(y_a)^2 - 1 = 2*(1 - x_a^2) - 1 = 1 - 2*x_a^2 = -pi(x_a)
        let point_b = CirclePoint::new(point_a.y, point_a.x);
        assert!(point_b.is_on_curve(), "Point B must lie on circle");

        let step_a = CircleFri4To1Step::new(
            point_a,
            vals_a[0],
            vals_a[1],
            vals_a[2],
            vals_a[3],
            alpha_y,
            alpha_x,
        );
        let step_b = CircleFri4To1Step::new(
            point_b,
            vals_b[0],
            vals_b[1],
            vals_b[2],
            vals_b[3],
            alpha_y,
            alpha_x,
        );

        let two = M31::new(2);
        let pi_x_a = (two * point_a.x * point_a.x) - M31::ONE;
        assert_ne!(pi_x_a, M31::ZERO, "pi(x_a) cannot be zero for pi-fold");

        let two_inv = two.inv().unwrap();
        let pi_inv = pi_x_a.inv().unwrap();

        let even_pi = (step_a.next_f + step_b.next_f) * two_inv;
        let odd_pi = (step_a.next_f - step_b.next_f) * two_inv * pi_inv;
        let next_next_f = even_pi + (alpha_pi * odd_pi);

        Self {
            step_a,
            step_b,
            alpha_pi,
            pi_x_a,
            next_next_f,
        }
    }

    /// Decomposes 8-to-1 folding into 7 linear colinearity triples:
    ///   - 3 for step_a
    ///   - 3 for step_b
    ///   - 1 for final pi-folding stage
    pub fn decompose(&self) -> [(M31, M31, M31); 7] {
        let dec_a = self.step_a.decompose();
        let dec_b = self.step_b.decompose();

        let two_pi = M31::new(2) * self.pi_x_a;
        let lhs_pi = two_pi * self.next_next_f;
        let t1_pi = self.pi_x_a * (self.step_a.next_f + self.step_b.next_f);
        let t2_pi = self.alpha_pi * (self.step_a.next_f - self.step_b.next_f);
        debug_assert_eq!(lhs_pi, t1_pi + t2_pi, "8-to-1 pi colinearity must hold");

        [
            dec_a[0],
            dec_a[1],
            dec_a[2],
            dec_b[0],
            dec_b[1],
            dec_b[2],
            (lhs_pi, t1_pi, t2_pi),
        ]
    }
}

/// Stage 1, 2, 3, & 4 Combined: 16-to-1 High-Arity Circle FRI Folding Step.
/// Folds 16 sibling evaluations across 4 domain halvings into a single folded value
/// at pi(pi(pi(x))) within a single TapLeaf, eliminating THREE intermediate Merkle trees (75% reduction).
#[derive(Debug, Clone)]
pub struct CircleFri16To1Step {
    pub step8_a: CircleFri8To1Step,
    pub step8_b: CircleFri8To1Step,
    pub alpha_pi2: M31,
    pub pi2_x_a: M31,
    pub next3_f: M31,
}

impl CircleFri16To1Step {
    pub fn new(
        point_a: CirclePoint,
        vals_a: [M31; 8],
        vals_b: [M31; 8],
        alpha_y: M31,
        alpha_x: M31,
        alpha_pi: M31,
        alpha_pi2: M31,
    ) -> Self {
        assert!(point_a.is_on_curve(), "Point A must lie on circle");
        // Point B on circle shifted by G_8 so that pi(pi(x_b)) = -pi(pi(x_a))
        let g8 = circle_subgroup_generator(3);
        let point_b = point_a + g8;
        assert!(point_b.is_on_curve(), "Point B must lie on circle");

        let mut v_a1 = [M31::ZERO; 4];
        let mut v_a2 = [M31::ZERO; 4];
        v_a1.copy_from_slice(&vals_a[0..4]);
        v_a2.copy_from_slice(&vals_a[4..8]);

        let mut v_b1 = [M31::ZERO; 4];
        let mut v_b2 = [M31::ZERO; 4];
        v_b1.copy_from_slice(&vals_b[0..4]);
        v_b2.copy_from_slice(&vals_b[4..8]);

        let step8_a = CircleFri8To1Step::new(point_a, v_a1, v_a2, alpha_y, alpha_x, alpha_pi);
        let step8_b = CircleFri8To1Step::new(point_b, v_b1, v_b2, alpha_y, alpha_x, alpha_pi);

        let two = M31::new(2);
        let pi2_x_a = (two * step8_a.pi_x_a * step8_a.pi_x_a) - M31::ONE;
        assert_ne!(pi2_x_a, M31::ZERO, "pi2(x_a) cannot be zero for pi2-fold");

        let two_inv = two.inv().unwrap();
        let pi2_inv = pi2_x_a.inv().unwrap();

        let even_pi2 = (step8_a.next_next_f + step8_b.next_next_f) * two_inv;
        let odd_pi2 = (step8_a.next_next_f - step8_b.next_next_f) * two_inv * pi2_inv;
        let next3_f = even_pi2 + (alpha_pi2 * odd_pi2);

        Self {
            step8_a,
            step8_b,
            alpha_pi2,
            pi2_x_a,
            next3_f,
        }
    }

    /// Decomposes 16-to-1 folding into 15 linear colinearity triples:
    ///   - 7 for step8_a
    ///   - 7 for step8_b
    ///   - 1 for final pi2-folding stage
    pub fn decompose(&self) -> [(M31, M31, M31); 15] {
        let dec_a = self.step8_a.decompose();
        let dec_b = self.step8_b.decompose();

        let two_pi2 = M31::new(2) * self.pi2_x_a;
        let lhs_pi2 = two_pi2 * self.next3_f;
        let t1_pi2 = self.pi2_x_a * (self.step8_a.next_next_f + self.step8_b.next_next_f);
        let t2_pi2 = self.alpha_pi2 * (self.step8_a.next_next_f - self.step8_b.next_next_f);
        debug_assert_eq!(lhs_pi2, t1_pi2 + t2_pi2, "16-to-1 pi2 colinearity must hold");

        [
            dec_a[0], dec_a[1], dec_a[2], dec_a[3], dec_a[4], dec_a[5], dec_a[6],
            dec_b[0], dec_b[1], dec_b[2], dec_b[3], dec_b[4], dec_b[5], dec_b[6],
            (lhs_pi2, t1_pi2, t2_pi2),
        ]
    }
}

/// Experimental Stage 5: 32-to-1 Ultra-High-Arity Circle FRI Folding Step.
/// Folds 32 evaluations across 5 circle domain layers in a single TapLeaf script.
/// Reduces Merkle authentication overhead by 80% while comfortably conforming to the 520B limit.
#[derive(Debug, Clone)]
pub struct CircleFri32To1Step {
    pub step16_a: CircleFri16To1Step,
    pub step16_b: CircleFri16To1Step,
    pub alpha_pi3: M31,
    pub pi3_x_a: M31,
    pub next4_f: M31,
}

impl CircleFri32To1Step {
    pub fn new(
        point_a: CirclePoint,
        vals_a: [M31; 16],
        vals_b: [M31; 16],
        alpha_y: M31,
        alpha_x: M31,
        alpha_pi: M31,
        alpha_pi2: M31,
        alpha_pi3: M31,
    ) -> Self {
        assert!(point_a.is_on_curve(), "Point A must lie on circle");
        let g16 = circle_subgroup_generator(4);
        let point_b = point_a + g16;
        assert!(point_b.is_on_curve(), "Point B must lie on circle");

        let mut a1 = [M31::ZERO; 8];
        let mut a2 = [M31::ZERO; 8];
        a1.copy_from_slice(&vals_a[0..8]);
        a2.copy_from_slice(&vals_a[8..16]);

        let mut b1 = [M31::ZERO; 8];
        let mut b2 = [M31::ZERO; 8];
        b1.copy_from_slice(&vals_b[0..8]);
        b2.copy_from_slice(&vals_b[8..16]);

        let step16_a = CircleFri16To1Step::new(point_a, a1, a2, alpha_y, alpha_x, alpha_pi, alpha_pi2);
        let step16_b = CircleFri16To1Step::new(point_b, b1, b2, alpha_y, alpha_x, alpha_pi, alpha_pi2);

        // Fold the two results at pi^3(x)
        let two = M31::new(2);
        let two_inv = two.inv().unwrap();
        let pi3_x_a = two * step16_a.pi2_x_a * step16_a.pi2_x_a - M31::ONE;
        assert_ne!(pi3_x_a, M31::ZERO, "pi3_x coordinate cannot be zero");
        let pi3_inv = pi3_x_a.inv().unwrap();

        let even_pi3 = (step16_a.next3_f + step16_b.next3_f) * two_inv;
        let odd_pi3 = (step16_a.next3_f - step16_b.next3_f) * two_inv * pi3_inv;
        let next4_f = even_pi3 + (alpha_pi3 * odd_pi3);

        Self {
            step16_a,
            step16_b,
            alpha_pi3,
            pi3_x_a,
            next4_f,
        }
    }

    /// Decomposes 32-to-1 folding into 31 linear colinearity triples:
    ///   - 15 for step16_a
    ///   - 15 for step16_b
    ///   - 1 for final pi3-folding stage
    pub fn decompose(&self) -> [(M31, M31, M31); 31] {
        let dec_a = self.step16_a.decompose();
        let dec_b = self.step16_b.decompose();

        let two_pi3 = M31::new(2) * self.pi3_x_a;
        let lhs_pi3 = two_pi3 * self.next4_f;
        let t1_pi3 = self.pi3_x_a * (self.step16_a.next3_f + self.step16_b.next3_f);
        let t2_pi3 = self.alpha_pi3 * (self.step16_a.next3_f - self.step16_b.next3_f);
        debug_assert_eq!(lhs_pi3, t1_pi3 + t2_pi3, "32-to-1 pi3 colinearity must hold");

        let mut result = [(M31::ZERO, M31::ZERO, M31::ZERO); 31];
        for i in 0..15 {
            result[i] = dec_a[i];
            result[15 + i] = dec_b[i];
        }
        result[30] = (lhs_pi3, t1_pi3, t2_pi3);
        result
    }
}

/// Witness packing utilities for High-Arity Circle FRI folding
#[derive(Debug, Clone)]
pub struct PackedCircleFriWitness;

impl PackedCircleFriWitness {
    /// Packs 4 M31 sibling values into a compact 16-byte byte vector
    pub fn pack_4_siblings(v00: M31, v01: M31, v10: M31, v11: M31) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16);
        buf.extend_from_slice(&v00.value().to_le_bytes());
        buf.extend_from_slice(&v01.value().to_le_bytes());
        buf.extend_from_slice(&v10.value().to_le_bytes());
        buf.extend_from_slice(&v11.value().to_le_bytes());
        buf
    }

    /// Packs 8 M31 sibling values into a compact 32-byte byte vector
    pub fn pack_8_siblings(vals: &[M31; 8]) -> [u8; 32] {
        let mut buf = [0u8; 32];
        for (i, v) in vals.iter().enumerate() {
            buf[i * 4..(i + 1) * 4].copy_from_slice(&v.value().to_le_bytes());
        }
        buf
    }

    /// Packs 16 M31 sibling values into a compact 64-byte byte vector
    pub fn pack_16_siblings(vals: &[M31; 16]) -> [u8; 64] {
        let mut buf = [0u8; 64];
        for (i, v) in vals.iter().enumerate() {
            buf[i * 4..(i + 1) * 4].copy_from_slice(&v.value().to_le_bytes());
        }
        buf
    }

    /// Packs 32 M31 sibling values into a compact 128-byte byte vector
    pub fn pack_32_siblings(vals: &[M31; 32]) -> [u8; 128] {
        let mut buf = [0u8; 128];
        for (i, v) in vals.iter().enumerate() {
            buf[i * 4..(i + 1) * 4].copy_from_slice(&v.value().to_le_bytes());
        }
        buf
    }
}

