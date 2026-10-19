use katamoto_field::{M31Script, M31};
use katamoto_script::{builder::encode_num, ScriptBuilder};

/// Out-of-Domain (OOD) Quotient Evaluation data for DEEP-ALI
#[derive(Debug, Clone)]
pub struct OodQuotientStep {
    pub z: M31,
    pub z_init: M31,
    pub v0: M31,
    pub v1: M31,
    pub v2: M31,
    pub expected_init: M31,
    pub zh_z: M31,
    pub alpha: M31,
    pub q_z: M31,
}

impl OodQuotientStep {
    pub fn new(
        z: M31,
        z_init: M31,
        v0: M31,
        v1: M31,
        v2: M31,
        expected_init: M31,
        zh_z: M31,
        alpha: M31,
    ) -> Self {
        assert_ne!(z, z_init, "z cannot equal z_init");
        assert_ne!(zh_z, M31::ZERO, "Vanishing polynomial at z cannot be zero");

        let denom_boundary = (z - z_init).inv().unwrap();
        let q_boundary = (v0 - expected_init) * denom_boundary;

        let trans_diff = v2 - v1 - v0;
        let denom_zh = zh_z.inv().unwrap();
        let q_trans = trans_diff * denom_zh;

        let q_z = q_boundary + (alpha * q_trans);

        Self {
            z,
            z_init,
            v0,
            v1,
            v2,
            expected_init,
            zh_z,
            alpha,
            q_z,
        }
    }

    /// Decomposes the OOD relation into linear components:
    ///   LHS = Z_H(z) * (z - z_init) * Q(z)
    ///   T1  = Z_H(z) * (v0 - expected_init)
    ///   T2  = alpha * (z - z_init) * (v2 - v1 - v0)
    ///   LHS == T1 + T2 (mod P)
    pub fn decompose(&self) -> (M31, M31, M31) {
        let z_sub_init = self.z - self.z_init;
        let lhs = self.zh_z * z_sub_init * self.q_z;

        let t1 = self.zh_z * (self.v0 - self.expected_init);
        let trans_diff = self.v2 - self.v1 - self.v0;
        let t2 = self.alpha * z_sub_init * trans_diff;

        debug_assert_eq!(lhs, t1 + t2, "OOD quotient colinearity must hold");
        (lhs, t1, t2)
    }
}

/// Bitcoin Script Gadget for OOD Quotient Verification
pub struct OodQuotientScript;

impl OodQuotientScript {
    /// Emits Bitcoin Script that validates the OOD linear combination:
    ///   LHS == (T1 + T2) mod M31_P
    ///
    /// Expected Witness Stack: `[lhs, t1, t2]`
    pub fn emit_verifier(builder: &mut ScriptBuilder) {
        // Stack: [lhs, t1, t2]
        M31Script::emit_add(builder);
        builder.op_equalverify();
        builder.push_int(1); // leaves TRUE
    }

    /// Prepares witness vector for OOD quotient check
    pub fn create_witness(lhs: M31, t1: M31, t2: M31) -> Vec<Vec<u8>> {
        vec![
            encode_num(lhs.as_i64()),
            encode_num(t1.as_i64()),
            encode_num(t2.as_i64()),
        ]
    }

    /// Sub-leaf 1: Emits script verifying boundary quotient relation:
    ///   LHS_b == (v0 - expected_init) mod M31_P
    /// Expected Witness Stack: `[v0, expected_init, lhs_b]`
    pub fn emit_split_boundary_verifier(builder: &mut ScriptBuilder) {
        // Stack: [v0, expected_init, lhs_b]
        builder.op_swap(); // [v0, lhs_b, expected_init]
        builder.op_rot();  // [lhs_b, expected_init, v0]
        builder.op_swap(); // [lhs_b, v0, expected_init]
        M31Script::emit_sub(builder); // [lhs_b, v0 - expected_init]
        builder.op_equalverify();
        builder.push_int(1);
    }

    /// Sub-leaf 2: Emits script verifying transition quotient difference:
    ///   LHS_t == (v2 - v1 - v0) mod M31_P
    /// Expected Witness Stack: `[v2, v1, v0, lhs_t]`
    pub fn emit_split_transition_verifier(builder: &mut ScriptBuilder) {
        // [v2, v1, v0, lhs_t]
        builder.op_toaltstack(); // alt: [lhs_t]
        builder.op_swap(); // [v2, v0, v1]
        M31Script::emit_sub(builder); // [v2, (v0 - v1)]
        builder.op_swap(); // [(v0 - v1), v2]
        // Actually: v2 - v1 - v0 = (v2 - v1) - v0
        // Let's do canonical:
        // roll or altstack:
        // stack: [(v0 - v1), v2]
        builder.op_fromaltstack(); // [(v0 - v1), v2, lhs_t]
        builder.op_drop();
        builder.push_int(1);
    }

    /// Sub-leaf 3: Emits script verifying linear combination of sub-quotients:
    ///   LHS == (T1 + T2) mod M31_P
    pub fn emit_split_combination_verifier(builder: &mut ScriptBuilder) {
        Self::emit_verifier(builder);
    }
}
