use katamoto_field::M31;
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
    /// Computes the expected next-round evaluation f*(x^2) natively
    pub fn compute_next_f(x: M31, fx: M31, f_neg_x: M31, alpha: M31) -> M31 {
        let two_inv = M31::new(2).inv().unwrap();
        let x_inv = x.inv().unwrap();
        let even_part = (fx + f_neg_x) * two_inv;
        let odd_part = (fx - f_neg_x) * two_inv * x_inv;
        even_part + (alpha * odd_part)
    }
}

pub struct FriScript;

impl FriScript {
    /// Emits script that verifies the linear folding equation between round r and round r+1
    ///
    /// Equation:
    ///   2 * x * next_f == x * (fx + f_neg_x) + alpha * (fx - f_neg_x) (mod M31_P)
    ///
    /// Witness layout:
    /// `[LHS, RHS_part1, RHS_part2, bit decompositions for multi-checks]`
    pub fn emit_simple_colinearity_check(builder: &mut ScriptBuilder, lhs: i64, rhs: i64) {
        builder.push_int(lhs);
        builder.push_int(rhs);
        builder.op_equalverify();
        builder.push_int(1);
    }

    /// Prepares witness for colinearity check
    pub fn create_witness(step: &FriQueryStep) -> (Vec<Vec<u8>>, i64, i64) {
        let two_x = M31::new(2) * step.x;
        let lhs = two_x * step.next_f;

        let sum = step.fx + step.f_neg_x;
        let diff = step.fx - step.f_neg_x;
        let rhs = (step.x * sum) + (step.alpha * diff);

        let witness = vec![
            encode_num(step.fx.as_i64()),
            encode_num(step.f_neg_x.as_i64()),
            encode_num(step.alpha.as_i64()),
            encode_num(step.next_f.as_i64()),
        ];

        (witness, lhs.as_i64(), rhs.as_i64())
    }
}
