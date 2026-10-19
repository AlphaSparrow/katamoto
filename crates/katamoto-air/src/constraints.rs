use katamoto_field::{qm31::QM31Script, M31Script, M31, QM31};
use katamoto_script::{builder::encode_num, ScriptBuilder};

/// Boundary constraint on a state machine trace column:
///   column[step] == expected_value
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundaryConstraint {
    pub column_index: usize,
    pub step: usize,
    pub expected_value: M31,
}

impl BoundaryConstraint {
    pub fn new(column_index: usize, step: usize, expected_value: M31) -> Self {
        Self {
            column_index,
            step,
            expected_value,
        }
    }

    /// Emits Bitcoin Script that checks whether the witness claimed value matches expected_value:
    ///
    /// Expected Witness Stack: `[claimed_boundary_value]`
    pub fn emit_verifier(builder: &mut ScriptBuilder, expected_value: M31) {
        builder.push_int(expected_value.as_i64());
        builder.op_equalverify();
        builder.push_int(1); // leaves TRUE
    }

    /// Emits script that verifies two boundary conditions (initial and terminal):
    /// Expected Witness Stack: `[initial_val, terminal_val]`
    pub fn emit_double_verifier(
        builder: &mut ScriptBuilder,
        initial_val: M31,
        terminal_val: M31,
    ) {
        // Top of stack is terminal_val
        builder.push_int(terminal_val.as_i64());
        builder.op_equalverify();
        // Next is initial_val
        builder.push_int(initial_val.as_i64());
        builder.op_equalverify();
        builder.push_int(1); // leaves TRUE
    }

    pub fn create_witness(value: M31) -> Vec<Vec<u8>> {
        vec![encode_num(value.as_i64())]
    }

    pub fn create_double_witness(initial_val: M31, terminal_val: M31) -> Vec<Vec<u8>> {
        vec![
            encode_num(initial_val.as_i64()),
            encode_num(terminal_val.as_i64()),
        ]
    }
}

/// Transition constraint for Fibonacci state machine:
///   F_{i+2} == (F_{i+1} + F_i) mod M31_P
pub struct FibonacciTransition;

impl FibonacciTransition {
    /// Emits Bitcoin Script that verifies a single Fibonacci transition step:
    ///
    /// Expected Witness Stack: `[f_next2, f_curr, f_next1]`
    /// Execution:
    /// 1. f_curr + f_next1 via M31Script::emit_add -> [f_next2, (f_curr + f_next1)%P]
    /// 2. op_equalverify -> confirms f_next2 == (f_curr + f_next1)%P
    /// 3. leaves TRUE (1) on stack
    pub fn emit_verifier(builder: &mut ScriptBuilder) {
        // Stack: [f_next2, f_curr, f_next1]
        M31Script::emit_add(builder); // stack: [f_next2, (f_curr + f_next1)%P]
        builder.op_equalverify();
        builder.push_int(1);
    }

    /// Prepares witness for a Fibonacci transition step
    pub fn create_witness(f_curr: M31, f_next1: M31, f_next2: M31) -> Vec<Vec<u8>> {
        vec![
            encode_num(f_next2.as_i64()),
            encode_num(f_curr.as_i64()),
            encode_num(f_next1.as_i64()),
        ]
    }
}

/// Precomputed or fixed table for Logarithmic Derivative Lookups (LogUp)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogUpTable {
    pub name: &'static str,
    pub entries: Vec<M31>,
}

impl LogUpTable {
    pub fn new(name: &'static str, entries: Vec<M31>) -> Self {
        Self { name, entries }
    }

    /// 8-bit range table: entries 0..255
    pub fn range_8bit() -> Self {
        let entries = (0..256).map(|i| M31::new(i as u64)).collect();
        Self::new("range_8bit", entries)
    }

    /// 16-bit range table: entries 0..65535
    pub fn range_16bit() -> Self {
        let entries = (0..65536).map(|i| M31::new(i as u64)).collect();
        Self::new("range_16bit", entries)
    }

    /// 8-bit XOR table: triples (a, b, a ^ b)
    pub fn xor_8bit_table() -> Vec<(u8, u8, u8)> {
        let mut triples = Vec::with_capacity(256 * 256);
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                triples.push((a, b, a ^ b));
            }
        }
        triples
    }

    /// 8-bit AND table: triples (a, b, a & b)
    pub fn and_8bit_table() -> Vec<(u8, u8, u8)> {
        let mut triples = Vec::with_capacity(256 * 256);
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                triples.push((a, b, a & b));
            }
        }
        triples
    }
}

/// LogUp Running-Sum Column Step over quartic extension field QM31
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogUpStep {
    pub prev_accum: QM31,
    pub curr_accum: QM31,
    pub input_val: M31,
    pub table_val: M31,
    pub multiplicity: M31,
    pub gamma: QM31,
}

impl LogUpStep {
    pub fn new(
        prev_accum: QM31,
        input_val: M31,
        table_val: M31,
        multiplicity: M31,
        gamma: QM31,
    ) -> Self {
        let gamma_m31_in = QM31::from_m31(input_val, M31::ZERO, M31::ZERO, M31::ZERO);
        let gamma_m31_tbl = QM31::from_m31(table_val, M31::ZERO, M31::ZERO, M31::ZERO);

        let d_f = (gamma - gamma_m31_in).inv().expect("gamma cannot equal input");
        let d_t = (gamma - gamma_m31_tbl).inv().expect("gamma cannot equal table entry");

        let mult_qm31 = QM31::from_m31(multiplicity, M31::ZERO, M31::ZERO, M31::ZERO);
        let delta = d_f - (mult_qm31 * d_t);
        let curr_accum = prev_accum + delta;

        Self {
            prev_accum,
            curr_accum,
            input_val,
            table_val,
            multiplicity,
            gamma,
        }
    }

    /// Decomposes the LogUp fractional step into linear polynomial equality:
    ///   LHS = (A_{k+1} - A_k) * (gamma - f_k) * (gamma - t_k)
    ///   RHS = (gamma - t_k) - multiplicity * (gamma - f_k)
    ///   LHS == RHS (over QM31)
    pub fn decompose(&self) -> (QM31, QM31) {
        let gamma_f = QM31::from_m31(self.input_val, M31::ZERO, M31::ZERO, M31::ZERO);
        let gamma_t = QM31::from_m31(self.table_val, M31::ZERO, M31::ZERO, M31::ZERO);
        let d_f = self.gamma - gamma_f;
        let d_t = self.gamma - gamma_t;

        let delta_a = self.curr_accum - self.prev_accum;
        let lhs = delta_a * d_f * d_t;

        let mult_qm31 = QM31::from_m31(self.multiplicity, M31::ZERO, M31::ZERO, M31::ZERO);
        let rhs = d_t - (mult_qm31 * d_f);

        (lhs, rhs)
    }
}

/// Bitcoin Script Gadget for LogUp Lookup Verification
pub struct LogUpScript;

impl LogUpScript {
    /// Emits Bitcoin Script that validates equality of QM31 LogUp polynomial components:
    /// Stack input: `[expected_LHS (4 items), actual_RHS (4 items)]`
    pub fn emit_qm31_verifier(builder: &mut ScriptBuilder) {
        QM31Script::emit_equalverify(builder);
    }

    /// Prepares witness for QM31 LogUp step verification
    pub fn create_qm31_witness(lhs: QM31, rhs: QM31) -> Vec<Vec<u8>> {
        let lhs_arr = lhs.to_array();
        let rhs_arr = rhs.to_array();
        let mut wit = Vec::with_capacity(8);
        for elem in &lhs_arr {
            wit.push(encode_num(elem.as_i64()));
        }
        for elem in &rhs_arr {
            wit.push(encode_num(elem.as_i64()));
        }
        wit
    }
}
