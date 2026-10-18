use katamoto_field::{M31Script, M31};
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
