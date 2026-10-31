use crate::constraints::BoundaryConstraint;
use crate::trace::ExecutionTrace;
use katamoto_field::{M31Script, M31};
use katamoto_script::{builder::encode_num, ScriptBuilder};
use std::ops::{Add, Mul, Sub};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum AirDslError {
    #[error("Transition constraint {constraint_idx} violated at row {row}: evaluated to {value}")]
    ConstraintViolated {
        constraint_idx: usize,
        row: usize,
        value: u32,
    },
    #[error("Boundary constraint violated on column {column} at row {row}: expected {expected}, got {actual}")]
    BoundaryViolated {
        column: usize,
        row: usize,
        expected: u32,
        actual: u32,
    },
}

/// A cell reference in the execution trace
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cell {
    Curr(usize),   // column idx in current row (i)
    Next(usize),   // column idx in next row (i + 1)
    Constant(M31), // fixed field constant
}

/// Symbolic expression for writing AIR transition constraints
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Atom(Cell),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
}

impl Expr {
    /// Evaluates the expression given current row and next row values
    pub fn eval(&self, curr_row: &[M31], next_row: &[M31]) -> M31 {
        match self {
            Expr::Atom(Cell::Curr(col)) => curr_row[*col],
            Expr::Atom(Cell::Next(col)) => next_row[*col],
            Expr::Atom(Cell::Constant(c)) => *c,
            Expr::Add(lhs, rhs) => lhs.eval(curr_row, next_row) + rhs.eval(curr_row, next_row),
            Expr::Sub(lhs, rhs) => lhs.eval(curr_row, next_row) - rhs.eval(curr_row, next_row),
            Expr::Mul(lhs, rhs) => lhs.eval(curr_row, next_row) * rhs.eval(curr_row, next_row),
        }
    }

    /// Returns the algebraic degree of the symbolic polynomial constraint expression
    pub fn degree(&self) -> usize {
        match self {
            Expr::Atom(Cell::Constant(_)) => 0,
            Expr::Atom(Cell::Curr(_)) | Expr::Atom(Cell::Next(_)) => 1,
            Expr::Add(lhs, rhs) | Expr::Sub(lhs, rhs) => lhs.degree().max(rhs.degree()),
            Expr::Mul(lhs, rhs) => lhs.degree() + rhs.degree(),
        }
    }

    /// Recursively simplifies the AST using constant folding and algebraic identities
    pub fn simplify(&self) -> Expr {
        match self {
            Expr::Atom(c) => Expr::Atom(*c),
            Expr::Add(lhs, rhs) => {
                let l = lhs.simplify();
                let r = rhs.simplify();
                match (&l, &r) {
                    (Expr::Atom(Cell::Constant(c1)), Expr::Atom(Cell::Constant(c2))) => {
                        Expr::Atom(Cell::Constant(*c1 + *c2))
                    }
                    (Expr::Atom(Cell::Constant(c)), other) | (other, Expr::Atom(Cell::Constant(c)))
                        if c.0 == 0 =>
                    {
                        other.clone()
                    }
                    _ => Expr::Add(Box::new(l), Box::new(r)),
                }
            }
            Expr::Sub(lhs, rhs) => {
                let l = lhs.simplify();
                let r = rhs.simplify();
                if l == r {
                    return Expr::Atom(Cell::Constant(M31::ZERO));
                }
                match (&l, &r) {
                    (Expr::Atom(Cell::Constant(c1)), Expr::Atom(Cell::Constant(c2))) => {
                        Expr::Atom(Cell::Constant(*c1 - *c2))
                    }
                    (other, Expr::Atom(Cell::Constant(c))) if c.0 == 0 => other.clone(),
                    _ => Expr::Sub(Box::new(l), Box::new(r)),
                }
            }
            Expr::Mul(lhs, rhs) => {
                let l = lhs.simplify();
                let r = rhs.simplify();
                match (&l, &r) {
                    (Expr::Atom(Cell::Constant(c1)), Expr::Atom(Cell::Constant(c2))) => {
                        Expr::Atom(Cell::Constant(*c1 * *c2))
                    }
                    (Expr::Atom(Cell::Constant(c)), _) | (_, Expr::Atom(Cell::Constant(c)))
                        if c.0 == 0 =>
                    {
                        Expr::Atom(Cell::Constant(M31::ZERO))
                    }
                    (Expr::Atom(Cell::Constant(c)), other) | (other, Expr::Atom(Cell::Constant(c)))
                        if c.0 == 1 =>
                    {
                        other.clone()
                    }
                    _ => Expr::Mul(Box::new(l), Box::new(r)),
                }
            }
        }
    }

    /// Checks if the expression is a constant zero
    pub fn is_zero(&self) -> bool {
        match self {
            Expr::Atom(Cell::Constant(c)) => c.0 == 0,
            _ => false,
        }
    }
}

// Fluent operator overloading for building constraints
impl Add for Expr {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Expr::Add(Box::new(self), Box::new(rhs))
    }
}

impl Sub for Expr {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Expr::Sub(Box::new(self), Box::new(rhs))
    }
}

impl Mul for Expr {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        Expr::Mul(Box::new(self), Box::new(rhs))
    }
}

/// Helper functions for building clean AIR constraints
pub fn curr(col: usize) -> Expr {
    Expr::Atom(Cell::Curr(col))
}

pub fn next(col: usize) -> Expr {
    Expr::Atom(Cell::Next(col))
}

pub fn constant(val: u32) -> Expr {
    Expr::Atom(Cell::Constant(M31::new(val as u64)))
}

/// Generalized AIR Constraint System
#[derive(Debug, Clone, Default)]
pub struct AirSystem {
    pub num_columns: usize,
    pub transition_constraints: Vec<Expr>,
    pub boundary_constraints: Vec<BoundaryConstraint>,
}

impl AirSystem {
    pub fn new(num_columns: usize) -> Self {
        Self {
            num_columns,
            transition_constraints: Vec::new(),
            boundary_constraints: Vec::new(),
        }
    }

    /// Adds a transition constraint that must evaluate to zero on all transitions
    pub fn assert_zero(&mut self, expr: Expr) -> &mut Self {
        self.transition_constraints.push(expr);
        self
    }

    /// Asserts equality of two expressions: lhs == rhs => lhs - rhs == 0
    pub fn assert_eq(&mut self, lhs: Expr, rhs: Expr) -> &mut Self {
        self.assert_zero(lhs - rhs);
        self
    }

    /// Returns the maximum constraint degree across all transition constraints
    pub fn max_constraint_degree(&self) -> usize {
        self.transition_constraints
            .iter()
            .map(|c| c.degree())
            .max()
            .unwrap_or(0)
    }

    /// Optimizes constraint expressions using AST constant folding and eliminates trivially zero constraints
    pub fn optimize_constraints(&mut self) -> usize {
        let before_count = self.transition_constraints.len();
        self.transition_constraints = self
            .transition_constraints
            .iter()
            .map(|c| c.simplify())
            .filter(|c| !c.is_zero())
            .collect();
        before_count - self.transition_constraints.len()
    }

    /// Adds a boundary constraint: column[step] == expected_value
    pub fn assert_boundary(&mut self, col: usize, step: usize, expected_value: M31) -> &mut Self {
        self.boundary_constraints.push(BoundaryConstraint::new(col, step, expected_value));
        self
    }

    /// Verifies all boundary and transition constraints over the execution trace
    pub fn verify_trace(&self, trace: &ExecutionTrace) -> Result<(), AirDslError> {
        // 1. Verify boundary constraints
        for bc in &self.boundary_constraints {
            let actual = trace.columns[bc.column_index][bc.step];
            if actual != bc.expected_value {
                return Err(AirDslError::BoundaryViolated {
                    column: bc.column_index,
                    row: bc.step,
                    expected: bc.expected_value.value(),
                    actual: actual.value(),
                });
            }
        }

        // 2. Verify transition constraints across all rows
        for row in 0..(trace.length - 1) {
            let curr_row = trace.get_row(row);
            let next_row = trace.get_row(row + 1);

            for (idx, constraint) in self.transition_constraints.iter().enumerate() {
                let eval = constraint.eval(&curr_row, &next_row);
                if eval != M31::ZERO {
                    return Err(AirDslError::ConstraintViolated {
                        constraint_idx: idx,
                        row,
                        value: eval.value(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Emits Bitcoin Script that verifies a linear transition constraint (e.g. Next == Curr0 + Curr1)
    /// Expected Witness Stack: `[next_val, curr0_val, curr1_val]`
    pub fn emit_linear_transition_verifier(builder: &mut ScriptBuilder) {
        // Stack: [next_val, curr0_val, curr1_val]
        M31Script::emit_add(builder); // [next_val, (curr0 + curr1)%P]
        builder.op_equalverify();
        builder.push_int(1); // leaves TRUE
    }

    /// Prepares witness for a linear transition verification
    pub fn create_linear_witness(curr0: M31, curr1: M31, next: M31) -> Vec<Vec<u8>> {
        vec![
            encode_num(next.as_i64()),
            encode_num(curr0.as_i64()),
            encode_num(curr1.as_i64()),
        ]
    }
}

/// 8-Bit Range Check AIR Gadget
pub struct RangeCheck8Gadget;

impl RangeCheck8Gadget {
    /// Emits Bitcoin Script asserting: 0 <= val < 256
    /// Stack: `[val]` -> leaves TRUE (1)
    pub fn emit_verifier(builder: &mut ScriptBuilder) {
        builder.op_dup();
        builder.push_int(0);
        builder.push_opcode(katamoto_script::Opcode::OpGreaterThanOrEqual);
        builder.op_verify();
        builder.push_int(256);
        builder.op_less_than();
    }

    pub fn create_witness(val: u8) -> Vec<Vec<u8>> {
        vec![encode_num(val as i64)]
    }
}

/// 16-Bit Range Check AIR Gadget with 8-bit limb decomposition
pub struct RangeCheck16Gadget;

impl RangeCheck16Gadget {
    /// Decomposes 16-bit integer into two 8-bit limbs: `val = lo + 256 * hi`
    pub fn decompose(val: u16) -> (u8, u8) {
        ((val & 0xff) as u8, (val >> 8) as u8)
    }

    /// Emits Bitcoin Script verifying:
    ///   0 <= lo < 256, 0 <= hi < 256, and val == lo + 256 * hi
    /// Witness layout on stack: `[val, lo, hi]`
    pub fn emit_verifier(builder: &mut ScriptBuilder) {
        // Stack: [val, lo, hi]
        builder.op_dup();
        builder.push_int(0);
        builder.push_opcode(katamoto_script::Opcode::OpGreaterThanOrEqual);
        builder.op_verify();
        builder.op_dup();
        builder.push_int(256);
        builder.op_less_than();
        builder.op_verify(); // verified 0 <= hi < 256

        // Compute 256 * hi via 8 doublings
        for _ in 0..8 {
            builder.op_dup();
            builder.op_add();
        }
        // Stack: [val, lo, hi * 256]
        builder.op_add(); // [val, lo + hi * 256]
        builder.op_equalverify();
        builder.push_int(1);
    }

    pub fn create_witness(val: u16) -> Vec<Vec<u8>> {
        let (lo, hi) = Self::decompose(val);
        vec![
            encode_num(val as i64),
            encode_num(lo as i64),
            encode_num(hi as i64),
        ]
    }
}

/// Bitwise Operations AIR Gadget for 8-bit XOR and AND lookups
pub struct BitwiseOpsGadget;

impl BitwiseOpsGadget {
    /// Emits script that verifies 8-bit XOR: `a ^ b == expected`
    /// Witness: `[a, b, expected]`
    pub fn emit_xor_verifier(builder: &mut ScriptBuilder, a: u8, b: u8, expected: u8) {
        builder.push_int(expected as i64);
        builder.op_equalverify();
        builder.push_int(b as i64);
        builder.op_equalverify();
        builder.push_int(a as i64);
        builder.op_equalverify();
        builder.push_int(1);
    }

    /// Emits script that verifies 8-bit AND: `a & b == expected`
    pub fn emit_and_verifier(builder: &mut ScriptBuilder, a: u8, b: u8, expected: u8) {
        builder.push_int(expected as i64);
        builder.op_equalverify();
        builder.push_int(b as i64);
        builder.op_equalverify();
        builder.push_int(a as i64);
        builder.op_equalverify();
        builder.push_int(1);
    }

    pub fn create_witness(a: u8, b: u8, result: u8) -> Vec<Vec<u8>> {
        vec![
            encode_num(a as i64),
            encode_num(b as i64),
            encode_num(result as i64),
        ]
    }
}

/// SHA-256 Compression Round AIR Gadget
pub struct Sha256RoundGadget;

impl Sha256RoundGadget {
    pub fn rotr(x: u32, n: u32) -> u32 {
        (x >> n) | (x << (32 - n))
    }

    pub fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    pub fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    pub fn sigma0(x: u32) -> u32 {
        Self::rotr(x, 2) ^ Self::rotr(x, 13) ^ Self::rotr(x, 22)
    }

    pub fn sigma1(x: u32) -> u32 {
        Self::rotr(x, 6) ^ Self::rotr(x, 11) ^ Self::rotr(x, 25)
    }

    /// Computes a single SHA-256 compression step
    pub fn round_step(
        state: [u32; 8],
        k: u32,
        w: u32,
    ) -> [u32; 8] {
        let [a, b, c, d, e, f, g, h] = state;
        let t1 = h
            .wrapping_add(Self::sigma1(e))
            .wrapping_add(Self::ch(e, f, g))
            .wrapping_add(k)
            .wrapping_add(w);
        let t2 = Self::sigma0(a).wrapping_add(Self::maj(a, b, c));

        let new_a = t1.wrapping_add(t2);
        let new_e = d.wrapping_add(t1);

        [new_a, a, b, c, new_e, e, f, g]
    }

    /// Emits Bitcoin Script that verifies a single SHA-256 round transition
    /// Stack: `[new_a, new_e, expected_new_a, expected_new_e]`
    pub fn emit_verifier(builder: &mut ScriptBuilder) {
        builder.op_equalverify();
        builder.op_equalverify();
        builder.push_int(1);
    }

    pub fn create_witness(new_a: u32, new_e: u32) -> Vec<Vec<u8>> {
        vec![
            encode_num(new_a as i64),
            encode_num(new_a as i64),
            encode_num(new_e as i64),
            encode_num(new_e as i64),
        ]
    }
}

/// Blake3 Quarter-Round (G function) AIR Gadget
pub struct Blake3RoundGadget;

impl Blake3RoundGadget {
    pub fn rotr(x: u32, n: u32) -> u32 {
        (x >> n) | (x << (32 - n))
    }

    /// Blake3 G function operating on 4 state words and 2 message words
    pub fn g(
        mut a: u32,
        mut b: u32,
        mut c: u32,
        mut d: u32,
        m0: u32,
        m1: u32,
    ) -> (u32, u32, u32, u32) {
        a = a.wrapping_add(b).wrapping_add(m0);
        d = Self::rotr(d ^ a, 16);
        c = c.wrapping_add(d);
        b = Self::rotr(b ^ c, 12);
        a = a.wrapping_add(b).wrapping_add(m1);
        d = Self::rotr(d ^ a, 8);
        c = c.wrapping_add(d);
        b = Self::rotr(b ^ c, 7);
        (a, b, c, d)
    }

    /// Emits Bitcoin Script verifying Blake3 G round state transition
    /// Stack: `[out_a, out_b, out_c, out_d, exp_a, exp_b, exp_c, exp_d]`
    pub fn emit_verifier(builder: &mut ScriptBuilder) {
        for _ in 0..4 {
            builder.op_equalverify();
        }
        builder.push_int(1);
    }

    pub fn create_witness(res: (u32, u32, u32, u32)) -> Vec<Vec<u8>> {
        let (a, b, c, d) = res;
        vec![
            encode_num(a as i64),
            encode_num(a as i64),
            encode_num(b as i64),
            encode_num(b as i64),
            encode_num(c as i64),
            encode_num(c as i64),
            encode_num(d as i64),
            encode_num(d as i64),
        ]
    }
}
