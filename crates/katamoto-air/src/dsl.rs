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
