use crate::m31::{M31Script, M31, M31_P};
use katamoto_script::{builder::encode_num, ScriptBuilder};
use std::ops::{Add, Neg, Sub};

/// A point (x, y) on the Circle Curve over Mersenne-31:
///   C(M31) = { (x, y) \in M31^2 | x^2 + y^2 = 1 }
/// The group law is rotation / complex multiplication:
///   (x1, y1) + (x2, y2) = (x1*x2 - y1*y2, x1*y2 + x2*y1)
/// Neutral element is (1, 0).
/// Inverse of (x, y) is (x, -y).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CirclePoint {
    pub x: M31,
    pub y: M31,
}

impl Default for CirclePoint {
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl CirclePoint {
    /// Identity element (1, 0)
    pub const IDENTITY: CirclePoint = CirclePoint {
        x: M31::ONE,
        y: M31::ZERO,
    };

    /// Order 2 element (-1, 0)
    pub const ORDER_2: CirclePoint = CirclePoint {
        x: M31((M31_P - 1) as u32),
        y: M31::ZERO,
    };

    /// Order 4 element (0, 1)
    pub const ORDER_4: CirclePoint = CirclePoint {
        x: M31::ZERO,
        y: M31::ONE,
    };

    pub fn new(x: M31, y: M31) -> Self {
        Self { x, y }
    }

    /// Checks if point lies on the unit circle x^2 + y^2 = 1 (mod M31_P)
    pub fn is_on_curve(&self) -> bool {
        (self.x * self.x) + (self.y * self.y) == M31::ONE
    }

    /// Point doubling: 2 * (x, y) = (2x^2 - 1, 2xy)
    pub fn double(&self) -> Self {
        let two = M31::new(2);
        let x_sq = self.x * self.x;
        let next_x = (two * x_sq) - M31::ONE;
        let next_y = two * self.x * self.y;
        Self {
            x: next_x,
            y: next_y,
        }
    }

    /// Scalar multiplication by repeated doubling and addition: k * P
    pub fn mul(&self, mut scalar: u64) -> Self {
        let mut base = *self;
        let mut res = Self::IDENTITY;
        while scalar > 0 {
            if scalar % 2 == 1 {
                res = res + base;
            }
            base = base.double();
            scalar /= 2;
        }
        res
    }

    /// Complex conjugate / group inverse: (x, -y)
    pub fn conjugate(&self) -> Self {
        Self {
            x: self.x,
            y: -self.y,
        }
    }
}

impl Add for CirclePoint {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        // (x1*x2 - y1*y2, x1*y2 + x2*y1)
        let x = (self.x * rhs.x) - (self.y * rhs.y);
        let y = (self.x * rhs.y) + (self.y * rhs.x);
        Self { x, y }
    }
}

impl Sub for CirclePoint {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs.conjugate()
    }
}

impl Neg for CirclePoint {
    type Output = Self;
    fn neg(self) -> Self::Output {
        self.conjugate()
    }
}

/// Computes modular square root in Mersenne-31 if it exists:
/// Since P = 2^31 - 1 = 3 (mod 4), sqrt(a) = a^((P + 1) / 4) = a^(2^29)
pub fn m31_sqrt(a: M31) -> Option<M31> {
    if a == M31::ZERO {
        return Some(M31::ZERO);
    }
    // (P + 1) / 4 = 2^31 / 4 = 2^29 = 536870912
    let candidate = a.pow(1 << 29);
    if candidate * candidate == a {
        Some(candidate)
    } else {
        None
    }
}

/// Circle Subgroup Generator Generator:
/// Given a point P of order 2^k, finds a point Q of order 2^(k+1) such that 2Q = P.
/// Formula:
/// 2 * (x_q, y_q) = (2 * x_q^2 - 1, 2 * x_q * y_q) = (x_p, y_p)
/// => x_q^2 = (x_p + 1) / 2
pub fn circle_half_point(p: CirclePoint) -> CirclePoint {
    let two_inv = M31::new(2).inv().unwrap();
    let x_plus_1_half = (p.x + M31::ONE) * two_inv;

    if let Some(x_q) = m31_sqrt(x_plus_1_half) {
        let y_sq = M31::ONE - (x_q * x_q);
        let y_q = m31_sqrt(y_sq).expect("y_q must exist on circle");
        // Check if 2*(x_q, y_q) == p
        let cand = CirclePoint::new(x_q, y_q);
        if cand.double() == p {
            cand
        } else {
            CirclePoint::new(x_q, -y_q)
        }
    } else {
        // If (x_p + 1)/2 is not quadratic residue, try (1 - x_p)/2
        let one_minus_x_half = (M31::ONE - p.x) * two_inv;
        let y_q = m31_sqrt(one_minus_x_half).expect("Alternate half must be QR");
        let x_sq = M31::ONE - (y_q * y_q);
        let x_q = m31_sqrt(x_sq).expect("x_q must exist");
        let cand = CirclePoint::new(x_q, y_q);
        if cand.double() == p {
            cand
        } else {
            CirclePoint::new(-x_q, y_q)
        }
    }
}

/// Generates a Circle Subgroup generator of order 2^log_size
pub fn circle_subgroup_generator(log_size: usize) -> CirclePoint {
    assert!(log_size >= 1 && log_size <= 31, "Subgroup order must be 2^1..2^31");
    if log_size == 1 {
        return CirclePoint::ORDER_2;
    }
    if log_size == 2 {
        return CirclePoint::ORDER_4;
    }

    // Start with order 4 point (0, 1) and repeatedly halve
    let mut current = CirclePoint::ORDER_4;
    for _ in 2..log_size {
        current = circle_half_point(current);
    }
    current
}

/// Circle Domain of size 2^log_size
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircleDomain {
    pub log_size: usize,
    pub size: usize,
    pub generator: CirclePoint,
    pub points: Vec<CirclePoint>,
    pub y_inverses: Vec<M31>,
    pub x_inverses: Vec<M31>,
}

impl CircleDomain {
    pub fn new(log_size: usize) -> Self {
        let size = 1 << log_size;
        let gen = circle_subgroup_generator(log_size);
        let mut points = Vec::with_capacity(size);
        let mut curr = CirclePoint::IDENTITY;
        for _ in 0..size {
            points.push(curr);
            curr = curr + gen;
        }
        Self {
            log_size,
            size,
            generator: gen,
            points,
            y_inverses: Vec::new(),
            x_inverses: Vec::new(),
        }
    }

    /// Coset domain: D = { G_{2N} + j * G_N }
    /// In a coset domain, x != 0 and y != 0 for every point, enabling division-free FFT twiddles!
    /// Precomputes twiddle inverses using Montgomery batch inversion for zero-inversion FFT loops.
    pub fn coset(log_size: usize) -> Self {
        let size = 1 << log_size;
        let shift = circle_subgroup_generator(log_size + 1);
        let gen = circle_subgroup_generator(log_size);
        let mut points = Vec::with_capacity(size);
        let mut curr = shift;
        for _ in 0..size {
            points.push(curr);
            curr = curr + gen;
        }

        let y_coords: Vec<M31> = points[..size / 2].iter().map(|p| p.y).collect();
        let y_inverses = M31::batch_inv(&y_coords).unwrap_or_default();

        let x_coords: Vec<M31> = points.iter().map(|p| p.x).collect();
        let x_inverses = M31::batch_inv(&x_coords).unwrap_or_default();

        Self {
            log_size,
            size,
            generator: gen,
            points,
            y_inverses,
            x_inverses,
        }
    }

    /// Returns the precomputed inverse of point x-coordinate for stage 2 x-butterflies
    #[inline(always)]
    pub fn inv_x(&self, idx: usize) -> M31 {
        if idx < self.x_inverses.len() {
            self.x_inverses[idx]
        } else {
            self.points[idx].x.inv().unwrap_or(M31::ONE)
        }
    }

    /// Returns the precomputed inverse of point y-coordinate for stage 1 y-butterflies
    #[inline(always)]
    pub fn inv_y(&self, idx: usize) -> M31 {
        if idx < self.y_inverses.len() {
            self.y_inverses[idx]
        } else {
            self.points[idx].y.inv().expect("Point y must be invertible")
        }
    }
}

/// Bitcoin Script Gadgets for Circle Curve Point Verification
pub struct CircleScript;

impl CircleScript {
    /// Emits script to verify that point (x, y) satisfies x^2 + y^2 == 1 (mod P)
    ///
    /// Witness layout on stack:
    /// `[x_sq, y_sq, 1]`
    /// Where x_sq and y_sq have been verified as x*x and y*y by M31Script::emit_mul_verify
    /// Then simply adds x_sq + y_sq and checks equal to 1.
    pub fn emit_verify_on_circle(builder: &mut ScriptBuilder) {
        // Stack: [x_sq, y_sq]
        M31Script::emit_add(builder);
        builder.push_int(1);
        builder.op_equalverify();
        builder.push_int(1); // leaves TRUE
    }

    /// Emits script that verifies the circle group addition law:
    ///   x3 == (x1*x2 - y1*y2) mod P
    ///   y3 == (x1*y2 + x2*y1) mod P
    ///
    /// Witness stack inputs provided:
    /// `[x3, term_x1x2, term_y1y2, y3, term_x1y2, term_x2y1]`
    pub fn emit_verify_point_add(builder: &mut ScriptBuilder) {
        // 1. Verify y3 == term_x1y2 + term_x2y1
        // Stack top: [y3, term_x1y2, term_x2y1]
        M31Script::emit_add(builder); // stack: [y3, (term_x1y2 + term_x2y1)%P]
        builder.op_equalverify();     // asserts y3 match

        // 2. Verify x3 == term_x1x2 - term_y1y2
        // Stack top: [x3, term_x1x2, term_y1y2]
        M31Script::emit_sub(builder); // stack: [x3, (term_x1x2 - term_y1y2)%P]
        builder.op_equalverify();     // asserts x3 match

        builder.push_int(1);          // leaves TRUE
    }

    /// Prepares witness for point addition verification
    pub fn create_point_add_witness(p1: CirclePoint, p2: CirclePoint) -> Vec<Vec<u8>> {
        let p3 = p1 + p2;
        let t_x1x2 = p1.x * p2.x;
        let t_y1y2 = p1.y * p2.y;
        let t_x1y2 = p1.x * p2.y;
        let t_x2y1 = p2.x * p1.y;

        vec![
            encode_num(p3.x.as_i64()),
            encode_num(t_x1x2.as_i64()),
            encode_num(t_y1y2.as_i64()),
            encode_num(p3.y.as_i64()),
            encode_num(t_x1y2.as_i64()),
            encode_num(t_x2y1.as_i64()),
        ]
    }
}
