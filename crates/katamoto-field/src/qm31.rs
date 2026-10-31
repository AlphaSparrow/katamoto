use crate::m31::{M31Script, M31};
use katamoto_script::ScriptBuilder;
use std::ops::{Add, Mul, Neg, Sub};

/// Complex Extension Field over Mersenne-31: CM31 = M31[i] / (i^2 + 1)
/// Elements are represented as a + b*i where a, b in M31.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct CM31 {
    pub a: M31,
    pub b: M31,
}

impl CM31 {
    pub const ZERO: CM31 = CM31 { a: M31::ZERO, b: M31::ZERO };
    pub const ONE: CM31 = CM31 { a: M31::ONE, b: M31::ZERO };
    pub const I: CM31 = CM31 { a: M31::ZERO, b: M31::ONE };

    pub fn new(a: u32, b: u32) -> Self {
        Self {
            a: M31::new(a as u64),
            b: M31::new(b as u64),
        }
    }

    pub fn from_m31(a: M31, b: M31) -> Self {
        Self { a, b }
    }

    /// Norm: a^2 + b^2 in M31
    pub fn norm(self) -> M31 {
        (self.a * self.a) + (self.b * self.b)
    }

    /// Fast squaring in CM31: (a + bi)^2 = (a^2 - b^2) + 2abi
    #[inline(always)]
    pub fn sqr(self) -> Self {
        let a_sq = self.a.sqr();
        let b_sq = self.b.sqr();
        let ab = self.a * self.b;
        Self {
            a: a_sq - b_sq,
            b: ab + ab,
        }
    }

    /// Multiplicative inverse: (a - b*i) / (a^2 + b^2)
    pub fn inv(self) -> Option<Self> {
        let n = self.norm();
        let inv_n = n.inv()?;
        Some(Self {
            a: self.a * inv_n,
            b: -self.b * inv_n,
        })
    }
}

impl Add for CM31 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self {
            a: self.a + rhs.a,
            b: self.b + rhs.b,
        }
    }
}

impl Sub for CM31 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            a: self.a - rhs.a,
            b: self.b - rhs.b,
        }
    }
}

impl Mul for CM31 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        // (a0 + a1*i)(b0 + b1*i) = (a0*b0 - a1*b1) + (a0*b1 + a1*b0)*i
        let real = (self.a * rhs.a) - (self.b * rhs.b);
        let imag = (self.a * rhs.b) + (self.b * rhs.a);
        Self { a: real, b: imag }
    }
}

impl Neg for CM31 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self {
            a: -self.a,
            b: -self.b,
        }
    }
}

/// Quartic Extension Field over Mersenne-31: QM31 = CM31[j] / (j^2 - (2 + i))
/// Field size is (2^31 - 1)^4 ~= 2^124, providing 124-bit cryptographic security for STARKs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct QM31 {
    pub c0: CM31,
    pub c1: CM31,
}

impl QM31 {
    pub const ZERO: QM31 = QM31 { c0: CM31::ZERO, c1: CM31::ZERO };
    pub const ONE: QM31 = QM31 { c0: CM31::ONE, c1: CM31::ZERO };

    pub fn new(c0: CM31, c1: CM31) -> Self {
        Self { c0, c1 }
    }

    pub fn from_u32(a: u32, b: u32, c: u32, d: u32) -> Self {
        Self {
            c0: CM31::new(a, b),
            c1: CM31::new(c, d),
        }
    }

    pub fn from_m31(a: M31, b: M31, c: M31, d: M31) -> Self {
        Self {
            c0: CM31::from_m31(a, b),
            c1: CM31::from_m31(c, d),
        }
    }

    /// Multiply by irreducible element (2 + i) in CM31
    fn mul_by_generator(z: CM31) -> CM31 {
        // (2 + i) * (u + v*i) = (2u - v) + (u + 2v)*i
        let two = M31::new(2);
        let real = (two * z.a) - z.b;
        let imag = z.a + (two * z.b);
        CM31 { a: real, b: imag }
    }

    /// Multiplicative inverse in QM31:
    /// (c0 + c1*j)^-1 = (c0 - c1*j) / (c0^2 - c1^2 * (2+i))
    pub fn inv(self) -> Option<Self> {
        let c0_sq = self.c0.sqr();
        let c1_sq = self.c1.sqr();
        let denom = c0_sq - Self::mul_by_generator(c1_sq);
        let denom_inv = denom.inv()?;
        Some(Self {
            c0: self.c0 * denom_inv,
            c1: -self.c1 * denom_inv,
        })
    }

    /// Fast squaring in QM31: (c0 + c1*j)^2 = (c0^2 + c1^2*(2+i)) + 2*c0*c1*j
    #[inline(always)]
    pub fn sqr(self) -> Self {
        let c0_sq = self.c0.sqr();
        let c1_sq = self.c1.sqr();
        let c01 = self.c0 * self.c1;
        Self {
            c0: c0_sq + Self::mul_by_generator(c1_sq),
            c1: c01 + c01,
        }
    }

    pub fn pow(self, mut exp: u64) -> Self {
        let mut base = self;
        let mut res = QM31::ONE;
        while exp > 0 {
            if exp % 2 == 1 {
                res = res * base;
            }
            base = base.sqr();
            exp /= 2;
        }
        res
    }

    /// Montgomery batch inversion for QM31 elements:
    /// Inverts an entire slice of QM31 elements using only a single M31 field inversion!
    /// Returns None if any element in `src` is non-invertible (zero).
    pub fn batch_inv(src: &[QM31]) -> Option<Vec<QM31>> {
        if src.is_empty() {
            return Some(Vec::new());
        }
        let n = src.len();
        let mut denoms = Vec::with_capacity(n);
        let mut norms = Vec::with_capacity(n);

        for x in src {
            let c0_sq = x.c0.sqr();
            let c1_sq = x.c1.sqr();
            let denom = c0_sq - Self::mul_by_generator(c1_sq);
            let norm = denom.norm();
            if norm.0 == 0 {
                return None;
            }
            denoms.push(denom);
            norms.push(norm);
        }

        let inv_norms = M31::batch_inv(&norms)?;
        let mut result = Vec::with_capacity(n);
        for (i, x) in src.iter().enumerate() {
            let denom = denoms[i];
            let inv_n = inv_norms[i];
            let denom_inv = CM31 {
                a: denom.a * inv_n,
                b: -denom.b * inv_n,
            };
            result.push(QM31 {
                c0: x.c0 * denom_inv,
                c1: -x.c1 * denom_inv,
            });
        }
        Some(result)
    }

    /// In-place Montgomery batch inversion for QM31 elements.
    pub fn batch_inv_in_place(items: &mut [QM31]) -> bool {
        if let Some(invs) = Self::batch_inv(items) {
            items.copy_from_slice(&invs);
            true
        } else {
            false
        }
    }

    /// As an array of 4 M31 elements: [c0.a, c0.b, c1.a, c1.b]
    pub fn to_array(self) -> [M31; 4] {
        [self.c0.a, self.c0.b, self.c1.a, self.c1.b]
    }

    /// In-place batch addition: dst[i] = dst[i] + src[i]
    #[inline(always)]
    pub fn batch_add(dst: &mut [QM31], src: &[QM31]) {
        assert_eq!(dst.len(), src.len());
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            *d = *d + *s;
        }
    }

    /// In-place batch subtraction: dst[i] = dst[i] - src[i]
    #[inline(always)]
    pub fn batch_sub(dst: &mut [QM31], src: &[QM31]) {
        assert_eq!(dst.len(), src.len());
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            *d = *d - *s;
        }
    }

    /// In-place batch multiplication: dst[i] = dst[i] * src[i]
    #[inline(always)]
    pub fn batch_mul(dst: &mut [QM31], src: &[QM31]) {
        assert_eq!(dst.len(), src.len());
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            *d = *d * *s;
        }
    }

    /// In-place batch scalar multiplication: dst[i] = dst[i] * scalar
    #[inline(always)]
    pub fn batch_scale(dst: &mut [QM31], scalar: QM31) {
        for d in dst.iter_mut() {
            *d = *d * scalar;
        }
    }
}

impl Add for QM31 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
        }
    }
}

impl Sub for QM31 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            c0: self.c0 - rhs.c0,
            c1: self.c1 - rhs.c1,
        }
    }
}

impl Mul for QM31 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        // (a0 + a1*j)(b0 + b1*j) = (a0*b0 + a1*b1*(2+i)) + (a0*b1 + a1*b0)*j
        let term0 = self.c0 * rhs.c0;
        let term1 = Self::mul_by_generator(self.c1 * rhs.c1);
        let cross = (self.c0 * rhs.c1) + (self.c1 * rhs.c0);
        Self {
            c0: term0 + term1,
            c1: cross,
        }
    }
}

impl Neg for QM31 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self {
            c0: -self.c0,
            c1: -self.c1,
        }
    }
}

/// Bitcoin Script Gadgets for QM31 extension field operations
pub struct QM31Script;

impl QM31Script {
    /// Emits script that adds two QM31 elements on the stack:
    /// Input Stack: `[..., A_0, A_1, A_2, A_3, B_0, B_1, B_2, B_3]`
    /// Output Stack: `[..., (A + B)_0, (A + B)_1, (A + B)_2, (A + B)_3]`
    pub fn emit_add(builder: &mut ScriptBuilder) {
        // Roll A3 and add with B3
        builder.op_roll(4);
        M31Script::emit_add(builder);
        builder.op_toaltstack(); // altstack: [R3]

        // Roll A2 and add with B2
        builder.op_roll(3);
        M31Script::emit_add(builder);
        builder.op_toaltstack(); // altstack: [R3, R2]

        // Roll A1 and add with B1
        builder.op_roll(2);
        M31Script::emit_add(builder);
        builder.op_toaltstack(); // altstack: [R3, R2, R1]

        // Add A0 and B0
        M31Script::emit_add(builder); // stack: [R0]

        // Restore R1, R2, R3 in canonical order [R0, R1, R2, R3]
        builder.op_fromaltstack(); // stack: [R0, R1]
        builder.op_fromaltstack(); // stack: [R0, R1, R2]
        builder.op_fromaltstack(); // stack: [R0, R1, R2, R3]
    }

    /// Emits script that subtracts two QM31 elements on the stack:
    /// Input Stack: `[..., A_0, A_1, A_2, A_3, B_0, B_1, B_2, B_3]`
    /// Output Stack: `[..., (A - B)_0, (A - B)_1, (A - B)_2, (A - B)_3]`
    pub fn emit_sub(builder: &mut ScriptBuilder) {
        // Roll A3 to top, swap to get A3 - B3
        builder.op_roll(4);
        builder.op_swap();
        M31Script::emit_sub(builder);
        builder.op_toaltstack(); // altstack: [R3]

        // Roll A2 to top, swap to get A2 - B2
        builder.op_roll(3);
        builder.op_swap();
        M31Script::emit_sub(builder);
        builder.op_toaltstack(); // altstack: [R3, R2]

        // Roll A1 to top, swap to get A1 - B1
        builder.op_roll(2);
        builder.op_swap();
        M31Script::emit_sub(builder);
        builder.op_toaltstack(); // altstack: [R3, R2, R1]

        // A0 - B0
        M31Script::emit_sub(builder); // stack: [R0]

        // Restore R1, R2, R3 in canonical order [R0, R1, R2, R3]
        builder.op_fromaltstack(); // stack: [R0, R1]
        builder.op_fromaltstack(); // stack: [R0, R1, R2]
        builder.op_fromaltstack(); // stack: [R0, R1, R2, R3]
    }

    /// Verifies equality of two QM31 elements on stack:
    /// Input Stack: `[expected_QM31 (A0..A3), actual_QM31 (B0..B3)]` (B3 on top)
    /// Leaves TRUE (1) on stack if identical.
    pub fn emit_equalverify(builder: &mut ScriptBuilder) {
        // Stack: [A0, A1, A2, A3, B0, B1, B2, B3]
        builder.op_roll(4);
        builder.op_equalverify(); // A3 == B3

        builder.op_roll(3);
        builder.op_equalverify(); // A2 == B2

        builder.op_roll(2);
        builder.op_equalverify(); // A1 == B1

        builder.op_equalverify(); // A0 == B0

        builder.push_int(1);
    }
}
