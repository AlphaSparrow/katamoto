use katamoto_script::{Opcode, ScriptBuilder};
use std::ops::{Add, Mul, Neg, Sub};

/// Mersenne-31 prime: P = 2^31 - 1 = 2,147,483,647
pub const M31_P: i64 = 2147483647;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct M31(pub u32);

impl M31 {
    pub const ZERO: M31 = M31(0);
    pub const ONE: M31 = M31(1);

    pub fn new(val: u64) -> Self {
        Self((val % (M31_P as u64)) as u32)
    }

    pub fn value(self) -> u32 {
        self.0
    }

    pub fn as_i64(self) -> i64 {
        self.0 as i64
    }

    pub fn inv(self) -> Option<Self> {
        if self.0 == 0 {
            return None;
        }
        // Fermat's Little Theorem: a^(P-2) mod P
        Some(self.pow(M31_P as u64 - 2))
    }

    pub fn pow(self, mut exp: u64) -> Self {
        let mut base = self;
        let mut res = M31::ONE;
        while exp > 0 {
            if exp % 2 == 1 {
                res = res * base;
            }
            base = base * base;
            exp /= 2;
        }
        res
    }

    /// Decomposes the field element into 31 binary bits (LSB first: bit_0, bit_1, ..., bit_30)
    pub fn to_bits(self) -> [u8; 31] {
        let mut bits = [0u8; 31];
        let mut val = self.0;
        for i in 0..31 {
            bits[i] = (val & 1) as u8;
            val >>= 1;
        }
        bits
    }
}

impl Add for M31 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        let sum = self.0 as u64 + rhs.0 as u64;
        let res = (sum & (M31_P as u64)) + (sum >> 31);
        M31((if res >= M31_P as u64 { res - M31_P as u64 } else { res }) as u32)
    }
}

impl Sub for M31 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        if self.0 >= rhs.0 {
            M31(self.0 - rhs.0)
        } else {
            M31((self.0 as i64 - rhs.0 as i64 + M31_P) as u32)
        }
    }
}

impl Mul for M31 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        let prod = (self.0 as u64) * (rhs.0 as u64);
        let res = (prod & (M31_P as u64)) + (prod >> 31);
        let res2 = (res & (M31_P as u64)) + (res >> 31);
        M31((if res2 >= M31_P as u64 { res2 - M31_P as u64 } else { res2 }) as u32)
    }
}

impl Neg for M31 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        if self.0 == 0 {
            M31::ZERO
        } else {
            M31((M31_P as u32) - self.0)
        }
    }
}

/// Script Gadgets for M31 field arithmetic in Bitcoin Script
pub struct M31Script;

impl M31Script {
    /// Emits script that adds top two stack items modulo M31_P:
    /// Input Stack: `[..., a, b]`
    /// Output Stack: `[..., (a + b) % M31_P]`
    pub fn emit_add(builder: &mut ScriptBuilder) {
        builder.op_add();
        builder.op_dup();
        builder.push_int(M31_P);
        builder.push_opcode(Opcode::OpGreaterThanOrEqual);
        builder.op_if();
        builder.push_int(M31_P);
        builder.op_sub();
        builder.op_endif();
    }

    /// Emits script that subtracts top two stack items modulo M31_P:
    /// Input Stack: `[..., a, b]` (computes a - b)
    /// Output Stack: `[..., (a - b) % M31_P]`
    pub fn emit_sub(builder: &mut ScriptBuilder) {
        builder.op_sub();
        builder.op_dup();
        builder.push_int(0);
        builder.push_opcode(Opcode::OpLessThan);
        builder.op_if();
        builder.push_int(M31_P);
        builder.op_add();
        builder.op_endif();
    }

    /// Emits script that doubles the top stack item modulo M31_P:
    /// Input Stack: `[..., a]`
    /// Output Stack: `[..., (2 * a) % M31_P]`
    pub fn emit_double(builder: &mut ScriptBuilder) {
        builder.op_dup();
        Self::emit_add(builder);
    }

    /// Emits script to verify: a * b == c (mod M31_P)
    /// Witness Layout Expected on Stack:
    /// `[expected_c, a, bit_30, bit_29, ..., bit_0]` (where sum(bit_i * 2^i) == b)
    ///
    /// Executes double-and-add inside Bitcoin Script and verifies equality with expected_c.
    pub fn emit_mul_verify(builder: &mut ScriptBuilder) {
        // Accumulator for product: acc = 0
        builder.push_int(0); // [c, a, bits..., acc]

        // For each bit from bit_0 up to bit_30:
        for i in 0..31 {
            // Stack at start of iteration:
            // depth to a is (31 - i + 2)
            // depth to bit_i is (31 - i + 1)
            // We want to do: if bit_i == 1 { acc = (acc + a) % P }; a = (2 * a) % P
            
            // Bring bit_i to top
            let bit_depth = 31 - i + 1;
            builder.op_roll(bit_depth as i64); // [..., acc, bit_i]

            // Validate bit is either 0 or 1
            builder.op_dup();
            builder.push_int(0);
            builder.push_opcode(Opcode::OpNumEqual);
            builder.op_over();
            builder.push_int(1);
            builder.push_opcode(Opcode::OpNumEqual);
            builder.push_opcode(Opcode::OpBoolOr);
            builder.op_verify(); // stack: [..., acc, bit_i]

            // If bit_i == 1: acc = (acc + a) % P
            builder.op_if();
            // Fetch 'a': depth is currently (31 - i + 1)
            let a_depth = 31 - i + 1;
            builder.op_pick(a_depth as i64); // [..., acc, a]
            Self::emit_add(builder); // [..., (acc + a) % P]
            builder.op_endif();

            // Double 'a' for the next bit, unless this is the last bit
            if i < 30 {
                let a_depth = 31 - i;
                builder.op_roll(a_depth as i64); // bring 'a' to top: [..., acc, a]
                Self::emit_double(builder); // [..., acc, (2*a)%P]
                builder.op_swap(); // keep acc on top: [..., (2*a)%P, acc]
            }
        }

        // Now stack is: [expected_c, final_a, final_acc]
        builder.op_swap();
        builder.op_drop(); // drop final_a -> [expected_c, final_acc]
        builder.op_equalverify(); // confirms final_acc == expected_c
        builder.push_int(1); // leaves TRUE on stack
    }
}
