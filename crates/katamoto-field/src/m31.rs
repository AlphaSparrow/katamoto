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
    /// `[expected_c, a, bit_30, bit_29, ..., bit_0]` (where sum(bit_i * 2^i) == b, with bit_0 at the top)
    ///
    /// Executes double-and-add inside Bitcoin Script and verifies equality with expected_c.
    pub fn emit_mul_verify(builder: &mut ScriptBuilder) {
        // Main stack: [expected_c, a, bit_30, bit_29, ..., bit_0]
        // Move 'a' to the top and transfer to altstack:
        // bit_0 is at depth 0, bit_30 is at depth 30, 'a' is at depth 31.
        builder.op_roll(31);
        builder.op_toaltstack(); // altstack: [a]

        // Push accumulator = 0 and transfer to altstack:
        builder.push_int(0);
        builder.op_toaltstack(); // altstack: [a, acc = 0]

        // Main stack now contains: [expected_c, bit_30, bit_29, ..., bit_0]
        // Top of main stack is bit_0.
        for i in 0..31 {
            // Validate bit_i is binary {0, 1}
            builder.op_dup();
            builder.push_int(0);
            builder.push_opcode(Opcode::OpNumEqual);
            builder.op_over();
            builder.push_int(1);
            builder.push_opcode(Opcode::OpNumEqual);
            builder.push_opcode(Opcode::OpBoolOr);
            builder.op_verify(); // leaves bit_i on top

            // If bit_i == 1: acc = (acc + a) % P
            builder.op_if();
            builder.op_fromaltstack(); // pop acc -> [..., acc]
            builder.op_fromaltstack(); // pop a   -> [..., acc, a]
            builder.op_dup();          // duplicate a: [..., acc, a, a]
            builder.op_toaltstack();   // restore 'a' to altstack: altstack=[a]
            Self::emit_add(builder);   // [..., (acc + a) % P]
            builder.op_toaltstack();   // store new_acc to altstack: altstack=[a, new_acc]
            builder.op_endif();

            // Double 'a' for the next round (unless this is the last bit round)
            if i < 30 {
                builder.op_fromaltstack(); // pop acc
                builder.op_fromaltstack(); // pop a
                Self::emit_double(builder); // (2 * a) % P
                builder.op_toaltstack();   // push doubled 'a': altstack=[2*a]
                builder.op_toaltstack();   // push acc: altstack=[2*a, acc]
            }
        }

        // All 31 bits have been processed and removed from main stack.
        // Main stack now contains: [expected_c]
        // Altstack contains: [final_a, final_acc]
        builder.op_fromaltstack(); // pop final_acc to main stack: [expected_c, final_acc]
        builder.op_equalverify();  // verifies expected_c == final_acc and drops both
        builder.op_fromaltstack(); // pop final_a from altstack
        builder.op_drop();         // clean up final_a
        builder.push_int(1);       // leaves TRUE (1) on stack
    }
}
