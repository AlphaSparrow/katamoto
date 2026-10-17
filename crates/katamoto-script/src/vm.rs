use crate::builder::{decode_num, encode_num};
use crate::opcodes::Opcode;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_STACK_SIZE: usize = 1000;
pub const MAX_ELEMENT_SIZE: usize = 520;
pub const MAX_SCRIPT_NUM_LENGTH: usize = 4; // 32-bit math standard in Bitcoin Script

#[derive(Error, Debug, PartialEq, Eq)]
pub enum VmError {
    #[error("Stack underflow: needed {needed} items, had {available}")]
    StackUnderflow { needed: usize, available: usize },
    #[error("Stack size exceeded maximum of {MAX_STACK_SIZE}")]
    StackOverflow,
    #[error("Element size exceeded maximum of {MAX_ELEMENT_SIZE} bytes (got {0})")]
    ElementTooLarge(usize),
    #[error("ScriptNum error: {0}")]
    ScriptNumError(String),
    #[error("OP_VERIFY or OP_EQUALVERIFY failed")]
    VerifyFailed,
    #[error("Unexpected end of script during push data")]
    UnexpectedEof,
    #[error("Invalid opcode encountered: 0x{0:02x}")]
    InvalidOpcode(u8),
    #[error("Unmatched conditional OP_IF/OP_ELSE/OP_ENDIF")]
    UnmatchedConditional,
    #[error("Script evaluated to FALSE or empty stack")]
    ScriptFailed,
    #[error("Disabled or forbidden opcode executed: 0x{0:02x}")]
    DisabledOpcode(u8),
}

#[derive(Debug, Clone, Default)]
pub struct ExecutionStats {
    pub opcodes_executed: usize,
    pub max_stack_depth: usize,
    pub total_cycles: usize,
}

#[derive(Debug, Clone)]
pub struct Vm {
    stack: Vec<Vec<u8>>,
    alt_stack: Vec<Vec<u8>>,
    cond_stack: Vec<bool>,
    stats: ExecutionStats,
}

impl Vm {
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            alt_stack: Vec::new(),
            cond_stack: Vec::new(),
            stats: ExecutionStats::default(),
        }
    }

    pub fn with_witness(witness: Vec<Vec<u8>>) -> Self {
        let max_depth = witness.len();
        Self {
            stack: witness,
            alt_stack: Vec::new(),
            cond_stack: Vec::new(),
            stats: ExecutionStats {
                max_stack_depth: max_depth,
                ..Default::default()
            },
        }
    }

    pub fn stack(&self) -> &[Vec<u8>] {
        &self.stack
    }

    pub fn stats(&self) -> &ExecutionStats {
        &self.stats
    }

    fn push(&mut self, item: Vec<u8>) -> Result<(), VmError> {
        if item.len() > MAX_ELEMENT_SIZE {
            return Err(VmError::ElementTooLarge(item.len()));
        }
        if self.stack.len() >= MAX_STACK_SIZE {
            return Err(VmError::StackOverflow);
        }
        self.stack.push(item);
        if self.stack.len() > self.stats.max_stack_depth {
            self.stats.max_stack_depth = self.stack.len();
        }
        Ok(())
    }

    fn pop(&mut self) -> Result<Vec<u8>, VmError> {
        self.stack.pop().ok_or(VmError::StackUnderflow {
            needed: 1,
            available: self.stack.len(),
        })
    }

    fn pop_num(&mut self) -> Result<i64, VmError> {
        let bytes = self.pop()?;
        decode_num(&bytes, MAX_SCRIPT_NUM_LENGTH)
            .map_err(|e| VmError::ScriptNumError(e.to_string()))
    }

    fn push_num(&mut self, val: i64) -> Result<(), VmError> {
        let bytes = encode_num(val);
        self.push(bytes)
    }

    fn is_executing(&self) -> bool {
        self.cond_stack.iter().all(|&c| c)
    }

    pub fn execute(&mut self, script: &[u8]) -> Result<bool, VmError> {
        let mut pc = 0;
        let len = script.len();

        while pc < len {
            let byte = script[pc];
            pc += 1;

            // Handle push data opcodes
            if byte <= 0x4e {
                let data_len = if byte == 0 {
                    0
                } else if byte <= 0x4b {
                    byte as usize
                } else if byte == 0x4c {
                    if pc >= len { return Err(VmError::UnexpectedEof); }
                    let l = script[pc] as usize;
                    pc += 1;
                    l
                } else if byte == 0x4d {
                    if pc + 2 > len { return Err(VmError::UnexpectedEof); }
                    let l = u16::from_le_bytes([script[pc], script[pc + 1]]) as usize;
                    pc += 2;
                    l
                } else {
                    if pc + 4 > len { return Err(VmError::UnexpectedEof); }
                    let l = u32::from_le_bytes([
                        script[pc], script[pc + 1], script[pc + 2], script[pc + 3]
                    ]) as usize;
                    pc += 4;
                    l
                };

                if pc + data_len > len {
                    return Err(VmError::UnexpectedEof);
                }

                let data = script[pc..pc + data_len].to_vec();
                pc += data_len;

                if self.is_executing() {
                    self.push(data)?;
                }
                continue;
            }

            // Small integer pushes: OP_1NEGATE, OP_1..OP_16
            if byte == 0x4f {
                if self.is_executing() { self.push_num(-1)?; }
                continue;
            }
            if (0x51..=0x60).contains(&byte) {
                if self.is_executing() {
                    let val = (byte - 0x50) as i64;
                    self.push_num(val)?;
                }
                continue;
            }

            let opcode = Opcode::from_u8(byte)
                .ok_or(VmError::InvalidOpcode(byte))?;

            // Flow control opcodes are processed even when not executing branches
            match opcode {
                Opcode::OpIf => {
                    let cond = if self.is_executing() {
                        let top = self.pop()?;
                        top.iter().any(|&b| b != 0)
                    } else {
                        false
                    };
                    self.cond_stack.push(cond);
                    continue;
                }
                Opcode::OpNotIf => {
                    let cond = if self.is_executing() {
                        let top = self.pop()?;
                        top.iter().all(|&b| b == 0)
                    } else {
                        false
                    };
                    self.cond_stack.push(cond);
                    continue;
                }
                Opcode::OpElse => {
                    let last = self.cond_stack.last_mut().ok_or(VmError::UnmatchedConditional)?;
                    *last = !*last;
                    continue;
                }
                Opcode::OpEndIf => {
                    self.cond_stack.pop().ok_or(VmError::UnmatchedConditional)?;
                    continue;
                }
                _ => {}
            }

            if !self.is_executing() {
                continue;
            }

            self.stats.opcodes_executed += 1;

            match opcode {
                Opcode::Op0 => self.push(vec![])?,
                Opcode::OpNop => {}
                Opcode::OpVerify => {
                    let top = self.pop()?;
                    if top.iter().all(|&b| b == 0) {
                        return Err(VmError::VerifyFailed);
                    }
                }
                Opcode::OpReturn => return Err(VmError::ScriptFailed),

                // Stack operations
                Opcode::OpToAltStack => {
                    let item = self.pop()?;
                    self.alt_stack.push(item);
                }
                Opcode::OpFromAltStack => {
                    let item = self.alt_stack.pop().ok_or(VmError::StackUnderflow { needed: 1, available: 0 })?;
                    self.push(item)?;
                }
                Opcode::OpDepth => {
                    let d = self.stack.len() as i64;
                    self.push_num(d)?;
                }
                Opcode::OpDrop => { self.pop()?; }
                Opcode::Op2Drop => { self.pop()?; self.pop()?; }
                Opcode::OpDup => {
                    let top = self.stack.last().ok_or(VmError::StackUnderflow { needed: 1, available: 0 })?.clone();
                    self.push(top)?;
                }
                Opcode::Op2Dup => {
                    let n = self.stack.len();
                    if n < 2 { return Err(VmError::StackUnderflow { needed: 2, available: n }); }
                    let a = self.stack[n - 2].clone();
                    let b = self.stack[n - 1].clone();
                    self.push(a)?;
                    self.push(b)?;
                }
                Opcode::Op3Dup => {
                    let n = self.stack.len();
                    if n < 3 { return Err(VmError::StackUnderflow { needed: 3, available: n }); }
                    let a = self.stack[n - 3].clone();
                    let b = self.stack[n - 2].clone();
                    let c = self.stack[n - 1].clone();
                    self.push(a)?;
                    self.push(b)?;
                    self.push(c)?;
                }
                Opcode::OpOver => {
                    let n = self.stack.len();
                    if n < 2 { return Err(VmError::StackUnderflow { needed: 2, available: n }); }
                    let item = self.stack[n - 2].clone();
                    self.push(item)?;
                }
                Opcode::Op2Over => {
                    let n = self.stack.len();
                    if n < 4 { return Err(VmError::StackUnderflow { needed: 4, available: n }); }
                    let a = self.stack[n - 4].clone();
                    let b = self.stack[n - 3].clone();
                    self.push(a)?;
                    self.push(b)?;
                }
                Opcode::OpSwap => {
                    let n = self.stack.len();
                    if n < 2 { return Err(VmError::StackUnderflow { needed: 2, available: n }); }
                    self.stack.swap(n - 1, n - 2);
                }
                Opcode::OpRot => {
                    let n = self.stack.len();
                    if n < 3 { return Err(VmError::StackUnderflow { needed: 3, available: n }); }
                    let top = self.stack.remove(n - 3);
                    self.stack.push(top);
                }
                Opcode::OpNip => {
                    let n = self.stack.len();
                    if n < 2 { return Err(VmError::StackUnderflow { needed: 2, available: n }); }
                    self.stack.remove(n - 2);
                }
                Opcode::OpTuck => {
                    let n = self.stack.len();
                    if n < 2 { return Err(VmError::StackUnderflow { needed: 2, available: n }); }
                    let top = self.stack.last().unwrap().clone();
                    self.stack.insert(n - 2, top);
                }
                Opcode::OpPick => {
                    let d = self.pop_num()?;
                    if d < 0 || (d as usize) >= self.stack.len() {
                        return Err(VmError::StackUnderflow { needed: (d + 1) as usize, available: self.stack.len() });
                    }
                    let idx = self.stack.len() - 1 - (d as usize);
                    let item = self.stack[idx].clone();
                    self.push(item)?;
                }
                Opcode::OpRoll => {
                    let d = self.pop_num()?;
                    if d < 0 || (d as usize) >= self.stack.len() {
                        return Err(VmError::StackUnderflow { needed: (d + 1) as usize, available: self.stack.len() });
                    }
                    let idx = self.stack.len() - 1 - (d as usize);
                    let item = self.stack.remove(idx);
                    self.push(item)?;
                }

                // BIP-347 OP_CAT
                Opcode::OpCat => {
                    let y = self.pop()?;
                    let x = self.pop()?;
                    let total_len = x.len() + y.len();
                    if total_len > MAX_ELEMENT_SIZE {
                        return Err(VmError::ElementTooLarge(total_len));
                    }
                    let mut result = Vec::with_capacity(total_len);
                    result.extend_from_slice(&x);
                    result.extend_from_slice(&y);
                    self.push(result)?;
                }

                // Equality
                Opcode::OpEqual => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push_num(if a == b { 1 } else { 0 })?;
                }
                Opcode::OpEqualVerify => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    if a != b {
                        return Err(VmError::VerifyFailed);
                    }
                }

                // Arithmetic
                Opcode::OpAdd => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_num(a.saturating_add(b))?;
                }
                Opcode::OpSub => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_num(a.saturating_sub(b))?;
                }
                Opcode::Op1Add => {
                    let a = self.pop_num()?;
                    self.push_num(a.saturating_add(1))?;
                }
                Opcode::Op1Sub => {
                    let a = self.pop_num()?;
                    self.push_num(a.saturating_sub(1))?;
                }
                Opcode::OpNegate => {
                    let a = self.pop_num()?;
                    self.push_num(-a)?;
                }
                Opcode::OpAbs => {
                    let a = self.pop_num()?;
                    self.push_num(a.abs())?;
                }
                Opcode::OpNot => {
                    let a = self.pop_num()?;
                    self.push_num(if a == 0 { 1 } else { 0 })?;
                }
                Opcode::Op0NotEqual => {
                    let a = self.pop_num()?;
                    self.push_num(if a != 0 { 1 } else { 0 })?;
                }
                Opcode::OpNumEqual => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_num(if a == b { 1 } else { 0 })?;
                }
                Opcode::OpNumEqualVerify => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    if a != b {
                        return Err(VmError::VerifyFailed);
                    }
                }
                Opcode::OpLessThan => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_num(if a < b { 1 } else { 0 })?;
                }
                Opcode::OpGreaterThan => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_num(if a > b { 1 } else { 0 })?;
                }
                Opcode::OpMin => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_num(a.min(b))?;
                }
                Opcode::OpMax => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_num(a.max(b))?;
                }

                // Hashes
                Opcode::OpSha256 => {
                    let item = self.pop()?;
                    let hash = Sha256::digest(&item);
                    self.push(hash.to_vec())?;
                }
                Opcode::OpHash256 => {
                    let item = self.pop()?;
                    let hash1 = Sha256::digest(&item);
                    let hash2 = Sha256::digest(hash1);
                    self.push(hash2.to_vec())?;
                }
                _ => return Err(VmError::DisabledOpcode(byte)),
            }
        }

        if !self.cond_stack.is_empty() {
            return Err(VmError::UnmatchedConditional);
        }

        // Final evaluation: top element must be non-zero (or true)
        match self.stack.last() {
            Some(top) => Ok(top.iter().any(|&b| b != 0)),
            None => Ok(false),
        }
    }
}
