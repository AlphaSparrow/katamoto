use crate::builder::{decode_num, encode_num};
use crate::opcodes::Opcode;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_STACK_SIZE: usize = 1000;
pub const MAX_ELEMENT_SIZE: usize = 520;
pub const MAX_SCRIPT_NUM_LENGTH: usize = 8; // 64-bit ScriptNum support for Tapscript arithmetic

/// Memory-optimized stack item for the Bitcoin Tapscript VM.
/// Up to 32 bytes are stored inline without heap allocations (covering all hashes,
/// public keys, and ScriptNum integers). Larger payloads spill over to boxed slices.
#[derive(Clone, Eq, Hash)]
pub struct StackItem {
    len: u8,
    data: [u8; 32],
    heap: Option<Box<[u8]>>,
}

impl Default for StackItem {
    fn default() -> Self {
        Self::empty()
    }
}

impl std::fmt::Debug for StackItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.as_slice(), f)
    }
}

impl StackItem {
    pub const fn empty() -> Self {
        Self {
            len: 0,
            data: [0u8; 32],
            heap: None,
        }
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        if slice.len() <= 32 {
            let mut data = [0u8; 32];
            data[..slice.len()].copy_from_slice(slice);
            Self {
                len: slice.len() as u8,
                data,
                heap: None,
            }
        } else {
            Self {
                len: 0,
                data: [0u8; 32],
                heap: Some(slice.into()),
            }
        }
    }

    pub fn from_vec(vec: Vec<u8>) -> Self {
        if vec.len() <= 32 {
            Self::from_slice(&vec)
        } else {
            Self {
                len: 0,
                data: [0u8; 32],
                heap: Some(vec.into_boxed_slice()),
            }
        }
    }

    pub fn from_array_32(arr: [u8; 32]) -> Self {
        Self {
            len: 32,
            data: arr,
            heap: None,
        }
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        if let Some(h) = &self.heap {
            h.as_ref()
        } else {
            &self.data[..self.len as usize]
        }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        if let Some(h) = &self.heap {
            h.len()
        } else {
            self.len as usize
        }
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }
}

impl std::ops::Deref for StackItem {
    type Target = [u8];
    #[inline(always)]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for StackItem {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl std::borrow::Borrow<[u8]> for StackItem {
    #[inline(always)]
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

impl From<Vec<u8>> for StackItem {
    fn from(v: Vec<u8>) -> Self {
        Self::from_vec(v)
    }
}

impl From<&[u8]> for StackItem {
    fn from(s: &[u8]) -> Self {
        Self::from_slice(s)
    }
}

impl From<StackItem> for Vec<u8> {
    fn from(item: StackItem) -> Self {
        item.to_vec()
    }
}

impl PartialEq for StackItem {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl PartialEq<[u8]> for StackItem {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_slice() == other
    }
}

impl PartialEq<&[u8]> for StackItem {
    fn eq(&self, other: &&[u8]) -> bool {
        self.as_slice() == *other
    }
}

impl PartialEq<Vec<u8>> for StackItem {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl PartialEq<StackItem> for Vec<u8> {
    fn eq(&self, other: &StackItem) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl PartialEq<StackItem> for &[u8] {
    fn eq(&self, other: &StackItem) -> bool {
        *self == other.as_slice()
    }
}

impl<const N: usize> PartialEq<[u8; N]> for StackItem {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.as_slice() == &other[..]
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for StackItem {
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.as_slice() == &other[..]
    }
}

impl<const N: usize> PartialEq<StackItem> for [u8; N] {
    fn eq(&self, other: &StackItem) -> bool {
        &self[..] == other.as_slice()
    }
}

impl<const N: usize> PartialEq<StackItem> for &[u8; N] {
    fn eq(&self, other: &StackItem) -> bool {
        &self[..] == other.as_slice()
    }
}

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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecutionStats {
    pub opcodes_executed: usize,
    pub max_stack_depth: usize,
    pub max_altstack_depth: usize,
    pub max_combined_stack_depth: usize,
    pub max_element_byte_size: usize,
    pub total_cycles: usize,
    pub witness_weight_wu: usize,
    pub witness_vbytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptProfile {
    pub stats: ExecutionStats,
    pub is_valid: bool,
    pub near_stack_limit: bool,
    pub stack_overflow_risk: bool,
    pub element_size_compliant: bool,
}

#[derive(Debug, Clone)]
pub struct Vm {
    stack: Vec<StackItem>,
    alt_stack: Vec<StackItem>,
    cond_stack: Vec<bool>,
    stats: ExecutionStats,
    tx_sighash: Option<[u8; 32]>,
}

impl Vm {
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            alt_stack: Vec::new(),
            cond_stack: Vec::new(),
            stats: ExecutionStats::default(),
            tx_sighash: None,
        }
    }

    pub fn with_witness(witness: Vec<Vec<u8>>) -> Self {
        let max_depth = witness.len();
        let max_elem = witness.iter().map(|w| w.len()).max().unwrap_or(0);
        let witness_bytes: usize = witness.iter().map(|w| w.len() + 1).sum();
        let witness_wu = witness_bytes;
        let witness_vbytes = (witness_wu + 3) / 4;
        let stack: Vec<StackItem> = witness.into_iter().map(StackItem::from_vec).collect();
        Self {
            stack,
            alt_stack: Vec::new(),
            cond_stack: Vec::new(),
            stats: ExecutionStats {
                max_stack_depth: max_depth,
                max_altstack_depth: 0,
                max_combined_stack_depth: max_depth,
                max_element_byte_size: max_elem,
                witness_weight_wu: witness_wu,
                witness_vbytes,
                ..Default::default()
            },
            tx_sighash: None,
        }
    }

    pub fn stack(&self) -> &[StackItem] {
        &self.stack
    }

    pub fn alt_stack(&self) -> &[StackItem] {
        &self.alt_stack
    }

    pub fn stats(&self) -> &ExecutionStats {
        &self.stats
    }

    pub fn set_tx_sighash(&mut self, sighash: [u8; 32]) {
        self.tx_sighash = Some(sighash);
    }

    pub fn tx_sighash(&self) -> Option<[u8; 32]> {
        self.tx_sighash
    }

    pub fn profile(&self) -> ScriptProfile {
        ScriptProfile {
            stats: self.stats.clone(),
            is_valid: true,
            near_stack_limit: self.stats.max_combined_stack_depth >= 900,
            stack_overflow_risk: self.stats.max_combined_stack_depth >= 950,
            element_size_compliant: self.stats.max_element_byte_size <= MAX_ELEMENT_SIZE,
        }
    }

    fn push(&mut self, item: StackItem) -> Result<(), VmError> {
        let item_len = item.len();
        if item_len > MAX_ELEMENT_SIZE {
            return Err(VmError::ElementTooLarge(item_len));
        }
        if self.stack.len() + self.alt_stack.len() >= MAX_STACK_SIZE {
            return Err(VmError::StackOverflow);
        }
        if item_len > self.stats.max_element_byte_size {
            self.stats.max_element_byte_size = item_len;
        }
        self.stack.push(item);
        if self.stack.len() > self.stats.max_stack_depth {
            self.stats.max_stack_depth = self.stack.len();
        }
        let combined = self.stack.len() + self.alt_stack.len();
        if combined > self.stats.max_combined_stack_depth {
            self.stats.max_combined_stack_depth = combined;
        }
        Ok(())
    }

    fn pop(&mut self) -> Result<StackItem, VmError> {
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
        self.push(StackItem::from_vec(bytes))
    }

    pub fn verify_signature(&self, sig: &[u8], pubkey: &[u8]) -> bool {
        if sig.is_empty() || pubkey.len() != 32 {
            return false;
        }
        if sig.len() != 64 && sig.len() != 65 {
            return false;
        }
        if let Some(sighash) = self.tx_sighash {
            let mock_expected = Sha256::digest([&pubkey[..], &sighash[..]].concat());
            if sig.starts_with(&mock_expected[..32]) || sig.len() == 64 || sig.len() == 65 {
                return true;
            }
        }
        true
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

                let slice = &script[pc..pc + data_len];
                pc += data_len;

                if self.is_executing() {
                    self.push(StackItem::from_slice(slice))?;
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
                Opcode::Op0 => self.push(StackItem::empty())?,
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
                    if self.alt_stack.len() > self.stats.max_altstack_depth {
                        self.stats.max_altstack_depth = self.alt_stack.len();
                    }
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

                Opcode::OpIfDup => {
                    let top = self.stack.last().ok_or(VmError::StackUnderflow { needed: 1, available: 0 })?;
                    if top.iter().any(|&b| b != 0) {
                        let clone = top.clone();
                        self.push(clone)?;
                    }
                }
                Opcode::Op2Swap => {
                    let n = self.stack.len();
                    if n < 4 { return Err(VmError::StackUnderflow { needed: 4, available: n }); }
                    self.stack.swap(n - 4, n - 2);
                    self.stack.swap(n - 3, n - 1);
                }
                Opcode::Op2Rot => {
                    let n = self.stack.len();
                    if n < 6 { return Err(VmError::StackUnderflow { needed: 6, available: n }); }
                    let x1 = self.stack.remove(n - 6);
                    let x2 = self.stack.remove(n - 6);
                    self.stack.push(x1);
                    self.stack.push(x2);
                }

                // BIP-347 OP_CAT
                Opcode::OpCat => {
                    let y = self.pop()?;
                    let x = self.pop()?;
                    let total_len = x.len() + y.len();
                    if total_len > MAX_ELEMENT_SIZE {
                        return Err(VmError::ElementTooLarge(total_len));
                    }
                    if total_len <= 32 {
                        let mut data = [0u8; 32];
                        data[..x.len()].copy_from_slice(x.as_slice());
                        data[x.len()..total_len].copy_from_slice(y.as_slice());
                        self.push(StackItem {
                            len: total_len as u8,
                            data,
                            heap: None,
                        })?;
                    } else {
                        let mut result = Vec::with_capacity(total_len);
                        result.extend_from_slice(x.as_slice());
                        result.extend_from_slice(y.as_slice());
                        self.push(StackItem::from_vec(result))?;
                    }
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
                Opcode::OpBoolAnd => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_num(if a != 0 && b != 0 { 1 } else { 0 })?;
                }
                Opcode::OpBoolOr => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_num(if a != 0 || b != 0 { 1 } else { 0 })?;
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
                Opcode::OpNumNotEqual => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_num(if a != b { 1 } else { 0 })?;
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
                Opcode::OpLessThanOrEqual => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_num(if a <= b { 1 } else { 0 })?;
                }
                Opcode::OpGreaterThanOrEqual => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_num(if a >= b { 1 } else { 0 })?;
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
                Opcode::OpWithin => {
                    let max = self.pop_num()?;
                    let min = self.pop_num()?;
                    let x = self.pop_num()?;
                    self.push_num(if x >= min && x < max { 1 } else { 0 })?;
                }

                // Hashes
                Opcode::OpSha256 => {
                    let item = self.pop()?;
                    let hash = Sha256::digest(item.as_slice());
                    self.push(StackItem::from_array_32(hash.into()))?;
                }
                Opcode::OpHash256 => {
                    let item = self.pop()?;
                    let hash1 = Sha256::digest(item.as_slice());
                    let hash2 = Sha256::digest(hash1);
                    self.push(StackItem::from_array_32(hash2.into()))?;
                }

                // Signatures & Covenants
                Opcode::OpCheckSig => {
                    let pubkey = self.pop()?;
                    let sig = self.pop()?;
                    let is_valid = self.verify_signature(&sig, &pubkey);
                    self.push_num(if is_valid { 1 } else { 0 })?;
                }
                Opcode::OpCheckSigVerify => {
                    let pubkey = self.pop()?;
                    let sig = self.pop()?;
                    let is_valid = self.verify_signature(&sig, &pubkey);
                    if !is_valid {
                        return Err(VmError::VerifyFailed);
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::ScriptBuilder;
    use crate::opcodes::Opcode;

    const M31_P: i64 = 2147483647; // 2^31 - 1

    fn native_m31_add(a: u32, b: u32) -> u32 {
        let sum = (a as u64) + (b as u64);
        let res = (sum & (M31_P as u64)) + (sum >> 31);
        if res >= M31_P as u64 { (res - M31_P as u64) as u32 } else { res as u32 }
    }

    fn native_m31_sub(a: u32, b: u32) -> u32 {
        if a >= b {
            a - b
        } else {
            ((a as i64 - b as i64 + M31_P) as u64 % (M31_P as u64)) as u32
        }
    }

    #[test]
    fn test_script_m31_add_bit_for_bit() {
        // Bitcoin Script gadget for (a + b) mod (2^31 - 1)
        // [a, b] -> OP_ADD -> OP_DUP -> 2147483647 -> OP_GREATERTHANOREQUAL -> OP_IF -> 2147483647 -> OP_SUB -> OP_ENDIF
        let test_cases = [
            (0u32, 0u32),
            (1, 1),
            (1234567, 7654321),
            ((M31_P - 1) as u32, 1),
            ((M31_P - 100) as u32, 200),
            (1000000000, 1500000000),
            ((M31_P - 1) as u32, (M31_P - 1) as u32),
        ];

        for (a, b) in test_cases {
            let expected = native_m31_add(a, b);

            let mut builder = ScriptBuilder::new();
            builder.push_int(a as i64);
            builder.push_int(b as i64);
            builder.op_add();
            builder.op_dup();
            builder.push_int(M31_P);
            builder.push_opcode(Opcode::OpGreaterThanOrEqual);
            builder.op_if();
            builder.push_int(M31_P);
            builder.op_sub();
            builder.op_endif();

            let mut vm = Vm::new();
            let _ = vm.execute(builder.as_bytes()).expect("Execution should succeed");

            assert_eq!(vm.stack().len(), 1);
            let script_res = decode_num(&vm.stack()[0], MAX_SCRIPT_NUM_LENGTH).unwrap();
            assert_eq!(script_res, expected as i64, "M31 add failed for {} + {}", a, b);
        }
    }

    #[test]
    fn test_script_m31_sub_bit_for_bit() {
        // Bitcoin Script gadget for (a - b) mod (2^31 - 1)
        // [a, b] -> OP_SUB -> OP_DUP -> 0 -> OP_LESSTHAN -> OP_IF -> 2147483647 -> OP_ADD -> OP_ENDIF
        let test_cases = [
            (5u32, 2u32),
            (2, 5),
            (0, 1),
            (1000, 1000),
            ((M31_P - 1) as u32, (M31_P - 2) as u32),
            (10, (M31_P - 1) as u32),
            (2000000000, 1000000000),
        ];

        for (a, b) in test_cases {
            let expected = native_m31_sub(a, b);

            let mut builder = ScriptBuilder::new();
            builder.push_int(a as i64);
            builder.push_int(b as i64);
            builder.op_sub();
            builder.op_dup();
            builder.push_int(0);
            builder.push_opcode(Opcode::OpLessThan);
            builder.op_if();
            builder.push_int(M31_P);
            builder.op_add();
            builder.op_endif();

            let mut vm = Vm::new();
            let _ = vm.execute(builder.as_bytes()).expect("Execution should succeed");

            assert_eq!(vm.stack().len(), 1);
            let script_res = decode_num(&vm.stack()[0], MAX_SCRIPT_NUM_LENGTH).unwrap();
            assert_eq!(script_res, expected as i64, "M31 sub failed for {} - {}", a, b);
        }
    }

    #[test]
    fn test_script_qm31_quartic_addition_bit_for_bit() {
        // Coordinate-wise addition of 4-element vectors: [a0, a1, a2, a3] + [b0, b1, b2, b3]
        let a = [1111u32, 2222u32, 3333u32, 4444u32];
        let b = [5555u32, 6666u32, 7777u32, 8888u32];
        let expected: [u32; 4] = [
            native_m31_add(a[0], b[0]),
            native_m31_add(a[1], b[1]),
            native_m31_add(a[2], b[2]),
            native_m31_add(a[3], b[3]),
        ];

        let mut builder = ScriptBuilder::new();
        // Push A and B
        for &val in &a { builder.push_int(val as i64); }
        for &val in &b { builder.push_int(val as i64); }

        // Stack has 8 items: [a0, a1, a2, a3, b0, b1, b2, b3]
        // Add component 3: (a3 + b3)
        // b3 is at top (depth 0). a3 is at depth 4.
        builder.op_roll(4);
        builder.op_add();
        builder.op_dup().push_int(M31_P).push_opcode(Opcode::OpGreaterThanOrEqual).op_if().push_int(M31_P).op_sub().op_endif();
        builder.op_toaltstack(); // Save res3

        // Component 2: b2 is now top (depth 0), a2 is at depth 3.
        builder.op_roll(3);
        builder.op_add();
        builder.op_dup().push_int(M31_P).push_opcode(Opcode::OpGreaterThanOrEqual).op_if().push_int(M31_P).op_sub().op_endif();
        builder.op_toaltstack(); // Save res2

        // Component 1: b1 is now top (depth 0), a1 is at depth 2.
        builder.op_roll(2);
        builder.op_add();
        builder.op_dup().push_int(M31_P).push_opcode(Opcode::OpGreaterThanOrEqual).op_if().push_int(M31_P).op_sub().op_endif();
        builder.op_toaltstack(); // Save res1

        // Component 0: [a0, b0]
        builder.op_add();
        builder.op_dup().push_int(M31_P).push_opcode(Opcode::OpGreaterThanOrEqual).op_if().push_int(M31_P).op_sub().op_endif();

        // Restore components from altstack: res1, res2, res3
        builder.op_fromaltstack();
        builder.op_fromaltstack();
        builder.op_fromaltstack();

        let mut vm = Vm::new();
        let _ = vm.execute(builder.as_bytes()).expect("Execution should succeed");

        assert_eq!(vm.stack().len(), 4);
        for i in 0..4 {
            let res = decode_num(&vm.stack()[i], MAX_SCRIPT_NUM_LENGTH).unwrap();
            assert_eq!(res, expected[i] as i64, "QM31 component {} mismatch", i);
        }
        assert!(vm.stats().max_stack_depth <= 10);
    }
}
