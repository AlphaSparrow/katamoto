use crate::opcodes::Opcode;

/// Encodes an integer as a Bitcoin ScriptNum (little-endian with sign-magnitude)
pub fn encode_num(val: i64) -> Vec<u8> {
    if val == 0 {
        return vec![];
    }
    let mut result = Vec::new();
    let neg = val < 0;
    let mut abs_val = val.unsigned_abs();

    while abs_val > 0 {
        result.push((abs_val & 0xff) as u8);
        abs_val >>= 8;
    }

    if (result.last().unwrap() & 0x80) != 0 {
        result.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        let len = result.len();
        result[len - 1] |= 0x80;
    }

    result
}

/// Decodes Bitcoin ScriptNum into an i64
pub fn decode_num(bytes: &[u8], max_len: usize) -> Result<i64, &'static str> {
    if bytes.len() > max_len {
        return Err("ScriptNum overflow beyond max length");
    }
    if bytes.is_empty() {
        return Ok(0);
    }
    let mut result: i64 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        result |= ((b as i64) & 0xff) << (i * 8);
    }

    if (bytes.last().unwrap() & 0x80) != 0 {
        let mask = 0x80_i64 << ((bytes.len() - 1) * 8);
        result &= !mask;
        result = -result;
    }

    Ok(result)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScriptBuilder {
    bytes: Vec<u8>,
    opcode_count: usize,
}

impl ScriptBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn opcode_count(&self) -> usize {
        self.opcode_count
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    pub fn push_opcode(&mut self, op: Opcode) -> &mut Self {
        self.bytes.push(op.to_u8());
        self.opcode_count += 1;
        self
    }

    pub fn push_slice(&mut self, data: &[u8]) -> &mut Self {
        let len = data.len();
        if len == 0 {
            self.bytes.push(Opcode::Op0.to_u8());
        } else if len == 1 && data[0] >= 1 && data[0] <= 16 {
            self.bytes.push(0x50 + data[0]);
        } else if len == 1 && data[0] == 0x81 {
            self.bytes.push(Opcode::Op1Negate.to_u8());
        } else if len < 76 {
            self.bytes.push(len as u8);
            self.bytes.extend_from_slice(data);
        } else if len <= 0xff {
            self.bytes.push(0x4c); // OP_PUSHDATA1
            self.bytes.push(len as u8);
            self.bytes.extend_from_slice(data);
        } else if len <= 0xffff {
            self.bytes.push(0x4d); // OP_PUSHDATA2
            self.bytes.extend_from_slice(&(len as u16).to_le_bytes());
            self.bytes.extend_from_slice(data);
        } else {
            self.bytes.push(0x4e); // OP_PUSHDATA4
            self.bytes.extend_from_slice(&(len as u32).to_le_bytes());
            self.bytes.extend_from_slice(data);
        }
        self
    }

    pub fn push_int(&mut self, val: i64) -> &mut Self {
        if val == 0 {
            self.push_opcode(Opcode::Op0);
        } else if val == -1 {
            self.push_opcode(Opcode::Op1Negate);
        } else if (1..=16).contains(&val) {
            let op_u8 = 0x50 + val as u8;
            self.push_opcode(Opcode::from_u8(op_u8).unwrap());
        } else {
            let encoded = encode_num(val);
            self.push_slice(&encoded);
        }
        self
    }

    // Convenience chaining methods for common operations
    pub fn op_cat(&mut self) -> &mut Self { self.push_opcode(Opcode::OpCat) }
    pub fn op_sha256(&mut self) -> &mut Self { self.push_opcode(Opcode::OpSha256) }
    pub fn op_hash256(&mut self) -> &mut Self { self.push_opcode(Opcode::OpHash256) }
    pub fn op_dup(&mut self) -> &mut Self { self.push_opcode(Opcode::OpDup) }
    pub fn op_drop(&mut self) -> &mut Self { self.push_opcode(Opcode::OpDrop) }
    pub fn op_swap(&mut self) -> &mut Self { self.push_opcode(Opcode::OpSwap) }
    pub fn op_rot(&mut self) -> &mut Self { self.push_opcode(Opcode::OpRot) }
    pub fn op_over(&mut self) -> &mut Self { self.push_opcode(Opcode::OpOver) }
    pub fn op_nip(&mut self) -> &mut Self { self.push_opcode(Opcode::OpNip) }
    pub fn op_toaltstack(&mut self) -> &mut Self { self.push_opcode(Opcode::OpToAltStack) }
    pub fn op_fromaltstack(&mut self) -> &mut Self { self.push_opcode(Opcode::OpFromAltStack) }
    pub fn op_roll(&mut self, depth: i64) -> &mut Self {
        self.push_int(depth);
        self.push_opcode(Opcode::OpRoll)
    }
    pub fn op_pick(&mut self, depth: i64) -> &mut Self {
        self.push_int(depth);
        self.push_opcode(Opcode::OpPick)
    }
    pub fn op_equal(&mut self) -> &mut Self { self.push_opcode(Opcode::OpEqual) }
    pub fn op_equalverify(&mut self) -> &mut Self { self.push_opcode(Opcode::OpEqualVerify) }
    pub fn op_num_equal(&mut self) -> &mut Self { self.push_opcode(Opcode::OpNumEqual) }
    pub fn op_num_equalverify(&mut self) -> &mut Self { self.push_opcode(Opcode::OpNumEqualVerify) }
    pub fn op_num_not_equal(&mut self) -> &mut Self { self.push_opcode(Opcode::OpNumNotEqual) }
    pub fn op_bool_and(&mut self) -> &mut Self { self.push_opcode(Opcode::OpBoolAnd) }
    pub fn op_bool_or(&mut self) -> &mut Self { self.push_opcode(Opcode::OpBoolOr) }
    pub fn op_not(&mut self) -> &mut Self { self.push_opcode(Opcode::OpNot) }
    pub fn op_less_than(&mut self) -> &mut Self { self.push_opcode(Opcode::OpLessThan) }
    pub fn op_greater_than(&mut self) -> &mut Self { self.push_opcode(Opcode::OpGreaterThan) }
    pub fn op_less_than_or_equal(&mut self) -> &mut Self { self.push_opcode(Opcode::OpLessThanOrEqual) }
    pub fn op_greater_than_or_equal(&mut self) -> &mut Self { self.push_opcode(Opcode::OpGreaterThanOrEqual) }
    pub fn op_min(&mut self) -> &mut Self { self.push_opcode(Opcode::OpMin) }
    pub fn op_max(&mut self) -> &mut Self { self.push_opcode(Opcode::OpMax) }
    pub fn op_within(&mut self) -> &mut Self { self.push_opcode(Opcode::OpWithin) }
    pub fn op_2dup(&mut self) -> &mut Self { self.push_opcode(Opcode::Op2Dup) }
    pub fn op_2drop(&mut self) -> &mut Self { self.push_opcode(Opcode::Op2Drop) }
    pub fn op_ifdup(&mut self) -> &mut Self { self.push_opcode(Opcode::OpIfDup) }
    pub fn op_verify(&mut self) -> &mut Self { self.push_opcode(Opcode::OpVerify) }
    pub fn op_add(&mut self) -> &mut Self { self.push_opcode(Opcode::OpAdd) }
    pub fn op_sub(&mut self) -> &mut Self { self.push_opcode(Opcode::OpSub) }
    pub fn op_if(&mut self) -> &mut Self { self.push_opcode(Opcode::OpIf) }
    pub fn op_else(&mut self) -> &mut Self { self.push_opcode(Opcode::OpElse) }
    pub fn op_endif(&mut self) -> &mut Self { self.push_opcode(Opcode::OpEndIf) }

    pub fn op_checksig(&mut self) -> &mut Self { self.push_opcode(Opcode::OpCheckSig) }
    pub fn op_checksigverify(&mut self) -> &mut Self { self.push_opcode(Opcode::OpCheckSigVerify) }

    pub fn extend(&mut self, other: &ScriptBuilder) -> &mut Self {
        self.bytes.extend_from_slice(&other.bytes);
        self.opcode_count += other.opcode_count;
        self
    }

    /// Converts the compiled script bytecode into an Intermediate Representation (IR)
    pub fn to_ir(&self) -> Result<Vec<ScriptOp>, String> {
        let mut ops = Vec::new();
        let mut pc = 0;
        let len = self.bytes.len();

        while pc < len {
            let byte = self.bytes[pc];
            pc += 1;

            if byte <= 0x4e {
                let data_len = if byte == 0 {
                    0
                } else if byte <= 0x4b {
                    byte as usize
                } else if byte == 0x4c {
                    if pc >= len { return Err("Unexpected EOF in pushdata1".into()); }
                    let l = self.bytes[pc] as usize;
                    pc += 1;
                    l
                } else if byte == 0x4d {
                    if pc + 2 > len { return Err("Unexpected EOF in pushdata2".into()); }
                    let l = u16::from_le_bytes([self.bytes[pc], self.bytes[pc + 1]]) as usize;
                    pc += 2;
                    l
                } else {
                    if pc + 4 > len { return Err("Unexpected EOF in pushdata4".into()); }
                    let l = u32::from_le_bytes([
                        self.bytes[pc], self.bytes[pc + 1], self.bytes[pc + 2], self.bytes[pc + 3]
                    ]) as usize;
                    pc += 4;
                    l
                };

                if pc + data_len > len {
                    return Err("Unexpected EOF in push data payload".into());
                }
                let data = self.bytes[pc..pc + data_len].to_vec();
                pc += data_len;
                ops.push(ScriptOp::Push(data));
                continue;
            }

            if byte == 0x4f {
                ops.push(ScriptOp::Op(Opcode::Op1Negate));
                continue;
            }

            if (0x51..=0x60).contains(&byte) {
                let op = Opcode::from_u8(byte).ok_or_else(|| format!("Invalid small int opcode 0x{:02x}", byte))?;
                ops.push(ScriptOp::Op(op));
                continue;
            }

            let op = Opcode::from_u8(byte).ok_or_else(|| format!("Invalid opcode 0x{:02x}", byte))?;
            ops.push(ScriptOp::Op(op));
        }

        Ok(ops)
    }

    /// Rebuilds a ScriptBuilder from an Intermediate Representation (IR) sequence
    pub fn from_ir(ops: &[ScriptOp]) -> Self {
        let mut builder = ScriptBuilder::new();
        for op in ops {
            match op {
                ScriptOp::Op(code) => {
                    builder.push_opcode(*code);
                }
                ScriptOp::Push(data) => {
                    builder.push_slice(data);
                }
            }
        }
        builder
    }

    /// Optimizes the script using peephole optimization passes
    pub fn optimize(&self) -> (Self, OptimizationReport) {
        ScriptOptimizer::optimize(self)
    }
}

/// Intermediate Representation (IR) operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptOp {
    Op(Opcode),
    Push(Vec<u8>),
}

/// Statistics detailing the optimization passes applied
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OptimizationReport {
    pub original_ops: usize,
    pub optimized_ops: usize,
    pub original_bytes: usize,
    pub optimized_bytes: usize,
    pub altstack_pairs_removed: usize,
    pub redundant_swaps_removed: usize,
    pub dup_drops_removed: usize,
    pub nops_removed: usize,
    pub arithmetic_cancels_removed: usize,
    pub stack_identities_applied: usize,
    pub constant_folds_applied: usize,
}

fn is_push_zero(op: &ScriptOp) -> bool {
    match op {
        ScriptOp::Push(data) => data.is_empty() || data.iter().all(|&b| b == 0),
        ScriptOp::Op(Opcode::Op0) => true,
        _ => false,
    }
}

fn is_push_one(op: &ScriptOp) -> bool {
    match op {
        ScriptOp::Push(data) => data == &[1],
        ScriptOp::Op(Opcode::Op1) => true,
        _ => false,
    }
}

/// Multi-pass Peephole Optimizer for Bitcoin Tapscript
pub struct ScriptOptimizer;

impl ScriptOptimizer {
    pub fn optimize(builder: &ScriptBuilder) -> (ScriptBuilder, OptimizationReport) {
        let mut report = OptimizationReport {
            original_ops: builder.opcode_count(),
            original_bytes: builder.len(),
            ..Default::default()
        };

        let mut ir = match builder.to_ir() {
            Ok(ops) => ops,
            Err(_) => return (builder.clone(), report),
        };

        let mut changed = true;
        while changed {
            changed = false;
            let mut next_ir = Vec::with_capacity(ir.len());
            let mut i = 0;
            while i < ir.len() {
                if i + 1 < ir.len() {
                    match (&ir[i], &ir[i + 1]) {
                        // OP_TOALTSTACK followed immediately by OP_FROMALTSTACK
                        (ScriptOp::Op(Opcode::OpToAltStack), ScriptOp::Op(Opcode::OpFromAltStack)) => {
                            report.altstack_pairs_removed += 1;
                            i += 2;
                            changed = true;
                            continue;
                        }
                        // OP_FROMALTSTACK followed immediately by OP_TOALTSTACK
                        (ScriptOp::Op(Opcode::OpFromAltStack), ScriptOp::Op(Opcode::OpToAltStack)) => {
                            report.altstack_pairs_removed += 1;
                            i += 2;
                            changed = true;
                            continue;
                        }
                        // Adjacent OP_SWAP cancellation
                        (ScriptOp::Op(Opcode::OpSwap), ScriptOp::Op(Opcode::OpSwap)) => {
                            report.redundant_swaps_removed += 1;
                            i += 2;
                            changed = true;
                            continue;
                        }
                        // OP_DUP followed immediately by OP_DROP
                        (ScriptOp::Op(Opcode::OpDup), ScriptOp::Op(Opcode::OpDrop)) => {
                            report.dup_drops_removed += 1;
                            i += 2;
                            changed = true;
                            continue;
                        }
                        // OP_OVER OP_OVER => OP_2DUP
                        (ScriptOp::Op(Opcode::OpOver), ScriptOp::Op(Opcode::OpOver)) => {
                            report.stack_identities_applied += 1;
                            next_ir.push(ScriptOp::Op(Opcode::Op2Dup));
                            i += 2;
                            changed = true;
                            continue;
                        }
                        // OP_DROP OP_DROP => OP_2DROP
                        (ScriptOp::Op(Opcode::OpDrop), ScriptOp::Op(Opcode::OpDrop)) => {
                            report.stack_identities_applied += 1;
                            next_ir.push(ScriptOp::Op(Opcode::Op2Drop));
                            i += 2;
                            changed = true;
                            continue;
                        }
                        // OP_2DUP followed immediately by OP_2DROP
                        (ScriptOp::Op(Opcode::Op2Dup), ScriptOp::Op(Opcode::Op2Drop)) => {
                            report.dup_drops_removed += 1;
                            i += 2;
                            changed = true;
                            continue;
                        }
                        // OP_1ADD followed by OP_1SUB or vice versa
                        (ScriptOp::Op(Opcode::Op1Add), ScriptOp::Op(Opcode::Op1Sub))
                        | (ScriptOp::Op(Opcode::Op1Sub), ScriptOp::Op(Opcode::Op1Add)) => {
                            report.arithmetic_cancels_removed += 1;
                            i += 2;
                            changed = true;
                            continue;
                        }
                        // Push 0 + OP_ADD => identity, eliminated
                        (op, ScriptOp::Op(Opcode::OpAdd)) if is_push_zero(op) => {
                            report.constant_folds_applied += 1;
                            i += 2;
                            changed = true;
                            continue;
                        }
                        // Push 0 + OP_SUB => identity, eliminated
                        (op, ScriptOp::Op(Opcode::OpSub)) if is_push_zero(op) => {
                            report.constant_folds_applied += 1;
                            i += 2;
                            changed = true;
                            continue;
                        }
                        // Push 1 + OP_ADD => OP_1ADD
                        (op, ScriptOp::Op(Opcode::OpAdd)) if is_push_one(op) => {
                            report.constant_folds_applied += 1;
                            next_ir.push(ScriptOp::Op(Opcode::Op1Add));
                            i += 2;
                            changed = true;
                            continue;
                        }
                        // Push 1 + OP_SUB => OP_1SUB
                        (op, ScriptOp::Op(Opcode::OpSub)) if is_push_one(op) => {
                            report.constant_folds_applied += 1;
                            next_ir.push(ScriptOp::Op(Opcode::Op1Sub));
                            i += 2;
                            changed = true;
                            continue;
                        }
                        // Push 0 + OP_EQUAL / OP_NUMEQUAL => OP_NOT
                        (op, ScriptOp::Op(Opcode::OpEqual)) | (op, ScriptOp::Op(Opcode::OpNumEqual))
                            if is_push_zero(op) =>
                        {
                            report.constant_folds_applied += 1;
                            next_ir.push(ScriptOp::Op(Opcode::OpNot));
                            i += 2;
                            changed = true;
                            continue;
                        }
                        // OP_NOT OP_NOT => OP_0NOTEQUAL
                        (ScriptOp::Op(Opcode::OpNot), ScriptOp::Op(Opcode::OpNot)) => {
                            report.constant_folds_applied += 1;
                            next_ir.push(ScriptOp::Op(Opcode::Op0NotEqual));
                            i += 2;
                            changed = true;
                            continue;
                        }
                        _ => {}
                    }
                }

                // Elimination of standalone OP_NOP
                if let ScriptOp::Op(Opcode::OpNop) = &ir[i] {
                    report.nops_removed += 1;
                    i += 1;
                    changed = true;
                    continue;
                }

                next_ir.push(ir[i].clone());
                i += 1;
            }
            ir = next_ir;
        }

        let opt_builder = ScriptBuilder::from_ir(&ir);
        report.optimized_ops = opt_builder.opcode_count();
        report.optimized_bytes = opt_builder.len();
        (opt_builder, report)
    }
}

/// Hint Packing: packs multiple 32-bit values into a single byte vector
pub fn pack_m31_hints(elements: &[u32]) -> Vec<u8> {
    let mut packed = Vec::with_capacity(elements.len() * 4);
    for &elem in elements {
        packed.extend_from_slice(&elem.to_le_bytes());
    }
    packed
}

/// Emits script that verifies a packed hint matches split parts using BIP-347 OP_CAT
/// Stack layout before: `[packed_expected, part_0, part_1, ..., part_{count-1}]`
pub fn emit_verify_packed_hints(builder: &mut ScriptBuilder, count: usize) {
    assert!(count >= 2, "Packed hint verification requires at least 2 parts");
    for _ in 1..count {
        builder.op_cat();
    }
    builder.op_equalverify();
    builder.push_int(1);
}
