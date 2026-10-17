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
    pub fn op_verify(&mut self) -> &mut Self { self.push_opcode(Opcode::OpVerify) }
    pub fn op_add(&mut self) -> &mut Self { self.push_opcode(Opcode::OpAdd) }
    pub fn op_sub(&mut self) -> &mut Self { self.push_opcode(Opcode::OpSub) }
    pub fn op_if(&mut self) -> &mut Self { self.push_opcode(Opcode::OpIf) }
    pub fn op_else(&mut self) -> &mut Self { self.push_opcode(Opcode::OpElse) }
    pub fn op_endif(&mut self) -> &mut Self { self.push_opcode(Opcode::OpEndIf) }

    pub fn extend(&mut self, other: &ScriptBuilder) -> &mut Self {
        self.bytes.extend_from_slice(&other.bytes);
        self.opcode_count += other.opcode_count;
        self
    }
}
