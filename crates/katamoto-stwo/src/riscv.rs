use katamoto_script::ScriptBuilder;
use sha2::{Digest, Sha256};

/// RISC-V 32-bit Base Integer Instruction Set (RV32I) opcodes supported by the zkVM
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiscvOpcode {
    Add = 0,
    Sub = 1,
    Xor = 2,
    Ori = 3,
    Lw = 4,
    Sw = 5,
    Beq = 6,
    Jal = 7,
    Bne = 8,
}

impl RiscvOpcode {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::Add),
            1 => Some(Self::Sub),
            2 => Some(Self::Xor),
            3 => Some(Self::Ori),
            4 => Some(Self::Lw),
            5 => Some(Self::Sw),
            6 => Some(Self::Beq),
            7 => Some(Self::Jal),
            8 => Some(Self::Bne),
            _ => None,
        }
    }
}

/// Public statement for a RISC-V zkVM execution to be verified on Bitcoin
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiscvStatement {
    pub initial_pc: u32,
    pub final_pc: u32,
    pub cycle_count: u64,
    pub initial_state_root: [u8; 32],
    pub final_state_root: [u8; 32],
    pub program_digest: [u8; 32],
}

impl RiscvStatement {
    /// Computes the 32-byte cryptographic commitment to the public statement
    pub fn statement_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.initial_pc.to_le_bytes());
        hasher.update(&self.final_pc.to_le_bytes());
        hasher.update(&self.cycle_count.to_le_bytes());
        hasher.update(&self.initial_state_root);
        hasher.update(&self.final_state_root);
        hasher.update(&self.program_digest);
        let res = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&res);
        out
    }
}

/// A single verified execution cycle step of the RISC-V processor
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiscvStep {
    pub pc_curr: u32,
    pub pc_next: u32,
    pub opcode: RiscvOpcode,
    pub rs1_val: u32,
    pub rs2_val: u32,
    pub rd_val: u32,
    pub imm: i32,
}

impl RiscvStep {
    /// Validates the CPU step transition semantics
    pub fn is_valid(&self) -> bool {
        match self.opcode {
            RiscvOpcode::Add => {
                self.rd_val == self.rs1_val.wrapping_add(self.rs2_val) && self.pc_next == self.pc_curr + 4
            }
            RiscvOpcode::Sub => {
                self.rd_val == self.rs1_val.wrapping_sub(self.rs2_val) && self.pc_next == self.pc_curr + 4
            }
            RiscvOpcode::Xor => {
                self.rd_val == (self.rs1_val ^ self.rs2_val) && self.pc_next == self.pc_curr + 4
            }
            RiscvOpcode::Ori => {
                self.rd_val == (self.rs1_val | (self.imm as u32)) && self.pc_next == self.pc_curr + 4
            }
            RiscvOpcode::Beq => {
                let target = (self.pc_curr as i64 + self.imm as i64) as u32;
                if self.rs1_val == self.rs2_val {
                    self.pc_next == target
                } else {
                    self.pc_next == self.pc_curr + 4
                }
            }
            RiscvOpcode::Bne => {
                let target = (self.pc_curr as i64 + self.imm as i64) as u32;
                if self.rs1_val != self.rs2_val {
                    self.pc_next == target
                } else {
                    self.pc_next == self.pc_curr + 4
                }
            }
            RiscvOpcode::Lw | RiscvOpcode::Sw => {
                let addr = (self.rs1_val as i64 + self.imm as i64) as u32;
                (addr % 4 == 0) && self.pc_next == self.pc_curr + 4
            }
            RiscvOpcode::Jal => {
                let target = (self.pc_curr as i64 + self.imm as i64) as u32;
                self.rd_val == self.pc_curr + 4 && self.pc_next == target
            }
        }
    }
}

/// Bitcoin Script verifiers for RISC-V execution transitions
pub struct RiscvScript;

impl RiscvScript {
    /// Emits script that verifies an ADD instruction execution step:
    /// Asserts:
    /// 1. `rd_val == rs1_val + rs2_val`
    /// 2. `pc_next == pc_curr + 4`
    ///
    /// Expected Witness Stack:
    /// `[pc_next, pc_curr, rd_val, rs2_val, rs1_val]`
    pub fn emit_add_step_verifier(builder: &mut ScriptBuilder) {
        // Stack top: [pc_next, pc_curr, rd_val, rs2_val, rs1_val]
        // 1. Check ALU: rs1_val + rs2_val == rd_val
        builder.op_add(); // [pc_next, pc_curr, rd_val, (rs1 + rs2)]
        builder.op_equalverify(); // [pc_next, pc_curr]

        // 2. Check PC: pc_curr + 4 == pc_next
        builder.push_int(4); // [pc_next, pc_curr, 4]
        builder.op_add();    // [pc_next, (pc_curr + 4)]
        builder.op_equalverify(); // []

        // Success flag
        builder.push_int(1);
    }

    /// Emits script that verifies a JAL (Jump and Link) instruction execution step:
    /// Asserts:
    /// 1. `rd_val == pc_curr + 4`
    /// 2. `pc_next == pc_curr + imm`
    ///
    /// Expected Witness Stack:
    /// `[imm, pc_next, rd_val, pc_curr]`
    pub fn emit_jal_step_verifier(builder: &mut ScriptBuilder) {
        // Stack top: [imm, pc_next, rd_val, pc_curr]
        builder.op_dup();    // [imm, pc_next, rd_val, pc_curr, pc_curr]
        builder.push_int(4); // [imm, pc_next, rd_val, pc_curr, pc_curr, 4]
        builder.op_add();    // [imm, pc_next, rd_val, pc_curr, (pc_curr + 4)]
        builder.op_rot();    // [imm, pc_next, pc_curr, (pc_curr + 4), rd_val]
        builder.op_equalverify(); // asserts rd_val == pc_curr + 4 -> [imm, pc_next, pc_curr]

        // Stack: [imm, pc_next, pc_curr]
        builder.op_rot();    // [pc_next, pc_curr, imm]
        builder.op_add();    // [pc_next, (pc_curr + imm)]
        builder.op_equalverify(); // asserts pc_next == pc_curr + imm -> []

        builder.push_int(1);
    }

    /// Emits script that verifies a SUB instruction execution step:
    /// Asserts:
    /// 1. `rs1_val == rd_val + rs2_val`
    /// 2. `pc_next == pc_curr + 4`
    ///
    /// Expected Witness Stack:
    /// `[pc_next, pc_curr, rs1_val, rs2_val, rd_val]`
    pub fn emit_sub_step_verifier(builder: &mut ScriptBuilder) {
        // Stack top: [pc_next, pc_curr, rs1_val, rs2_val, rd_val]
        // 1. Check ALU: rs2_val + rd_val == rs1_val
        builder.op_add(); // [pc_next, pc_curr, rs1_val, (rs2 + rd)]
        builder.op_equalverify(); // [pc_next, pc_curr]

        // 2. Check PC: pc_curr + 4 == pc_next
        builder.push_int(4);
        builder.op_add();
        builder.op_equalverify();

        builder.push_int(1);
    }

    /// Emits script that verifies a BEQ (Branch if Equal) instruction execution step:
    /// Asserts:
    /// - If `rs1_val == rs2_val`, `pc_next == pc_curr + imm`
    /// - Else, `pc_next == pc_curr + 4`
    ///
    /// Expected Witness Stack:
    /// `[imm, pc_next, pc_curr, rs2_val, rs1_val]`
    pub fn emit_beq_step_verifier(builder: &mut ScriptBuilder) {
        // Stack top: [imm, pc_next, pc_curr, rs2_val, rs1_val]
        builder.op_equal(); // [imm, pc_next, pc_curr, is_eq]
        builder.op_if();
        // Branch Taken: target = pc_curr + imm
        builder.op_rot(); // [pc_next, pc_curr, imm]
        builder.op_add(); // [pc_next, (pc_curr + imm)]
        builder.op_else();
        // Branch Not Taken: target = pc_curr + 4
        builder.op_rot();  // [pc_next, pc_curr, imm]
        builder.op_drop(); // [pc_next, pc_curr]
        builder.push_int(4);
        builder.op_add(); // [pc_next, (pc_curr + 4)]
        builder.op_endif();

        builder.op_equalverify(); // Assert target == pc_next
        builder.push_int(1);
    }

    /// Emits script that verifies a BNE (Branch if Not Equal) instruction execution step:
    /// Asserts:
    /// - If `rs1_val != rs2_val`, `pc_next == pc_curr + imm`
    /// - Else, `pc_next == pc_curr + 4`
    ///
    /// Expected Witness Stack:
    /// `[imm, pc_next, pc_curr, rs2_val, rs1_val]`
    pub fn emit_bne_step_verifier(builder: &mut ScriptBuilder) {
        // Stack top: [imm, pc_next, pc_curr, rs2_val, rs1_val]
        builder.op_equal(); // [imm, pc_next, pc_curr, is_eq]
        builder.op_not();   // [imm, pc_next, pc_curr, is_not_eq]
        builder.op_if();
        // Branch Taken: target = pc_curr + imm
        builder.op_rot();
        builder.op_add();
        builder.op_else();
        // Branch Not Taken: target = pc_curr + 4
        builder.op_rot();
        builder.op_drop();
        builder.push_int(4);
        builder.op_add();
        builder.op_endif();

        builder.op_equalverify();
        builder.push_int(1);
    }

    /// Emits script that verifies a LW (Load Word) memory instruction execution step:
    /// Asserts:
    /// 1. Address alignment: `effective_addr == 4 * word_idx`
    /// 2. Value binding: `rd_val == mem_val`
    /// 3. PC transition: `pc_next == pc_curr + 4`
    ///
    /// Expected Witness Stack:
    /// `[word_idx, mem_val, pc_next, pc_curr, rd_val, imm, rs1_val]`
    pub fn emit_lw_step_verifier(builder: &mut ScriptBuilder) {
        // Stack: [word_idx, mem_val, pc_next, pc_curr, rd_val, imm, rs1_val]
        builder.op_add(); // rs1 + imm -> effective_addr: [word_idx, mem_val, pc_next, pc_curr, rd_val, eff_addr]

        // Roll word_idx (index 5)
        builder.op_roll(5); // [mem_val, pc_next, pc_curr, rd_val, eff_addr, word_idx]
        // Compute word_idx * 4 using double-add
        builder.op_dup();
        builder.op_add(); // word_idx * 2
        builder.op_dup();
        builder.op_add(); // word_idx * 4

        // Verify alignment: eff_addr == 4 * word_idx
        builder.op_equalverify(); // [mem_val, pc_next, pc_curr, rd_val]

        // Verify rd_val == mem_val
        builder.op_roll(3); // [pc_next, pc_curr, rd_val, mem_val]
        builder.op_equalverify(); // [pc_next, pc_curr]

        // Verify PC: pc_curr + 4 == pc_next
        builder.push_int(4);
        builder.op_add();
        builder.op_equalverify();

        builder.push_int(1);
    }

    /// Emits script that verifies a SW (Store Word) memory instruction execution step:
    /// Asserts:
    /// 1. Address alignment: `effective_addr == 4 * word_idx`
    /// 2. Value binding: `rs2_val == mem_val`
    /// 3. PC transition: `pc_next == pc_curr + 4`
    ///
    /// Expected Witness Stack:
    /// `[word_idx, mem_val, pc_next, pc_curr, rs2_val, imm, rs1_val]`
    pub fn emit_sw_step_verifier(builder: &mut ScriptBuilder) {
        // Stack: [word_idx, mem_val, pc_next, pc_curr, rs2_val, imm, rs1_val]
        builder.op_add(); // rs1 + imm -> effective_addr: [word_idx, mem_val, pc_next, pc_curr, rs2_val, eff_addr]

        // Roll word_idx (index 5)
        builder.op_roll(5);
        builder.op_dup();
        builder.op_add();
        builder.op_dup();
        builder.op_add(); // word_idx * 4

        // Verify alignment: eff_addr == 4 * word_idx
        builder.op_equalverify(); // [mem_val, pc_next, pc_curr, rs2_val]

        // Verify rs2_val == mem_val
        builder.op_roll(3); // [pc_next, pc_curr, rs2_val, mem_val]
        builder.op_equalverify(); // [pc_next, pc_curr]

        // Verify PC: pc_curr + 4 == pc_next
        builder.push_int(4);
        builder.op_add();
        builder.op_equalverify();

        builder.push_int(1);
    }

    /// Creates witness vector for ADD instruction verification
    pub fn create_add_witness(step: &RiscvStep) -> Vec<Vec<u8>> {
        vec![
            katamoto_script::builder::encode_num(step.pc_next as i64),
            katamoto_script::builder::encode_num(step.pc_curr as i64),
            katamoto_script::builder::encode_num(step.rd_val as i64),
            katamoto_script::builder::encode_num(step.rs2_val as i64),
            katamoto_script::builder::encode_num(step.rs1_val as i64),
        ]
    }

    /// Creates witness vector for SUB instruction verification
    pub fn create_sub_witness(step: &RiscvStep) -> Vec<Vec<u8>> {
        vec![
            katamoto_script::builder::encode_num(step.pc_next as i64),
            katamoto_script::builder::encode_num(step.pc_curr as i64),
            katamoto_script::builder::encode_num(step.rs1_val as i64),
            katamoto_script::builder::encode_num(step.rs2_val as i64),
            katamoto_script::builder::encode_num(step.rd_val as i64),
        ]
    }

    /// Creates witness vector for BEQ or BNE branch instruction verification
    pub fn create_branch_witness(step: &RiscvStep) -> Vec<Vec<u8>> {
        vec![
            katamoto_script::builder::encode_num(step.imm as i64),
            katamoto_script::builder::encode_num(step.pc_next as i64),
            katamoto_script::builder::encode_num(step.pc_curr as i64),
            katamoto_script::builder::encode_num(step.rs2_val as i64),
            katamoto_script::builder::encode_num(step.rs1_val as i64),
        ]
    }

    /// Creates witness vector for LW instruction verification
    pub fn create_lw_witness(step: &RiscvStep) -> Vec<Vec<u8>> {
        let eff_addr = (step.rs1_val as i64 + step.imm as i64) as u32;
        let word_idx = (eff_addr / 4) as i64;
        vec![
            katamoto_script::builder::encode_num(word_idx),
            katamoto_script::builder::encode_num(step.rd_val as i64),
            katamoto_script::builder::encode_num(step.pc_next as i64),
            katamoto_script::builder::encode_num(step.pc_curr as i64),
            katamoto_script::builder::encode_num(step.rd_val as i64),
            katamoto_script::builder::encode_num(step.imm as i64),
            katamoto_script::builder::encode_num(step.rs1_val as i64),
        ]
    }

    /// Creates witness vector for SW instruction verification
    pub fn create_sw_witness(step: &RiscvStep) -> Vec<Vec<u8>> {
        let eff_addr = (step.rs1_val as i64 + step.imm as i64) as u32;
        let word_idx = (eff_addr / 4) as i64;
        vec![
            katamoto_script::builder::encode_num(word_idx),
            katamoto_script::builder::encode_num(step.rs2_val as i64),
            katamoto_script::builder::encode_num(step.pc_next as i64),
            katamoto_script::builder::encode_num(step.pc_curr as i64),
            katamoto_script::builder::encode_num(step.rs2_val as i64),
            katamoto_script::builder::encode_num(step.imm as i64),
            katamoto_script::builder::encode_num(step.rs1_val as i64),
        ]
    }

    /// Creates witness vector for JAL instruction verification
    pub fn create_jal_witness(step: &RiscvStep) -> Vec<Vec<u8>> {
        vec![
            katamoto_script::builder::encode_num(step.imm as i64),
            katamoto_script::builder::encode_num(step.pc_next as i64),
            katamoto_script::builder::encode_num(step.rd_val as i64),
            katamoto_script::builder::encode_num(step.pc_curr as i64),
        ]
    }
}
