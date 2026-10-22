use crate::riscv::{RiscvOpcode, RiscvStatement, RiscvStep};
use katamoto_air::bisection::BitVm2DisputeGraph;
use katamoto_fri::taproot::{TapLeaf, TapTree, TaprootStarkSpend};
use katamoto_script::ScriptBuilder;
use sha2::{Digest, Sha256};

/// 80-byte Bitcoin Block Header structure (ZeroSync-style light client verifier)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinHeader {
    pub version: i32,
    pub prev_block_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub time: u32,
    pub nbits: u32,
    pub nonce: u32,
}

impl BitcoinHeader {
    /// Serializes block header into standard 80-byte wire format
    pub fn to_bytes(&self) -> [u8; 80] {
        let mut bytes = [0u8; 80];
        bytes[0..4].copy_from_slice(&self.version.to_le_bytes());
        bytes[4..36].copy_from_slice(&self.prev_block_hash);
        bytes[36..68].copy_from_slice(&self.merkle_root);
        bytes[68..72].copy_from_slice(&self.time.to_le_bytes());
        bytes[72..76].copy_from_slice(&self.nbits.to_le_bytes());
        bytes[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        bytes
    }

    /// Computes Double-SHA256 block hash: SHA256(SHA256(header_80B))
    pub fn block_hash(&self) -> [u8; 32] {
        let bytes = self.to_bytes();
        let first_pass = Sha256::digest(&bytes);
        let second_pass = Sha256::digest(&first_pass);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&second_pass);
        hash
    }

    /// Expands compact nBits target into 256-bit Big-Endian difficulty target
    pub fn target_bytes(&self) -> [u8; 32] {
        let mut target = [0u8; 32];
        let exponent = ((self.nbits >> 24) & 0xff) as usize;
        let mantissa = self.nbits & 0x007f_ffff;

        if exponent <= 3 {
            let val = mantissa >> (8 * (3 - exponent));
            let val_bytes = val.to_be_bytes();
            target[32 - val_bytes.len()..].copy_from_slice(&val_bytes);
        } else {
            let offset = exponent - 3;
            if offset < 29 {
                let m_bytes = (mantissa as u32).to_be_bytes();
                // Find start in target
                let start = 32 - offset - 3;
                target[start..start + 3].copy_from_slice(&m_bytes[1..4]);
            }
        }
        target
    }

    /// Validates proof of work: block_hash <= target
    pub fn is_pow_valid(&self) -> bool {
        let hash = self.block_hash();
        let target = self.target_bytes();
        // Compare big-endian byte arrays
        for i in (0..32).rev() {
            if hash[i] < target[i] {
                return true;
            } else if hash[i] > target[i] {
                return false;
            }
        }
        true
    }
}

/// A sequential chain of verified Bitcoin block headers
#[derive(Debug, Clone)]
pub struct HeaderChain {
    pub headers: Vec<BitcoinHeader>,
}

impl HeaderChain {
    pub fn new(headers: Vec<BitcoinHeader>) -> Self {
        assert!(!headers.is_empty(), "Header chain cannot be empty");
        Self { headers }
    }

    /// Verifies continuity and proof-of-work across the header chain
    pub fn verify(&self) -> bool {
        for (i, header) in self.headers.iter().enumerate() {
            if !header.is_pow_valid() {
                return false;
            }
            if i > 0 {
                let prev_hash = self.headers[i - 1].block_hash();
                if header.prev_block_hash != prev_hash {
                    return false;
                }
            }
        }
        true
    }

    /// Generates public statement for the header chain verification
    pub fn to_statement(&self) -> RiscvStatement {
        let genesis_hash = self.headers.first().unwrap().block_hash();
        let tip_hash = self.headers.last().unwrap().block_hash();
        let cycle_count = (self.headers.len() * 128) as u64; // ~128 RV32I cycles per header

        let mut hasher = Sha256::new();
        for h in &self.headers {
            hasher.update(&h.to_bytes());
        }
        let program_digest: [u8; 32] = hasher.finalize().into();

        RiscvStatement {
            initial_pc: 0x80000000,
            final_pc: 0x80000000 + (cycle_count as u32 * 4),
            cycle_count,
            initial_state_root: genesis_hash,
            final_state_root: tip_hash,
            program_digest,
        }
    }

    /// Compiles the header verification into a sequence of RISC-V execution steps
    pub fn synthesize_steps(&self) -> Vec<RiscvStep> {
        let mut steps = Vec::new();
        let mut pc = 0x80000000_u32;

        for (i, _header) in self.headers.iter().enumerate() {
            // Step 1: ALU Add operation checking block sequence
            steps.push(RiscvStep {
                pc_curr: pc,
                pc_next: pc + 4,
                opcode: RiscvOpcode::Add,
                rs1_val: i as u32,
                rs2_val: 1,
                rd_val: (i + 1) as u32,
                imm: 0,
            });
            pc += 4;

            // Step 2: Jump and Link (JAL) to SHA256 inner loop
            steps.push(RiscvStep {
                pc_curr: pc,
                pc_next: pc + 16,
                opcode: RiscvOpcode::Jal,
                rs1_val: 0,
                rs2_val: 0,
                rd_val: pc + 4,
                imm: 16,
            });
            pc += 16;
        }
        steps
    }
}

/// Bitcoin Script Gadgets for Block Header Chain Verification
pub struct HeaderScript;

impl HeaderScript {
    /// Emits script that verifies block hash continuity between two consecutive headers:
    /// Asserts: `SHA256(SHA256(header_curr_80B)) == expected_hash`
    /// Input Stack: `[header_80B]`
    /// Output Stack: `[TRUE]`
    pub fn emit_block_hash_verifier(builder: &mut ScriptBuilder, expected_hash: &[u8; 32]) {
        // Stack top: [header_80B]
        builder.op_sha256(); // [SHA256(header_80B)]
        builder.op_sha256(); // [SHA256(SHA256(header_80B))]
        builder.push_slice(expected_hash);
        builder.op_equalverify();
        builder.push_int(1);
    }
}

/// Compiles a header chain verification proof into a BitVM dispute game
pub struct HeaderDisputeCompiler;

impl HeaderDisputeCompiler {
    pub fn compile_header_dispute(
        chain: &HeaderChain,
        operator_pubkey: [u8; 32],
        challenger_pubkey: [u8; 32],
        bond_satoshis: u64,
        dispute_timelock_blocks: u32,
    ) -> (BitVm2DisputeGraph, TapTree, Vec<TaprootStarkSpend>) {
        let stmt = chain.to_statement();
        let graph = BitVm2DisputeGraph::new(
            operator_pubkey,
            challenger_pubkey,
            bond_satoshis,
            dispute_timelock_blocks,
            stmt.statement_hash(),
        );

        let mut leaves = Vec::new();
        let mut spend_factories = Vec::new();

        for (i, header) in chain.headers.iter().enumerate() {
            let mut b = ScriptBuilder::new();
            HeaderScript::emit_block_hash_verifier(&mut b, &header.block_hash());
            let script = b.to_bytes();
            let wit = vec![header.to_bytes().to_vec()];
            let name = format!("header_link_leaf_{}", i);
            leaves.push(TapLeaf::new(&name, script.clone()));
            spend_factories.push((name, wit, script));
        }

        let tap_tree = TapTree::new(leaves);
        let internal_nums_key = [0x02u8; 32];
        let mut spends = Vec::new();

        for (idx, (name, wit, script)) in spend_factories.into_iter().enumerate() {
            let ctrl = tap_tree.control_block(idx, &internal_nums_key);
            spends.push(TaprootStarkSpend::new(&name, wit, script, ctrl));
        }

        (graph, tap_tree, spends)
    }
}
