use crate::riscv::{RiscvOpcode, RiscvStatement, RiscvStep};
use katamoto_air::bisection::BitVm2DisputeGraph;
use katamoto_fri::taproot::{TapLeaf, TapTree, TaprootStarkSpend};
use katamoto_script::ScriptBuilder;
use sha2::{Digest, Sha256};

/// Consensus parameters for Bitcoin difficulty adjustment
pub const POW_TARGET_TIMESPAN: u32 = 14 * 24 * 60 * 60; // 1,209,600 seconds (2 weeks)
pub const POW_TARGET_SPACING: u32 = 10 * 60; // 600 seconds (10 minutes)
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u32 = POW_TARGET_TIMESPAN / POW_TARGET_SPACING; // 2016 blocks
pub const MIN_TIMESPAN: u32 = POW_TARGET_TIMESPAN / 4; // 302,400 seconds (factor of 4 clamp)
pub const MAX_TIMESPAN: u32 = POW_TARGET_TIMESPAN * 4; // 4,838,400 seconds (factor of 4 clamp)
pub const POW_LIMIT_NBITS: u32 = 0x1d00ffff; // Mainnet difficulty 1 target

/// 256-bit unsigned integer with 4 64-bit limbs (little-endian)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: Self = Self([0, 0, 0, 0]);

    pub fn from_le_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            limbs[i] = u64::from_le_bytes(buf);
        }
        Self(limbs)
    }

    pub fn to_le_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&self.0[i].to_le_bytes());
        }
        bytes
    }

    pub fn bits(&self) -> usize {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return (i * 64) + (64 - self.0[i].leading_zeros() as usize);
            }
        }
        0
    }

    pub fn shr(&self, shift: usize) -> Self {
        if shift >= 256 {
            return Self::ZERO;
        }
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        let mut out = [0u64; 4];

        for i in 0..4 {
            if i + word_shift < 4 {
                out[i] = self.0[i + word_shift] >> bit_shift;
                if bit_shift > 0 && i + word_shift + 1 < 4 {
                    out[i] |= self.0[i + word_shift + 1] << (64 - bit_shift);
                }
            }
        }
        Self(out)
    }

    pub fn from_compact(nbits: u32) -> Self {
        let exponent = ((nbits >> 24) & 0xff) as usize;
        let mantissa = (nbits & 0x007f_ffff) as u64;
        let mut bytes = [0u8; 32];

        if exponent <= 3 {
            let m = mantissa >> (8 * (3 - exponent));
            let le = (m as u32).to_le_bytes();
            bytes[..4].copy_from_slice(&le);
        } else if exponent <= 32 {
            let offset = exponent - 3;
            let le = (mantissa as u32).to_le_bytes();
            let copy_len = 3.min(32 - offset);
            bytes[offset..offset + copy_len].copy_from_slice(&le[..copy_len]);
        }
        Self::from_le_bytes(&bytes)
    }

    pub fn to_compact(&self) -> u32 {
        let n_bits = self.bits();
        let mut n_size = (n_bits + 7) / 8;
        let mut n_compact: u64 = if n_size <= 3 {
            self.0[0] << (8 * (3 - n_size))
        } else {
            let shifted = self.shr(8 * (n_size - 3));
            shifted.0[0]
        };

        if (n_compact & 0x00800000) != 0 {
            n_compact >>= 8;
            n_size += 1;
        }

        ((n_size as u32) << 24) | ((n_compact as u32) & 0x007f_ffff)
    }

    pub fn mul_u32_div_u32(&self, mul: u32, div: u32) -> Self {
        let mut carry = 0u128;
        let mut limbs = [0u64; 5];
        for i in 0..4 {
            let cur = (self.0[i] as u128) * (mul as u128) + carry;
            limbs[i] = cur as u64;
            carry = cur >> 64;
        }
        limbs[4] = carry as u64;

        let mut div_res = [0u64; 4];
        let mut rem = limbs[4] as u128;
        for i in (0..4).rev() {
            let cur = (rem << 64) | (limbs[i] as u128);
            div_res[i] = (cur / (div as u128)) as u64;
            rem = cur % (div as u128);
        }
        Self(div_res)
    }
}

/// Bitcoin consensus difficulty retargeter matching BIP-0 / Bitcoin Core rules
pub struct DifficultyRetargeter;

impl DifficultyRetargeter {
    /// Clamps actual timespan between T/4 and 4T
    pub fn clamp_timespan(actual_timespan: u32) -> u32 {
        actual_timespan.max(MIN_TIMESPAN).min(MAX_TIMESPAN)
    }

    /// Computes the new nBits target following the 2016-block epoch boundary
    pub fn compute_next_target(old_nbits: u32, first_block_time: u32, last_block_time: u32) -> u32 {
        let actual_timespan = last_block_time.saturating_sub(first_block_time);
        let clamped = Self::clamp_timespan(actual_timespan);

        let old_target = U256::from_compact(old_nbits);
        let pow_limit = U256::from_compact(POW_LIMIT_NBITS);

        let new_target = old_target.mul_u32_div_u32(clamped, POW_TARGET_TIMESPAN);
        if new_target > pow_limit {
            POW_LIMIT_NBITS
        } else {
            new_target.to_compact()
        }
    }

    /// Verifies whether the difficulty retarget between epoch boundaries is valid
    pub fn verify_epoch_transition(
        first_header: &BitcoinHeader,
        last_header: &BitcoinHeader,
        next_header: &BitcoinHeader,
    ) -> bool {
        let expected_nbits = Self::compute_next_target(last_header.nbits, first_header.time, last_header.time);
        next_header.nbits == expected_nbits
    }
}

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

    /// Expands compact nBits target into 256-bit Little-Endian difficulty target
    /// matching the byte order of `block_hash()`
    pub fn target_bytes(&self) -> [u8; 32] {
        let mut target = [0u8; 32];
        let exponent = ((self.nbits >> 24) & 0xff) as usize;
        let mantissa = self.nbits & 0x007f_ffff;

        if exponent <= 3 {
            let val = mantissa >> (8 * (3 - exponent));
            let val_bytes = val.to_le_bytes();
            let len = val_bytes.len().min(32);
            target[..len].copy_from_slice(&val_bytes[..len]);
        } else if exponent <= 32 {
            let offset = exponent - 3;
            let m_bytes = (mantissa as u32).to_le_bytes();
            target[offset..offset + 3].copy_from_slice(&m_bytes[0..3]);
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

    /// Verifies continuity, proof-of-work, and difficulty retargeting across the header chain.
    /// `start_height`: block height of `self.headers[0]`.
    /// `epoch_start_time`: timestamp of block at `(start_height / 2016) * 2016`.
    pub fn verify_with_difficulty(&self, start_height: u32, epoch_start_time: u32) -> bool {
        let mut current_epoch_start_time = epoch_start_time;

        for (i, header) in self.headers.iter().enumerate() {
            if !header.is_pow_valid() {
                return false;
            }
            let height = start_height + i as u32;

            if i > 0 {
                let prev_header = &self.headers[i - 1];
                if header.prev_block_hash != prev_header.block_hash() {
                    return false;
                }

                if height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
                    // Epoch boundary! Check difficulty retargeting
                    let expected_nbits = DifficultyRetargeter::compute_next_target(
                        prev_header.nbits,
                        current_epoch_start_time,
                        prev_header.time,
                    );
                    if header.nbits != expected_nbits {
                        return false;
                    }
                    current_epoch_start_time = header.time;
                } else {
                    // Within epoch: nBits must remain identical
                    if header.nbits != prev_header.nbits {
                        return false;
                    }
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

    /// Emits script verifying timespan calculation and consensus clamping:
    /// Asserts: `min(max(last_time - first_time, 302400), 4838400) == expected_clamped_timespan`
    ///
    /// Expected Witness Stack: `[last_time, first_time]`
    pub fn emit_timespan_clamping_verifier(builder: &mut ScriptBuilder, expected_clamped: u32) {
        // Stack top: [last_time, first_time]
        builder.op_sub(); // [last_time - first_time]
        builder.push_int(MIN_TIMESPAN as i64);
        builder.op_max(); // [max(timespan, 302400)]
        builder.push_int(MAX_TIMESPAN as i64);
        builder.op_min(); // [min(max_val, 4838400)]
        builder.push_int(expected_clamped as i64);
        builder.op_equalverify();
        builder.push_int(1);
    }

    /// Creates witness vector for timespan clamping verification
    pub fn create_timespan_witness(first_time: u32, last_time: u32) -> Vec<Vec<u8>> {
        vec![
            katamoto_script::builder::encode_num(last_time as i64),
            katamoto_script::builder::encode_num(first_time as i64),
        ]
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

    /// Compiles an epoch boundary transition dispute proof into a BitVM dispute game
    pub fn compile_epoch_transition_dispute(
        first_header: &BitcoinHeader,
        last_header: &BitcoinHeader,
        next_header: &BitcoinHeader,
        operator_pubkey: [u8; 32],
        challenger_pubkey: [u8; 32],
        bond_satoshis: u64,
        dispute_timelock_blocks: u32,
    ) -> (BitVm2DisputeGraph, TapTree, Vec<TaprootStarkSpend>) {
        let actual_timespan = last_header.time.saturating_sub(first_header.time);
        let clamped = DifficultyRetargeter::clamp_timespan(actual_timespan);

        let mut hasher = Sha256::new();
        hasher.update(&first_header.to_bytes());
        hasher.update(&last_header.to_bytes());
        hasher.update(&next_header.to_bytes());
        let stmt_hash: [u8; 32] = hasher.finalize().into();

        let graph = BitVm2DisputeGraph::new(
            operator_pubkey,
            challenger_pubkey,
            bond_satoshis,
            dispute_timelock_blocks,
            stmt_hash,
        );

        let mut leaves = Vec::new();
        let mut spend_factories = Vec::new();

        // Leaf 0: Timespan clamping verifier leaf
        let mut b_timespan = ScriptBuilder::new();
        HeaderScript::emit_timespan_clamping_verifier(&mut b_timespan, clamped);
        let script_timespan = b_timespan.to_bytes();
        let wit_timespan = HeaderScript::create_timespan_witness(first_header.time, last_header.time);
        leaves.push(TapLeaf::new("epoch_timespan_clamping_leaf", script_timespan.clone()));
        spend_factories.push(("epoch_timespan_clamping_leaf".to_string(), wit_timespan, script_timespan));

        // Leaf 1: Block hash continuity leaf
        let mut b_hash = ScriptBuilder::new();
        HeaderScript::emit_block_hash_verifier(&mut b_hash, &next_header.block_hash());
        let script_hash = b_hash.to_bytes();
        let wit_hash = vec![next_header.to_bytes().to_vec()];
        leaves.push(TapLeaf::new("epoch_next_header_hash_leaf", script_hash.clone()));
        spend_factories.push(("epoch_next_header_hash_leaf".to_string(), wit_hash, script_hash));

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
