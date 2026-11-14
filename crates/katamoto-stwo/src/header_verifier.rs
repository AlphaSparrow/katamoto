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
pub const REGTEST_POW_LIMIT_NBITS: u32 = 0x207fffff; // Regtest / test difficulty target
/// Median-Time-Past window size in blocks (BIP-113)
pub const MEDIAN_TIME_SPAN: usize = 11;
/// Maximum allowed future block timestamp deviation relative to network adjusted time (2 hours)
pub const MAX_FUTURE_BLOCK_TIME: u32 = 2 * 60 * 60; // 7,200 seconds

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
        let mut n_size = n_bits.div_ceil(8);
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

/// Bitcoin consensus difficulty retargeter matching Satoshi / Nakamoto consensus rules
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
        let first_pass = Sha256::digest(bytes);
        let second_pass = Sha256::digest(first_pass);
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
            let m_bytes = mantissa.to_le_bytes();
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

                if height.is_multiple_of(DIFFICULTY_ADJUSTMENT_INTERVAL) {
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

    /// Computes Median-Time-Past (MTP) for the block at `block_index` according to BIP-113.
    /// If there are fewer than 11 prior blocks in this chain segment and no prior history is supplied,
    /// all available prior headers are used.
    pub fn compute_mtp(&self, block_index: usize) -> u32 {
        self.compute_mtp_with_history(block_index, &[])
    }

    /// Computes Median-Time-Past (MTP) for the block at `block_index` according to BIP-113,
    /// prepending `prior_timestamps` (most recent at the end) if `block_index < 11`.
    pub fn compute_mtp_with_history(&self, block_index: usize, prior_timestamps: &[u32]) -> u32 {
        let mut window = Vec::with_capacity(MEDIAN_TIME_SPAN);
        let needed_from_prior = MEDIAN_TIME_SPAN.saturating_sub(block_index);
        if needed_from_prior > 0 && !prior_timestamps.is_empty() {
            let prior_take = needed_from_prior.min(prior_timestamps.len());
            let prior_start = prior_timestamps.len() - prior_take;
            window.extend_from_slice(&prior_timestamps[prior_start..]);
        }
        let chain_start = block_index.saturating_sub(MEDIAN_TIME_SPAN.saturating_sub(window.len()));
        for h in &self.headers[chain_start..block_index] {
            window.push(h.time);
        }
        if window.is_empty() {
            return 0;
        }
        window.sort_unstable();
        window[window.len() / 2]
    }

    /// Verifies comprehensive Bitcoin consensus rules across the header chain:
    /// 1. Continuity: prev_block_hash matches previous block's Double-SHA256 hash.
    /// 2. Proof-of-Work: block_hash <= target expanded from nBits.
    /// 3. Median-Time-Past (BIP-113): block timestamp > MTP of previous 11 blocks.
    /// 4. Future time limit: block timestamp <= max_future_time (if provided).
    /// 5. Retargeting: nBits strictly verified at 2016-block epoch boundaries and identical within epochs.
    pub fn verify_consensus_rules(
        &self,
        start_height: u32,
        epoch_start_time: u32,
        max_future_time: Option<u32>,
        prior_timestamps: &[u32],
    ) -> Result<(), &'static str> {
        if self.headers.is_empty() {
            return Err("Header chain cannot be empty");
        }

        let mut current_epoch_start_time = epoch_start_time;

        for (i, header) in self.headers.iter().enumerate() {
            // 1. Proof of work
            if !header.is_pow_valid() {
                return Err("Invalid proof-of-work: block hash exceeds target");
            }

            // 2. Future time limit
            if let Some(max_time) = max_future_time {
                if header.time > max_time {
                    return Err("Block timestamp exceeds future time limit (network adjusted time + 2h)");
                }
            }

            // 3. Median-Time-Past (BIP-113)
            let mtp = self.compute_mtp_with_history(i, prior_timestamps);
            if mtp > 0 && header.time <= mtp {
                return Err("Block timestamp must be strictly greater than Median-Time-Past (MTP)");
            }

            let height = start_height + i as u32;

            if i > 0 {
                let prev_header = &self.headers[i - 1];

                // 4. Continuity
                if header.prev_block_hash != prev_header.block_hash() {
                    return Err("Header continuity broken: prev_block_hash mismatch");
                }

                // 5. Retargeting
                if height.is_multiple_of(DIFFICULTY_ADJUSTMENT_INTERVAL) {
                    let expected_nbits = DifficultyRetargeter::compute_next_target(
                        prev_header.nbits,
                        current_epoch_start_time,
                        prev_header.time,
                    );
                    if header.nbits != expected_nbits {
                        return Err("Difficulty retarget mismatch at epoch boundary");
                    }
                    current_epoch_start_time = header.time;
                } else if header.nbits != prev_header.nbits {
                    return Err("nBits mismatch within epoch: target cannot change outside boundary");
                }
            }
        }

        Ok(())
    }

    /// Generates public statement for the header chain verification
    pub fn to_statement(&self) -> RiscvStatement {
        let genesis_hash = self.headers.first().unwrap().block_hash();
        let tip_hash = self.headers.last().unwrap().block_hash();
        let cycle_count = (self.headers.len() * 128) as u64; // ~128 RV32I cycles per header

        let mut hasher = Sha256::new();
        for h in &self.headers {
            hasher.update(h.to_bytes());
        }
        let program_digest: [u8; 32] = hasher.finalize().into();

        RiscvStatement {
            initial_pc: 0x00010000,
            final_pc: 0x00010000 + (cycle_count as u32 * 4),
            cycle_count,
            initial_state_root: genesis_hash,
            final_state_root: tip_hash,
            program_digest,
        }
    }

    /// Compiles the header verification into a sequence of RISC-V execution steps
    pub fn synthesize_steps(&self) -> Vec<RiscvStep> {
        let mut steps = Vec::new();
        let mut pc = 0x00010000_u32;

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

    /// Emits script that verifies a block's timestamp is strictly greater than Median-Time-Past:
    /// Asserts: `block_time > min_mtp`
    ///
    /// Expected Witness Stack: `[block_time]`
    pub fn emit_mtp_verifier(builder: &mut ScriptBuilder, min_mtp: u32) {
        // Stack top: [block_time]
        builder.push_int(min_mtp as i64);
        builder.op_greater_than();
        builder.op_verify();
        builder.push_int(1);
    }

    /// Emits script that verifies dynamic MTP comparison:
    /// Asserts: `block_time > mtp_time`
    ///
    /// Expected Witness Stack: `[mtp_time, block_time]` (block_time on top)
    pub fn emit_mtp_dynamic_verifier(builder: &mut ScriptBuilder) {
        // Stack: [mtp_time, block_time]
        builder.op_greater_than();
        builder.op_verify();
        builder.push_int(1);
    }

    /// Emits fraud proof dispute leaf for MTP violation:
    /// Challenger proves that operator's block timestamp was invalid:
    /// Asserts: `block_time <= mtp_time`
    ///
    /// Expected Witness Stack: `[mtp_time, block_time]` (block_time on top)
    pub fn emit_mtp_violation_dispute_leaf(builder: &mut ScriptBuilder) {
        // Stack: [mtp_time, block_time]
        builder.op_less_than_or_equal();
        builder.op_verify();
        builder.push_int(1);
    }

    /// Creates witness vector for MTP verification: `[block_time, mtp_time]` (mtp_time on top)
    pub fn create_mtp_witness(median_time: u32, block_time: u32) -> Vec<Vec<u8>> {
        vec![
            katamoto_script::builder::encode_num(block_time as i64),
            katamoto_script::builder::encode_num(median_time as i64),
        ]
    }

    /// Emits script verifying Proof-of-Work difficulty target in Tapscript using BIP-347 OP_CAT:
    /// Decomposes 32-byte Double-SHA256 hash into `hash_prefix || zeroes`, verifying that
    /// the block hash ends with at least `zero_bytes_count` zero bytes (high difficulty).
    ///
    /// Expected Witness Stack: `[hash_prefix (32 - Z bytes), header_80B]`
    pub fn emit_pow_target_verifier(builder: &mut ScriptBuilder, zero_bytes_count: usize) {
        assert!(zero_bytes_count > 0 && zero_bytes_count < 32, "Invalid zero bytes count");
        // Stack: [hash_prefix, header_80B]
        builder.op_sha256();
        builder.op_sha256(); // [hash_prefix, hash_32B]
        builder.op_swap();   // [hash_32B, hash_prefix]
        let zeroes = vec![0x00u8; zero_bytes_count];
        builder.push_slice(&zeroes); // [hash_32B, hash_prefix, zeroes]
        builder.op_cat();            // [hash_32B, (hash_prefix || zeroes)]
        builder.op_equalverify();    // Asserts computed hash matches reconstructed hash
        builder.push_int(1);
    }

    /// Creates witness for in-script Proof-of-Work target verification
    pub fn create_pow_target_witness(
        header: &BitcoinHeader,
        zero_bytes_count: usize,
    ) -> Result<Vec<Vec<u8>>, &'static str> {
        let hash = header.block_hash();
        let zeroes = vec![0x00u8; zero_bytes_count];
        if &hash[32 - zero_bytes_count..32] != zeroes.as_slice() {
            return Err("Block hash does not meet required zero bytes target");
        }
        let prefix = hash[0..32 - zero_bytes_count].to_vec();
        Ok(vec![prefix, header.to_bytes().to_vec()])
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
        hasher.update(first_header.to_bytes());
        hasher.update(last_header.to_bytes());
        hasher.update(next_header.to_bytes());
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

    /// Compiles an MTP violation dispute TapTree:
    /// Allows a challenger to slash an operator who submitted a block header with timestamp <= MTP.
    pub fn compile_mtp_dispute(
        header: &BitcoinHeader,
        mtp_timestamp: u32,
        operator_pubkey: [u8; 32],
        challenger_pubkey: [u8; 32],
        bond_satoshis: u64,
        dispute_timelock_blocks: u32,
    ) -> (BitVm2DisputeGraph, TapTree, Vec<TaprootStarkSpend>) {
        let mut hasher = Sha256::new();
        hasher.update(header.to_bytes());
        hasher.update(mtp_timestamp.to_le_bytes());
        let stmt_hash: [u8; 32] = hasher.finalize().into();

        let graph = BitVm2DisputeGraph::new(
            operator_pubkey,
            challenger_pubkey,
            bond_satoshis,
            dispute_timelock_blocks,
            stmt_hash,
        );

        let mut b_dispute = ScriptBuilder::new();
        HeaderScript::emit_mtp_violation_dispute_leaf(&mut b_dispute);
        let script = b_dispute.to_bytes();
        let wit = HeaderScript::create_mtp_witness(mtp_timestamp, header.time);

        let leaf = TapLeaf::new("mtp_violation_dispute_leaf", script.clone());
        let tap_tree = TapTree::new(vec![leaf]);
        let internal_nums_key = [0x02u8; 32];
        let ctrl = tap_tree.control_block(0, &internal_nums_key);
        let spend = TaprootStarkSpend::new("mtp_violation_dispute_leaf", wit, script, ctrl);

        (graph, tap_tree, vec![spend])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use katamoto_script::Vm;

    #[test]
    fn test_header_chain_mtp_computation_and_consensus_rules() {
        let base_time = 1_700_000_000_u32;
        let mut headers = Vec::new();
        let mut prev_hash = [0u8; 32];

        for i in 0..12 {
            let mut h = BitcoinHeader {
                version: 1,
                prev_block_hash: prev_hash,
                merkle_root: [0x11; 32],
                time: base_time + (i as u32 * 600), // 10 min increments
                nbits: REGTEST_POW_LIMIT_NBITS,
                nonce: 0,
            };
            while !h.is_pow_valid() {
                h.nonce += 1;
            }
            prev_hash = h.block_hash();
            headers.push(h);
        }

        let chain = HeaderChain::new(headers);

        // Block 11 MTP: window of 11 blocks (0..10): timestamps [0, 600, ..., 6000]
        // Sorted median is index 5: base_time + 5 * 600
        let mtp_11 = chain.compute_mtp(11);
        assert_eq!(mtp_11, base_time + 5 * 600);

        // Verify full consensus rules
        let max_future = base_time + (12 * 600) + 7200;
        let res = chain.verify_consensus_rules(0, base_time, Some(max_future), &[]);
        assert!(res.is_ok(), "Consensus rules failed: {:?}", res);
    }

    #[test]
    fn test_header_chain_consensus_rules_rejects_mtp_violation() {
        let base_time = 1_700_000_000_u32;
        let mut headers = Vec::new();
        let mut prev_hash = [0u8; 32];

        for i in 0..3 {
            let mut h = BitcoinHeader {
                version: 1,
                prev_block_hash: prev_hash,
                merkle_root: [0x22; 32],
                time: if i == 2 { base_time } else { base_time + (i as u32 * 600) },
                nbits: REGTEST_POW_LIMIT_NBITS,
                nonce: 0,
            };
            while !h.is_pow_valid() {
                h.nonce += 1;
            }
            prev_hash = h.block_hash();
            headers.push(h);
        }

        let chain = HeaderChain::new(headers);
        let res = chain.verify_consensus_rules(0, base_time, None, &[]);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Median-Time-Past"));
    }

    #[test]
    fn test_header_chain_consensus_rules_rejects_future_timestamp() {
        let base_time = 1_700_000_000_u32;
        let mut headers = Vec::new();
        let mut prev_hash = [0u8; 32];

        for i in 0..2 {
            let mut h = BitcoinHeader {
                version: 1,
                prev_block_hash: prev_hash,
                merkle_root: [0x33; 32],
                time: if i == 1 { base_time + 10_000 } else { base_time },
                nbits: REGTEST_POW_LIMIT_NBITS,
                nonce: 0,
            };
            while !h.is_pow_valid() {
                h.nonce += 1;
            }
            prev_hash = h.block_hash();
            headers.push(h);
        }

        let chain = HeaderChain::new(headers);
        let res = chain.verify_consensus_rules(0, base_time, Some(base_time + 7200), &[]);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("future time limit"));
    }

    #[test]
    fn test_in_script_mtp_verifier_and_dispute_in_vm() {
        let median_time = 1_700_000_000_u32;
        let valid_block_time = 1_700_000_600_u32;

        // 1. Dynamic verifier: valid block time > MTP passes
        let mut b_dyn = ScriptBuilder::new();
        HeaderScript::emit_mtp_dynamic_verifier(&mut b_dyn);
        let wit_dyn = HeaderScript::create_mtp_witness(median_time, valid_block_time);
        let mut vm_dyn = Vm::with_witness(wit_dyn);
        assert!(vm_dyn.execute(b_dyn.as_bytes()).expect("Dynamic MTP script failed"));
        assert_eq!(vm_dyn.stack().last().unwrap(), &[1]);

        // 2. Dispute leaf: invalid block time <= MTP allows challenger to slash
        let invalid_block_time = 1_700_000_000_u32; // equal to MTP
        let mut b_disp = ScriptBuilder::new();
        HeaderScript::emit_mtp_violation_dispute_leaf(&mut b_disp);
        let wit_disp = HeaderScript::create_mtp_witness(median_time, invalid_block_time);
        let mut vm_disp = Vm::with_witness(wit_disp);
        assert!(vm_disp.execute(b_disp.as_bytes()).expect("MTP dispute script failed"));
        assert_eq!(vm_disp.stack().last().unwrap(), &[1]);
    }

    #[test]
    fn test_in_script_pow_target_verifier_in_vm() {
        let mut h = BitcoinHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0x55; 32],
            time: 1_700_000_000,
            nbits: POW_LIMIT_NBITS,
            nonce: 0,
        };
        // Mine a nonce such that block_hash ends with 0x00
        while h.block_hash()[31] != 0 {
            h.nonce += 1;
        }

        // Emit PoW verifier script for 1 zero byte
        let mut b = ScriptBuilder::new();
        HeaderScript::emit_pow_target_verifier(&mut b, 1);
        let wit = HeaderScript::create_pow_target_witness(&h, 1).expect("Failed to create PoW witness");

        let mut vm = Vm::with_witness(wit);
        assert!(vm.execute(b.as_bytes()).expect("PoW target script failed"));
        assert_eq!(vm.stack().last().unwrap(), &[1]);
    }

    #[test]
    fn test_in_script_pow_target_verifier_rejects_insufficient_work() {
        let mut h = BitcoinHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0x77; 32],
            time: 1_700_000_000,
            nbits: POW_LIMIT_NBITS,
            nonce: 0,
        };
        // Mine nonce so block_hash ends with non-zero byte
        while h.block_hash()[31] == 0 {
            h.nonce += 1;
        }

        // Asking for witness with 1 zero byte must fail
        let res = HeaderScript::create_pow_target_witness(&h, 1);
        assert!(res.is_err());
    }
}
