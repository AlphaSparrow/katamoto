use katamoto_field::M31;
use katamoto_script::ScriptBuilder;
use sha2::{Digest, Sha256};

pub const TRANSCRIPT_INIT_SEED: &[u8] = b"KATAMOTO_STARK_TRANSCRIPT_V1";

/// Fiat-Shamir Transcript engine for generating verified random challenges
#[derive(Debug, Clone)]
pub struct Transcript {
    state: [u8; 32],
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

impl Transcript {
    /// Initializes a fresh transcript seeded with domain separator
    pub fn new() -> Self {
        let hash = Sha256::digest(TRANSCRIPT_INIT_SEED);
        let mut state = [0u8; 32];
        state.copy_from_slice(&hash);
        Self { state }
    }

    /// Absorbs arbitrary byte payload into the rolling hash state:
    /// state <- SHA256(state || payload)
    pub fn absorb(&mut self, payload: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&self.state);
        hasher.update(payload);
        let res = hasher.finalize();
        self.state.copy_from_slice(&res);
    }

    /// Current transcript state
    pub fn state(&self) -> [u8; 32] {
        self.state
    }

    /// Squeezes a 31-bit challenge modulo M31_P.
    /// Returns:
    /// - M31 challenge
    /// - prefix 4-byte slice
    /// - suffix 28-byte slice
    pub fn squeeze_m31_challenge(&mut self) -> (M31, [u8; 4], [u8; 28]) {
        // Roll state forward
        self.absorb(b"squeeze_m31");
        
        let mut prefix = [0u8; 4];
        let mut suffix = [0u8; 28];
        prefix.copy_from_slice(&self.state[0..4]);
        suffix.copy_from_slice(&self.state[4..32]);

        // Mask off high bit to fit inside M31 (< 2^31 - 1)
        let raw = u32::from_le_bytes(prefix) & 0x7fffffff;
        let val = if raw == 0x7fffffff { raw - 1 } else { raw };
        let challenge = M31::new(val as u64);

        (challenge, prefix, suffix)
    }
}

/// Bitcoin Script Gadgets for verifying Fiat-Shamir transcript evolution
pub struct TranscriptScript;

impl TranscriptScript {
    /// Emits script that updates transcript state by absorbing data on stack:
    /// Input Stack: `[..., current_state (32B), data (variable/32B)]`
    /// Output Stack: `[..., next_state (32B)]`
    /// Uses BIP-347 OP_CAT + OP_SHA256
    pub fn emit_absorb(builder: &mut ScriptBuilder) {
        builder.op_cat();
        builder.op_sha256();
    }

    /// Emits script that verifies a challenge decomposition from the transcript hash.
    ///
    /// Expected Witness Stack:
    /// `[transcript_state (32B), suffix (28B), challenge_bytes (4B)]`
    ///
    /// Execution:
    /// 1. Concatenates challenge_bytes || suffix via OP_CAT -> reconstructed 32B hash
    /// 2. Asserts reconstructed == transcript_state via OP_EQUALVERIFY
    /// 3. Leaves TRUE (1) on stack
    pub fn emit_verify_challenge_extraction(builder: &mut ScriptBuilder) {
        // Stack: [transcript_state, suffix_28B, challenge_4B]
        builder.op_swap(); // [transcript_state, challenge_4B, suffix_28B]
        builder.op_cat();  // [transcript_state, (challenge_4B || suffix_28B)]
        builder.op_equalverify(); // confirms exact 32B match!
        builder.push_int(1); // leaves TRUE on stack
    }

    /// Creates witness vector for transcript challenge extraction
    pub fn create_challenge_witness(state: &[u8; 32], prefix: &[u8; 4], suffix: &[u8; 28]) -> Vec<Vec<u8>> {
        vec![
            state.to_vec(),
            suffix.to_vec(),
            prefix.to_vec(),
        ]
    }
}
