use katamoto_field::{qm31::QM31, M31};
use katamoto_fri::transcript::Transcript;
use katamoto_script::ScriptBuilder;

pub const STWO_CHANNEL_INIT_SEED: &[u8] = b"STWO_CIRCLE_STARK_CHANNEL_V1";

/// Fiat-Shamir channel adapter for Stwo Circle STARK provers.
/// Maps Stwo's channel protocol directly into Katamoto's rolling SHA-256 transcript.
#[derive(Debug, Clone)]
pub struct StwoChannel {
    transcript: Transcript,
}

impl Default for StwoChannel {
    fn default() -> Self {
        Self::new(STWO_CHANNEL_INIT_SEED)
    }
}

impl StwoChannel {
    /// Creates a new channel seeded with domain separator
    pub fn new(seed: &[u8]) -> Self {
        let mut transcript = Transcript::new();
        transcript.absorb(seed);
        Self { transcript }
    }

    /// Current channel state digest
    pub fn state(&self) -> [u8; 32] {
        self.transcript.state()
    }

    /// Mixes an external 32-byte digest into the channel (e.g. Merkle tree root)
    pub fn mix_digest(&mut self, digest: &[u8; 32]) {
        self.transcript.absorb(digest);
    }

    /// Mixes a vector of M31 field elements into the channel
    pub fn mix_felts(&mut self, felts: &[M31]) {
        let mut bytes = Vec::with_capacity(felts.len() * 4);
        for felt in felts {
            bytes.extend_from_slice(&felt.value().to_le_bytes());
        }
        self.transcript.absorb(&bytes);
    }

    /// Draws a random M31 field element challenge from the channel
    pub fn draw_felt(&mut self) -> (M31, [u8; 4], [u8; 28]) {
        self.transcript.squeeze_m31_challenge()
    }

    /// Draws a random QM31 quartic extension field element challenge (4 x M31)
    pub fn draw_qm31(&mut self) -> QM31 {
        let (c0, _, _) = self.draw_felt();
        let (c1, _, _) = self.draw_felt();
        let (c2, _, _) = self.draw_felt();
        let (c3, _, _) = self.draw_felt();
        QM31::from_m31(c0, c1, c2, c3)
    }

    /// Draws an out-of-domain evaluation point (x, y) on the unit circle C(QM31)
    /// x = (1 - t^2) / (1 + t^2), y = 2t / (1 + t^2)
    pub fn draw_random_circle_point(&mut self) -> (QM31, QM31) {
        let t = self.draw_qm31();
        let t_sq = t * t;
        let one = QM31::ONE;
        let denom = (one + t_sq).inv().unwrap_or(one);
        let x = (one - t_sq) * denom;
        let two = QM31::from_u32(2, 0, 0, 0);
        let y = (two * t) * denom;
        (x, y)
    }

    /// Verifies if a given nonce satisfies the Proof of Work difficulty
    pub fn check_pow(&self, nonce: u64, pow_bits: u32) -> bool {
        Transcript::verify_pow(&self.transcript.state(), nonce, pow_bits)
    }

    /// Grinds a 64-bit nonce that satisfies `pow_bits` leading zero bits
    pub fn grind_pow(&self, pow_bits: u32) -> u64 {
        self.transcript.grind_pow(pow_bits)
    }

    /// Access inner transcript reference
    pub fn transcript(&self) -> &Transcript {
        &self.transcript
    }

    /// Access mutable transcript reference
    pub fn transcript_mut(&mut self) -> &mut Transcript {
        &mut self.transcript
    }
}

/// Bitcoin Script Gadget for Stwo Fiat-Shamir channel transitions
pub struct StwoChannelScript;

impl StwoChannelScript {
    /// Emits script that verifies state transition from state_k to state_{k+1}
    /// after absorbing a 32-byte commitment (e.g. tree root):
    /// Input Stack: `[commitment (32B)]`
    /// Output Stack: `[TRUE]`
    pub fn emit_mix_digest_verifier(
        builder: &mut ScriptBuilder,
        prev_state: &[u8; 32],
        expected_next_state: &[u8; 32],
    ) {
        // Stack top: [commitment_32B]
        builder.push_slice(prev_state);
        builder.op_swap();
        builder.op_cat();
        builder.op_sha256(); // leaves computed next_state
        builder.push_slice(expected_next_state);
        builder.op_equalverify();
        builder.push_int(1);
    }
}
