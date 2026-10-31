use crate::builder::ScriptBuilder;
use sha2::{Digest, Sha256};

/// Winternitz One-Time Signature (W-OTS with w=16 / 4-bit nibbles)
/// Provides compact, quantum-resistant one-time signatures verifiable in Bitcoin Tapscript with OP_CAT.
pub const WOTS_W: usize = 16;
pub const WOTS_NIBBLES: usize = 64; // 256 bits / 4 bits
pub const WOTS_CHECKSUM_NIBBLES: usize = 3; // sum <= 64 * 15 = 960 < 16^3 = 4096
pub const WOTS_TOTAL_NIBBLES: usize = WOTS_NIBBLES + WOTS_CHECKSUM_NIBBLES; // 67

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WotsPrivateKey {
    pub seeds: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WotsPublicKey {
    pub public_keys: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WotsSignature {
    pub signatures: Vec<[u8; 32]>,
}

pub struct WinternitzOTS;

impl WinternitzOTS {
    fn hash_chain(seed: &[u8; 32], times: usize) -> [u8; 32] {
        let mut curr = *seed;
        for _ in 0..times {
            let hash = Sha256::digest(&curr);
            curr.copy_from_slice(&hash);
        }
        curr
    }

    /// Generates a deterministic keypair from a 32-byte master seed
    pub fn keygen(master_seed: &[u8; 32]) -> (WotsPrivateKey, WotsPublicKey) {
        let mut seeds = Vec::with_capacity(WOTS_TOTAL_NIBBLES);
        let mut public_keys = Vec::with_capacity(WOTS_TOTAL_NIBBLES);

        for i in 0..WOTS_TOTAL_NIBBLES {
            let mut hasher = Sha256::new();
            hasher.update(master_seed);
            hasher.update(&(i as u32).to_le_bytes());
            let seed: [u8; 32] = hasher.finalize().into();

            let pk = Self::hash_chain(&seed, WOTS_W - 1); // 15 hashes
            seeds.push(seed);
            public_keys.push(pk);
        }

        (WotsPrivateKey { seeds }, WotsPublicKey { public_keys })
    }

    /// Decomposes 32-byte message into 64 nibbles + 3 checksum nibbles
    pub fn message_to_nibbles(message: &[u8; 32]) -> Vec<u8> {
        let mut nibbles = Vec::with_capacity(WOTS_TOTAL_NIBBLES);
        let mut checksum = 0usize;

        for byte in message {
            let lo = byte & 0x0f;
            let hi = (byte >> 4) & 0x0f;
            nibbles.push(hi);
            nibbles.push(lo);
            checksum += (WOTS_W - 1 - hi as usize) + (WOTS_W - 1 - lo as usize);
        }

        // 3 checksum nibbles
        nibbles.push(((checksum >> 8) & 0x0f) as u8);
        nibbles.push(((checksum >> 4) & 0x0f) as u8);
        nibbles.push((checksum & 0x0f) as u8);

        nibbles
    }

    /// Signs a 32-byte message using Winternitz OTS
    pub fn sign(sk: &WotsPrivateKey, message: &[u8; 32]) -> WotsSignature {
        let nibbles = Self::message_to_nibbles(message);
        let mut signatures = Vec::with_capacity(WOTS_TOTAL_NIBBLES);

        for (i, &nibble) in nibbles.iter().enumerate() {
            let sig_i = Self::hash_chain(&sk.seeds[i], nibble as usize);
            signatures.push(sig_i);
        }

        WotsSignature { signatures }
    }

    /// Verifies signature in native Rust
    pub fn verify(pk: &WotsPublicKey, message: &[u8; 32], sig: &WotsSignature) -> bool {
        let nibbles = Self::message_to_nibbles(message);
        if sig.signatures.len() != WOTS_TOTAL_NIBBLES || pk.public_keys.len() != WOTS_TOTAL_NIBBLES {
            return false;
        }

        for (i, &nibble) in nibbles.iter().enumerate() {
            let remaining_hashes = WOTS_W - 1 - (nibble as usize);
            let expected_pk = Self::hash_chain(&sig.signatures[i], remaining_hashes);
            if expected_pk != pk.public_keys[i] {
                return false;
            }
        }
        true
    }

    /// Emits a compact Tapscript verifier for a committed Winternitz signature chunk.
    /// Stack layout: `[sig_i]`
    /// Script applies `(15 - digit)` OP_SHA256 operations and asserts equal to `pk[i]`.
    pub fn emit_digit_verifier(
        builder: &mut ScriptBuilder,
        digit: u8,
        expected_pk: &[u8; 32],
    ) {
        let remaining_hashes = (WOTS_W - 1) - (digit as usize);
        for _ in 0..remaining_hashes {
            builder.op_sha256();
        }
        builder.push_slice(expected_pk);
        builder.op_equalverify();
    }

    /// Emits Bitcoin Script that validates a full or sliced W-OTS message verification.
    /// Stack layout: `[sig_0, sig_1, ..., sig_{K-1}]` (sig_0 at bottom, sig_{K-1} on top)
    pub fn emit_verifier(
        builder: &mut ScriptBuilder,
        pk: &WotsPublicKey,
        message: &[u8; 32],
        digit_count: usize,
    ) {
        let nibbles = Self::message_to_nibbles(message);
        let count = digit_count.min(WOTS_TOTAL_NIBBLES);

        // Process from top of stack (last digit) down to bottom
        for i in (0..count).rev() {
            Self::emit_digit_verifier(builder, nibbles[i], &pk.public_keys[i]);
        }
        builder.push_int(1); // leaves TRUE
    }

    /// Prepares witness for W-OTS verification
    pub fn create_witness(sig: &WotsSignature, digit_count: usize) -> Vec<Vec<u8>> {
        let count = digit_count.min(sig.signatures.len());
        sig.signatures[..count].iter().map(|s| s.to_vec()).collect()
    }
}

/// Lamport One-Time Signature for arbitrary bit strings
pub struct LamportOTS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LamportPrivateKey {
    pub pairs: Vec<([u8; 32], [u8; 32])>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LamportPublicKey {
    pub pairs: Vec<([u8; 32], [u8; 32])>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LamportSignature {
    pub preimages: Vec<[u8; 32]>,
}

impl LamportOTS {
    pub fn keygen(master_seed: &[u8; 32], bit_count: usize) -> (LamportPrivateKey, LamportPublicKey) {
        let mut priv_pairs = Vec::with_capacity(bit_count);
        let mut pub_pairs = Vec::with_capacity(bit_count);

        for i in 0..bit_count {
            let mut hasher0 = Sha256::new();
            hasher0.update(master_seed);
            hasher0.update(&(i as u32).to_le_bytes());
            hasher0.update(b"0");
            let sk0: [u8; 32] = hasher0.finalize().into();

            let mut hasher1 = Sha256::new();
            hasher1.update(master_seed);
            hasher1.update(&(i as u32).to_le_bytes());
            hasher1.update(b"1");
            let sk1: [u8; 32] = hasher1.finalize().into();

            let pk0: [u8; 32] = Sha256::digest(&sk0).into();
            let pk1: [u8; 32] = Sha256::digest(&sk1).into();

            priv_pairs.push((sk0, sk1));
            pub_pairs.push((pk0, pk1));
        }

        (LamportPrivateKey { pairs: priv_pairs }, LamportPublicKey { pairs: pub_pairs })
    }

    pub fn sign(sk: &LamportPrivateKey, bits: &[bool]) -> LamportSignature {
        assert_eq!(sk.pairs.len(), bits.len());
        let mut preimages = Vec::with_capacity(bits.len());

        for (i, &bit) in bits.iter().enumerate() {
            let preimage = if bit { sk.pairs[i].1 } else { sk.pairs[i].0 };
            preimages.push(preimage);
        }

        LamportSignature { preimages }
    }

    /// Emits Script to verify Lamport signature preimages
    pub fn emit_verifier(builder: &mut ScriptBuilder, pk: &LamportPublicKey, bits: &[bool]) {
        for i in (0..bits.len()).rev() {
            let expected_pk = if bits[i] { pk.pairs[i].1 } else { pk.pairs[i].0 };
            builder.op_sha256();
            builder.push_slice(&expected_pk);
            builder.op_equalverify();
        }
        builder.push_int(1);
    }
}

/// Winternitz OTS for 31-bit Mersenne-31 (M31) state commitments.
/// Used in Mainnet BitVM Emulation mode to commit to intermediate trace / FRI
/// evaluations across transactions WITHOUT OP_CAT!
pub const WOTS_M31_NIBBLES: usize = 8;
pub const WOTS_M31_CHECKSUM_NIBBLES: usize = 2; // max sum = 8 * 15 = 120 < 256
pub const WOTS_M31_TOTAL: usize = WOTS_M31_NIBBLES + WOTS_M31_CHECKSUM_NIBBLES; // 10

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WotsM31PrivateKey {
    pub seeds: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WotsM31PublicKey {
    pub public_keys: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WotsM31Signature {
    pub preimages: Vec<[u8; 32]>,
}

pub struct WotsM31Commitment;

impl WotsM31Commitment {
    /// Generates keypair for a 31-bit M31 state commitment (10 chains of length 16)
    pub fn keygen(master_seed: &[u8; 32], commitment_tag: &[u8]) -> (WotsM31PrivateKey, WotsM31PublicKey) {
        let mut seeds = Vec::with_capacity(WOTS_M31_TOTAL);
        let mut public_keys = Vec::with_capacity(WOTS_M31_TOTAL);

        for i in 0..WOTS_M31_TOTAL {
            let mut hasher = Sha256::new();
            hasher.update(master_seed);
            hasher.update(commitment_tag);
            hasher.update(&(i as u32).to_le_bytes());
            let seed: [u8; 32] = hasher.finalize().into();

            let pk = WinternitzOTS::hash_chain(&seed, WOTS_W - 1);
            seeds.push(seed);
            public_keys.push(pk);
        }

        (WotsM31PrivateKey { seeds }, WotsM31PublicKey { public_keys })
    }

    /// Converts a 31-bit value into 8 data nibbles + 2 checksum nibbles
    pub fn value_to_nibbles(val: u32) -> Vec<u8> {
        let mut nibbles = Vec::with_capacity(WOTS_M31_TOTAL);
        let mut checksum = 0usize;

        let bytes = val.to_le_bytes();
        for &byte in &bytes {
            let lo = byte & 0x0f;
            let hi = (byte >> 4) & 0x0f;
            nibbles.push(hi);
            nibbles.push(lo);
            checksum += (WOTS_W - 1 - hi as usize) + (WOTS_W - 1 - lo as usize);
        }

        // 2 checksum nibbles
        nibbles.push(((checksum >> 4) & 0x0f) as u8);
        nibbles.push((checksum & 0x0f) as u8);

        nibbles
    }

    /// Signs an M31 value
    pub fn sign(sk: &WotsM31PrivateKey, val: u32) -> WotsM31Signature {
        let nibbles = Self::value_to_nibbles(val);
        let mut preimages = Vec::with_capacity(WOTS_M31_TOTAL);

        for (i, &nibble) in nibbles.iter().enumerate() {
            let sig_i = WinternitzOTS::hash_chain(&sk.seeds[i], nibble as usize);
            preimages.push(sig_i);
        }

        WotsM31Signature { preimages }
    }

    /// Verifies signature in Rust
    pub fn verify(pk: &WotsM31PublicKey, val: u32, sig: &WotsM31Signature) -> bool {
        if sig.preimages.len() != WOTS_M31_TOTAL || pk.public_keys.len() != WOTS_M31_TOTAL {
            return false;
        }
        let nibbles = Self::value_to_nibbles(val);

        for (i, &nibble) in nibbles.iter().enumerate() {
            let remaining = WOTS_W - 1 - (nibble as usize);
            let expected_pk = WinternitzOTS::hash_chain(&sig.preimages[i], remaining);
            if expected_pk != pk.public_keys[i] {
                return false;
            }
        }
        true
    }

    /// Emits OP_CAT-free Bitcoin Script to verify an M31 state commitment.
    /// Operates purely with standard OP_SHA256 and OP_EQUALVERIFY.
    /// Stack layout: `[sig_0, sig_1, ..., sig_9]` (sig_9 on top)
    pub fn emit_verifier(builder: &mut ScriptBuilder, pk: &WotsM31PublicKey, val: u32) {
        let nibbles = Self::value_to_nibbles(val);
        for i in (0..WOTS_M31_TOTAL).rev() {
            let remaining = WOTS_W - 1 - (nibbles[i] as usize);
            for _ in 0..remaining {
                builder.op_sha256();
            }
            builder.push_slice(&pk.public_keys[i]);
            builder.op_equalverify();
        }
        builder.push_int(1);
    }

    /// Witness vector for M31 W-OTS verification
    pub fn create_witness(sig: &WotsM31Signature) -> Vec<Vec<u8>> {
        sig.preimages.iter().map(|s| s.to_vec()).collect()
    }
}

/// Winternitz OTS for 124-bit QM31 Quartic Extension Field state commitments.
/// Consists of 4 M31 commitments (32 data nibbles + 3 checksum nibbles = 35 total).
pub const WOTS_QM31_NIBBLES: usize = 32;
pub const WOTS_QM31_CHECKSUM_NIBBLES: usize = 3; // max sum = 32 * 15 = 480 < 4096
pub const WOTS_QM31_TOTAL: usize = WOTS_QM31_NIBBLES + WOTS_QM31_CHECKSUM_NIBBLES; // 35

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WotsQm31PrivateKey {
    pub seeds: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WotsQm31PublicKey {
    pub public_keys: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WotsQm31Signature {
    pub preimages: Vec<[u8; 32]>,
}

pub struct WotsQm31Commitment;

impl WotsQm31Commitment {
    pub fn keygen(master_seed: &[u8; 32], commitment_tag: &[u8]) -> (WotsQm31PrivateKey, WotsQm31PublicKey) {
        let mut seeds = Vec::with_capacity(WOTS_QM31_TOTAL);
        let mut public_keys = Vec::with_capacity(WOTS_QM31_TOTAL);

        for i in 0..WOTS_QM31_TOTAL {
            let mut hasher = Sha256::new();
            hasher.update(master_seed);
            hasher.update(commitment_tag);
            hasher.update(b"QM31");
            hasher.update(&(i as u32).to_le_bytes());
            let seed: [u8; 32] = hasher.finalize().into();

            let pk = WinternitzOTS::hash_chain(&seed, WOTS_W - 1);
            seeds.push(seed);
            public_keys.push(pk);
        }

        (WotsQm31PrivateKey { seeds }, WotsQm31PublicKey { public_keys })
    }

    pub fn value_to_nibbles(components: [u32; 4]) -> Vec<u8> {
        let mut nibbles = Vec::with_capacity(WOTS_QM31_TOTAL);
        let mut checksum = 0usize;

        for val in components {
            for &byte in &val.to_le_bytes() {
                let lo = byte & 0x0f;
                let hi = (byte >> 4) & 0x0f;
                nibbles.push(hi);
                nibbles.push(lo);
                checksum += (WOTS_W - 1 - hi as usize) + (WOTS_W - 1 - lo as usize);
            }
        }

        // 3 checksum nibbles
        nibbles.push(((checksum >> 8) & 0x0f) as u8);
        nibbles.push(((checksum >> 4) & 0x0f) as u8);
        nibbles.push((checksum & 0x0f) as u8);

        nibbles
    }

    pub fn sign(sk: &WotsQm31PrivateKey, components: [u32; 4]) -> WotsQm31Signature {
        let nibbles = Self::value_to_nibbles(components);
        let mut preimages = Vec::with_capacity(WOTS_QM31_TOTAL);

        for (i, &nibble) in nibbles.iter().enumerate() {
            let sig_i = WinternitzOTS::hash_chain(&sk.seeds[i], nibble as usize);
            preimages.push(sig_i);
        }

        WotsQm31Signature { preimages }
    }

    pub fn verify(pk: &WotsQm31PublicKey, components: [u32; 4], sig: &WotsQm31Signature) -> bool {
        if sig.preimages.len() != WOTS_QM31_TOTAL || pk.public_keys.len() != WOTS_QM31_TOTAL {
            return false;
        }
        let nibbles = Self::value_to_nibbles(components);

        for (i, &nibble) in nibbles.iter().enumerate() {
            let remaining = WOTS_W - 1 - (nibble as usize);
            let expected_pk = WinternitzOTS::hash_chain(&sig.preimages[i], remaining);
            if expected_pk != pk.public_keys[i] {
                return false;
            }
        }
        true
    }

    pub fn emit_verifier(builder: &mut ScriptBuilder, pk: &WotsQm31PublicKey, components: [u32; 4]) {
        let nibbles = Self::value_to_nibbles(components);
        for i in (0..WOTS_QM31_TOTAL).rev() {
            let remaining = WOTS_W - 1 - (nibbles[i] as usize);
            for _ in 0..remaining {
                builder.op_sha256();
            }
            builder.push_slice(&pk.public_keys[i]);
            builder.op_equalverify();
        }
        builder.push_int(1);
    }

    pub fn create_witness(sig: &WotsQm31Signature) -> Vec<Vec<u8>> {
        sig.preimages.iter().map(|s| s.to_vec()).collect()
    }
}

/// Fraud proof for detecting operator equivocation (signing two different M31 values)
#[derive(Debug, Clone)]
pub struct EquivocationProof {
    pub nibble_index: usize,
    pub val_a: u32,
    pub val_b: u32,
    pub sig_a_nibble: [u8; 32],
    pub sig_b_nibble: [u8; 32],
}

impl EquivocationProof {
    /// Detects if an operator equivocated by signing two contradictory values
    pub fn detect(
        val_a: u32,
        sig_a: &WotsM31Signature,
        val_b: u32,
        sig_b: &WotsM31Signature,
    ) -> Option<Self> {
        if val_a == val_b {
            return None;
        }
        let nibbles_a = WotsM31Commitment::value_to_nibbles(val_a);
        let nibbles_b = WotsM31Commitment::value_to_nibbles(val_b);

        for i in 0..WOTS_M31_TOTAL {
            if nibbles_a[i] != nibbles_b[i] {
                return Some(Self {
                    nibble_index: i,
                    val_a,
                    val_b,
                    sig_a_nibble: sig_a.preimages[i],
                    sig_b_nibble: sig_b.preimages[i],
                });
            }
        }
        None
    }

    /// Emits script that verifies contradictory signatures for the same key chain,
    /// proving operator fraud and slashing their bond.
    pub fn emit_slasher(builder: &mut ScriptBuilder, expected_pk_chain: &[u8; 32], nibble_a: u8, nibble_b: u8) {
        assert_ne!(nibble_a, nibble_b);

        // Stack: [sig_b_nibble, sig_a_nibble]
        // 1. Verify sig_a hashes to expected_pk
        let rem_a = WOTS_W - 1 - (nibble_a as usize);
        for _ in 0..rem_a {
            builder.op_sha256();
        }
        builder.push_slice(expected_pk_chain);
        builder.op_equalverify();

        // 2. Verify sig_b hashes to expected_pk
        let rem_b = WOTS_W - 1 - (nibble_b as usize);
        for _ in 0..rem_b {
            builder.op_sha256();
        }
        builder.push_slice(expected_pk_chain);
        builder.op_equalverify();

        // Prover signed two distinct preimages for the same public key chain!
        builder.push_int(1);
    }
}

/// Chained State Transition Commitment for BitVM dispute games.
/// Binds consecutive state representations (S_t, S_{t+1}) using two Winternitz OTS keys,
/// enabling trustless on-chain dispute refereeing on Bitcoin mainnet without OP_CAT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WotsStateTransitionCommitment {
    pub pre_pk: WotsM31PublicKey,
    pub post_pk: WotsM31PublicKey,
    pub step_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WotsStateTransitionSignature {
    pub pre_sig: WotsM31Signature,
    pub post_sig: WotsM31Signature,
}

impl WotsStateTransitionCommitment {
    /// Generates keypair for a contiguous state transition (pre_state -> post_state)
    pub fn keygen(
        master_seed: &[u8; 32],
        step_index: u32,
    ) -> (
        (WotsM31PrivateKey, WotsM31PrivateKey),
        Self,
    ) {
        let tag_pre = format!("STATE_TRANSITION_{}_PRE", step_index);
        let tag_post = format!("STATE_TRANSITION_{}_POST", step_index);
        let (sk_pre, pk_pre) = WotsM31Commitment::keygen(master_seed, tag_pre.as_bytes());
        let (sk_post, pk_post) = WotsM31Commitment::keygen(master_seed, tag_post.as_bytes());

        (
            (sk_pre, sk_post),
            Self {
                pre_pk: pk_pre,
                post_pk: pk_post,
                step_index,
            },
        )
    }

    /// Signs both pre-state and post-state to commit to a step transition
    pub fn sign(
        sks: &(WotsM31PrivateKey, WotsM31PrivateKey),
        pre_val: u32,
        post_val: u32,
    ) -> WotsStateTransitionSignature {
        let pre_sig = WotsM31Commitment::sign(&sks.0, pre_val);
        let post_sig = WotsM31Commitment::sign(&sks.1, post_val);
        WotsStateTransitionSignature { pre_sig, post_sig }
    }

    /// Verifies that both pre-state and post-state commitments are authentic
    pub fn verify(
        &self,
        pre_val: u32,
        post_val: u32,
        sig: &WotsStateTransitionSignature,
    ) -> bool {
        WotsM31Commitment::verify(&self.pre_pk, pre_val, &sig.pre_sig)
            && WotsM31Commitment::verify(&self.post_pk, post_val, &sig.post_sig)
    }

    /// Emits script that verifies both pre and post commitments on Bitcoin Script
    pub fn emit_verifier(
        builder: &mut ScriptBuilder,
        pk: &WotsStateTransitionCommitment,
        pre_val: u32,
        post_val: u32,
    ) {
        // Stack layout on entry: `[post_sig_items..., pre_sig_items...]`
        WotsM31Commitment::emit_verifier(builder, &pk.pre_pk, pre_val);
        builder.op_verify();
        WotsM31Commitment::emit_verifier(builder, &pk.post_pk, post_val);
    }

    /// Creates combined witness for the state transition verification script
    pub fn create_witness(sig: &WotsStateTransitionSignature) -> Vec<Vec<u8>> {
        let mut witness = WotsM31Commitment::create_witness(&sig.post_sig);
        let pre_witness = WotsM31Commitment::create_witness(&sig.pre_sig);
        witness.extend(pre_witness);
        witness
    }
}

