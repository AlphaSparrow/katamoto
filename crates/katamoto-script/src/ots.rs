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
        for (i, &bit) in bits.iter().enumerate().rev() {
            let expected_pk = if bit { pk.pairs[i].1 } else { pk.pairs[i].0 };
            builder.op_sha256();
            builder.push_slice(&expected_pk);
            builder.op_equalverify();
        }
        builder.push_int(1);
    }
}
