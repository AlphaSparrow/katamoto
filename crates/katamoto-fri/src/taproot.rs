use sha2::{Digest, Sha256};

pub const TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;

/// Standard BIP-340 / BIP-341 Tagged Hash:
/// TaggedHash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Taproot Script Leaf (BIP-342)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapLeaf {
    pub name: String,
    pub script: Vec<u8>,
    pub version: u8,
}

impl TapLeaf {
    pub fn new(name: impl Into<String>, script: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            script,
            version: TAPSCRIPT_LEAF_VERSION,
        }
    }

    /// Computes BIP-341 TapLeaf hash:
    /// TapLeafHash = TaggedHash("TapLeaf", version || compact_size(len) || script)
    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        buf.push(self.version);
        // Compact size encoding for script length
        let len = self.script.len();
        if len < 0xfd {
            buf.push(len as u8);
        } else if len <= 0xffff {
            buf.push(0xfd);
            buf.extend_from_slice(&(len as u16).to_le_bytes());
        } else {
            buf.push(0xfe);
            buf.extend_from_slice(&(len as u32).to_le_bytes());
        }
        buf.extend_from_slice(&self.script);
        tagged_hash("TapLeaf", &buf)
    }
}

/// Taproot Script Tree compiling multiple STARK verification leaves (BIP-341)
#[derive(Debug, Clone)]
pub struct TapTree {
    pub leaves: Vec<TapLeaf>,
    leaf_hashes: Vec<[u8; 32]>,
}

impl TapTree {
    pub fn new(leaves: Vec<TapLeaf>) -> Self {
        assert!(!leaves.is_empty(), "TapTree must have at least one leaf");
        let leaf_hashes = leaves.iter().map(|l| l.leaf_hash()).collect();
        Self { leaves, leaf_hashes }
    }

    /// Computes the TapBranch hash of two child nodes with lexicographical ordering:
    /// TapBranch = TaggedHash("TapBranch", min(left, right) || max(left, right))
    pub fn branch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut buf = [0u8; 64];
        if a <= b {
            buf[0..32].copy_from_slice(a);
            buf[32..64].copy_from_slice(b);
        } else {
            buf[0..32].copy_from_slice(b);
            buf[32..64].copy_from_slice(a);
        }
        tagged_hash("TapBranch", &buf)
    }

    /// Computes the overall TapTree Merkle root
    pub fn root(&self) -> [u8; 32] {
        if self.leaf_hashes.len() == 1 {
            return self.leaf_hashes[0];
        }

        let mut current = self.leaf_hashes.clone();
        while current.len() > 1 {
            let mut next = Vec::with_capacity((current.len() + 1) / 2);
            for chunk in current.chunks(2) {
                if chunk.len() == 2 {
                    next.push(Self::branch_hash(&chunk[0], &chunk[1]));
                } else {
                    next.push(chunk[0]);
                }
            }
            current = next;
        }
        current[0]
    }

    /// Generates the BIP-341 Control Block for a given leaf index:
    /// ControlBlock = (version & 0xfe) | output_key_parity || internal_key (32B) || sibling_hashes...
    pub fn control_block(&self, leaf_index: usize, internal_key: &[u8; 32]) -> Vec<u8> {
        let leaf = &self.leaves[leaf_index];
        let mut ctrl = Vec::new();
        // Version (bit 0 indicates parity of output pubkey, default 0 for simulated NUMS point)
        ctrl.push(leaf.version);
        ctrl.extend_from_slice(internal_key);

        // Compute sibling path
        if self.leaf_hashes.len() > 1 {
            let mut idx = leaf_index;
            let mut current = self.leaf_hashes.clone();

            while current.len() > 1 {
                let is_odd = (idx % 2) == 1;
                let sibling_idx = if is_odd { idx - 1 } else { idx + 1 };
                if sibling_idx < current.len() {
                    ctrl.extend_from_slice(&current[sibling_idx]);
                }

                let mut next = Vec::with_capacity((current.len() + 1) / 2);
                for chunk in current.chunks(2) {
                    if chunk.len() == 2 {
                        next.push(Self::branch_hash(&chunk[0], &chunk[1]));
                    } else {
                        next.push(chunk[0]);
                    }
                }
                current = next;
                idx /= 2;
            }
        }

        ctrl
    }

    /// Computes the BIP-341 TapTweak:
    /// t = TaggedHash("TapTweak", internal_key || tap_tree_root)
    pub fn tweak(&self, internal_key: &[u8; 32]) -> [u8; 32] {
        let root = self.root();
        let mut data = [0u8; 64];
        data[0..32].copy_from_slice(internal_key);
        data[32..64].copy_from_slice(&root);
        tagged_hash("TapTweak", &data)
    }
}

/// Complete Bitcoin L1 Taproot Spend Package for a STARK Leaf
#[derive(Debug, Clone)]
pub struct TaprootStarkSpend {
    pub leaf_name: String,
    pub witness_items: Vec<Vec<u8>>,
    pub leaf_script: Vec<u8>,
    pub control_block: Vec<u8>,
}

impl TaprootStarkSpend {
    pub fn new(
        leaf_name: impl Into<String>,
        witness_items: Vec<Vec<u8>>,
        leaf_script: Vec<u8>,
        control_block: Vec<u8>,
    ) -> Self {
        Self {
            leaf_name: leaf_name.into(),
            witness_items,
            leaf_script,
            control_block,
        }
    }

    /// Full Bitcoin witness stack for spending this Taproot leaf:
    /// `[witness_item_0, witness_item_1, ..., leaf_script, control_block]`
    pub fn full_witness_stack(&self) -> Vec<Vec<u8>> {
        let mut stack = self.witness_items.clone();
        stack.push(self.leaf_script.clone());
        stack.push(self.control_block.clone());
        stack
    }

    /// Total witness weight in witness bytes
    pub fn total_witness_size(&self) -> usize {
        self.full_witness_stack().iter().map(|item| item.len()).sum()
    }

    /// Builds a full signed/witnessed Bitcoin transaction spending this Taproot leaf
    pub fn build_spending_tx(
        &self,
        funding_outpoint: katamoto_script::OutPoint,
        destination_script_pubkey: Vec<u8>,
        output_satoshis: u64,
    ) -> katamoto_script::Transaction {
        let input = katamoto_script::TxIn::new_taproot(funding_outpoint);
        let output = katamoto_script::TxOut::new(output_satoshis, destination_script_pubkey);
        let witness = katamoto_script::Witness::new(self.full_witness_stack());
        katamoto_script::Transaction::new(2, vec![input], vec![output], vec![witness])
    }
}
