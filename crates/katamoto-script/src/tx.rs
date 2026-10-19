use crate::builder::ScriptBuilder;
use crate::vm::{MAX_ELEMENT_SIZE, MAX_STACK_SIZE};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Maximum standard transaction weight (BIP-141)
pub const MAX_STANDARD_TX_WEIGHT: usize = 400_000;

/// Standard sequence number enabling locktime disable
pub const SEQUENCE_FINAL: u32 = 0xffff_ffff;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ConsensusError {
    #[error("Witness stack element exceeds maximum size of {MAX_ELEMENT_SIZE} bytes (got {0})")]
    WitnessElementTooLarge(usize),
    #[error("Witness stack items count exceeds maximum of {MAX_STACK_SIZE} (got {0})")]
    WitnessStackOverflow(usize),
    #[error("Transaction weight exceeds standard maximum of {MAX_STANDARD_TX_WEIGHT} WU (got {0})")]
    TxWeightTooLarge(usize),
    #[error("Transaction must contain at least one input and one output")]
    EmptyTx,
    #[error("Witness count ({0}) does not match input count ({1})")]
    WitnessInputMismatch(usize, usize),
}

/// OutPoint referencing a specific UTXO (txid + vout index)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

impl OutPoint {
    pub fn new(txid: [u8; 32], vout: u32) -> Self {
        Self { txid, vout }
    }

    pub fn from_hex(txid_hex: &str, vout: u32) -> Result<Self, hex::FromHexError> {
        let mut raw = hex::decode(txid_hex)?;
        // Bitcoin txids are displayed in reverse (big-endian) byte order
        raw.reverse();
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&raw);
        Ok(Self { txid, vout })
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.txid);
        buf.extend_from_slice(&self.vout.to_le_bytes());
    }
}

/// Transaction input
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    pub previous_output: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

impl TxIn {
    pub fn new_taproot(previous_output: OutPoint) -> Self {
        Self {
            previous_output,
            script_sig: Vec::new(), // Taproot spends have empty scriptSig
            sequence: SEQUENCE_FINAL,
        }
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        self.previous_output.serialize(buf);
        write_varint(buf, self.script_sig.len() as u64);
        buf.extend_from_slice(&self.script_sig);
        buf.extend_from_slice(&self.sequence.to_le_bytes());
    }
}

/// Transaction output
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64, // Satoshis
    pub script_pubkey: Vec<u8>,
}

impl TxOut {
    pub fn new(value: u64, script_pubkey: Vec<u8>) -> Self {
        Self { value, script_pubkey }
    }

    /// Creates a P2TR (Pay-to-Taproot, BIP-341) output: OP_1 (0x51) PUSH32 (0x20) <32-byte output_key>
    pub fn p2tr(output_key: &[u8; 32], satoshis: u64) -> Self {
        let mut spk = Vec::with_capacity(34);
        spk.push(0x51); // OP_1 (witness v1)
        spk.push(0x20); // 32 bytes push
        spk.extend_from_slice(output_key);
        Self {
            value: satoshis,
            script_pubkey: spk,
        }
    }

    /// Creates an OP_RETURN data carrier output: OP_RETURN (0x6a) <push data>
    pub fn op_return(data: &[u8], satoshis: u64) -> Self {
        let mut spk = Vec::with_capacity(data.len() + 2);
        spk.push(0x6a); // OP_RETURN
        if data.len() < 76 {
            spk.push(data.len() as u8);
        } else {
            spk.push(0x4c);
            spk.push(data.len() as u8);
        }
        spk.extend_from_slice(data);
        Self {
            value: satoshis,
            script_pubkey: spk,
        }
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.value.to_le_bytes());
        write_varint(buf, self.script_pubkey.len() as u64);
        buf.extend_from_slice(&self.script_pubkey);
    }
}

/// Bitcoin Witness for an input (list of stack element byte buffers)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Witness {
    pub items: Vec<Vec<u8>>,
}

impl Witness {
    pub fn new(items: Vec<Vec<u8>>) -> Self {
        Self { items }
    }

    pub fn push(&mut self, item: Vec<u8>) {
        self.items.push(item);
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        write_varint(buf, self.items.len() as u64);
        for item in &self.items {
            write_varint(buf, item.len() as u64);
            buf.extend_from_slice(item);
        }
    }
}

/// Bitcoin Transaction (BIP-141 / BIP-341 Segregated Witness + Taproot v1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub witnesses: Vec<Witness>,
    pub lock_time: u32,
}

impl Transaction {
    pub fn new(version: i32, inputs: Vec<TxIn>, outputs: Vec<TxOut>, witnesses: Vec<Witness>) -> Self {
        Self {
            version,
            inputs,
            outputs,
            witnesses,
            lock_time: 0,
        }
    }

    pub fn has_witness(&self) -> bool {
        self.witnesses.iter().any(|w| !w.is_empty())
    }

    /// Serializes transaction into Bitcoin wire format
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.version.to_le_bytes());

        let has_wit = self.has_witness();
        if has_wit {
            buf.push(0x00); // Segwit marker
            buf.push(0x01); // Segwit flag
        }

        // Inputs
        write_varint(&mut buf, self.inputs.len() as u64);
        for input in &self.inputs {
            input.serialize(&mut buf);
        }

        // Outputs
        write_varint(&mut buf, self.outputs.len() as u64);
        for output in &self.outputs {
            output.serialize(&mut buf);
        }

        // Witnesses (if segwit)
        if has_wit {
            for wit in &self.witnesses {
                wit.serialize(&mut buf);
            }
        }

        // Lock time
        buf.extend_from_slice(&self.lock_time.to_le_bytes());
        buf
    }

    /// Serializes legacy transaction without witness (for TXID calculation)
    pub fn serialize_legacy(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.version.to_le_bytes());

        write_varint(&mut buf, self.inputs.len() as u64);
        for input in &self.inputs {
            input.serialize(&mut buf);
        }

        write_varint(&mut buf, self.outputs.len() as u64);
        for output in &self.outputs {
            output.serialize(&mut buf);
        }

        buf.extend_from_slice(&self.lock_time.to_le_bytes());
        buf
    }

    /// Computes TXID: SHA256(SHA256(serialize_legacy)) in display (reverse) order
    pub fn txid(&self) -> String {
        let legacy = self.serialize_legacy();
        let hash = double_sha256(&legacy);
        let mut rev = hash;
        rev.reverse();
        hex::encode(rev)
    }

    /// Computes WTXID: SHA256(SHA256(serialize)) in display (reverse) order
    pub fn wtxid(&self) -> String {
        let serialized = self.serialize();
        let hash = double_sha256(&serialized);
        let mut rev = hash;
        rev.reverse();
        hex::encode(rev)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.serialize())
    }

    /// Computes transaction weight in Weight Units (WU) according to BIP-141
    pub fn weight(&self) -> usize {
        let base_size = self.serialize_legacy().len();
        let total_size = self.serialize().len();
        (base_size * 3) + total_size
    }

    /// Computes virtual transaction size (vsize / vB)
    pub fn vsize(&self) -> usize {
        (self.weight() + 3) / 4
    }

    /// Validates Bitcoin consensus rules for Tapscript execution:
    /// - Witness items cannot exceed 520 bytes (MAX_ELEMENT_SIZE)
    /// - Witness stack depth cannot exceed 1000 items (MAX_STACK_SIZE)
    /// - Total transaction weight must be <= 400,000 WU
    pub fn validate_consensus_limits(&self) -> Result<(), ConsensusError> {
        if self.inputs.is_empty() || self.outputs.is_empty() {
            return Err(ConsensusError::EmptyTx);
        }

        if !self.witnesses.is_empty() && self.witnesses.len() != self.inputs.len() {
            return Err(ConsensusError::WitnessInputMismatch(
                self.witnesses.len(),
                self.inputs.len(),
            ));
        }

        for wit in &self.witnesses {
            if wit.len() > MAX_STACK_SIZE {
                return Err(ConsensusError::WitnessStackOverflow(wit.len()));
            }
            for item in &wit.items {
                if item.len() > MAX_ELEMENT_SIZE {
                    return Err(ConsensusError::WitnessElementTooLarge(item.len()));
                }
            }
        }

        let weight = self.weight();
        if weight > MAX_STANDARD_TX_WEIGHT {
            return Err(ConsensusError::TxWeightTooLarge(weight));
        }

        Ok(())
    }

    /// Computes BIP-341 sighash preimage for a given input
    pub fn build_sighash_preimage(&self, input_index: usize, prevouts: &[TxOut]) -> TaprootSighashPreimage {
        let sha_prevouts = compute_sha_prevouts(&self.inputs);
        let amounts: Vec<u64> = prevouts.iter().map(|p| p.value).collect();
        let sha_amounts = compute_sha_amounts(&amounts);
        let spks: Vec<Vec<u8>> = prevouts.iter().map(|p| p.script_pubkey.clone()).collect();
        let sha_scriptpubkeys = compute_sha_scriptpubkeys(&spks);
        let sha_sequences = compute_sha_sequences(&self.inputs);
        let sha_outputs = compute_sha_outputs(&self.outputs);

        TaprootSighashPreimage {
            epoch: 0x00,
            hash_type: 0x00,
            version: (self.version as u32).to_le_bytes(),
            lock_time: self.lock_time.to_le_bytes(),
            sha_prevouts,
            sha_amounts,
            sha_scriptpubkeys,
            sha_sequences,
            sha_outputs,
            spend_type: 0x02, // Script path spend
            input_index: (input_index as u32).to_le_bytes(),
        }
    }

    /// Computes BIP-341 Taproot Sighash for spending an input
    pub fn taproot_sighash(&self, input_index: usize, prevouts: &[TxOut]) -> [u8; 32] {
        let preimage = self.build_sighash_preimage(input_index, prevouts);
        preimage.compute_sighash()
    }
}

/// Bitcoin Variable Length Integer (CompactSize) encoding
pub fn write_varint(buf: &mut Vec<u8>, val: u64) {
    if val < 0xfd {
        buf.push(val as u8);
    } else if val <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

/// Double SHA256 helper
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Computes BIP-340/341 Tagged Hash: SHA256(SHA256(tag) || SHA256(tag) || data)
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Computes SHA256(outpoint_0 || outpoint_1 || ...)
pub fn compute_sha_prevouts(inputs: &[TxIn]) -> [u8; 32] {
    let mut buf = Vec::new();
    for input in inputs {
        input.previous_output.serialize(&mut buf);
    }
    let res = Sha256::digest(&buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(&res);
    out
}

/// Computes SHA256(amount_0 || amount_1 || ...) where amounts are 8-byte LE
pub fn compute_sha_amounts(amounts: &[u64]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(amounts.len() * 8);
    for &amt in amounts {
        buf.extend_from_slice(&amt.to_le_bytes());
    }
    let res = Sha256::digest(&buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(&res);
    out
}

/// Computes SHA256(spk_0 || spk_1 || ...) where each is prefixed by CompactSize length
pub fn compute_sha_scriptpubkeys(spks: &[Vec<u8>]) -> [u8; 32] {
    let mut buf = Vec::new();
    for spk in spks {
        write_varint(&mut buf, spk.len() as u64);
        buf.extend_from_slice(spk);
    }
    let res = Sha256::digest(&buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(&res);
    out
}

/// Computes SHA256(seq_0 || seq_1 || ...) where sequences are 4-byte LE
pub fn compute_sha_sequences(inputs: &[TxIn]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(inputs.len() * 4);
    for input in inputs {
        buf.extend_from_slice(&input.sequence.to_le_bytes());
    }
    let res = Sha256::digest(&buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(&res);
    out
}

/// Computes SHA256(txout_0 || txout_1 || ...)
pub fn compute_sha_outputs(outputs: &[TxOut]) -> [u8; 32] {
    let mut buf = Vec::new();
    for output in outputs {
        output.serialize(&mut buf);
    }
    let res = Sha256::digest(&buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(&res);
    out
}

/// Taproot BIP-341 / BIP-342 Sighash Preimage components
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaprootSighashPreimage {
    pub epoch: u8,
    pub hash_type: u8,
    pub version: [u8; 4],
    pub lock_time: [u8; 4],
    pub sha_prevouts: [u8; 32],
    pub sha_amounts: [u8; 32],
    pub sha_scriptpubkeys: [u8; 32],
    pub sha_sequences: [u8; 32],
    pub sha_outputs: [u8; 32],
    pub spend_type: u8,
    pub input_index: [u8; 4],
}

impl TaprootSighashPreimage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(175);
        buf.push(self.epoch);
        buf.push(self.hash_type);
        buf.extend_from_slice(&self.version);
        buf.extend_from_slice(&self.lock_time);
        buf.extend_from_slice(&self.sha_prevouts);
        buf.extend_from_slice(&self.sha_amounts);
        buf.extend_from_slice(&self.sha_scriptpubkeys);
        buf.extend_from_slice(&self.sha_sequences);
        buf.extend_from_slice(&self.sha_outputs);
        buf.push(self.spend_type);
        buf.extend_from_slice(&self.input_index);
        buf
    }

    /// Computes the TapSighash digest
    pub fn compute_sighash(&self) -> [u8; 32] {
        let bytes = self.to_bytes();
        tagged_hash("TapSighash", &bytes)
    }

    /// Splits preimage into witness chunks suitable for OP_CAT stack reconstruction
    pub fn to_witness_chunks(&self) -> Vec<Vec<u8>> {
        let mut control_prefix = Vec::with_capacity(10);
        control_prefix.push(self.epoch);
        control_prefix.push(self.hash_type);
        control_prefix.extend_from_slice(&self.version);
        control_prefix.extend_from_slice(&self.lock_time);

        let mut control_suffix = Vec::with_capacity(5);
        control_suffix.push(self.spend_type);
        control_suffix.extend_from_slice(&self.input_index);

        vec![
            control_prefix,
            self.sha_prevouts.to_vec(),
            self.sha_amounts.to_vec(),
            self.sha_scriptpubkeys.to_vec(),
            self.sha_sequences.to_vec(),
            self.sha_outputs.to_vec(),
            control_suffix,
        ]
    }
}

/// Bitcoin Script Gadget for BIP-347 OP_CAT Sighash Introspection Covenants
pub struct CovenantScript;

impl CovenantScript {
    /// Emits Bitcoin Script that:
    /// 1. Asserts `sha_outputs == expected_sha_outputs` (constrains the spending transaction's outputs)
    /// 2. Assembles the sighash preimage using BIP-347 OP_CAT
    /// 3. Computes the sighash using OP_SHA256
    /// 4. Verifies the signature with OP_CHECKSIG against covenant_pubkey
    ///
    /// Expected Witness Stack:
    /// `[sig, pubkey, control_prefix, sha_prevouts, sha_amounts, sha_scriptpubkeys, sha_sequences, sha_outputs, control_suffix]`
    pub fn emit_sighash_covenant_verifier(
        builder: &mut ScriptBuilder,
        expected_sha_outputs: &[u8; 32],
        covenant_pubkey: &[u8; 32],
    ) {
        // Altstack: stash control_suffix
        builder.op_toaltstack(); // alt: [control_suffix]

        // Assert sha_outputs matches expected_sha_outputs
        builder.op_dup();
        builder.push_slice(expected_sha_outputs);
        builder.op_equalverify();

        // Concatenate sighash chunks with OP_CAT:
        // Stack top: [sig, pubkey, control_prefix, sha_prevouts, sha_amounts, sha_scriptpubkeys, sha_sequences, sha_outputs]
        builder.op_cat(); // sha_sequences || sha_outputs
        builder.op_cat(); // sha_scriptpubkeys || (sha_sequences || sha_outputs)
        builder.op_cat(); // sha_amounts || ...
        builder.op_cat(); // sha_prevouts || ...
        builder.op_cat(); // control_prefix || ...

        // Restore control_suffix from altstack
        builder.op_fromaltstack(); // [sig, pubkey, preimage_partial, control_suffix]
        builder.op_cat(); // [sig, pubkey, full_preimage]

        // Hash to obtain sighash
        builder.op_sha256(); // [sig, pubkey, sighash]
        builder.op_drop();   // in Tapscript OP_CHECKSIG verifies internally using sighash

        // Verify covenant pubkey and signature
        builder.op_dup();
        builder.push_slice(covenant_pubkey);
        builder.op_equalverify(); // confirms pubkey == covenant_pubkey
        builder.op_checksig();    // verifies sig with covenant_pubkey
    }

    /// Prepares witness for sighash introspection covenant spend
    pub fn create_covenant_witness(
        sig: &[u8],
        pubkey: &[u8; 32],
        preimage: &TaprootSighashPreimage,
    ) -> Vec<Vec<u8>> {
        let mut witness = Vec::new();
        witness.push(sig.to_vec());
        witness.push(pubkey.to_vec());
        let chunks = preimage.to_witness_chunks();
        for chunk in chunks {
            witness.push(chunk);
        }
        witness
    }
}

/// Formatter for Bitcoin Core / Bitcoin Inquisition RPC `testmempoolaccept`
pub struct TestMempoolAccept;

impl TestMempoolAccept {
    /// Formats JSON-RPC request for `testmempoolaccept`
    pub fn format_rpc_request(raw_tx_hex: &str) -> String {
        format!(
            r#"{{"jsonrpc":"1.0","id":"katamoto-verifier","method":"testmempoolaccept","params":[["{}"]]}}"#,
            raw_tx_hex
        )
    }

    /// Formats a curl shell command to test against a running Bitcoin Inquisition node
    pub fn format_curl_command(raw_tx_hex: &str, rpc_user: &str, rpc_pass: &str, rpc_port: u16) -> String {
        format!(
            r#"curl --user {}:{} --data-binary '{}' -H 'content-type: text/plain;' http://127.0.0.1:{}/"#,
            rpc_user,
            rpc_pass,
            Self::format_rpc_request(raw_tx_hex),
            rpc_port
        )
    }
}
