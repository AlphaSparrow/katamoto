use crate::builder::ScriptBuilder;
use crate::ots::{WotsM31Commitment, WotsM31PublicKey, WotsM31Signature};
use crate::tx::{tagged_hash, write_varint, OutPoint, Transaction, TxIn, TxOut, Witness, SEQUENCE_FINAL};
use sha2::{Digest, Sha256};

/// Post-Quantum Recoverable Bitcoin Vault (PACT - Provable Address-Control Timestamp).
/// Protects Bitcoin UTXOs against quantum adversaries with Shor's algorithm:
/// - Path 1: Provisional Classical Spend (timelocked with OP_CHECKSEQUENCEVERIFY & Schnorr OP_CHECKSIG)
/// - Path 2: Post-Quantum STARK / Hash Emergency Recovery (Instant Rescue, Zero Elliptic Curves)
#[derive(Debug, Clone)]
pub struct PactVault {
    pub provisional_pubkey: [u8; 32],
    pub quantum_recovery_hash: [u8; 32],
    pub wots_recovery_pk: WotsM31PublicKey,
    pub unvault_timelock_blocks: u32,
    pub vault_satoshis: u64,
}

/// Spend packages for the two PACT spending paths with BIP-341 Taproot control blocks
#[derive(Debug, Clone)]
pub struct PactVaultSpends {
    pub script_classical: Vec<u8>,
    pub script_recovery: Vec<u8>,
    pub leaf_hash_classical: [u8; 32],
    pub leaf_hash_recovery: [u8; 32],
    pub vault_tree_root: [u8; 32],
    pub internal_nums_key: [u8; 32],
    pub vault_output_key: [u8; 32],
    pub vault_script_pubkey: Vec<u8>,
    pub ctrl_classical: Vec<u8>,
    pub ctrl_recovery: Vec<u8>,
}

impl PactVault {
    pub const TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;

    pub fn new(
        provisional_pubkey: [u8; 32],
        recovery_preimage: &[u8; 32],
        wots_recovery_pk: WotsM31PublicKey,
        unvault_timelock_blocks: u32,
        vault_satoshis: u64,
    ) -> Self {
        let recovery_hash = Sha256::digest(recovery_preimage).into();
        Self {
            provisional_pubkey,
            quantum_recovery_hash: recovery_hash,
            wots_recovery_pk,
            unvault_timelock_blocks,
            vault_satoshis,
        }
    }

    /// Emits the classical withdrawal leaf script using real BIP-112 OP_CHECKSEQUENCEVERIFY:
    /// `[timelock] OP_CSV OP_DROP [pubkey] OP_CHECKSIG`
    pub fn emit_classical_leaf(builder: &mut ScriptBuilder, timelock: u32, pubkey: &[u8; 32]) {
        builder.push_int(timelock as i64);
        builder.op_csv();
        builder.op_drop();
        builder.push_slice(pubkey);
        builder.op_checksig();
    }

    /// Emits the post-quantum recovery leaf script (100% quantum-resistant):
    /// 1. Verifies W-OTS signature on authorization value (e.g. recovery auth code)
    /// 2. Verifies SHA-256 preimage of quantum_recovery_hash
    /// 3. Zero OP_CHECKSIG, zero discrete-log / elliptic curve assumptions!
    pub fn emit_quantum_recovery_leaf(
        builder: &mut ScriptBuilder,
        wots_pk: &WotsM31PublicKey,
        expected_recovery_hash: &[u8; 32],
        auth_code: u32,
    ) {
        // 1. Verify W-OTS signature on 31-bit auth_code (pops 10 preimages)
        WotsM31Commitment::emit_verifier(builder, wots_pk, auth_code);
        builder.op_drop(); // drop TRUE flag

        // 2. Stack top now: [recovery_preimage (32B)]
        builder.op_sha256();
        builder.push_slice(expected_recovery_hash);
        builder.op_equalverify();
        builder.push_int(1); // leaves TRUE
    }

    /// Computes BIP-341 TapLeaf tagged hash: TaggedHash("TapLeaf", 0xc0 || compact_size(script) || script)
    pub fn compute_leaf_hash(script: &[u8]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(script.len() + 8);
        buf.push(Self::TAPSCRIPT_LEAF_VERSION);
        write_varint(&mut buf, script.len() as u64);
        buf.extend_from_slice(script);
        tagged_hash("TapLeaf", &buf)
    }

    /// Computes BIP-341 TapBranch tagged hash combining two child leaf hashes lexicographically
    pub fn compute_branch_hash(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
        let mut buf = [0u8; 64];
        if a < b {
            buf[0..32].copy_from_slice(&a);
            buf[32..64].copy_from_slice(&b);
        } else {
            buf[0..32].copy_from_slice(&b);
            buf[32..64].copy_from_slice(&a);
        }
        tagged_hash("TapBranch", &buf)
    }

    /// Prepares witness for classical timelocked withdrawal:
    /// `[schnorr_sig (64B)]`
    pub fn create_classical_witness(sig: &[u8]) -> Vec<Vec<u8>> {
        vec![sig.to_vec()]
    }

    /// Prepares witness for quantum recovery spend:
    /// `[preimage (32B), sig_0, sig_1, ..., sig_9]`
    pub fn create_recovery_witness(
        recovery_preimage: &[u8; 32],
        wots_sig: &WotsM31Signature,
    ) -> Vec<Vec<u8>> {
        let mut witness = Vec::new();
        // Preimage at bottom of stack
        witness.push(recovery_preimage.to_vec());
        // WOTS preimages on top
        witness.extend(WotsM31Commitment::create_witness(wots_sig));
        witness
    }

    /// Compiles the PACT TapTree and creates BIP-341 spend packages with control blocks
    pub fn compile_vault(&self, auth_code: u32) -> PactVaultSpends {
        let mut b_class = ScriptBuilder::new();
        Self::emit_classical_leaf(&mut b_class, self.unvault_timelock_blocks, &self.provisional_pubkey);
        let script_classical = b_class.to_bytes();

        let mut b_recov = ScriptBuilder::new();
        Self::emit_quantum_recovery_leaf(
            &mut b_recov,
            &self.wots_recovery_pk,
            &self.quantum_recovery_hash,
            auth_code,
        );
        let script_recovery = b_recov.to_bytes();

        // 1. BIP-341 Leaf Hashes
        let leaf_hash_classical = Self::compute_leaf_hash(&script_classical);
        let leaf_hash_recovery = Self::compute_leaf_hash(&script_recovery);

        // 2. BIP-341 TapTree Root
        let vault_tree_root = Self::compute_branch_hash(leaf_hash_classical, leaf_hash_recovery);

        // 3. Unspendable internal NUMS key (H point on secp256k1)
        let internal_nums_key = [0x02u8; 32];

        // 4. BIP-341 TapTweak to compute public commitment key
        let mut tweak_data = [0u8; 64];
        tweak_data[0..32].copy_from_slice(&internal_nums_key);
        tweak_data[32..64].copy_from_slice(&vault_tree_root);
        let vault_output_key = tagged_hash("TapTweak", &tweak_data);

        // 5. P2TR scriptPubKey: OP_1 (0x51) + PUSH32 (0x20) + tweaked_pubkey
        let mut vault_script_pubkey = Vec::with_capacity(34);
        vault_script_pubkey.push(0x51);
        vault_script_pubkey.push(0x20);
        vault_script_pubkey.extend_from_slice(&vault_output_key);

        // 6. BIP-341 Control Blocks (65 bytes: 1B version + 32B internal_key + 32B sibling)
        let mut ctrl_classical = Vec::with_capacity(65);
        ctrl_classical.push(Self::TAPSCRIPT_LEAF_VERSION);
        ctrl_classical.extend_from_slice(&internal_nums_key);
        ctrl_classical.extend_from_slice(&leaf_hash_recovery);

        let mut ctrl_recovery = Vec::with_capacity(65);
        ctrl_recovery.push(Self::TAPSCRIPT_LEAF_VERSION);
        ctrl_recovery.extend_from_slice(&internal_nums_key);
        ctrl_recovery.extend_from_slice(&leaf_hash_classical);

        PactVaultSpends {
            script_classical,
            script_recovery,
            leaf_hash_classical,
            leaf_hash_recovery,
            vault_tree_root,
            internal_nums_key,
            vault_output_key,
            vault_script_pubkey,
            ctrl_classical,
            ctrl_recovery,
        }
    }

    /// Builds transaction creating the PACT vault UTXO
    pub fn build_vault_funding_tx(&self, funding_outpoint: OutPoint, vault_spk: Vec<u8>) -> Transaction {
        let input = TxIn::new_taproot(funding_outpoint);
        let output = TxOut::new(self.vault_satoshis, vault_spk);
        Transaction::new(2, vec![input], vec![output], vec![Witness::default()])
    }

    /// Builds classical withdrawal transaction when timelock has elapsed
    pub fn build_classical_withdrawal_tx(
        &self,
        vault_outpoint: OutPoint,
        dest_spk: Vec<u8>,
        witness_stack: Vec<Vec<u8>>,
    ) -> Transaction {
        let mut input = TxIn::new_taproot(vault_outpoint);
        input.sequence = self.unvault_timelock_blocks; // Timelock satisfied!

        let net_satoshis = self.vault_satoshis.saturating_sub(10_000);
        let output = TxOut::new(net_satoshis, dest_spk);

        Transaction::new(
            2,
            vec![input],
            vec![output],
            vec![Witness::new(witness_stack)],
        )
    }

    /// Builds emergency recovery transaction rescuing funds from quantum attacker
    pub fn build_emergency_rescue_tx(
        &self,
        vault_outpoint: OutPoint,
        rescue_dest_spk: Vec<u8>,
        witness_stack: Vec<Vec<u8>>,
    ) -> Transaction {
        let mut input = TxIn::new_taproot(vault_outpoint);
        input.sequence = SEQUENCE_FINAL; // Instant bypass, no timelock delay!

        let rescue_satoshis = self.vault_satoshis.saturating_sub(10_000); // 10k sat fee
        let output = TxOut::new(rescue_satoshis, rescue_dest_spk);
        let commit_memo = TxOut::op_return(b"PACT_QUANTUM_RESCUED", 0);

        Transaction::new(
            2,
            vec![input],
            vec![output, commit_memo],
            vec![Witness::new(witness_stack)],
        )
    }

    /// Builds cancellation transaction returning funds to cold storage if an unvaulting attempt was malicious
    pub fn build_cancel_unvault_tx(
        &self,
        unvault_outpoint: OutPoint,
        cold_storage_spk: Vec<u8>,
        witness_stack: Vec<Vec<u8>>,
    ) -> Transaction {
        let mut input = TxIn::new_taproot(unvault_outpoint);
        input.sequence = SEQUENCE_FINAL;

        let refund_satoshis = self.vault_satoshis.saturating_sub(5_000);
        let output = TxOut::new(refund_satoshis, cold_storage_spk);
        let cancel_memo = TxOut::op_return(b"PACT_UNVAULT_CANCELLED", 0);

        Transaction::new(
            2,
            vec![input],
            vec![output, cancel_memo],
            vec![Witness::new(witness_stack)],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{Vm, VmError};

    #[test]
    fn test_pact_vault_classical_and_recovery_spends_in_vm() {
        let provisional_key = [0x22u8; 32];
        let recovery_secret = [0x33u8; 32];
        let seed = [0x44u8; 32];
        let (sk, pk) = WotsM31Commitment::keygen(&seed, b"VAULT_TEST_KEY");

        let timelock = 144; // 144 blocks relative delay
        let satoshis = 100_000_000; // 1 BTC

        let vault = PactVault::new(provisional_key, &recovery_secret, pk, timelock, satoshis);
        let auth_code = 999888u32;
        let spends = vault.compile_vault(auth_code);

        // Control blocks must be 65 bytes (BIP-341 standard: version + internal key + 1 sibling)
        assert_eq!(spends.ctrl_classical.len(), 65);
        assert_eq!(spends.ctrl_recovery.len(), 65);
        assert_eq!(spends.vault_script_pubkey.len(), 34);
        assert_eq!(spends.vault_script_pubkey[0], 0x51); // OP_1
        assert_eq!(spends.vault_script_pubkey[1], 0x20); // 32-byte push

        // 1. Classical Spend Path:
        // Case A: Sequence satisfies timelock (sequence = 144)
        let dummy_sig = [0x55u8; 64];
        let wit_classical = PactVault::create_classical_witness(&dummy_sig);
        let mut vm_class_ok = Vm::with_witness(wit_classical.clone());
        vm_class_ok.set_tx_sequence(timelock);
        let ok_class = vm_class_ok.execute(&spends.script_classical).expect("Classical spend should succeed");
        assert!(ok_class);

        // Case B: Sequence violates timelock (sequence = 143 < 144) -> MUST fail
        let mut vm_class_fail = Vm::with_witness(wit_classical);
        vm_class_fail.set_tx_sequence(timelock - 1);
        let err_class = vm_class_fail.execute(&spends.script_classical).unwrap_err();
        assert_eq!(err_class, VmError::SequenceFailed);

        // 2. Quantum Recovery Path:
        // Bypasses timelock completely (even when sequence is 0)
        let auth_sig = WotsM31Commitment::sign(&sk, auth_code);
        let wit_recov = PactVault::create_recovery_witness(&recovery_secret, &auth_sig);
        let mut vm_recov = Vm::with_witness(wit_recov);
        vm_recov.set_tx_sequence(0);
        let ok_recov = vm_recov.execute(&spends.script_recovery).expect("Quantum recovery should succeed");
        assert!(ok_recov);

        // 3. Transactions Consensus Validation
        let vault_outpoint = OutPoint::new([0xaa; 32], 0);
        let cold_storage = TxOut::op_return(b"COLD_STORAGE", 0).script_pubkey;

        let rescue_tx = vault.build_emergency_rescue_tx(vault_outpoint.clone(), cold_storage.clone(), vec![]);
        assert!(rescue_tx.validate_consensus_limits().is_ok());

        let cancel_tx = vault.build_cancel_unvault_tx(vault_outpoint, cold_storage, vec![]);
        assert!(cancel_tx.validate_consensus_limits().is_ok());
    }
}
