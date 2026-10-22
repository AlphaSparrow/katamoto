use crate::builder::ScriptBuilder;
use crate::ots::{WotsM31Commitment, WotsM31PublicKey, WotsM31Signature};
use crate::tx::{OutPoint, Transaction, TxIn, TxOut, Witness, SEQUENCE_FINAL};
use sha2::{Digest, Sha256};

/// Post-Quantum Recoverable Bitcoin Vault (PACT - Provable Address-Control Timestamp).
/// Protects Bitcoin UTXOs against quantum adversaries with Shor's algorithm:
/// - Path 1: Provisional Classical Spend (timelocked with Schnorr OP_CHECKSIG)
/// - Path 2: Post-Quantum STARK / Hash Emergency Recovery (Instant Rescue, Zero Elliptic Curves)
#[derive(Debug, Clone)]
pub struct PactVault {
    pub provisional_pubkey: [u8; 32],
    pub quantum_recovery_hash: [u8; 32],
    pub wots_recovery_pk: WotsM31PublicKey,
    pub unvault_timelock_blocks: u32,
    pub vault_satoshis: u64,
}

/// Spend packages for the two PACT spending paths
pub struct PactVaultSpends {
    pub script_classical: Vec<u8>,
    pub script_recovery: Vec<u8>,
    pub vault_tree_root: [u8; 32],
}

impl PactVault {
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

    /// Emits the classical withdrawal leaf script:
    /// `[timelock] OP_DROP [pubkey] OP_CHECKSIG`
    pub fn emit_classical_leaf(builder: &mut ScriptBuilder, timelock: u32, pubkey: &[u8; 32]) {
        builder.push_int(timelock as i64);
        builder.push_opcode(crate::Opcode::OpDrop); // Simulated OP_CSV relative timelock
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

    /// Compiles the PACT TapTree and creates spend templates
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

        // Compute simulated TapTree root: SHA256(leaf_class || leaf_recov)
        let mut hasher = Sha256::new();
        hasher.update(&script_classical);
        hasher.update(&script_recovery);
        let vault_tree_root: [u8; 32] = hasher.finalize().into();

        PactVaultSpends {
            script_classical,
            script_recovery,
            vault_tree_root,
        }
    }

    /// Builds transaction creating the PACT vault UTXO
    pub fn build_vault_funding_tx(&self, funding_outpoint: OutPoint, vault_spk: Vec<u8>) -> Transaction {
        let input = TxIn::new_taproot(funding_outpoint);
        let output = TxOut::new(self.vault_satoshis, vault_spk);
        Transaction::new(2, vec![input], vec![output], vec![Witness::default()])
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
}
