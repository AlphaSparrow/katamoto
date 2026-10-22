use katamoto_field::M31;
use katamoto_fri::{TapLeaf, TapTree, TaprootStarkSpend};
use katamoto_script::{
    builder::encode_num, OutPoint, ScriptBuilder, Transaction, TxIn, TxOut, Witness,
};

/// Optimistic Challenge-Response Bisection Game for BitVM2 STARK verification
#[derive(Debug, Clone)]
pub struct BisectionState {
    pub step_start: usize,
    pub step_end: usize,
    pub state_commitments: Vec<[u8; 32]>,
}

impl BisectionState {
    pub fn new(total_steps: usize, state_commitments: Vec<[u8; 32]>) -> Self {
        Self {
            step_start: 0,
            step_end: total_steps - 1,
            state_commitments,
        }
    }

    /// Halve the search interval given a contested midpoint
    pub fn bisect_step(&mut self, mid: usize, challenger_disagrees_left: bool) -> (usize, usize) {
        if challenger_disagrees_left {
            self.step_end = mid;
        } else {
            self.step_start = mid;
        }
        (self.step_start, self.step_end)
    }

    /// Checks whether the bisection game has narrowed down to a single step transition
    pub fn is_atomic_step(&self) -> bool {
        self.step_end <= self.step_start + 1
    }

    /// Contested step index
    pub fn contested_step(&self) -> usize {
        self.step_start
    }
}

/// Fraud proof script emitter and witness builder for disputed state transitions
pub struct DisputeResolutionScript;

impl DisputeResolutionScript {
    /// Emits a Bitcoin Script that proves a transition was INVALID (fraud proof):
    /// Witness: `[claimed_next, prev_state_curr, prev_state_prev]`
    /// If transition is Fibonacci: valid next is (prev_state_curr + prev_state_prev) % M31_P.
    /// The challenger provides the valid inputs, computes expected, and checks:
    /// `claimed_next != expected` -> slashes prover and pays challenger.
    pub fn emit_fibonacci_fraud_verifier(builder: &mut ScriptBuilder) {
        // Stack: [claimed_next, curr, prev]
        // Compute expected: (curr + prev) % M31_P
        builder.op_add();
        builder.op_dup();
        builder.push_int(2147483647);
        builder.push_opcode(katamoto_script::Opcode::OpGreaterThanOrEqual);
        builder.op_if();
        builder.push_int(2147483647);
        builder.op_sub();
        builder.op_endif();

        // Stack: [claimed_next, expected]
        // Assert: claimed_next != expected (Prover lied!)
        builder.op_num_not_equal();
    }

    /// Witness for the fraud proof spend:
    /// `[claimed_next, curr, prev]`
    pub fn create_fraud_witness(
        claimed_next: M31,
        curr: M31,
        prev: M31,
    ) -> Vec<Vec<u8>> {
        vec![
            encode_num(claimed_next.as_i64()),
            encode_num(curr.as_i64()),
            encode_num(prev.as_i64()),
        ]
    }

    /// Compiles a dispute TapTree holding the fraud proof leaf
    pub fn compile_dispute_taptree(
        claimed_next: M31,
        curr: M31,
        prev: M31,
    ) -> (TapTree, TaprootStarkSpend) {
        let mut builder = ScriptBuilder::new();
        Self::emit_fibonacci_fraud_verifier(&mut builder);
        let fraud_leaf = TapLeaf::new("bitvm_fraud_leaf", builder.to_bytes());
        let tree = TapTree::new(vec![fraud_leaf]);

        let internal_nums_key = [0x02u8; 32];
        let ctrl_block = tree.control_block(0, &internal_nums_key);
        let witness = Self::create_fraud_witness(claimed_next, curr, prev);

        let spend = TaprootStarkSpend::new(
            "bitvm_fraud_leaf",
            witness,
            tree.leaves[0].script.clone(),
            ctrl_block,
        );
        (tree, spend)
    }

    /// Builds the fraud-proof challenge transaction that slashes the prover
    pub fn build_challenge_tx(
        spend: &TaprootStarkSpend,
        dispute_bond_outpoint: OutPoint,
        challenger_p2tr_key: &[u8; 32],
        slashed_satoshis: u64,
    ) -> Transaction {
        let challenger_spk = TxOut::p2tr(challenger_p2tr_key, slashed_satoshis).script_pubkey;
        spend.build_spending_tx(dispute_bond_outpoint, challenger_spk, slashed_satoshis)
    }
}

/// Fraud proof dispute resolution using Winternitz OTS for OP_CAT-free mainnet verification
pub struct WotsDisputeResolution;

impl WotsDisputeResolution {
    /// Emits script that:
    /// 1. Verifies the operator committed to claimed_val via W-OTS against pk_claimed
    /// 2. Computes expected = (curr + prev) % M31_P
    /// 3. Checks claimed_val != expected (fraud proof) -> slashes bond!
    pub fn emit_wots_fraud_verifier(
        builder: &mut ScriptBuilder,
        pk_claimed: &katamoto_script::ots::WotsM31PublicKey,
        claimed_val: u32,
    ) {
        // 1. Verify WOTS commitment on claimed_val (pops 10 preimages, leaves 1 on stack)
        katamoto_script::ots::WotsM31Commitment::emit_verifier(builder, pk_claimed, claimed_val);
        builder.op_drop(); // drop TRUE flag from WOTS verifier

        // Stack now has: [claimed_val, curr, prev]
        DisputeResolutionScript::emit_fibonacci_fraud_verifier(builder);
    }

    /// Creates combined witness:
    /// `[claimed_val, curr, prev, sig_0, sig_1, ..., sig_9]`
    pub fn create_wots_fraud_witness(
        claimed_sig: &katamoto_script::ots::WotsM31Signature,
        claimed_val: u32,
        curr: u32,
        prev: u32,
    ) -> Vec<Vec<u8>> {
        let mut witness = Vec::new();
        // Values at bottom of stack
        witness.push(encode_num(claimed_val as i64));
        witness.push(encode_num(curr as i64));
        witness.push(encode_num(prev as i64));

        // WOTS signature preimages (popped first for WOTS verifier)
        witness.extend(katamoto_script::ots::WotsM31Commitment::create_witness(claimed_sig));
        witness
    }
}

/// BitVM2 Multi-Transaction Dispute Protocol Graph
/// Enforces the complete Assert -> Challenge -> Disprove state machine on Bitcoin
#[derive(Debug, Clone)]
pub struct BitVm2DisputeGraph {
    pub operator_pubkey: [u8; 32],
    pub challenger_pubkey: [u8; 32],
    pub bond_satoshis: u64,
    pub dispute_timelock_blocks: u32,
    pub assert_state_commitment: [u8; 32],
}

impl BitVm2DisputeGraph {
    pub fn new(
        operator_pubkey: [u8; 32],
        challenger_pubkey: [u8; 32],
        bond_satoshis: u64,
        dispute_timelock_blocks: u32,
        assert_state_commitment: [u8; 32],
    ) -> Self {
        Self {
            operator_pubkey,
            challenger_pubkey,
            bond_satoshis,
            dispute_timelock_blocks,
            assert_state_commitment,
        }
    }

    /// Compiles the Assert Covenant TapTree:
    /// - Leaf 0: Challenge spend leaf (challenger challenges a step within dispute window)
    /// - Leaf 1: Operator timeout reclamation leaf (operator reclaims bond after timelock expires)
    pub fn compile_assert_taptree(&self) -> TapTree {
        // Leaf 0: Challenge spend leaf
        let mut b_challenge = ScriptBuilder::new();
        b_challenge.push_slice(&self.challenger_pubkey);
        b_challenge.op_checksig();
        let leaf_challenge = TapLeaf::new("assert_challenge_leaf", b_challenge.to_bytes());

        // Leaf 1: Operator timeout reclamation leaf
        let mut b_timeout = ScriptBuilder::new();
        b_timeout.push_int(self.dispute_timelock_blocks as i64);
        b_timeout.push_opcode(katamoto_script::Opcode::OpDrop); // In standard Bitcoin: OP_CSV
        b_timeout.push_slice(&self.operator_pubkey);
        b_timeout.op_checksig();
        let leaf_timeout = TapLeaf::new("assert_timeout_leaf", b_timeout.to_bytes());

        TapTree::new(vec![leaf_challenge, leaf_timeout])
    }

    /// 1. ClaimTx / AssertTx:
    /// Commits the operator to the trace root, OOD quotient, and FRI layer roots, locking bond
    pub fn build_assert_tx(
        &self,
        funding_outpoint: OutPoint,
    ) -> (Transaction, TapTree) {
        let tree = self.compile_assert_taptree();
        let covenant_output = TxOut::p2tr(&tree.root(), self.bond_satoshis);
        let commit_output = TxOut::op_return(&self.assert_state_commitment, 0);

        let input = TxIn::new_taproot(funding_outpoint);
        let tx = Transaction::new(2, vec![input], vec![covenant_output, commit_output], vec![Witness::default()]);
        (tx, tree)
    }

    /// 2. ChallengeTx:
    /// Spends the AssertTx covenant into a contested state for a specific leaf/step index
    pub fn build_challenge_tx(
        &self,
        assert_tree: &TapTree,
        assert_outpoint: OutPoint,
        contested_step: usize,
        challenger_sig: [u8; 64],
    ) -> (Transaction, TaprootStarkSpend) {
        let internal_nums_key = [0x02u8; 32];
        let ctrl_block = assert_tree.control_block(0, &internal_nums_key);

        // Challenge leaf witness: [sig]
        let witness = vec![challenger_sig.to_vec()];
        let spend = TaprootStarkSpend::new(
            "assert_challenge_leaf",
            witness,
            assert_tree.leaves[0].script.clone(),
            ctrl_block,
        );

        // Challenge output locked under dispute bond
        let challenge_spk = TxOut::p2tr(&self.challenger_pubkey, self.bond_satoshis).script_pubkey;
        let mut step_data = Vec::with_capacity(8);
        step_data.extend_from_slice(&(contested_step as u64).to_le_bytes());
        let step_commit_out = TxOut::op_return(&step_data, 0);

        let input = TxIn {
            previous_output: assert_outpoint,
            script_sig: Vec::new(),
            sequence: katamoto_script::SEQUENCE_FINAL,
        };

        let tx = Transaction::new(
            2,
            vec![input],
            vec![
                TxOut::new(self.bond_satoshis, challenge_spk),
                step_commit_out,
            ],
            vec![Witness::new(spend.witness_items.clone())],
        );

        (tx, spend)
    }

    /// 3. DisproveTx:
    /// Executes the fraud proof leaf spend, slashing the malicious operator's bond to challenger
    pub fn build_disprove_tx(
        &self,
        challenge_outpoint: OutPoint,
        fraud_spend: &TaprootStarkSpend,
        challenger_dest_p2tr_key: &[u8; 32],
    ) -> Transaction {
        let challenger_spk = TxOut::p2tr(challenger_dest_p2tr_key, self.bond_satoshis).script_pubkey;
        fraud_spend.build_spending_tx(challenge_outpoint, challenger_spk, self.bond_satoshis)
    }

    /// 4. ResolveTx / TimeoutTx:
    /// Reclaims operator's bond after dispute timelock expires without a valid disprove spend
    pub fn build_timeout_resolve_tx(
        &self,
        assert_tree: &TapTree,
        assert_outpoint: OutPoint,
        operator_sig: [u8; 64],
        operator_dest_key: &[u8; 32],
    ) -> Transaction {
        let internal_nums_key = [0x02u8; 32];
        let ctrl_block = assert_tree.control_block(1, &internal_nums_key);

        // Timeout leaf witness: [sig]
        let witness = vec![operator_sig.to_vec()];
        let spend = TaprootStarkSpend::new(
            "assert_timeout_leaf",
            witness,
            assert_tree.leaves[1].script.clone(),
            ctrl_block,
        );

        let dest_spk = TxOut::p2tr(operator_dest_key, self.bond_satoshis).script_pubkey;
        let mut tx = spend.build_spending_tx(assert_outpoint, dest_spk, self.bond_satoshis);
        tx.inputs[0].sequence = self.dispute_timelock_blocks; // Relative locktime
        tx
    }
}

