use katamoto_field::M31;
use katamoto_fri::{TapLeaf, TapTree, TaprootStarkSpend};
use katamoto_script::{builder::encode_num, OutPoint, ScriptBuilder, Transaction, TxOut};

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
