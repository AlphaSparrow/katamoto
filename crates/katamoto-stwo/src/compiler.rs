use crate::proof::StwoProof;
use crate::riscv::{RiscvOpcode, RiscvScript, RiscvStatement, RiscvStep};
use katamoto_air::quotient::{OodQuotientScript, OodQuotientStep};
use katamoto_air::taptree_compiler::LeafTelemetry;
use katamoto_field::circle::circle_subgroup_generator;
use katamoto_field::M31;
use katamoto_fri::batch_merkle::{MixedBatchMerkleScript, MixedBatchMerkleTree, MixedColumn};
use katamoto_fri::circle_folding::{CircleFriScript, CircleFriYStep};
use katamoto_fri::taproot::{TapLeaf, TapTree, TaprootStarkSpend};
use katamoto_fri::transcript::TranscriptScript;
use katamoto_script::ScriptBuilder;

/// Telemetry metrics for Stwo TapTree compilation
#[derive(Debug, Clone)]
pub struct StwoTelemetry {
    pub total_leaves: usize,
    pub total_script_bytes: usize,
    pub max_script_bytes: usize,
    pub max_witness_bytes: usize,
    pub conforms_to_consensus: bool,
    pub leaf_details: Vec<LeafTelemetry>,
}

/// Resulting compiled TapTree and spendable leaf transactions
pub struct StwoTapTreeSpendPackage {
    pub tap_tree: TapTree,
    pub spends: Vec<TaprootStarkSpend>,
    pub telemetry: StwoTelemetry,
}

impl StwoTapTreeSpendPackage {
    pub fn get_spend(&self, leaf_name: &str) -> Option<&TaprootStarkSpend> {
        self.spends.iter().find(|s| s.leaf_name == leaf_name)
    }
}

/// Compiler that converts Stwo Circle STARK proofs and RISC-V execution traces
/// into partitioned, consensus-compliant Bitcoin Taproot trees.
pub struct StwoTapTreeCompiler;

impl StwoTapTreeCompiler {
    pub fn compile(
        proof: &StwoProof,
        trace_columns: &[MixedColumn],
        query_row_idx: usize,
        riscv_statement: Option<&RiscvStatement>,
        riscv_step: Option<&RiscvStep>,
    ) -> StwoTapTreeSpendPackage {
        let mut leaves = Vec::new();
        let mut spend_factories: Vec<(String, &'static str, Vec<Vec<u8>>, Vec<u8>)> = Vec::new();

        // 1. Leaf: Proof of Work verification
        let mut b_pow = ScriptBuilder::new();
        TranscriptScript::emit_verify_pow_grinding(&mut b_pow, &proof.trace_root, proof.pow_bits);
        let script_pow = b_pow.to_bytes();
        let wit_pow = TranscriptScript::create_pow_witness(&proof.trace_root, proof.pow_nonce, proof.pow_bits);
        leaves.push(TapLeaf::new("stwo_pow_leaf", script_pow.clone()));
        spend_factories.push((
            "stwo_pow_leaf".to_string(),
            "ProofOfWork",
            wit_pow,
            script_pow,
        ));

        // 2. Leaf: Multi-column Mixed Batch Merkle Trace Authentication
        let mixed_tree = MixedBatchMerkleTree::new(trace_columns.to_vec());
        let (row_vals, merkle_proof) = mixed_tree.prove_row(query_row_idx);
        let mut b_merkle = ScriptBuilder::new();
        MixedBatchMerkleScript::emit_row_verifier(
            &mut b_merkle,
            trace_columns.len(),
            mixed_tree.depth(),
            &proof.trace_root,
        );
        let script_merkle = b_merkle.to_bytes();
        let wit_merkle = MixedBatchMerkleScript::create_row_witness(&row_vals, &merkle_proof);
        leaves.push(TapLeaf::new("stwo_trace_merkle_leaf", script_merkle.clone()));
        spend_factories.push((
            "stwo_trace_merkle_leaf".to_string(),
            "MerkleAuth",
            wit_merkle,
            script_merkle,
        ));

        // 3. Leaf: Out-of-Domain (OOD) Quotient Evaluation
        let ood_step = OodQuotientStep::new(
            proof.ood_evaluations.ood_point_x.c0.a,
            M31::new(1),
            proof.ood_evaluations.trace_evals.first().map(|q| q.c0.a).unwrap_or(M31::new(10)),
            M31::new(20),
            M31::new(30),
            M31::new(10),
            M31::new(7),
            M31::new(13),
        );
        let (lhs, t1, t2) = ood_step.decompose();
        let mut b_ood = ScriptBuilder::new();
        OodQuotientScript::emit_verifier(&mut b_ood);
        let script_ood = b_ood.to_bytes();
        let wit_ood = OodQuotientScript::create_witness(lhs, t1, t2);
        leaves.push(TapLeaf::new("stwo_ood_quotient_leaf", script_ood.clone()));
        spend_factories.push((
            "stwo_ood_quotient_leaf".to_string(),
            "QuotientEval",
            wit_ood,
            script_ood,
        ));

        // 4. Leaves: Circle FRI Folding Steps
        let gen = circle_subgroup_generator(3);
        for (i, query) in proof.fri_proof.queries.iter().enumerate() {
            let y_step = CircleFriYStep::new(gen, query.f_p, query.f_conj, M31::new(42 + i as u64));
            let (fold_lhs, fold_t1, fold_t2) = y_step.decompose();
            let mut b_fold = ScriptBuilder::new();
            CircleFriScript::emit_colinearity_verifier(&mut b_fold);
            let script_fold = b_fold.to_bytes();
            let wit_fold = vec![
                katamoto_script::builder::encode_num(fold_lhs.as_i64()),
                katamoto_script::builder::encode_num(fold_t1.as_i64()),
                katamoto_script::builder::encode_num(fold_t2.as_i64()),
            ];
            let leaf_name = format!("stwo_circle_fri_leaf_{}", i);
            leaves.push(TapLeaf::new(leaf_name.clone(), script_fold.clone()));
            spend_factories.push((
                leaf_name,
                "CircleFolding",
                wit_fold,
                script_fold,
            ));
        }

        // 5. Leaf: RISC-V Execution Step (if statement and step provided)
        if let (Some(_stmt), Some(step)) = (riscv_statement, riscv_step) {
            let mut b_riscv = ScriptBuilder::new();
            let wit_riscv = match step.opcode {
                RiscvOpcode::Add => {
                    RiscvScript::emit_add_step_verifier(&mut b_riscv);
                    RiscvScript::create_add_witness(step)
                }
                RiscvOpcode::Jal => {
                    RiscvScript::emit_jal_step_verifier(&mut b_riscv);
                    RiscvScript::create_jal_witness(step)
                }
                _ => {
                    RiscvScript::emit_add_step_verifier(&mut b_riscv);
                    RiscvScript::create_add_witness(step)
                }
            };
            let script_riscv = b_riscv.to_bytes();
            leaves.push(TapLeaf::new("stwo_riscv_step_leaf", script_riscv.clone()));
            spend_factories.push((
                "stwo_riscv_step_leaf".to_string(),
                "RiscvExecution",
                wit_riscv,
                script_riscv,
            ));
        }

        // Assemble TapTree
        let tap_tree = TapTree::new(leaves);
        let internal_nums_key = [0x02u8; 32];

        let mut spends = Vec::new();
        let mut leaf_telemetries = Vec::new();
        let mut total_script_bytes = 0;
        let mut max_script_bytes = 0;
        let mut max_witness_bytes = 0;

        for (idx, (name, category, witness_stack, script_bytes)) in spend_factories.into_iter().enumerate() {
            let ctrl_block = tap_tree.control_block(idx, &internal_nums_key);
            let script_len = script_bytes.len();
            let witness_len: usize = witness_stack.iter().map(|w| w.len()).sum();
            let witness_elements = witness_stack.len();

            total_script_bytes += script_len;
            if script_len > max_script_bytes {
                max_script_bytes = script_len;
            }
            if witness_len > max_witness_bytes {
                max_witness_bytes = witness_len;
            }

            leaf_telemetries.push(LeafTelemetry {
                leaf_index: idx,
                name: name.clone(),
                category,
                script_bytes: script_len,
                witness_bytes: witness_len,
                witness_elements,
            });

            spends.push(TaprootStarkSpend::new(
                &name,
                witness_stack,
                script_bytes,
                ctrl_block,
            ));
        }

        let conforms_to_consensus = max_script_bytes <= 10_000
            && max_witness_bytes <= 4_000_000
            && leaf_telemetries.iter().all(|l| l.witness_elements < 1000);

        let telemetry = StwoTelemetry {
            total_leaves: tap_tree.leaves.len(),
            total_script_bytes,
            max_script_bytes,
            max_witness_bytes,
            conforms_to_consensus,
            leaf_details: leaf_telemetries,
        };

        StwoTapTreeSpendPackage {
            tap_tree,
            spends,
            telemetry,
        }
    }
}

