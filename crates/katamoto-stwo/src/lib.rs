pub mod channel;
pub mod compiler;
pub mod proof;
pub mod riscv;

pub use channel::{StwoChannel, StwoChannelScript, STWO_CHANNEL_INIT_SEED};
pub use compiler::{StwoTapTreeCompiler, StwoTapTreeSpendPackage, StwoTelemetry};
pub use proof::{StwoFriProof, StwoFriQuery, StwoOodEvaluations, StwoProof, StwoProofError};
pub use riscv::{RiscvOpcode, RiscvScript, RiscvStatement, RiscvStep};

#[cfg(test)]
mod tests {
    use super::*;
    use katamoto_field::{qm31::QM31, M31};
    use katamoto_fri::batch_merkle::{MixedBatchMerkleTree, MixedColumn};
    use katamoto_fri::merkle::MerkleProof;
    use katamoto_script::Vm;

    #[test]
    fn test_stwo_channel_fiat_shamir_and_pow() {
        let mut channel = StwoChannel::default();
        let digest = [0x5au8; 32];
        channel.mix_digest(&digest);

        // Draw M31 challenge
        let (felt, _, _) = channel.draw_felt();
        assert!(felt.value() < (1 << 31) - 1);

        // Draw QM31 challenge
        let qm31 = channel.draw_qm31();
        assert!(qm31.c0.a.value() < (1 << 31) - 1);

        // Draw Circle Point
        let (x, y) = channel.draw_random_circle_point();
        // Check on-curve over QM31: x^2 + y^2 == 1
        let one = QM31::ONE;
        let diff = (x * x) + (y * y) - one;
        assert_eq!(diff, QM31::ZERO);

        // Test PoW grinding and verification
        let pow_bits = 8;
        let nonce = channel.grind_pow(pow_bits);
        assert!(channel.check_pow(nonce, pow_bits));
    }

    #[test]
    fn test_riscv_instruction_step_verification_in_vm() {
        use katamoto_script::ScriptBuilder;

        // 1. Test ADD instruction: x3 = x1 + x2 (10 + 25 = 35), PC: 0x1000 -> 0x1004
        let add_step = RiscvStep {
            pc_curr: 0x1000,
            pc_next: 0x1004,
            opcode: RiscvOpcode::Add,
            rs1_val: 10,
            rs2_val: 25,
            rd_val: 35,
            imm: 0,
        };
        assert!(add_step.is_valid());

        let mut b_add = ScriptBuilder::new();
        RiscvScript::emit_add_step_verifier(&mut b_add);
        let wit_add = RiscvScript::create_add_witness(&add_step);

        let mut vm_add = Vm::with_witness(wit_add);
        let ok_add = vm_add.execute(b_add.as_bytes()).expect("RISC-V ADD step failed");
        assert!(ok_add);
        assert_eq!(vm_add.stack().last().unwrap(), &[1]);

        // 2. Test JAL instruction: PC: 0x2000 -> 0x2020 (imm = 32), rd = 0x2004
        let jal_step = RiscvStep {
            pc_curr: 0x2000,
            pc_next: 0x2020,
            opcode: RiscvOpcode::Jal,
            rs1_val: 0,
            rs2_val: 0,
            rd_val: 0x2004,
            imm: 32,
        };
        assert!(jal_step.is_valid());

        let mut b_jal = ScriptBuilder::new();
        RiscvScript::emit_jal_step_verifier(&mut b_jal);
        let wit_jal = RiscvScript::create_jal_witness(&jal_step);

        let mut vm_jal = Vm::with_witness(wit_jal);
        let ok_jal = vm_jal.execute(b_jal.as_bytes()).expect("RISC-V JAL step failed");
        assert!(ok_jal);
        assert_eq!(vm_jal.stack().last().unwrap(), &[1]);
    }

    #[test]
    fn test_end_to_end_stwo_proof_to_taptree_compilation() {
        // Setup 3 mixed-degree trace columns
        let col0 = MixedColumn::new((0..16).map(|i| M31::new(i * 10)).collect());
        let col1 = MixedColumn::new((0..8).map(|i| M31::new(i * 20 + 1)).collect());
        let col2 = MixedColumn::new((0..4).map(|i| M31::new(i * 30 + 2)).collect());
        let columns = vec![col0, col1, col2];

        let mixed_tree = MixedBatchMerkleTree::new(columns.clone());
        let trace_root = mixed_tree.root();

        // Grind PoW for trace root
        let pow_bits = 8;
        let trace_pow_nonce = {
            let mut nonce = 0u64;
            while !katamoto_fri::Transcript::verify_pow(&trace_root, nonce, pow_bits) {
                nonce += 1;
            }
            nonce
        };

        // Construct mock Stwo proof
        let (ood_x, ood_y) = (QM31::from_u32(17, 0, 0, 0), QM31::from_u32(0, 0, 0, 0));
        let ood_evaluations = StwoOodEvaluations {
            ood_point_x: ood_x,
            ood_point_y: ood_y,
            trace_evals: vec![QM31::from_u32(10, 0, 0, 0)],
            quotient_eval: QM31::from_u32(5, 0, 0, 0),
        };

        let fri_proof = StwoFriProof {
            round_commitments: vec![[0x11u8; 32], [0x22u8; 32]],
            queries: vec![
                StwoFriQuery {
                    query_idx: 3,
                    f_p: M31::new(100),
                    f_conj: M31::new(200),
                    merkle_proof: MerkleProof {
                        leaf: [0u8; 32],
                        siblings: vec![],
                        directions: vec![],
                    },
                },
            ],
            final_poly_coefficients: vec![QM31::ONE],
        };

        let proof = StwoProof {
            statement_hash: [0xaa; 32],
            preprocessed_root: None,
            trace_root,
            lookup_root: None,
            quotient_root: [0xbb; 32],
            ood_evaluations,
            fri_proof,
            pow_nonce: trace_pow_nonce,
            pow_bits,
        };

        let riscv_statement = RiscvStatement {
            initial_pc: 0x80000000,
            final_pc: 0x80000004,
            cycle_count: 1,
            initial_state_root: [0x01; 32],
            final_state_root: [0x02; 32],
            program_digest: [0x03; 32],
        };

        let riscv_step = RiscvStep {
            pc_curr: 0x80000000,
            pc_next: 0x80000004,
            opcode: RiscvOpcode::Add,
            rs1_val: 100,
            rs2_val: 200,
            rd_val: 300,
            imm: 0,
        };

        // Compile Stwo Proof into TapTree
        let package = StwoTapTreeCompiler::compile(
            &proof,
            &columns,
            7, // query row index 7
            Some(&riscv_statement),
            Some(&riscv_step),
        );

        assert!(package.telemetry.conforms_to_consensus);
        assert_eq!(package.tap_tree.leaves.len(), 5);

        // Execute and verify EVERY leaf spend in the Bitcoin Script Vm!
        for spend in &package.spends {
            let mut vm = Vm::with_witness(spend.witness_items.clone());
            let ok = vm
                .execute(&spend.leaf_script)
                .unwrap_or_else(|e| panic!("Execution of leaf '{}' failed: {:?}", spend.leaf_name, e));
            assert!(ok, "Leaf '{}' did not evaluate to true", spend.leaf_name);
            assert_eq!(
                vm.stack().last().unwrap(),
                &[1],
                "Leaf '{}' stack top must be 1",
                spend.leaf_name
            );
        }

        println!(
            "Stwo TapTree Verified Successfully! Leaves={}, Total Script={} B, Max Witness={} B",
            package.telemetry.total_leaves,
            package.telemetry.total_script_bytes,
            package.telemetry.max_witness_bytes
        );
    }
}
