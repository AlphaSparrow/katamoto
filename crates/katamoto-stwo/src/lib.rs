pub mod channel;
pub mod compiler;
pub mod header_verifier;
pub mod proof;
pub mod recursive_verifier;
pub mod riscv;

pub use header_verifier::{BitcoinHeader, HeaderChain, HeaderDisputeCompiler, HeaderScript};

pub use channel::{StwoChannel, StwoChannelScript, STWO_CHANNEL_INIT_SEED};
pub use compiler::{
    DualBackendCompiler, DualBackendSpendPackage, SettlementMetrics, StwoTapTreeCompiler,
    StwoTapTreeSpendPackage, StwoTelemetry, VerificationBackend,
};
pub use proof::{StwoFriProof, StwoFriQuery, StwoOodEvaluations, StwoProof, StwoProofError};
pub use recursive_verifier::{
    CanonicalRecursiveProof, CanonicalRecursiveTapTree, RecursiveVerifierConfig,
};
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

        // 3. Test SUB instruction: x3 = x1 - x2 (50 - 20 = 30), PC: 0x1000 -> 0x1004
        let sub_step = RiscvStep {
            pc_curr: 0x1000,
            pc_next: 0x1004,
            opcode: RiscvOpcode::Sub,
            rs1_val: 50,
            rs2_val: 20,
            rd_val: 30,
            imm: 0,
        };
        assert!(sub_step.is_valid());

        let mut b_sub = ScriptBuilder::new();
        RiscvScript::emit_sub_step_verifier(&mut b_sub);
        let wit_sub = RiscvScript::create_sub_witness(&sub_step);

        let mut vm_sub = Vm::with_witness(wit_sub);
        let ok_sub = vm_sub.execute(b_sub.as_bytes()).expect("RISC-V SUB step failed");
        assert!(ok_sub);
        assert_eq!(vm_sub.stack().last().unwrap(), &[1]);

        // 4. Test BEQ instruction:
        // Case 4a: rs1 == rs2 -> Branch Taken: target = 0x1000 + 40 = 0x1028
        let beq_taken = RiscvStep {
            pc_curr: 0x1000,
            pc_next: 0x1028,
            opcode: RiscvOpcode::Beq,
            rs1_val: 77,
            rs2_val: 77,
            rd_val: 0,
            imm: 40,
        };
        assert!(beq_taken.is_valid());
        let mut b_beq_t = ScriptBuilder::new();
        RiscvScript::emit_beq_step_verifier(&mut b_beq_t);
        let wit_beq_t = RiscvScript::create_branch_witness(&beq_taken);
        let mut vm_beq_t = Vm::with_witness(wit_beq_t);
        assert!(vm_beq_t.execute(b_beq_t.as_bytes()).expect("BEQ taken failed"));
        assert_eq!(vm_beq_t.stack().last().unwrap(), &[1]);

        // Case 4b: rs1 != rs2 -> Branch Not Taken: target = 0x1000 + 4 = 0x1004
        let beq_not_taken = RiscvStep {
            pc_curr: 0x1000,
            pc_next: 0x1004,
            opcode: RiscvOpcode::Beq,
            rs1_val: 77,
            rs2_val: 99,
            rd_val: 0,
            imm: 40,
        };
        assert!(beq_not_taken.is_valid());
        let mut b_beq_nt = ScriptBuilder::new();
        RiscvScript::emit_beq_step_verifier(&mut b_beq_nt);
        let wit_beq_nt = RiscvScript::create_branch_witness(&beq_not_taken);
        let mut vm_beq_nt = Vm::with_witness(wit_beq_nt);
        assert!(vm_beq_nt.execute(b_beq_nt.as_bytes()).expect("BEQ not taken failed"));
        assert_eq!(vm_beq_nt.stack().last().unwrap(), &[1]);

        // 5. Test BNE instruction:
        // Case 5a: rs1 != rs2 -> Branch Taken: target = 0x1000 + 16 = 0x1010
        let bne_taken = RiscvStep {
            pc_curr: 0x1000,
            pc_next: 0x1010,
            opcode: RiscvOpcode::Bne,
            rs1_val: 12,
            rs2_val: 34,
            rd_val: 0,
            imm: 16,
        };
        assert!(bne_taken.is_valid());
        let mut b_bne_t = ScriptBuilder::new();
        RiscvScript::emit_bne_step_verifier(&mut b_bne_t);
        let wit_bne_t = RiscvScript::create_branch_witness(&bne_taken);
        let mut vm_bne_t = Vm::with_witness(wit_bne_t);
        assert!(vm_bne_t.execute(b_bne_t.as_bytes()).expect("BNE taken failed"));
        assert_eq!(vm_bne_t.stack().last().unwrap(), &[1]);

        // Case 5b: rs1 == rs2 -> Branch Not Taken: target = 0x1000 + 4 = 0x1004
        let bne_not_taken = RiscvStep {
            pc_curr: 0x1000,
            pc_next: 0x1004,
            opcode: RiscvOpcode::Bne,
            rs1_val: 55,
            rs2_val: 55,
            rd_val: 0,
            imm: 16,
        };
        assert!(bne_not_taken.is_valid());
        let mut b_bne_nt = ScriptBuilder::new();
        RiscvScript::emit_bne_step_verifier(&mut b_bne_nt);
        let wit_bne_nt = RiscvScript::create_branch_witness(&bne_not_taken);
        let mut vm_bne_nt = Vm::with_witness(wit_bne_nt);
        assert!(vm_bne_nt.execute(b_bne_nt.as_bytes()).expect("BNE not taken failed"));
        assert_eq!(vm_bne_nt.stack().last().unwrap(), &[1]);

        // 6. Test LW / SW memory instructions:
        // Eff addr = 0x200 + 12 = 0x20C (word 0x83)
        let lw_step = RiscvStep {
            pc_curr: 0x1000,
            pc_next: 0x1004,
            opcode: RiscvOpcode::Lw,
            rs1_val: 0x200,
            rs2_val: 0,
            rd_val: 0xDEADBEEF_u32,
            imm: 12,
        };
        assert!(lw_step.is_valid());
        let mut b_lw = ScriptBuilder::new();
        RiscvScript::emit_lw_step_verifier(&mut b_lw);
        let wit_lw = RiscvScript::create_lw_witness(&lw_step);
        let mut vm_lw = Vm::with_witness(wit_lw);
        assert!(vm_lw.execute(b_lw.as_bytes()).expect("LW step failed"));
        assert_eq!(vm_lw.stack().last().unwrap(), &[1]);

        let sw_step = RiscvStep {
            pc_curr: 0x1000,
            pc_next: 0x1004,
            opcode: RiscvOpcode::Sw,
            rs1_val: 0x300,
            rs2_val: 0xCAFEBABE_u32,
            rd_val: 0,
            imm: 8,
        };
        assert!(sw_step.is_valid());
        let mut b_sw = ScriptBuilder::new();
        RiscvScript::emit_sw_step_verifier(&mut b_sw);
        let wit_sw = RiscvScript::create_sw_witness(&sw_step);
        let mut vm_sw = Vm::with_witness(wit_sw);
        assert!(vm_sw.execute(b_sw.as_bytes()).expect("SW step failed"));
        assert_eq!(vm_sw.stack().last().unwrap(), &[1]);
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

    #[test]
    fn test_canonical_fixed_recursive_taptree_verification() {
        let stmt = RiscvStatement {
            initial_pc: 0x80000000,
            final_pc: 0x80000020,
            cycle_count: 8,
            initial_state_root: [0x11; 32],
            final_state_root: [0x22; 32],
            program_digest: [0x33; 32],
        };

        // Synthesize canonical recursive proof
        let recursive_proof = CanonicalRecursiveProof::synthesize(stmt);
        assert_eq!(recursive_proof.canonical_columns.len(), 16);
        assert_eq!(recursive_proof.config.log_degree, 8);

        // Compile into pinned 8-leaf TapTree
        let (tap_tree, spends) = CanonicalRecursiveTapTree::compile(&recursive_proof, 42);
        assert_eq!(tap_tree.leaves.len(), CanonicalRecursiveTapTree::PINNED_LEAF_COUNT);
        assert_eq!(spends.len(), CanonicalRecursiveTapTree::PINNED_LEAF_COUNT);

        // Verify leaf names match constant specification
        for (i, name) in CanonicalRecursiveTapTree::PINNED_LEAF_NAMES.iter().enumerate() {
            assert_eq!(&spends[i].leaf_name, name);
        }

        // Execute all 8 pinned leaves in Bitcoin Script VM!
        for spend in &spends {
            let mut vm = Vm::with_witness(spend.witness_items.clone());
            let ok = vm
                .execute(&spend.leaf_script)
                .unwrap_or_else(|e| panic!("Execution of leaf '{}' failed: {:?}", spend.leaf_name, e));
            assert!(ok, "Leaf '{}' failed", spend.leaf_name);
            assert_eq!(vm.stack().last().unwrap(), &[1]);
        }

        println!(
            "Canonical Recursive Verifier TapTree Verified! Pinned Leaves={}, Root=0x{}",
            tap_tree.leaves.len(),
            hex::encode(tap_tree.root())
        );
    }

    #[test]
    fn test_dual_backend_compiler_opcat_vs_bitvm() {
        let col0 = MixedColumn::new((0..16).map(|i| M31::new(i * 10)).collect());
        let col1 = MixedColumn::new((0..8).map(|i| M31::new(i * 20 + 1)).collect());
        let columns = vec![col0, col1];
        let mixed_tree = MixedBatchMerkleTree::new(columns.clone());
        let trace_root = mixed_tree.root();

        let ood_evaluations = StwoOodEvaluations {
            ood_point_x: QM31::from_u32(17, 0, 0, 0),
            ood_point_y: QM31::ZERO,
            trace_evals: vec![QM31::from_u32(10, 0, 0, 0)],
            quotient_eval: QM31::from_u32(5, 0, 0, 0),
        };

        let fri_proof = StwoFriProof {
            round_commitments: vec![[0x11u8; 32]],
            queries: vec![
                StwoFriQuery {
                    query_idx: 1,
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

        let pow_bits = 8;
        let mut pow_nonce = 0u64;
        while !katamoto_fri::Transcript::verify_pow(&trace_root, pow_nonce, pow_bits) {
            pow_nonce += 1;
        }

        let proof = StwoProof {
            statement_hash: [0xaa; 32],
            preprocessed_root: None,
            trace_root,
            lookup_root: None,
            quotient_root: [0xbb; 32],
            ood_evaluations,
            fri_proof,
            pow_nonce,
            pow_bits,
        };

        // 1. Compile for Backend A: OP_CAT Signet
        let pkg_opcat = DualBackendCompiler::compile(
            &proof,
            &columns,
            3,
            None,
            None,
            VerificationBackend::OpCatSignet,
        );
        assert_eq!(pkg_opcat.metrics.backend, VerificationBackend::OpCatSignet);
        assert!(pkg_opcat.metrics.op_cat_required);
        assert_eq!(pkg_opcat.metrics.tx_count, 1);

        // 2. Compile for Backend B: Mainnet BitVM OTS
        let pkg_bitvm = DualBackendCompiler::compile(
            &proof,
            &columns,
            3,
            None,
            None,
            VerificationBackend::MainnetBitVmOts,
        );
        assert_eq!(pkg_bitvm.metrics.backend, VerificationBackend::MainnetBitVmOts);
        assert!(!pkg_bitvm.metrics.op_cat_required, "Mainnet BitVM must NOT require OP_CAT");
        assert_eq!(pkg_bitvm.metrics.tx_count, 4);
        assert!(pkg_bitvm.dispute_graph.is_some());

        // Verify that the disprove leaf executes successfully in the Bitcoin Script VM
        let disprove_spend = &pkg_bitvm.spends[1];
        let mut vm = Vm::with_witness(disprove_spend.witness_items.clone());
        let ok = vm.execute(&disprove_spend.leaf_script).expect("BitVM disprove spend failed");
        assert!(ok);
        assert_eq!(vm.stack().last().unwrap(), &[1]);

        println!(
            "Dual-Backend Comparison: OP_CAT vBytes={} (Txs: {}), BitVM OTS vBytes={} (Txs: {})",
            pkg_opcat.metrics.total_vbytes,
            pkg_opcat.metrics.tx_count,
            pkg_bitvm.metrics.total_vbytes,
            pkg_bitvm.metrics.tx_count
        );
    }

    #[test]
    fn test_zerosync_header_chain_verification_and_dispute_game() {
        // Construct a chain of 2 consecutive Bitcoin headers
        let header0 = BitcoinHeader {
            version: 1,
            prev_block_hash: [0x00; 32],
            merkle_root: [0xaa; 32],
            time: 1231006505,
            nbits: 0x1d00ffff, // Mainnet difficulty 1 target
            nonce: 2083236893,
        };

        let h0_hash = header0.block_hash();

        let header1 = BitcoinHeader {
            version: 1,
            prev_block_hash: h0_hash,
            merkle_root: [0xbb; 32],
            time: 1231007105,
            nbits: 0x1d00ffff,
            nonce: 2573394689,
        };

        let chain = HeaderChain::new(vec![header0, header1]);
        let stmt = chain.to_statement();
        assert_eq!(stmt.initial_state_root, h0_hash);
        assert_eq!(stmt.final_state_root, chain.headers[1].block_hash());

        let steps = chain.synthesize_steps();
        assert_eq!(steps.len(), 4); // 2 steps per header

        // Verify steps semantics in zkVM
        for step in &steps {
            assert!(step.is_valid());
        }

        // Compile header chain dispute tree
        let operator_key = [0x55; 32];
        let challenger_key = [0x66; 32];
        let (_graph, tree, spends) = HeaderDisputeCompiler::compile_header_dispute(
            &chain,
            operator_key,
            challenger_key,
            100_000_000,
            144,
        );

        assert_eq!(tree.leaves.len(), 2);
        assert_eq!(spends.len(), 2);

        // Execute header continuity checks in the Bitcoin Script VM
        for spend in &spends {
            let mut vm = Vm::with_witness(spend.witness_items.clone());
            let ok = vm.execute(&spend.leaf_script).expect("Header script failed");
            assert!(ok);
            assert_eq!(vm.stack().last().unwrap(), &[1]);
        }

        println!(
            "ZeroSync Header Chain Light Client: Verified {} headers, Genesis=0x{}, Tip=0x{}",
            chain.headers.len(),
            hex::encode(h0_hash),
            hex::encode(stmt.final_state_root)
        );
    }
}



