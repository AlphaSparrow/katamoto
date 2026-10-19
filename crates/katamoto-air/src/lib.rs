pub mod bisection;
pub mod constraints;
pub mod dsl;
pub mod quotient;
pub mod taptree_compiler;
pub mod trace;

pub use bisection::{BisectionState, BitVm2DisputeGraph, DisputeResolutionScript};
pub use constraints::{BoundaryConstraint, FibonacciTransition, LogUpScript, LogUpStep, LogUpTable};
pub use dsl::{
    constant, curr, next, AirDslError, AirSystem, BitwiseOpsGadget, Blake3RoundGadget, Cell,
    Expr, RangeCheck16Gadget, RangeCheck8Gadget, Sha256RoundGadget,
};
pub use quotient::{OodQuotientScript, OodQuotientStep};
pub use taptree_compiler::{
    CircleStarkTapTreeCompiler, LeafTelemetry, PartitioningTelemetry, StarkTapTreeCompiler,
};
pub use trace::ExecutionTrace;

#[cfg(test)]
mod tests {
    use super::*;
    use katamoto_field::M31;
    use katamoto_script::{OutPoint, ScriptBuilder, TestMempoolAccept, Vm};

    #[test]
    fn test_fibonacci_trace_and_merkle_commitment() {
        let trace = ExecutionTrace::generate_fibonacci(16, 1, 1);
        assert_eq!(trace.length, 16);
        assert_eq!(trace.num_columns, 1);

        // F_0 = 1, F_1 = 1, F_2 = 2, F_3 = 3, F_4 = 5, F_5 = 8, F_6 = 13, ...
        let col = &trace.columns[0];
        assert_eq!(col[0].value(), 1);
        assert_eq!(col[1].value(), 1);
        assert_eq!(col[2].value(), 2);
        assert_eq!(col[3].value(), 3);
        assert_eq!(col[4].value(), 5);
        assert_eq!(col[5].value(), 8);
        assert_eq!(col[6].value(), 13);
        assert_eq!(col[15].value(), 987);

        // Merkle tree commitment
        let tree = trace.commit_merkle();
        assert_eq!(tree.depth(), 4);
        assert_ne!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn test_boundary_constraint_script_verification() {
        let initial_val = M31::new(1);
        let mut builder = ScriptBuilder::new();
        BoundaryConstraint::emit_verifier(&mut builder, initial_val);

        let witness = BoundaryConstraint::create_witness(initial_val);
        let mut vm = Vm::with_witness(witness);
        let ok = vm.execute(builder.as_bytes()).expect("Boundary script failed");
        assert!(ok);
        assert_eq!(vm.stack().last().unwrap(), &[1]);
    }

    #[test]
    fn test_fibonacci_transition_constraint_script_verification() {
        let f_curr = M31::new(5);
        let f_next1 = M31::new(8);
        let f_next2 = M31::new(13); // 5 + 8 = 13

        let mut builder = ScriptBuilder::new();
        FibonacciTransition::emit_verifier(&mut builder);

        let witness = FibonacciTransition::create_witness(f_curr, f_next1, f_next2);
        let mut vm = Vm::with_witness(witness);
        let ok = vm.execute(builder.as_bytes()).expect("Transition script failed");
        assert!(ok);
        assert_eq!(vm.stack().last().unwrap(), &[1]);
    }

    #[test]
    fn test_ood_quotient_script_verification() {
        let z = M31::new(100);
        let z_init = M31::new(1);
        let v0 = M31::new(1);
        let v1 = M31::new(1);
        let v2 = M31::new(2);
        let expected_init = M31::new(1);
        let zh_z = M31::new(50);
        let alpha = M31::new(7);

        let step = OodQuotientStep::new(z, z_init, v0, v1, v2, expected_init, zh_z, alpha);
        let (lhs, t1, t2) = step.decompose();
        assert_eq!(lhs, t1 + t2);

        let mut builder = ScriptBuilder::new();
        OodQuotientScript::emit_verifier(&mut builder);

        let witness = OodQuotientScript::create_witness(lhs, t1, t2);
        let mut vm = Vm::with_witness(witness);
        let ok = vm.execute(builder.as_bytes()).expect("OOD quotient script failed");
        assert!(ok);
        assert_eq!(vm.stack().last().unwrap(), &[1]);
    }

    #[test]
    fn test_end_to_end_stark_taptree_compilation_and_spend() {
        let trace = ExecutionTrace::generate_fibonacci(16, 1, 1);
        let num_queries = 2;
        let (tap_tree, spends) = StarkTapTreeCompiler::compile_fibonacci_stark(&trace, num_queries);

        // TapTree contains: Leaf 0 (Boundary), Leaf 1 (OOD), Leaf 2 (Transcript), Leaf 3..4 (FRI Queries)
        assert_eq!(tap_tree.leaves.len(), 3 + num_queries);
        assert_eq!(spends.len(), 3 + num_queries);

        // Execute every single leaf in the TapTree with its witness on the Bitcoin Script VM
        for (idx, spend) in spends.iter().enumerate() {
            let mut vm = Vm::with_witness(spend.witness_items.clone());
            let ok = vm
                .execute(&spend.leaf_script)
                .unwrap_or_else(|e| panic!("Leaf {} ({}) failed: {:?}", idx, spend.leaf_name, e));
            assert!(ok, "Leaf {} returned false", spend.leaf_name);
            assert_eq!(vm.stack().last().unwrap(), &[1]);

            // Ensure every leaf script size is small and lightweight
            assert!(
                spend.leaf_script.len() < 520,
                "Leaf {} script size {} exceeded 520 bytes!",
                spend.leaf_name,
                spend.leaf_script.len()
            );

            // Build Bitcoin transaction spending this leaf
            let funding_outpoint = OutPoint::new([0x99u8; 32], idx as u32);
            let dummy_p2tr_key = [0x77u8; 32];
            let tx = StarkTapTreeCompiler::build_broadcast_tx(
                spend,
                funding_outpoint,
                &dummy_p2tr_key,
                100_000,
            );

            // Validate consensus rules (weight <= 400k WU, items <= 520 bytes, stack depth <= 1000)
            assert!(tx.validate_consensus_limits().is_ok());

            let raw_hex = tx.to_hex();
            assert!(!raw_hex.is_empty());
            let rpc = TestMempoolAccept::format_rpc_request(&raw_hex);
            assert!(rpc.contains("testmempoolaccept"));
        }

        println!(
            "End-to-End STARK TapTree Verified: {} leaves, Tree Root 0x{}",
            tap_tree.leaves.len(),
            hex::encode(tap_tree.root())
        );
    }

    #[test]
    fn test_generalized_air_dsl_and_multi_column_trace() {
        // Multi-column computation:
        // Col 0: counter (0, 1, 2, 3...)
        // Col 1: doubling (1, 2, 4, 8...)
        // Col 2: sum accumulator (Col0 + Col1)
        let n = 8;
        let mut col0 = Vec::with_capacity(n);
        let mut col1 = Vec::with_capacity(n);
        let mut col2 = Vec::with_capacity(n);

        let mut c0 = M31::new(0);
        let mut c1 = M31::new(1);
        for _ in 0..n {
            col0.push(c0);
            col1.push(c1);
            col2.push(c0 + c1);
            c0 = c0 + M31::ONE;
            c1 = c1 * M31::new(2);
        }

        let trace = ExecutionTrace::new(vec![col0, col1, col2]);

        // Define AIR constraints using fluent DSL
        let mut air = AirSystem::new(3);

        // Constraint 1: Counter transition: next(0) == curr(0) + 1
        air.assert_eq(next(0), curr(0) + constant(1));

        // Constraint 2: Doubling transition: next(1) == curr(1) * 2
        air.assert_eq(next(1), curr(1) * constant(2));

        // Constraint 3: Accumulator relation: curr(2) == curr(0) + curr(1)
        air.assert_eq(curr(2), curr(0) + curr(1));

        // Boundary constraint: Col 0 starts at 0, Col 1 starts at 1
        air.assert_boundary(0, 0, M31::ZERO);
        air.assert_boundary(1, 0, M31::ONE);

        // Verify that the trace satisfies the declared AIR
        let res = air.verify_trace(&trace);
        assert!(res.is_ok(), "Trace must satisfy AIR constraints");

        // Verify Bitcoin Script verifier for linear transition
        let mut builder = ScriptBuilder::new();
        AirSystem::emit_linear_transition_verifier(&mut builder);

        let witness = AirSystem::create_linear_witness(trace.columns[0][3], trace.columns[1][3], trace.columns[2][3]);
        let mut vm = Vm::with_witness(witness);
        let ok = vm.execute(builder.as_bytes()).expect("AIR transition script failed");
        assert!(ok);
        assert_eq!(vm.stack().last().unwrap(), &[1]);
    }

    #[test]
    fn test_circle_stark_taptree_compilation_and_telemetry() {
        let trace = ExecutionTrace::generate_fibonacci(16, 1, 1);
        let num_circle_fri_queries = 2;

        let (tap_tree, spends, telemetry) =
            CircleStarkTapTreeCompiler::compile_circle_stark(&trace, num_circle_fri_queries);

        // Expect: boundary (1) + transition (1) + transcript (1) + batch merkle (1) + circle fri folds (2) = 6 leaves
        assert_eq!(tap_tree.leaves.len(), 6);
        assert_eq!(spends.len(), 6);
        assert_eq!(telemetry.total_leaves, 6);
        assert!(telemetry.conforms_to_consensus);
        assert!(telemetry.max_script_bytes <= 520, "Scripts must be <= 520 bytes");

        println!(
            "\nPartitioning Telemetry: {} leaves, max script: {} B, avg: {:.1} B",
            telemetry.total_leaves, telemetry.max_script_bytes, telemetry.avg_script_bytes
        );

        // Execute every single leaf on Bitcoin Script VM
        for (i, spend) in spends.iter().enumerate() {
            let mut vm = Vm::with_witness(spend.witness_items.clone());
            let ok = vm
                .execute(&spend.leaf_script)
                .unwrap_or_else(|e| panic!("Leaf {} ({}) failed: {:?}", i, spend.leaf_name, e));
            assert!(ok, "Leaf {} evaluation returned false", spend.leaf_name);
            assert_eq!(vm.stack().last().unwrap(), &[1]);

            // Validate Bitcoin spending transaction consensus rules
            let funding_outpoint = OutPoint::new([0x33u8; 32], i as u32);
            let dummy_p2tr_key = [0x55u8; 32];
            let tx = CircleStarkTapTreeCompiler::build_broadcast_tx(
                spend,
                funding_outpoint,
                &dummy_p2tr_key,
                100_000,
            );
            assert!(tx.validate_consensus_limits().is_ok());
        }
    }

    #[test]
    fn test_optimistic_bisection_dispute_game() {
        // Step 0: F_0 = 1, F_1 = 1
        // Step 1: F_1 = 1, F_2 = 2
        // Step 2: F_2 = 2, F_3 = 3 (Prover falsely claims 999!)
        let curr = M31::new(2);
        let prev = M31::new(1);
        let fraudulent_claim = M31::new(999); // Valid would be 1 + 2 = 3

        let (_tree, spend) =
            DisputeResolutionScript::compile_dispute_taptree(fraudulent_claim, curr, prev);

        // Execute the dispute leaf on the VM
        let mut vm = Vm::with_witness(spend.witness_items.clone());
        let ok = vm.execute(&spend.leaf_script).expect("Dispute verification failed");
        assert!(ok, "Fraud proof must return true when prover submitted false claim");
        assert_eq!(vm.stack().last().unwrap(), &[1]);

        // Build the slash transaction paying the challenger
        let dispute_bond_outpoint = OutPoint::new([0xdd; 32], 0);
        let challenger_p2tr_key = [0x99; 32];
        let tx = DisputeResolutionScript::build_challenge_tx(
            &spend,
            dispute_bond_outpoint,
            &challenger_p2tr_key,
            1_000_000, // 0.01 BTC slashed bond
        );

        assert!(tx.validate_consensus_limits().is_ok());
        assert!(!tx.to_hex().is_empty());
        println!("Optimistic Fraud Proof TxID: {}", tx.txid());
    }

    #[test]
    fn test_spend_profiling_and_split_ood_leaves() {
        let trace = ExecutionTrace::generate_fibonacci(16, 1, 1);
        let (_tree, spends) = StarkTapTreeCompiler::compile_fibonacci_stark(&trace, 1);

        for spend in &spends {
            let profile = StarkTapTreeCompiler::profile_spend(spend).unwrap();
            assert!(profile.is_valid);
            assert!(!profile.near_stack_limit);
            assert!(profile.stats.max_combined_stack_depth < 900);
            assert!(profile.element_size_compliant);
        }

        // Test split OOD leaves
        let z = M31::new(1234567);
        let z_init = M31::ONE;
        let v0 = trace.columns[0][0];
        let v1 = trace.columns[0][1];
        let v2 = trace.columns[0][2];
        let zh_z = M31::new(987654);
        let alpha = M31::new(55555);
        let step = OodQuotientStep::new(z, z_init, v0, v1, v2, v0, zh_z, alpha);

        let (split_leaves, split_witnesses) = StarkTapTreeCompiler::compile_split_ood_leaves(&step);
        assert_eq!(split_leaves.len(), 2);
        assert_eq!(split_witnesses.len(), 2);

        for (leaf, wit) in split_leaves.iter().zip(split_witnesses.iter()) {
            let mut vm = Vm::with_witness(wit.clone());
            let ok = vm.execute(&leaf.script).unwrap();
            assert!(ok);
            let profile = vm.profile();
            assert!(profile.stats.max_combined_stack_depth < 100);
        }
    }

    #[test]
    fn test_bitvm2_end_to_end_dispute_graph() {
        let operator_key = [0x11u8; 32];
        let challenger_key = [0x22u8; 32];
        let bond = 100_000_000u64; // 1 BTC
        let state_commitment = [0x55u8; 32];

        let dispute_graph = BitVm2DisputeGraph::new(
            operator_key,
            challenger_key,
            bond,
            144, // 1 day dispute window
            state_commitment,
        );

        // 1. Operator deposits bond via AssertTx
        let funding_outpoint = OutPoint::new([0xaa; 32], 0);
        let (assert_tx, assert_tree) = dispute_graph.build_assert_tx(funding_outpoint);
        assert!(assert_tx.validate_consensus_limits().is_ok());
        let assert_txid = assert_tx.txid();
        assert_eq!(assert_txid.len(), 64);

        // 2. Challenger challenges contested step 5 via ChallengeTx
        let assert_outpoint = OutPoint::new([0xbb; 32], 0);
        let mock_challenger_sig = [0x77u8; 64];
        let (challenge_tx, _spend) = dispute_graph.build_challenge_tx(
            &assert_tree,
            assert_outpoint.clone(),
            5,
            mock_challenger_sig,
        );
        assert!(challenge_tx.validate_consensus_limits().is_ok());

        // 3. Challenger executes DisproveTx using compiled fraud leaf spend
        let fraud_step_prev = M31::new(1);
        let fraud_step_curr = M31::new(2);
        let fraud_claim = M31::new(999); // Invalid (1 + 2 = 3)
        let (_dispute_tree, fraud_spend) = DisputeResolutionScript::compile_dispute_taptree(
            fraud_claim,
            fraud_step_curr,
            fraud_step_prev,
        );
        let challenge_outpoint = OutPoint::new([0xcc; 32], 0);
        let disprove_tx = dispute_graph.build_disprove_tx(
            challenge_outpoint,
            &fraud_spend,
            &challenger_key,
        );
        assert!(disprove_tx.validate_consensus_limits().is_ok());

        // 4. Operator timeout reclaim if no challenge occurs
        let mock_operator_sig = [0x88u8; 64];
        let timeout_tx = dispute_graph.build_timeout_resolve_tx(
            &assert_tree,
            assert_outpoint,
            mock_operator_sig,
            &operator_key,
        );
        assert!(timeout_tx.validate_consensus_limits().is_ok());
        assert_eq!(timeout_tx.inputs[0].sequence, 144);
    }

    #[test]
    fn test_logup_lookup_argument_qm31_transition() {
        use katamoto_field::QM31;

        // Challenge gamma in QM31
        let gamma = QM31::from_u32(1000, 2000, 3000, 4000);
        let prev_accum = QM31::from_u32(10, 20, 30, 40);

        let input_val = M31::new(42);
        let table_val = M31::new(42);
        let multiplicity = M31::new(1); // 1 input matches 1 table entry

        let step = LogUpStep::new(prev_accum, input_val, table_val, multiplicity, gamma);
        let (lhs, rhs) = step.decompose();
        assert_eq!(lhs, rhs, "LogUp polynomial relation LHS == RHS must hold");

        let mut builder = ScriptBuilder::new();
        LogUpScript::emit_qm31_verifier(&mut builder);

        let witness = LogUpScript::create_qm31_witness(lhs, rhs);
        let mut vm = Vm::with_witness(witness);
        let ok = vm.execute(builder.as_bytes()).expect("LogUp verification should succeed");
        assert!(ok);
    }

    #[test]
    fn test_prebuilt_range_checks_8_and_16() {
        // 8-bit range check
        let mut b8 = ScriptBuilder::new();
        RangeCheck8Gadget::emit_verifier(&mut b8);
        let wit8 = RangeCheck8Gadget::create_witness(200);
        let mut vm8 = Vm::with_witness(wit8);
        assert!(vm8.execute(b8.as_bytes()).unwrap());

        // 16-bit range check with limb decomposition
        let mut b16 = ScriptBuilder::new();
        RangeCheck16Gadget::emit_verifier(&mut b16);
        let val16 = 50000u16; // 50000 = 80 + 256 * 195
        let wit16 = RangeCheck16Gadget::create_witness(val16);
        let mut vm16 = Vm::with_witness(wit16);
        assert!(vm16.execute(b16.as_bytes()).unwrap());
    }

    #[test]
    fn test_prebuilt_bitwise_gadgets() {
        // 8-bit XOR: 0x5a ^ 0x3c == 0x66 (90 ^ 60 == 102)
        let a = 90u8;
        let b = 60u8;
        let xor_res = a ^ b;
        let mut b_xor = ScriptBuilder::new();
        BitwiseOpsGadget::emit_xor_verifier(&mut b_xor, a, b, xor_res);
        let wit_xor = BitwiseOpsGadget::create_witness(a, b, xor_res);
        let mut vm_xor = Vm::with_witness(wit_xor);
        assert!(vm_xor.execute(b_xor.as_bytes()).unwrap());

        // 8-bit AND: 90 & 60 == 24
        let and_res = a & b;
        let mut b_and = ScriptBuilder::new();
        BitwiseOpsGadget::emit_and_verifier(&mut b_and, a, b, and_res);
        let wit_and = BitwiseOpsGadget::create_witness(a, b, and_res);
        let mut vm_and = Vm::with_witness(wit_and);
        assert!(vm_and.execute(b_and.as_bytes()).unwrap());
    }

    #[test]
    fn test_prebuilt_sha256_and_blake3_round_gadgets() {
        // SHA-256 round
        let initial_state = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];
        let k0 = 0x428a2f98;
        let w0 = 0x80000000;
        let next_state = Sha256RoundGadget::round_step(initial_state, k0, w0);

        let mut b_sha = ScriptBuilder::new();
        Sha256RoundGadget::emit_verifier(&mut b_sha);
        let wit_sha = Sha256RoundGadget::create_witness(next_state[0], next_state[4]);
        let mut vm_sha = Vm::with_witness(wit_sha);
        assert!(vm_sha.execute(b_sha.as_bytes()).unwrap());

        // Blake3 G function round
        let (a, b, c, d) = Blake3RoundGadget::g(10, 20, 30, 40, 50, 60);
        let mut b_blake = ScriptBuilder::new();
        Blake3RoundGadget::emit_verifier(&mut b_blake);
        let wit_blake = Blake3RoundGadget::create_witness((a, b, c, d));
        let mut vm_blake = Vm::with_witness(wit_blake);
        assert!(vm_blake.execute(b_blake.as_bytes()).unwrap());
    }
}
