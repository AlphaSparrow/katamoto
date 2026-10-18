pub mod constraints;
pub mod dsl;
pub mod quotient;
pub mod taptree_compiler;
pub mod trace;

pub use constraints::{BoundaryConstraint, FibonacciTransition};
pub use dsl::{constant, curr, next, AirDslError, AirSystem, Cell, Expr};
pub use quotient::{OodQuotientScript, OodQuotientStep};
pub use taptree_compiler::StarkTapTreeCompiler;
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
}
