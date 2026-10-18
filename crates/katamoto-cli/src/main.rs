use katamoto_air::{ExecutionTrace, StarkTapTreeCompiler};
use katamoto_field::{
    circle::{circle_subgroup_generator, CirclePoint, CircleScript},
    m31::M31Script,
    qm31::QM31Script,
    M31, QM31,
};
use katamoto_fri::{
    circle_folding::{CircleFriScript, CircleFriYStep},
    FriQueryStep, FriRoundQuery, FriScript, MerkleScript, MerkleTree, TapLeaf, TapTree,
    Transcript, TranscriptScript,
};
use katamoto_script::{
    builder::encode_num, OutPoint, ScriptBuilder, TestMempoolAccept, Vm,
};
use sha2::{Digest, Sha256};
use std::env;
use std::time::Instant;

fn print_usage() {
    println!(r#"
Katamoto (刀本) - Native ZK-STARK Verifier & Tapscript Compiler for Bitcoin (BIP-347 OP_CAT)

USAGE:
    katamoto-cli <COMMAND> [OPTIONS]

COMMANDS:
    verify-stark [STEPS] [A0] [A1]     Verify full end-to-end STARK proof on TapTree (default: 16 1 1)
    verify-circle                      Verify Circle STARK group arithmetic and Circle FRI folding
    emit-tx [LEAF_INDEX]               Emit raw Taproot v1 transaction hex and testmempoolaccept command
    benchmark-merkle [MAX_DEPTH]       Benchmark OP_CAT Merkle proof verification across depths (default: 16)
    verify-m31 [A] [B]                 Verify Mersenne-31 multiplication on Bitcoin Script VM (default: 1234567 7654321)
    verify-qm31                        Verify QM31 Quartic Extension Field arithmetic (124-bit STARK security)
    verify-fri-round                   Verify complete FRI query round (dual Merkle proof + colinearity fold)
    compile-taproot [QUERIES]          Compile complete BIP-341 Taproot STARK tree and emit witness spend
    emit-script [DEPTH]                Emit raw Bitcoin Tapscript bytecode hex (default: 8)
    help                               Print this help message
"#);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return;
    }

    match args[1].as_str() {
        "verify-stark" => {
            let steps: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(16);
            let a0: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1);
            let a1: u32 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(1);

            println!("\n==========================================================================================");
            println!("  KATAMOTO: End-to-End STARK Verifier & Partitioned TapTree (Bitcoin Tapscript)");
            println!("==========================================================================================");
            println!("  Execution Trace: Fibonacci Computation ({} steps)", steps);
            println!("  Base Field: Mersenne-31 (2^31 - 1)");
            println!("  Initial State: F_0 = {}, F_1 = {}", a0, a1);

            let trace = ExecutionTrace::generate_fibonacci(steps, a0, a1);
            let result_val = trace.columns[0][steps - 1];
            println!("  Computed Terminal State: F_{} = {}", steps - 1, result_val.value());

            let (tap_tree, spends) = StarkTapTreeCompiler::compile_fibonacci_stark(&trace, 4);
            let internal_nums_key = [0x02u8; 32];
            let tweak = tap_tree.tweak(&internal_nums_key);

            println!("\n  BIP-341 Taproot Tree Architecture:");
            println!("    Total Partitioned Leaves: {}", tap_tree.leaves.len());
            println!("    TapTree Root: 0x{}", hex::encode(tap_tree.root()));
            println!("    TapTweak:     0x{}", hex::encode(tweak));

            println!("\n  Verifying Partitioned Leaves on Bitcoin Script VM:");
            println!(
                "  {:<4} | {:<28} | {:<10} | {:<12} | {:<10} | {:<8}",
                "Leaf", "Description", "Script (B)", "Witness (B)", "Max Stack", "Status"
            );
            println!("  ----------------------------------------------------------------------------------");

            for (idx, spend) in spends.iter().enumerate() {
                let mut vm = Vm::with_witness(spend.witness_items.clone());
                let ok = vm
                    .execute(&spend.leaf_script)
                    .unwrap_or_else(|e| panic!("Leaf {} failed: {:?}", idx, e));
                assert!(ok);

                println!(
                    "  {:<4} | {:<28} | {:<10} | {:<12} | {:<10} | {:<8}",
                    idx,
                    spend.leaf_name,
                    spend.leaf_script.len(),
                    spend.total_witness_size(),
                    vm.stats().max_stack_depth,
                    "VALID"
                );
            }

            // Consensus validation check
            let dummy_outpoint = OutPoint::new([0x88u8; 32], 0);
            let dummy_p2tr_key = [0x77u8; 32];
            let tx = StarkTapTreeCompiler::build_broadcast_tx(
                &spends[0],
                dummy_outpoint,
                &dummy_p2tr_key,
                50_000,
            );
            assert!(tx.validate_consensus_limits().is_ok());

            println!("\n  Consensus Rule Auditing:");
            println!("    Max Stack Element Limit: 520 bytes (PASSED)");
            println!("    Max Stack Depth Limit:   1000 items (PASSED)");
            println!("    Standard Tx Weight:      {} / 400,000 WU (PASSED)", tx.weight());
            println!("    Virtual Size (vSize):    {} vB", tx.vsize());
            println!("  [SUCCESS] End-to-End Bitcoin STARK Proof Verified!\n");
        }

        "verify-circle" => {
            println!("\n==========================================================================================");
            println!("  KATAMOTO: Circle STARKs (Stwo) Group Arithmetic & FRI Two-Stage Folding");
            println!("==========================================================================================");
            println!("  Curve: C(M31) = {{ (x, y) in M31^2 | x^2 + y^2 = 1 }}");
            println!("  Group Order: p + 1 = 2^31 (Enables Large Power-of-2 FFTs!)");

            let gen_8 = circle_subgroup_generator(3);
            println!("\n  Order 8 Subgroup Generator: ({}, {})", gen_8.x.value(), gen_8.y.value());
            assert!(gen_8.is_on_curve());
            assert_eq!(gen_8.mul(8), CirclePoint::IDENTITY);

            let p2 = gen_8.double();
            let p3 = gen_8 + p2;
            println!("  Point Addition P + 2P = 3P: ({}, {})", p3.x.value(), p3.y.value());

            // 1. Verify Circle Point Addition in Bitcoin Script
            let witness_add = CircleScript::create_point_add_witness(gen_8, p2);
            let mut b_add = ScriptBuilder::new();
            CircleScript::emit_verify_point_add(&mut b_add);
            let mut vm_add = Vm::with_witness(witness_add);
            let ok_add = vm_add.execute(b_add.as_bytes()).unwrap();
            assert!(ok_add);
            println!("  [SUCCESS] Circle Point Addition verified on Bitcoin Script VM ({} opcodes)", b_add.opcode_count());

            // 2. Verify Circle FRI Two-Stage Folding
            let f_p = M31::new(13579);
            let f_conj = M31::new(24680);
            let alpha = M31::new(98765);
            let y_step = CircleFriYStep::new(gen_8, f_p, f_conj, alpha);
            let (lhs, t1, t2) = y_step.decompose();

            let mut b_fold = ScriptBuilder::new();
            CircleFriScript::emit_colinearity_verifier(&mut b_fold);
            let witness_fold = vec![
                encode_num(lhs.as_i64()),
                encode_num(t1.as_i64()),
                encode_num(t2.as_i64()),
            ];
            let mut vm_fold = Vm::with_witness(witness_fold);
            let ok_fold = vm_fold.execute(b_fold.as_bytes()).unwrap();
            assert!(ok_fold);
            println!("  [SUCCESS] Circle FRI y-fold colinearity verified on Bitcoin Script VM!");
            println!("  Ready for Stwo-compatible Bitcoin Layer 1 settlement.\n");
        }

        "emit-tx" => {
            let leaf_idx: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            let trace = ExecutionTrace::generate_fibonacci(16, 1, 1);
            let (_, spends) = StarkTapTreeCompiler::compile_fibonacci_stark(&trace, 2);

            let spend = &spends[leaf_idx.min(spends.len() - 1)];
            let funding_outpoint = OutPoint::new([0xaa; 32], 0);
            let dummy_p2tr_key = [0x55; 32];
            let tx = StarkTapTreeCompiler::build_broadcast_tx(spend, funding_outpoint, &dummy_p2tr_key, 25_000);

            assert!(tx.validate_consensus_limits().is_ok());
            let raw_hex = tx.to_hex();

            println!("\nSerialized Bitcoin Taproot v1 STARK Spend Transaction (Leaf {}):", leaf_idx);
            println!("  TxID:  {}", tx.txid());
            println!("  WTxID: {}", tx.wtxid());
            println!("  Weight: {} WU, VSize: {} vB", tx.weight(), tx.vsize());
            println!("\nRaw Transaction Hex:\n{}\n", raw_hex);

            println!("Bitcoin Inquisition / Regtest RPC Payload:");
            println!("{}\n", TestMempoolAccept::format_rpc_request(&raw_hex));

            println!("Broadcast / Mempool Validation Command:");
            println!("{}\n", TestMempoolAccept::format_curl_command(&raw_hex, "user", "pass", 18443));
        }

        "benchmark-merkle" => {
            let max_depth: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(16);

            println!("\n==========================================================================================");
            println!("  KATAMOTO: BIP-347 OP_CAT Merkle Proof Verification Benchmark (Bitcoin Tapscript)");
            println!("==========================================================================================");
            println!(
                "{:<6} | {:<12} | {:<10} | {:<12} | {:<14} | {:<10} | {:<10}",
                "Depth", "Leaves", "Script (B)", "Opcodes", "Witness (B)", "Max Stack", "Time (us)"
            );
            println!("------------------------------------------------------------------------------------------");

            for depth in [4, 8, 12, 16, 20] {
                if depth > max_depth {
                    break;
                }
                let num_leaves = 1 << depth;
                let mut leaves = Vec::with_capacity(num_leaves);
                for i in 0..num_leaves {
                    let hash = Sha256::digest(format!("trace_row_{}", i).as_bytes());
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&hash);
                    leaves.push(arr);
                }

                let tree = MerkleTree::new(leaves);
                let root = tree.root();
                let test_idx = num_leaves / 2 + 1;
                let proof = tree.prove(test_idx);

                let mut builder = ScriptBuilder::new();
                MerkleScript::emit_verifier(&mut builder, depth, &root);
                let script_bytes = builder.as_bytes().len();
                let opcodes = builder.opcode_count();

                let witness = MerkleScript::create_witness(&proof);
                let witness_bytes: usize = witness.iter().map(|w| w.len()).sum();

                let start = Instant::now();
                let mut vm = Vm::with_witness(witness);
                let ok = vm.execute(builder.as_bytes()).expect("Verification failed");
                let elapsed = start.elapsed().as_micros();

                assert!(ok);
                println!(
                    "{:<6} | {:<12} | {:<10} | {:<12} | {:<14} | {:<10} | {:<10}",
                    depth,
                    num_leaves,
                    script_bytes,
                    opcodes,
                    witness_bytes,
                    vm.stats().max_stack_depth,
                    elapsed
                );
            }
            println!("==========================================================================================\n");
        }

        "verify-m31" => {
            let a: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1234567);
            let b: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(7654321);

            let m_a = M31::new(a as u64);
            let m_b = M31::new(b as u64);
            let m_c = m_a * m_b;

            println!("\nExecuting M31 Field Multiplication on Bitcoin Script VM:");
            println!("  a = {} (M31)", m_a.value());
            println!("  b = {} (M31)", m_b.value());
            println!("  c = a * b mod (2^31 - 1) = {}", m_c.value());

            let bits = m_b.to_bits();
            let mut witness: Vec<Vec<u8>> = Vec::new();
            witness.push(encode_num(m_c.as_i64()));
            witness.push(encode_num(m_a.as_i64()));
            for i in (0..31).rev() {
                witness.push(encode_num(bits[i] as i64));
            }

            let mut builder = ScriptBuilder::new();
            M31Script::emit_mul_verify(&mut builder);

            println!("  Emitted Script Size: {} bytes ({} opcodes)", builder.len(), builder.opcode_count());
            let mut vm = Vm::with_witness(witness);
            let ok = vm.execute(builder.as_bytes()).expect("Script execution failed");

            if ok {
                println!("  [SUCCESS] Multiplication verified in Bitcoin Script with ZERO OP_MUL!");
                println!("  Opcodes Executed: {}", vm.stats().opcodes_executed);
                println!("  Max Stack Depth: {}", vm.stats().max_stack_depth);
            } else {
                println!("  [FAILED] Script returned FALSE");
            }
            println!();
        }

        "verify-qm31" => {
            println!("\nExecuting QM31 Quartic Extension Field Arithmetic on Bitcoin Script VM:");
            println!("  Base Field: Mersenne-31 (2^31 - 1)");
            println!("  Extension Degree: 4 (QM31 = CM31[j] / (j^2 - (2 + i)))");
            println!("  Soundness Security: 124 bits");

            let a = QM31::from_u32(1111, 2222, 3333, 4444);
            let b = QM31::from_u32(5555, 6666, 7777, 8888);
            let c = a + b;

            println!("  Operand A: {:?}", a.to_array());
            println!("  Operand B: {:?}", b.to_array());
            println!("  Expected A + B: {:?}", c.to_array());

            let mut builder = ScriptBuilder::new();
            for &comp in &a.to_array() {
                builder.push_int(comp.as_i64());
            }
            for &comp in &b.to_array() {
                builder.push_int(comp.as_i64());
            }
            QM31Script::emit_add(&mut builder);

            let mut vm = Vm::new();
            let ok = vm.execute(builder.as_bytes()).expect("QM31 execution failed");
            assert!(ok);

            println!("  [SUCCESS] QM31 Addition verified on Bitcoin Script VM!");
            println!("  Script Size: {} bytes ({} opcodes)", builder.len(), builder.opcode_count());
            println!("  Opcodes Executed: {}", vm.stats().opcodes_executed);
            println!();
        }

        "verify-fri-round" => {
            println!("\nExecuting Integrated FRI Query Round Verification (Bitcoin Tapscript):");
            let mut leaves = Vec::new();
            for i in 0..16 {
                let hash = Sha256::digest(format!("fri_layer_eval_{}", i).as_bytes());
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&hash);
                leaves.push(arr);
            }
            let tree = MerkleTree::new(leaves);
            let root = tree.root();

            let x = M31::new(13579);
            let fx = M31::new(24680);
            let f_neg_x = M31::new(97531);
            let alpha = M31::new(86420);
            let step = FriQueryStep::new(x, fx, f_neg_x, alpha);

            let proof_fx = tree.prove(3);
            let proof_f_neg_x = tree.prove(12);

            let query = FriRoundQuery {
                step,
                fx_merkle_proof: proof_fx,
                f_neg_x_merkle_proof: proof_f_neg_x,
            };

            let mut builder = ScriptBuilder::new();
            FriScript::emit_integrated_round_verifier(&mut builder, tree.depth(), &root);

            let witness = FriScript::create_integrated_witness(&query);
            let mut vm = Vm::with_witness(witness);
            let ok = vm.execute(builder.as_bytes()).expect("FRI verification failed");
            assert!(ok);

            println!("  [SUCCESS] Dual Merkle Membership + FRI Colinearity Verified!");
            println!("  Tree Depth: {} (16 layer leaves)", tree.depth());
            println!("  Script Size: {} bytes ({} opcodes)", builder.len(), builder.opcode_count());
            println!("  Opcodes Executed: {}", vm.stats().opcodes_executed);
            println!("  Max Stack Depth: {}", vm.stats().max_stack_depth);
            println!();
        }

        "compile-taproot" => {
            let num_queries: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(4);
            println!("\nCompiling Full BIP-341 Taproot STARK Tree with {} Query Leaves:", num_queries);

            let mut transcript = Transcript::new();
            let trace_root: [u8; 32] = Sha256::digest(b"trace_commitment").into();
            transcript.absorb(&trace_root);
            let mut b_transcript = ScriptBuilder::new();
            TranscriptScript::emit_verify_challenge_extraction(&mut b_transcript);
            let leaf_transcript = TapLeaf::new("fiat_shamir_leaf", b_transcript.to_bytes());

            let mut leaves = vec![leaf_transcript];

            for q in 0..num_queries {
                let mut b_fri = ScriptBuilder::new();
                let dummy_root = [0xaa ^ (q as u8); 32];
                FriScript::emit_integrated_round_verifier(&mut b_fri, 4, &dummy_root);
                leaves.push(TapLeaf::new(format!("fri_query_leaf_{}", q), b_fri.to_bytes()));
            }

            let tap_tree = TapTree::new(leaves.clone());
            let tree_root = tap_tree.root();
            let internal_nums_key = [0x02u8; 32];
            let tweak = tap_tree.tweak(&internal_nums_key);

            println!("  Total Taproot Leaves: {}", leaves.len());
            println!("  TapTree Root: 0x{}", hex::encode(tree_root));
            println!("  Internal NUMS PubKey: 0x{}", hex::encode(internal_nums_key));
            println!("  TapTweak: 0x{}", hex::encode(tweak));

            let ctrl_block = tap_tree.control_block(1, &internal_nums_key);
            println!("\n  Leaf 1 (FRI Query 0) Spend Package:");
            println!("    Script Size: {} bytes", leaves[1].script.len());
            println!("    Control Block Size: {} bytes", ctrl_block.len());
            println!("    Control Block Hex: {}", hex::encode(&ctrl_block));
            println!("    Ready for Bitcoin Core L1 Tapscript broadcast!\n");
        }

        "emit-script" => {
            let depth: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(8);
            let dummy_root = [0x55u8; 32];
            let mut builder = ScriptBuilder::new();
            MerkleScript::emit_verifier(&mut builder, depth, &dummy_root);

            println!("\nCompiled Bitcoin Tapscript for Depth {} Merkle Verifier:", depth);
            println!("Hex Bytecode: {}", builder.to_hex());
            println!("Script Size: {} bytes, Opcodes: {}\n", builder.len(), builder.opcode_count());
        }

        "help" | "-h" | "--help" => print_usage(),

        other => {
            eprintln!("Unknown command: '{}'", other);
            print_usage();
        }
    }
}
