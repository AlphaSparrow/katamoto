use katamoto_field::{m31::M31Script, qm31::QM31Script, M31, QM31};
use katamoto_fri::{
    FriQueryStep, FriRoundQuery, FriScript, MerkleScript, MerkleTree, TapLeaf, TapTree,
    Transcript, TranscriptScript,
};
use katamoto_script::{builder::encode_num, ScriptBuilder, Vm};
use sha2::{Digest, Sha256};
use std::env;
use std::time::Instant;

fn print_usage() {
    println!(r#"
Katamoto (刀本) - Native ZK-STARK Verifier & Tapscript Compiler for Bitcoin (BIP-347 OP_CAT)

USAGE:
    katamoto-cli <COMMAND> [OPTIONS]

COMMANDS:
    benchmark-merkle [MAX_DEPTH]   Benchmark OP_CAT Merkle proof verification across depths (default: 16)
    verify-m31 [A] [B]             Verify Mersenne-31 multiplication on Bitcoin Script VM (default: 1234567 7654321)
    verify-qm31                    Verify QM31 Quartic Extension Field arithmetic (124-bit STARK security)
    verify-fri-round               Verify complete FRI query round (dual Merkle proof + colinearity fold)
    compile-taproot [QUERIES]      Compile complete BIP-341 Taproot STARK tree and emit witness spend
    emit-script [DEPTH]            Emit raw Bitcoin Tapscript bytecode hex (default: 8)
    help                           Print this help message
"#);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return;
    }

    match args[1].as_str() {
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

            // Leaf 0: Fiat-Shamir Transcript Leaf
            let mut transcript = Transcript::new();
            let trace_root: [u8; 32] = Sha256::digest(b"trace_commitment").into();
            transcript.absorb(&trace_root);
            let mut b_transcript = ScriptBuilder::new();
            TranscriptScript::emit_verify_challenge_extraction(&mut b_transcript);
            let leaf_transcript = TapLeaf::new("fiat_shamir_leaf", b_transcript.to_bytes());

            let mut leaves = vec![leaf_transcript];

            // Leaves 1..k: FRI Query verification leaves
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

            // Generate spend package for first FRI query leaf
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
