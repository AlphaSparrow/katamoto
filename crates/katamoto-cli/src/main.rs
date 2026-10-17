use katamoto_field::{m31::M31Script, M31};
use katamoto_fri::{MerkleScript, MerkleTree};
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
