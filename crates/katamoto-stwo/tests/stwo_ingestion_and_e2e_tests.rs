use katamoto_field::{qm31::QM31, M31};
use katamoto_fri::batch_merkle::{MixedBatchMerkleTree, MixedColumn};
use katamoto_fri::merkle::MerkleProof;
use katamoto_script::Vm;
use katamoto_stwo::{
    RiscvOpcode, RiscvStatement, RiscvStep, StwoFriProof, StwoFriQuery,
    StwoOodEvaluations, StwoProof, StwoTapTreeCompiler,
};
use std::fs;
use std::path::Path;

#[test]
fn test_stwo_native_ingestion_serialization_and_taptree_e2e() {
    let test_dir = Path::new("target/test_fixtures");
    fs::create_dir_all(test_dir).expect("Failed to create test fixtures directory");
    let bin_path = test_dir.join("test_stwo_proof.bin");

    // 1. Construct 16-row multi-step execution loop trace (Fibonacci-like state transitions)
    // col0: fib(n), col1: fib(n+1), col2: running accumulator
    let mut f0 = 0u32;
    let mut f1 = 1u32;
    let mut col0_vals = Vec::with_capacity(16);
    let mut col1_vals = Vec::with_capacity(16);
    let mut col2_vals = Vec::with_capacity(16);

    for i in 0..16 {
        col0_vals.push(M31::new(f0 as u64));
        col1_vals.push(M31::new(f1 as u64));
        col2_vals.push(M31::new(f0.wrapping_add(i) as u64));
        let next = f0.wrapping_add(f1);
        f0 = f1;
        f1 = next;
    }

    let col0 = MixedColumn::new(col0_vals);
    let col1 = MixedColumn::new(col1_vals);
    let col2 = MixedColumn::new(col2_vals);
    let columns = vec![col0, col1, col2];

    let mixed_tree = MixedBatchMerkleTree::new(columns.clone());
    let trace_root = mixed_tree.root();

    // 2. Compute valid PoW grinding nonce for trace root
    let pow_bits = 8;
    let mut trace_pow_nonce = 0u64;
    while !katamoto_fri::Transcript::verify_pow(&trace_root, trace_pow_nonce, pow_bits) {
        trace_pow_nonce += 1;
    }

    // 3. Assemble complete StwoProof
    let ood_x = QM31::from_u32(314159, 271828, 141421, 173205);
    let ood_y = QM31::from_u32(12345, 67890, 11223, 44556);
    let ood_evaluations = StwoOodEvaluations {
        ood_point_x: ood_x,
        ood_point_y: ood_y,
        trace_evals: vec![
            QM31::from_u32(100, 200, 300, 400),
            QM31::from_u32(500, 600, 700, 800),
            QM31::from_u32(900, 1000, 1100, 1200),
        ],
        quotient_eval: QM31::from_u32(42, 84, 126, 168),
    };

    let fri_proof = StwoFriProof {
        round_commitments: vec![[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]],
        queries: vec![
            StwoFriQuery {
                query_idx: 5,
                f_p: M31::new(1337),
                f_conj: M31::new(7331),
                merkle_proof: MerkleProof {
                    leaf: [0x55u8; 32],
                    siblings: vec![[0x66u8; 32], [0x77u8; 32]],
                    directions: vec![false, true],
                },
            },
            StwoFriQuery {
                query_idx: 11,
                f_p: M31::new(2048),
                f_conj: M31::new(4096),
                merkle_proof: MerkleProof {
                    leaf: [0x88u8; 32],
                    siblings: vec![[0x99u8; 32]],
                    directions: vec![true],
                },
            },
        ],
        final_poly_coefficients: vec![QM31::ONE, QM31::from_u32(7, 13, 19, 23)],
    };

    let original_proof = StwoProof {
        statement_hash: [0xca; 32],
        preprocessed_root: Some([0xfe; 32]),
        trace_root,
        lookup_root: Some([0xba; 32]),
        quotient_root: [0xbe; 32],
        ood_evaluations,
        fri_proof,
        pow_nonce: trace_pow_nonce,
        pow_bits,
    };

    // 4. Save to disk in native binary format
    original_proof
        .save_to_file(&bin_path)
        .expect("Failed to save StwoProof to binary file");

    // 5. Ingest from disk and verify exact byte-for-byte fidelity
    let loaded_proof =
        StwoProof::load_from_file(&bin_path).expect("Failed to load StwoProof from binary file");
    assert_eq!(
        original_proof, loaded_proof,
        "Loaded proof must be byte-level identical to original"
    );

    // 6. Test Hex serialization and roundtrip
    let hex_repr = loaded_proof.to_hex();
    let proof_from_hex = StwoProof::from_hex(&hex_repr).expect("Failed to parse hex proof");
    assert_eq!(
        original_proof, proof_from_hex,
        "Hex-deserialized proof must match original"
    );

    // 7. Define RISC-V state transition statement and step
    let riscv_statement = RiscvStatement {
        initial_pc: 0x00010000,
        final_pc: 0x00010004,
        cycle_count: 1,
        initial_state_root: [0x11; 32],
        final_state_root: [0x22; 32],
        program_digest: [0x33; 32],
    };

    let riscv_step = RiscvStep {
        pc_curr: 0x00010000,
        pc_next: 0x00010004,
        opcode: RiscvOpcode::Add,
        rs1_val: 10,
        rs2_val: 20,
        rd_val: 30,
        imm: 0,
    };

    // 8. Compile ingested proof into TapTree
    let package = StwoTapTreeCompiler::compile(
        &loaded_proof,
        &columns,
        5, // query row index
        Some(&riscv_statement),
        Some(&riscv_step),
    );

    // 9. Verify consensus conformance & telemetry
    assert!(
        package.telemetry.conforms_to_consensus,
        "TapTree scripts must strictly conform to BIP-342 consensus limits"
    );
    assert!(
        package.telemetry.max_witness_bytes < 4000,
        "Max witness size must remain minimal"
    );
    assert_eq!(package.tap_tree.leaves.len(), 3 + loaded_proof.fri_proof.queries.len() + 1);

    // 10. Execute and verify EVERY leaf spend in the Tapscript Vm
    for spend in &package.spends {
        let mut vm = Vm::with_witness(spend.witness_items.clone());
        let ok = vm.execute(&spend.leaf_script).unwrap_or_else(|e| {
            panic!(
                "Execution of leaf '{}' failed: {:?}",
                spend.leaf_name, e
            )
        });
        assert!(
            ok,
            "Leaf '{}' execution did not return true",
            spend.leaf_name
        );
        assert_eq!(
            vm.stack().last().unwrap(),
            &[1],
            "Leaf '{}' stack top must be 1 (true)",
            spend.leaf_name
        );
    }

    // 11. Negative test: verify tampered witness fails Vm execution
    let mut tampered_witness = package.spends[0].witness_items.clone();
    if let Some(item) = tampered_witness.first_mut() {
        if !item.is_empty() {
            item[0] ^= 0xff; // Invert first byte
        } else {
            *item = vec![0xff];
        }
    }
    let mut tampered_vm = Vm::with_witness(tampered_witness);
    let tampered_res = tampered_vm.execute(&package.spends[0].leaf_script);
    // Either it errors out or evaluates to false / not 1
    let passed = match tampered_res {
        Ok(res) => res && tampered_vm.stack().last().map(|s| s.as_slice()) == Some(&[1]),
        Err(_) => false,
    };
    assert!(
        !passed,
        "Tampered witness MUST fail validation in the Tapscript Vm"
    );

    // Clean up test file
    let _ = fs::remove_file(bin_path);
}
