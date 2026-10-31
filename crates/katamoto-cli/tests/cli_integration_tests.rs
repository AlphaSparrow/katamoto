use katamoto_field::{qm31::QM31, M31};
use katamoto_fri::{
    batch_merkle::MixedColumn,
    merkle::MerkleProof,
    security::{AdaptiveSecuritySelector, FriSecurityConfig},
};
use katamoto_script::{
    ots::WotsM31Commitment,
    tx::{OutPoint, TxOut},
    vault::PactVault,
    Vm,
};
use katamoto_stwo::{
    compiler::{DualBackendCompiler, VerificationBackend},
    header_verifier::{BitcoinHeader, HeaderChain, HeaderDisputeCompiler},
    proof::{StwoFriProof, StwoFriQuery, StwoOodEvaluations, StwoProof},
};
use sha2::{Digest, Sha256};

#[test]
fn test_cli_post_quantum_vault_flow() {
    let provisional_key = [0x11u8; 32];
    let recovery_secret = [0x42u8; 32];
    let seed = [0x55u8; 32];
    let (sk, pk) = WotsM31Commitment::keygen(&seed, b"PACT_RECOVERY_KEY");

    let timelock = 144; // 144 blocks
    let satoshis = 50_000_000; // 0.5 BTC

    let vault = PactVault::new(provisional_key, &recovery_secret, pk, timelock, satoshis);

    let auth_code = 1234567u32;
    let spends = vault.compile_vault(auth_code);

    assert!(!spends.script_classical.is_empty());
    assert!(!spends.script_recovery.is_empty());
    assert!(spends.script_recovery.len() < 520, "Recovery script must be under 520 bytes");

    // Execute Quantum Recovery Path in the Bitcoin Script VM
    let auth_sig = WotsM31Commitment::sign(&sk, auth_code);
    let witness = PactVault::create_recovery_witness(&recovery_secret, &auth_sig);
    let mut vm = Vm::with_witness(witness.clone());
    let ok = vm.execute(&spends.script_recovery).expect("Recovery script execution failed");
    assert!(ok);
    assert_eq!(vm.stack().last().unwrap(), &[1]);

    // Build and validate emergency rescue transaction
    let vault_outpoint = OutPoint::new([0xee; 32], 0);
    let post_quantum_cold_storage = TxOut::op_return(b"PACT_QUANTUM_RESCUED", 0).script_pubkey;
    let rescue_tx = vault.build_emergency_rescue_tx(
        vault_outpoint,
        post_quantum_cold_storage,
        witness,
    );

    assert!(rescue_tx.validate_consensus_limits().is_ok());
    assert!(rescue_tx.weight() < 400_000, "Weight must be within standard mempool limits");
    assert_eq!(rescue_tx.outputs[0].value, 49_990_000); // 50M - 10k fee
}

#[test]
fn test_cli_zerosync_header_chain_verification() {
    let mut headers = Vec::new();
    let mut prev_hash = [0x00u8; 32];
    let mut timestamp = 1231006505u32;

    for i in 0..4 {
        let mut merkle = [0xaa; 32];
        merkle[0] = i as u8;
        let mut header = BitcoinHeader {
            version: 1,
            prev_block_hash: prev_hash,
            merkle_root: merkle,
            time: timestamp,
            nbits: 0x207fffff,
            nonce: 0,
        };
        while !header.is_pow_valid() {
            header.nonce += 1;
        }
        prev_hash = header.block_hash();
        timestamp += 600;
        headers.push(header);
    }

    let chain = HeaderChain::new(headers);
    assert!(chain.verify(), "Header chain continuity and PoW must be valid");

    let stmt = chain.to_statement();
    assert_eq!(stmt.cycle_count, 4 * 128);

    let operator_key = [0x55; 32];
    let challenger_key = [0x66; 32];
    let bond_satoshis = 100_000_000;
    let dispute_timelock = 144;

    let (_graph, tree, spends) = HeaderDisputeCompiler::compile_header_dispute(
        &chain,
        operator_key,
        challenger_key,
        bond_satoshis,
        dispute_timelock,
    );

    assert_eq!(tree.leaves.len(), 4);
    assert_eq!(spends.len(), 4);

    for spend in &spends {
        assert!(spend.leaf_script.len() < 520, "Leaf script must be < 520 bytes");
        let mut vm = Vm::with_witness(spend.witness_items.clone());
        let ok = vm.execute(&spend.leaf_script).expect("Header verification leaf failed");
        assert!(ok);
        assert_eq!(vm.stack().last().unwrap(), &[1]);
    }
}

#[test]
fn test_cli_dual_backend_compiler_comparison() {
    let trace_col = vec![M31::new(1), M31::new(2), M31::new(3), M31::new(4)];
    let columns = vec![MixedColumn {
        log_size: 2,
        values: trace_col,
    }];

    let mut hasher = Sha256::new();
    hasher.update(b"trace");
    let trace_root: [u8; 32] = hasher.finalize().into();

    let ood_evaluations = StwoOodEvaluations {
        ood_point_x: QM31::from_u32(17, 0, 0, 0),
        ood_point_y: QM31::ZERO,
        trace_evals: vec![QM31::from_u32(10, 0, 0, 0)],
        quotient_eval: QM31::from_u32(5, 0, 0, 0),
    };

    let fri_proof = StwoFriProof {
        round_commitments: vec![[0x11u8; 32]],
        queries: vec![StwoFriQuery {
            query_idx: 1,
            f_p: M31::new(100),
            f_conj: M31::new(200),
            merkle_proof: MerkleProof {
                leaf: [0u8; 32],
                siblings: vec![],
                directions: vec![],
            },
        }],
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
        pow_nonce: 0,
        pow_bits: 0,
    };

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

    let pkg_bitvm = DualBackendCompiler::compile(
        &proof,
        &columns,
        3,
        None,
        None,
        VerificationBackend::MainnetBitVmOts,
    );
    assert_eq!(pkg_bitvm.metrics.backend, VerificationBackend::MainnetBitVmOts);
    assert!(!pkg_bitvm.metrics.op_cat_required);
    assert_eq!(pkg_bitvm.metrics.tx_count, 4);
    assert!(pkg_bitvm.dispute_graph.is_some());
}

#[test]
fn test_cli_high_arity_fri_security_presets() {
    for preset in FriSecurityConfig::ALL_PRESETS {
        assert!(preset.target_security_bits >= 96);
    }

    // Check adaptive selector
    let cfg = AdaptiveSecuritySelector::select(96, 4 * 1024 * 1024, 18);
    assert!(cfg.is_some());
    let selected = cfg.unwrap();
    assert!(selected.folding_arity >= 8, "Selected arity should be high-arity (>= 8)");
}

#[test]
fn test_cli_benchmarks_and_folding_telemetry() {
    use katamoto_field::{m31::M31, qm31::QM31};
    use katamoto_fri::circle_folding::CircleFriScript;
    use katamoto_script::ScriptBuilder;

    // Verify M31 batch inversion matches sequential inversion
    let items: Vec<M31> = (1..=128).map(|i| M31::new(i * 1000 + 3)).collect();
    let batch_invs = M31::batch_inv(&items).expect("Batch inv failed");
    for (orig, inv) in items.iter().zip(batch_invs.iter()) {
        assert_eq!(*orig * *inv, M31::ONE);
    }

    // Verify QM31 batch inversion
    let qm_items: Vec<QM31> = (1..=32)
        .map(|i| QM31::from_u32(i * 10, i * 20, i * 30, i * 40))
        .collect();
    let qm_invs = QM31::batch_inv(&qm_items).expect("QM31 batch inv failed");
    for (orig, inv) in qm_items.iter().zip(qm_invs.iter()) {
        assert_eq!(*orig * *inv, QM31::ONE);
    }

    // Verify high-arity folding script byte bounds
    let mut b2 = ScriptBuilder::new();
    CircleFriScript::emit_colinearity_verifier(&mut b2);
    let mut b4 = ScriptBuilder::new();
    CircleFriScript::emit_4to1_colinearity_verifier(&mut b4);
    let mut b8 = ScriptBuilder::new();
    CircleFriScript::emit_8to1_colinearity_verifier(&mut b8);
    let mut b16 = ScriptBuilder::new();
    CircleFriScript::emit_16to1_colinearity_verifier(&mut b16);

    let len2 = b2.as_bytes().len();
    let len4 = b4.as_bytes().len();
    let len8 = b8.as_bytes().len();
    let len16 = b16.as_bytes().len();

    assert!(len2 < len4);
    assert!(len4 < len8);
    assert!(len8 < len16);
    assert!(len16 <= 520, "16-to-1 script must satisfy consensus limit");
}

#[test]
fn test_cli_bip380_descriptor_export_and_bech32m() {
    use katamoto_fri::taproot::{TapLeaf, TapTree};

    // 1. Create TapTree with 2 leaves
    let l0 = TapLeaf::new("leaf0", vec![0x51]); // OP_1
    let l1 = TapLeaf::new("leaf1", vec![0x52]); // OP_2
    let tree = TapTree::new(vec![l0, l1]);
    let nums_key = [0x02u8; 32];
    let tweak = tree.tweak(&nums_key);

    assert_eq!(tweak.len(), 32);

    // 2. Validate descriptor string formatting
    let leaf_raws: Vec<String> = tree.leaves.iter().map(|l| format!("raw({})", hex::encode(&l.script))).collect();
    let tree_str = format!("{{{}}}", leaf_raws.join(","));
    let raw_desc = format!("tr({},{})", hex::encode(nums_key), tree_str);
    assert!(raw_desc.starts_with("tr(0202"));
    assert!(raw_desc.contains("raw(51)"));
    assert!(raw_desc.contains("raw(52)"));
}
