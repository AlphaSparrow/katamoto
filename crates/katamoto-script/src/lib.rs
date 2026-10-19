pub mod builder;
pub mod opcodes;
pub mod ots;
pub mod tx;
pub mod vm;

pub use builder::{
    decode_num, emit_verify_packed_hints, encode_num, pack_m31_hints, OptimizationReport,
    ScriptBuilder, ScriptOp, ScriptOptimizer,
};
pub use opcodes::Opcode;
pub use ots::{
    LamportOTS, LamportPrivateKey, LamportPublicKey, LamportSignature, WinternitzOTS,
    WotsPrivateKey, WotsPublicKey, WotsSignature,
};
pub use tx::{
    compute_sha_amounts, compute_sha_outputs, compute_sha_prevouts, compute_sha_scriptpubkeys,
    compute_sha_sequences, tagged_hash, write_varint, ConsensusError, CovenantScript, OutPoint,
    TaprootSighashPreimage, TestMempoolAccept, Transaction, TxIn, TxOut, Witness,
    MAX_STANDARD_TX_WEIGHT, SEQUENCE_FINAL,
};
pub use vm::{ExecutionStats, ScriptProfile, Vm, VmError, MAX_ELEMENT_SIZE, MAX_STACK_SIZE};

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    #[test]
    fn test_bip347_op_cat_basic() {
        let mut builder = ScriptBuilder::new();
        builder.push_slice(b"Hello, ");
        builder.push_slice(b"Bitcoin OP_CAT!");
        builder.op_cat();

        let mut vm = Vm::new();
        let res = vm.execute(builder.as_bytes()).expect("Execution should succeed");
        assert!(res);
        assert_eq!(vm.stack().len(), 1);
        assert_eq!(vm.stack()[0], b"Hello, Bitcoin OP_CAT!");
    }

    #[test]
    fn test_bip347_op_cat_max_element_limit() {
        let mut builder = ScriptBuilder::new();
        let chunk300 = vec![0x42; 300];
        builder.push_slice(&chunk300);
        builder.push_slice(&chunk300);
        builder.op_cat(); // 300 + 300 = 600 > 520!

        let mut vm = Vm::new();
        let err = vm.execute(builder.as_bytes()).unwrap_err();
        assert_eq!(err, VmError::ElementTooLarge(600));
    }

    #[test]
    fn test_merkle_parent_hash_gadget() {
        use sha2::{Digest, Sha256};

        let left = Sha256::digest(b"leaf_0").to_vec();
        let right = Sha256::digest(b"leaf_1").to_vec();

        // Expected parent hash: SHA256(left || right)
        let mut combined = left.clone();
        combined.extend_from_slice(&right);
        let expected_parent = Sha256::digest(&combined).to_vec();

        // Bitcoin script with OP_CAT:
        // [left, right] -> OP_CAT -> OP_SHA256 -> expected_parent -> OP_EQUAL
        let mut builder = ScriptBuilder::new();
        builder.push_slice(&left);
        builder.push_slice(&right);
        builder.op_cat();
        builder.op_sha256();
        builder.push_slice(&expected_parent);
        builder.op_equal();

        let mut vm = Vm::new();
        let ok = vm.execute(builder.as_bytes()).expect("Merkle step execution failed");
        assert!(ok);
        assert_eq!(vm.stack().last().unwrap(), &[1]);
    }

    #[test]
    fn test_script_num_encoding() {
        assert_eq!(encode_num(0), Vec::<u8>::new());
        assert_eq!(encode_num(1), vec![0x01]);
        assert_eq!(encode_num(-1), vec![0x81]);
        assert_eq!(encode_num(127), vec![0x7f]);
        assert_eq!(encode_num(128), vec![0x80, 0x00]);
        assert_eq!(encode_num(-128), vec![0x80, 0x80]);

        for num in [-2147483647, -1000, -1, 0, 1, 1000, 2147483647] {
            let enc = encode_num(num);
            let dec = decode_num(&enc, 4).unwrap();
            assert_eq!(num, dec);
        }
    }

    #[test]
    fn test_comparison_and_logic_opcodes() {
        // Test GreaterThanOrEqual & LessThanOrEqual
        let mut b = ScriptBuilder::new();
        b.push_int(10).push_int(10).op_greater_than_or_equal(); // 1
        b.push_int(9).push_int(10).op_less_than_or_equal(); // 1
        b.op_bool_and(); // 1
        b.push_int(5).push_int(2).push_int(10).op_within(); // 1 (2 <= 5 < 10)
        b.op_bool_and(); // 1
        b.push_int(7).push_int(8).op_num_not_equal(); // 1
        b.op_bool_and(); // 1

        let mut vm = Vm::new();
        let ok = vm.execute(b.as_bytes()).unwrap();
        assert!(ok);
        assert_eq!(vm.stack().last().unwrap(), &[1]);

        // Test 2SWAP and 2ROT
        let mut b2 = ScriptBuilder::new();
        // push 1, 2, 3, 4 -> 2SWAP -> 3, 4, 1, 2
        b2.push_int(1).push_int(2).push_int(3).push_int(4);
        b2.push_opcode(Opcode::Op2Swap);
        let mut vm2 = Vm::new();
        vm2.execute(b2.as_bytes()).unwrap();
        assert_eq!(vm2.stack()[0], encode_num(3));
        assert_eq!(vm2.stack()[1], encode_num(4));
        assert_eq!(vm2.stack()[2], encode_num(1));
        assert_eq!(vm2.stack()[3], encode_num(2));
    }

    #[test]
    fn test_taproot_tx_serialization_and_weights() {
        let dummy_txid = [0xabu8; 32];
        let outpoint = OutPoint::new(dummy_txid, 0);
        let input = TxIn::new_taproot(outpoint);

        let output_key = [0x55u8; 32];
        let output = TxOut::p2tr(&output_key, 100_000_000); // 1 BTC

        let witness = Witness::new(vec![
            vec![0x01, 0x02, 0x03], // witness item
            vec![0x60],             // dummy script
            vec![0xc0; 33],         // dummy control block
        ]);

        let tx = Transaction::new(2, vec![input], vec![output], vec![witness]);
        assert!(tx.has_witness());

        let raw_bytes = tx.serialize();
        assert!(!raw_bytes.is_empty());
        assert_eq!(&raw_bytes[0..4], &2i32.to_le_bytes()); // version
        assert_eq!(raw_bytes[4], 0x00); // segwit marker
        assert_eq!(raw_bytes[5], 0x01); // segwit flag

        let legacy_bytes = tx.serialize_legacy();
        assert!(legacy_bytes.len() < raw_bytes.len());

        let txid = tx.txid();
        let wtxid = tx.wtxid();
        assert_eq!(txid.len(), 64);
        assert_eq!(wtxid.len(), 64);
        assert_ne!(txid, wtxid);

        assert!(tx.weight() > 0);
        assert!(tx.vsize() > 0);
        assert!(tx.validate_consensus_limits().is_ok());
    }

    #[test]
    fn test_taproot_tx_consensus_limits_enforced() {
        let outpoint = OutPoint::new([0x11u8; 32], 0);
        let input = TxIn::new_taproot(outpoint);
        let output = TxOut::op_return(b"KATAMOTO_PROOF", 0);

        // Case 1: Witness item exceeding 520 bytes
        let oversized_item = vec![0x77u8; 521];
        let invalid_witness = Witness::new(vec![oversized_item]);
        let invalid_tx = Transaction::new(2, vec![input.clone()], vec![output.clone()], vec![invalid_witness]);
        assert_eq!(
            invalid_tx.validate_consensus_limits().unwrap_err(),
            ConsensusError::WitnessElementTooLarge(521)
        );

        // Case 2: Witness items count exceeding 1000
        let many_items = vec![vec![1u8]; 1001];
        let stack_overflow_wit = Witness::new(many_items);
        let stack_overflow_tx = Transaction::new(2, vec![input], vec![output], vec![stack_overflow_wit]);
        assert_eq!(
            stack_overflow_tx.validate_consensus_limits().unwrap_err(),
            ConsensusError::WitnessStackOverflow(1001)
        );
    }

    #[test]
    fn test_testmempoolaccept_rpc_formatter() {
        let raw_hex = "020000000001010000000000";
        let req = TestMempoolAccept::format_rpc_request(raw_hex);
        assert!(req.contains("testmempoolaccept"));
        assert!(req.contains(raw_hex));

        let curl = TestMempoolAccept::format_curl_command(raw_hex, "user", "pass", 18443);
        assert!(curl.contains("18443"));
        assert!(curl.contains("user:pass"));
    }

    #[test]
    fn test_script_optimizer_peephole_passes() {
        let mut builder = ScriptBuilder::new();
        // Push items
        builder.push_int(42);
        builder.push_int(100);

        // Redundant swap pair
        builder.op_swap();
        builder.op_swap();

        // Redundant altstack pair
        builder.op_toaltstack();
        builder.op_fromaltstack();

        // Redundant dup + drop
        builder.op_dup();
        builder.op_drop();

        // Nop
        builder.push_opcode(Opcode::OpNop);

        // Arithmetic 1add + 1sub cancellation
        builder.push_opcode(Opcode::Op1Add);
        builder.push_opcode(Opcode::Op1Sub);

        let (opt, report) = builder.optimize();
        assert_eq!(report.redundant_swaps_removed, 1);
        assert_eq!(report.altstack_pairs_removed, 1);
        assert_eq!(report.dup_drops_removed, 1);
        assert_eq!(report.nops_removed, 1);
        assert_eq!(report.arithmetic_cancels_removed, 1);
        assert!(opt.len() < builder.len());

        // Verify VM executes optimized script identically
        let mut vm = Vm::new();
        let res = vm.execute(opt.as_bytes()).unwrap();
        assert!(res);
        assert_eq!(vm.stack().len(), 2);
    }

    #[test]
    fn test_vm_watermark_profiler_and_limits() {
        let mut builder = ScriptBuilder::new();
        for _ in 0..50 {
            builder.push_int(1);
            builder.op_toaltstack();
        }
        for _ in 0..50 {
            builder.push_int(2);
        }

        let mut vm = Vm::new();
        vm.execute(builder.as_bytes()).unwrap();

        let profile = vm.profile();
        assert_eq!(profile.stats.max_altstack_depth, 50);
        assert_eq!(profile.stats.max_combined_stack_depth, 100);
        assert!(!profile.near_stack_limit);
        assert!(profile.element_size_compliant);

        // Test combined limit overflow: 1000 items
        let mut overflow_builder = ScriptBuilder::new();
        for _ in 0..1001 {
            overflow_builder.push_int(1);
        }
        let mut overflow_vm = Vm::new();
        let err = overflow_vm.execute(overflow_builder.as_bytes()).unwrap_err();
        assert_eq!(err, VmError::StackOverflow);
    }

    #[test]
    fn test_hint_packing_and_cat_verification() {
        let hints = vec![12345u32, 67890u32, 11111u32];
        let packed = pack_m31_hints(&hints);
        assert_eq!(packed.len(), 12);

        let mut builder = ScriptBuilder::new();
        emit_verify_packed_hints(&mut builder, hints.len());

        // Witness layout: [packed, part_0, part_1, part_2]
        let witness = vec![
            packed.clone(),
            hints[0].to_le_bytes().to_vec(),
            hints[1].to_le_bytes().to_vec(),
            hints[2].to_le_bytes().to_vec(),
        ];

        let mut vm = Vm::with_witness(witness);
        let res = vm.execute(builder.as_bytes()).unwrap();
        assert!(res);
    }

    #[test]
    fn test_sighash_introspection_covenant() {
        let covenant_pubkey = [0x33u8; 32];
        let outpoint = OutPoint::new([0xaa; 32], 0);
        let input = TxIn::new_taproot(outpoint);
        let expected_output = TxOut::p2tr(&[0x44; 32], 50_000_000);
        let tx = Transaction::new(2, vec![input], vec![expected_output.clone()], vec![Witness::default()]);

        let prevout = TxOut::p2tr(&covenant_pubkey, 50_000_000);
        let preimage = tx.build_sighash_preimage(0, &[prevout]);
        let sighash = preimage.compute_sighash();

        // Expected output hash from the transaction
        let expected_sha_outputs = compute_sha_outputs(&tx.outputs);

        // Build covenant script
        let mut builder = ScriptBuilder::new();
        CovenantScript::emit_sighash_covenant_verifier(&mut builder, &expected_sha_outputs, &covenant_pubkey);

        // Build valid signature
        let mut mock_sig = [0u8; 64];
        let tag = sha2::Sha256::digest([&covenant_pubkey[..], &sighash[..]].concat());
        mock_sig[..32].copy_from_slice(&tag);

        let witness = CovenantScript::create_covenant_witness(&mock_sig, &covenant_pubkey, &preimage);
        let mut vm = Vm::with_witness(witness);
        vm.set_tx_sighash(sighash);

        let res = vm.execute(builder.as_bytes()).expect("Covenant execution should succeed");
        assert!(res);

        // Tampering test: different output hash must cause verification failure
        let tampered_outputs = [0xffu8; 32];
        let mut tampered_builder = ScriptBuilder::new();
        CovenantScript::emit_sighash_covenant_verifier(&mut tampered_builder, &tampered_outputs, &covenant_pubkey);
        let tampered_witness = CovenantScript::create_covenant_witness(&mock_sig, &covenant_pubkey, &preimage);
        let mut tampered_vm = Vm::with_witness(tampered_witness);
        tampered_vm.set_tx_sighash(sighash);
        assert_eq!(tampered_vm.execute(tampered_builder.as_bytes()).unwrap_err(), VmError::VerifyFailed);
    }

    #[test]
    fn test_winternitz_ots_and_tapscript_verification() {
        let seed = [0x55u8; 32];
        let (sk, pk) = WinternitzOTS::keygen(&seed);

        let message = [0x7au8; 32];
        let sig = WinternitzOTS::sign(&sk, &message);
        assert!(WinternitzOTS::verify(&pk, &message, &sig));

        // Test 4-digit slice verification in Bitcoin Script
        let slice_count = 4;
        let mut builder = ScriptBuilder::new();
        WinternitzOTS::emit_verifier(&mut builder, &pk, &message, slice_count);

        let witness = WinternitzOTS::create_witness(&sig, slice_count);
        let mut vm = Vm::with_witness(witness);
        let res = vm.execute(builder.as_bytes()).expect("WOTS script verification should succeed");
        assert!(res);
    }

    #[test]
    fn test_lamport_ots_and_tapscript_verification() {
        let seed = [0x88u8; 32];
        let bit_count = 8;
        let (sk, pk) = LamportOTS::keygen(&seed, bit_count);

        let bits = vec![true, false, true, true, false, false, true, false];
        let sig = LamportOTS::sign(&sk, &bits);

        let mut builder = ScriptBuilder::new();
        LamportOTS::emit_verifier(&mut builder, &pk, &bits);

        let witness: Vec<Vec<u8>> = sig.preimages.into_iter().map(|p| p.to_vec()).collect();
        let mut vm = Vm::with_witness(witness);
        let res = vm.execute(builder.as_bytes()).expect("Lamport script verification should succeed");
        assert!(res);
    }
}
