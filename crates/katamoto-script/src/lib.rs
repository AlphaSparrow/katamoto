pub mod builder;
pub mod opcodes;
pub mod vm;

pub use builder::{decode_num, encode_num, ScriptBuilder};
pub use opcodes::Opcode;
pub use vm::{ExecutionStats, Vm, VmError, MAX_ELEMENT_SIZE, MAX_STACK_SIZE};

#[cfg(test)]
mod tests {
    use super::*;

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
}
