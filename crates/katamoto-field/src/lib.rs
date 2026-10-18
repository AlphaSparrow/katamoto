pub mod m31;
pub mod qm31;

pub use m31::{M31Script, M31, M31_P};
pub use qm31::{CM31, QM31, QM31Script};

#[cfg(test)]
mod tests {
    use super::*;
    use katamoto_script::{builder::encode_num, ScriptBuilder, Vm};

    #[test]
    fn test_m31_native_math() {
        let a = M31::new(2000000000);
        let b = M31::new(200000000);
        let c = a + b;
        assert_eq!(c.value(), 52516353);

        let p_minus_1 = M31::new(M31_P as u64 - 1);
        let one = M31::ONE;
        assert_eq!((p_minus_1 + one).value(), 0);

        let diff = M31::new(5) - M31::new(10);
        assert_eq!(diff.value(), (M31_P - 5) as u32);

        // Multiplication & inversion
        let x = M31::new(1234567);
        let inv_x = x.inv().expect("Non-zero element has inverse");
        assert_eq!((x * inv_x).value(), 1);
    }

    #[test]
    fn test_m31_script_add_gadget() {
        let a = 1500000000i64;
        let b = 1000000000i64;
        let expected = ((a + b) % M31_P) as i64;

        let mut builder = ScriptBuilder::new();
        builder.push_int(a);
        builder.push_int(b);
        M31Script::emit_add(&mut builder);

        let mut vm = Vm::new();
        let ok = vm.execute(builder.as_bytes()).expect("Script execution failed");
        assert!(ok);
        assert_eq!(vm.stack().len(), 1);
        assert_eq!(vm.stack()[0], encode_num(expected));
    }

    #[test]
    fn test_m31_script_sub_gadget() {
        let a = 100i64;
        let b = 500i64;
        let expected = (a - b + M31_P) as i64;

        let mut builder = ScriptBuilder::new();
        builder.push_int(a);
        builder.push_int(b);
        M31Script::emit_sub(&mut builder);

        let mut vm = Vm::new();
        let ok = vm.execute(builder.as_bytes()).expect("Script execution failed");
        assert!(ok);
        assert_eq!(vm.stack().len(), 1);
        assert_eq!(vm.stack()[0], encode_num(expected));
    }

    #[test]
    fn test_m31_script_mul_verify_gadget() {
        let a = M31::new(12345);
        let b = M31::new(6789);
        let c = a * b;

        let bits = b.to_bits();

        // Witness layout on stack:
        // [expected_c, a, bit_30, bit_29, ..., bit_0]
        let mut witness: Vec<Vec<u8>> = Vec::new();
        witness.push(encode_num(c.as_i64()));
        witness.push(encode_num(a.as_i64()));
        // Push bits from 30 down to 0
        for i in (0..31).rev() {
            witness.push(encode_num(bits[i] as i64));
        }

        let mut builder = ScriptBuilder::new();
        M31Script::emit_mul_verify(&mut builder);

        let mut vm = Vm::with_witness(witness);
        let ok = vm.execute(builder.as_bytes()).expect("Multiplication verification failed");
        assert!(ok);
        assert_eq!(vm.stack().last().unwrap(), &[1]);
    }

    #[test]
    fn test_qm31_native_math() {
        let a = QM31::from_u32(1, 2, 3, 4);
        let b = QM31::from_u32(5, 6, 7, 8);

        // Addition and Subtraction
        let sum = a + b;
        assert_eq!(sum, QM31::from_u32(6, 8, 10, 12));
        assert_eq!(sum - b, a);

        // Multiplication & Inversion
        let x = QM31::from_u32(12, 34, 56, 78);
        let inv_x = x.inv().expect("Non-zero QM31 has inverse");
        let prod = x * inv_x;
        assert_eq!(prod, QM31::ONE);

        // Distributive law: a * (b + c) == a * b + a * c
        let c = QM31::from_u32(9, 10, 11, 12);
        assert_eq!(a * (b + c), (a * b) + (a * c));
    }

    #[test]
    fn test_qm31_script_add_sub() {
        let a = QM31::from_u32(100, 200, 300, 400);
        let b = QM31::from_u32(50, 75, 125, 150);
        let expected_sum = a + b;

        let mut builder = ScriptBuilder::new();
        // Push A components
        for &comp in &a.to_array() {
            builder.push_int(comp.as_i64());
        }
        // Push B components
        for &comp in &b.to_array() {
            builder.push_int(comp.as_i64());
        }
        QM31Script::emit_add(&mut builder);

        let mut vm = Vm::new();
        let ok = vm.execute(builder.as_bytes()).expect("QM31 add failed");
        assert!(ok);
        assert_eq!(vm.stack().len(), 4);
        for (i, &comp) in expected_sum.to_array().iter().enumerate() {
            assert_eq!(vm.stack()[i], encode_num(comp.as_i64()));
        }
    }
}
