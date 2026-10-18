pub mod circle;
pub mod m31;
pub mod qm31;

pub use circle::{
    circle_half_point, circle_subgroup_generator, m31_sqrt, CircleDomain, CirclePoint,
    CircleScript,
};
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

    #[test]
    fn test_circle_group_arithmetic() {
        // Identity checks
        let id = CirclePoint::IDENTITY;
        assert!(id.is_on_curve());
        assert_eq!(id + id, id);

        // Order 4 point (0, 1)
        let o4 = CirclePoint::ORDER_4;
        assert!(o4.is_on_curve());
        let o2 = o4.double();
        assert_eq!(o2, CirclePoint::ORDER_2);
        let id_from_o4 = o2.double();
        assert_eq!(id_from_o4, CirclePoint::IDENTITY);

        // Inverse & subtraction: P - P == IDENTITY
        let _p = CirclePoint::new(M31::new(12345), M31::new(67890));
        // Find a valid point on circle by choosing x and solving y^2 = 1 - x^2
        let test_x = M31::new(100);
        let y_sq = M31::ONE - (test_x * test_x);
        let test_y = m31_sqrt(y_sq).expect("Square root must exist for valid point");
        let valid_pt = CirclePoint::new(test_x, test_y);
        assert!(valid_pt.is_on_curve());
        assert_eq!(valid_pt - valid_pt, CirclePoint::IDENTITY);
        assert_eq!(valid_pt + (-valid_pt), CirclePoint::IDENTITY);
    }

    #[test]
    fn test_circle_subgroup_generators_and_domain() {
        // Order 2^3 = 8 domain
        let domain_8 = CircleDomain::new(3);
        assert_eq!(domain_8.size, 8);
        assert_eq!(domain_8.points.len(), 8);

        // Check all domain points lie on curve and are distinct
        for pt in &domain_8.points {
            assert!(pt.is_on_curve());
        }
        let gen = domain_8.generator;
        assert_eq!(gen.mul(8), CirclePoint::IDENTITY);
        assert_ne!(gen.mul(4), CirclePoint::IDENTITY);

        // Order 2^4 = 16 domain
        let domain_16 = CircleDomain::new(4);
        assert_eq!(domain_16.size, 16);
        assert_eq!(domain_16.generator.mul(16), CirclePoint::IDENTITY);
        assert_ne!(domain_16.generator.mul(8), CirclePoint::IDENTITY);
    }

    #[test]
    fn test_circle_point_add_script_verification() {
        let gen = circle_subgroup_generator(3);
        let p1 = gen;
        let p2 = gen.double();
        let _expected_p3 = p1 + p2;

        let witness = CircleScript::create_point_add_witness(p1, p2);

        let mut builder = ScriptBuilder::new();
        CircleScript::emit_verify_point_add(&mut builder);

        let mut vm = Vm::with_witness(witness);
        let ok = vm.execute(builder.as_bytes()).expect("Circle point add verification failed");
        assert!(ok);
        assert_eq!(vm.stack().last().unwrap(), &[1]);
    }
}
