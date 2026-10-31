pub mod circle;
pub mod fft;
pub mod m31;
pub mod qm31;

pub use circle::{
    circle_half_point, circle_subgroup_generator, m31_sqrt, CircleDomain, CirclePoint,
    CircleScript,
};
pub use fft::{bit_reverse_index, bit_reverse_permute, circle_fft, circle_ifft};
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

    #[test]
    fn test_circle_fft_and_ifft_roundtrip() {
        let domain_8 = CircleDomain::coset(3);
        let evals: Vec<M31> = (0..8).map(|i| M31::new((i * 123 + 456) as u64)).collect();

        // Forward Circle FFT
        let coeffs = circle_fft(&evals, &domain_8);
        assert_eq!(coeffs.len(), 8);

        // Inverse Circle FFT (Interpolation)
        let recovered = circle_ifft(&coeffs, &domain_8);
        assert_eq!(recovered.len(), 8);

        for i in 0..8 {
            assert_eq!(
                evals[i], recovered[i],
                "Mismatch at index {}: original={:?}, recovered={:?}",
                i, evals[i], recovered[i]
            );
        }

        // Test with order 16 domain
        let domain_16 = CircleDomain::coset(4);
        let evals_16: Vec<M31> = (0..16).map(|i| M31::new((i * 789 + 101) as u64)).collect();
        let coeffs_16 = circle_fft(&evals_16, &domain_16);
        let recovered_16 = circle_ifft(&coeffs_16, &domain_16);
        for i in 0..16 {
            assert_eq!(evals_16[i], recovered_16[i]);
        }
    }

    #[test]
    fn test_bit_reversal_permutation() {
        let mut data = vec![0, 1, 2, 3, 4, 5, 6, 7];
        bit_reverse_permute(&mut data);
        assert_eq!(data, vec![0, 4, 2, 6, 1, 5, 3, 7]);
        // Applying again recovers identity
        bit_reverse_permute(&mut data);
        assert_eq!(data, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_batch_field_operations() {
        let mut a = vec![M31::new(10), M31::new(20), M31::new(30)];
        let b = vec![M31::new(5), M31::new(15), M31::new(25)];

        M31::batch_add(&mut a, &b);
        assert_eq!(a, vec![M31::new(15), M31::new(35), M31::new(55)]);

        M31::batch_scale(&mut a, M31::new(2));
        assert_eq!(a, vec![M31::new(30), M31::new(70), M31::new(110)]);

        let mut qa = vec![QM31::from_u32(1, 2, 3, 4), QM31::from_u32(5, 6, 7, 8)];
        let qb = vec![QM31::from_u32(10, 10, 10, 10), QM31::from_u32(20, 20, 20, 20)];
        QM31::batch_add(&mut qa, &qb);
        assert_eq!(qa[0], QM31::from_u32(11, 12, 13, 14));
        assert_eq!(qa[1], QM31::from_u32(25, 26, 27, 28));
    }

    #[test]
    fn test_m31_fast_squaring_and_batch_inversion() {
        // Fast squaring correctness
        for v in [0, 1, 2, 7, 1024, 65537, 2147483645, 2147483646] {
            let elem = M31::new(v);
            assert_eq!(elem.sqr(), elem * elem, "Squaring failed for {}", v);
        }

        // Montgomery batch inversion
        let elems: Vec<M31> = (1..=100).map(|i| M31::new(i * 1337)).collect();
        let invs = M31::batch_inv(&elems).expect("All non-zero elements must be invertible");
        assert_eq!(invs.len(), elems.len());
        for (x, inv_x) in elems.iter().zip(invs.iter()) {
            assert_eq!(*x * *inv_x, M31::ONE);
            assert_eq!(Some(*inv_x), x.inv());
        }

        // In-place batch inversion
        let mut in_place_elems = elems.clone();
        assert!(M31::batch_inv_in_place(&mut in_place_elems));
        assert_eq!(in_place_elems, invs);

        // Zero element error handling
        let with_zero = vec![M31::new(5), M31::ZERO, M31::new(10)];
        assert!(M31::batch_inv(&with_zero).is_none());
        assert!(!M31::batch_inv_in_place(&mut with_zero.clone()));
    }

    #[test]
    fn test_qm31_fast_squaring_and_batch_inversion() {
        // Fast squaring in CM31 and QM31
        let q = QM31::from_u32(11, 22, 33, 44);
        assert_eq!(q.sqr(), q * q);
        assert_eq!(q.c0.sqr(), q.c0 * q.c0);
        assert_eq!(q.c1.sqr(), q.c1 * q.c1);

        // Montgomery batch inversion in QM31
        let q_elems = vec![
            QM31::from_u32(1, 2, 3, 4),
            QM31::from_u32(100, 200, 300, 400),
            QM31::from_u32(1337, 7331, 42, 999),
            QM31::from_u32(2147483640, 2147483641, 1, 2),
        ];
        let q_invs = QM31::batch_inv(&q_elems).expect("Batch inv failed");
        for (orig, inv) in q_elems.iter().zip(q_invs.iter()) {
            assert_eq!(*orig * *inv, QM31::ONE);
            assert_eq!(Some(*inv), orig.inv());
        }

        // In-place batch inversion
        let mut q_in_place = q_elems.clone();
        assert!(QM31::batch_inv_in_place(&mut q_in_place));
        assert_eq!(q_in_place, q_invs);

        // Zero element error handling
        let q_zero = vec![QM31::from_u32(1, 2, 3, 4), QM31::ZERO];
        assert!(QM31::batch_inv(&q_zero).is_none());
    }
}
