use crate::circle::CircleDomain;
use crate::m31::M31;

/// Computes bit-reversal permutation index of an integer of log_n bits
pub fn bit_reverse_index(mut n: usize, log_n: usize) -> usize {
    let mut result = 0;
    for _ in 0..log_n {
        result = (result << 1) | (n & 1);
        n >>= 1;
    }
    result
}

/// Permutes slice in-place according to bit-reversal order
pub fn bit_reverse_permute<T: Copy>(slice: &mut [T]) {
    let n = slice.len();
    assert!(n.is_power_of_two(), "Slice length must be a power of 2");
    let log_n = n.trailing_zeros() as usize;

    for i in 0..n {
        let j = bit_reverse_index(i, log_n);
        if i < j {
            slice.swap(i, j);
        }
    }
}

/// Fast Circle Fast Fourier Transform (Circle FFT) over a Circle Coset Domain
/// Transforms evaluations over the circle domain into frequency-domain polynomial coefficients
pub fn circle_fft(evals: &[M31], domain: &CircleDomain) -> Vec<M31> {
    assert_eq!(evals.len(), domain.size, "Evaluations length must match domain size");
    assert!(evals.len().is_power_of_two(), "Domain size must be power of 2");

    let n = evals.len();
    if n <= 1 {
        return evals.to_vec();
    }

    let mut res = evals.to_vec();
    let two_inv = M31::new(2).inv().unwrap();

    // Stage 1: y-butterfly across twin conjugate pairs in the coset domain
    // In CircleDomain::coset, point j and point (n - 1 - j) are conjugates!
    for j in 0..(n / 2) {
        let conj_j = n - 1 - j;
        let y_inv = domain.inv_y(j);

        let v_p = res[j];
        let v_conj = res[conj_j];

        let even = (v_p + v_conj) * two_inv;
        let odd = (v_p - v_conj) * two_inv * y_inv;

        res[j] = even;
        res[conj_j] = odd;
    }

    // Stage 2: Recursive x-butterfly reductions on projected domains
    let mut step = n / 2;
    while step >= 2 {
        let half = step / 2;
        let num_blocks = n / step;
        for block in 0..num_blocks {
            let offset = block * step;
            for i in 0..half {
                let idx1 = offset + i;
                let idx2 = offset + half + i;

                let pt_idx = i * num_blocks;
                let x_inv = domain.inv_x(pt_idx);

                let u1 = res[idx1];
                let u2 = res[idx2];

                let even = (u1 + u2) * two_inv;
                let odd = (u1 - u2) * two_inv * x_inv;

                res[idx1] = even;
                res[idx2] = odd;
            }
        }
        step /= 2;
    }

    res
}

/// Inverse Circle Fast Fourier Transform (Circle iFFT)
/// Interpolates frequency-domain polynomial coefficients back to evaluations on the Circle Domain
pub fn circle_ifft(coeffs: &[M31], domain: &CircleDomain) -> Vec<M31> {
    assert_eq!(coeffs.len(), domain.size, "Coefficients length must match domain size");
    assert!(coeffs.len().is_power_of_two(), "Domain size must be power of 2");

    let n = coeffs.len();
    if n <= 1 {
        return coeffs.to_vec();
    }

    let mut res = coeffs.to_vec();

    // Inverse Stage 2: Reverse x-butterfly expansions
    let mut step = 2;
    while step <= n / 2 {
        let half = step / 2;
        let num_blocks = n / step;
        for block in 0..num_blocks {
            let offset = block * step;
            for i in 0..half {
                let idx1 = offset + i;
                let idx2 = offset + half + i;

                let twiddle_x = domain.points[i * num_blocks].x;
                let even = res[idx1];
                let odd = res[idx2];

                res[idx1] = even + (twiddle_x * odd);
                res[idx2] = even - (twiddle_x * odd);
            }
        }
        step *= 2;
    }

    // Inverse Stage 1: Reverse y-butterfly across twin conjugate pairs
    for j in 0..(n / 2) {
        let conj_j = n - 1 - j;
        let y = domain.points[j].y;

        let even = res[j];
        let odd = res[conj_j];

        res[j] = even + (y * odd);
        res[conj_j] = even - (y * odd);
    }

    res
}
