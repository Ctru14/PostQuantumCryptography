use crate::kyber::*;
use rand::{Rng, RngCore};
use std::ops::Range;

pub fn random_poly(n: usize, range: &Range<i32>) -> Poly {
    let mut rng = rand::rng();
    Poly {
        coefs: (0..n).map(|_| rng.random_range(range.clone())).collect(),
    }
}

pub fn random_bit_string(n_bits: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    (0..(n_bits + 7) / 8).map(|_| rng.next_u32() as u8).collect()
}

pub fn poly_mat_vec_mul_add_mod(
    mat: &Vec<Vec<Poly>>,
    mult: &Vec<Poly>,
    add: &Vec<Poly>,
    q: i32,
) -> Vec<Poly> {
    // mat: k x k, vec: k, add: k, returns k polynomials
    let out = poly_mat_vec_mul_mod(mat, mult, q);
    out.into_iter()
        .zip(add.iter())
        .map(|(mut poly, v_add)| {
            for (i, v) in poly.coefs.iter_mut().enumerate() {
                *v = (*v + v_add.coefs[i]) % q;
            }
            poly
        })
        .collect()
}

pub fn poly_mat_vec_mul_mod(mat: &Vec<Vec<Poly>>, vec: &Vec<Poly>, q: i32) -> Vec<Poly> {
    // mat: k x k, vec: k, returns k polynomials
    let k = mat.len(); // 2
    let n = mat[0][0].coefs.len(); // 4
    assert_eq!(k, vec.len());
    (0..k)
        .map(|i| {
            let mut res = vec![0; n];
            for j in 0..k {
                for l in 0..n {
                    for m in 0..n {
                        let mat_coef = mat[i][j].coefs[l];
                        let vec_coef = vec[j].coefs[m];
                        let term = (mat_coef * vec_coef) % q;

                        if l + m < n {
                            res[(l + m) % n] += term;
                        } else {
                            // Polynomial division by x^n + 1 wraps around and subtracts
                            res[(l + m) % n] -= term;
                        }
                    }
                }
            }

            // Set to positive mod q
            for i in 0..n {
                while res[i] < 0 {
                    res[i] += q;
                }
            }
            Poly { coefs: res }
        })
        .collect()
}

pub fn poly_vec_inner_mult(v1: &Vec<Poly>, v2: &Vec<Poly>, q: i32) -> Poly {
    assert_eq!(v1.len(), v2.len());
    let n = v1[0].coefs.len();
    let mut res = vec![0; n];
    for i in 0..v1.len() {
        for j in 0..n {
            for k in 0..n {
                let coef1 = v1[i].coefs[j];
                let coef2 = v2[i].coefs[k];
                let term = (coef1 * coef2) % q;

                if j + k < n {
                    res[(j + k) % n] += term;
                } else {
                    // Polynomial division by x^n + 1 wraps around and subtracts
                    res[(j + k) % n] -= term;
                }
            }
        }
    }

    // Set to positive mod q
    for i in 0..n {
        while res[i] < 0 {
            res[i] += q;
        }
    }
    Poly { coefs: res }
}

pub fn poly_mat_transpose(mat: &Vec<Vec<Poly>>) -> Vec<Vec<Poly>> {
    if mat.is_empty() || mat[0].is_empty() {
        return vec![];
    }
    let rows = mat.len();
    let cols = mat[0].len();
    let mut transposed = vec![vec![mat[0][0].clone(); rows]; cols];
    for i in 0..rows {
        for j in 0..cols {
            transposed[j][i] = mat[i][j].clone();
        }
    }
    transposed
}

pub fn message_binary_to_coefs(m: &Vec<u8>, n: usize, q: i32) -> Poly {
    let mut coefs = vec![0; n];
    let q_over_2 = q / 2 + q % 2; // Round up for odd q
    for i in 0..n {
        let bit = if i / 8 < m.len() {
            (m[i / 8] >> (i % 8)) & 1
        } else {
            0
        };
        coefs[n - i - 1] = if bit == 1 { q_over_2 } else { 0 };
    }
    Poly { coefs }
}

pub fn poly_coefs_to_message_binary(poly: &Poly, q: i32) -> Vec<u8> {
    let n = poly.degree();
    let mut m = vec![0; (n + 7) / 8];
    // Range for 1 bit is [ceil(q/4), floor(3q/4)]
    let bit_1_range = (q / 4 + q % 4)..=(3 * q) / 4;
    for i in 0..n {
        let bit = if bit_1_range.contains(&poly.coefs[n - i - 1]) {
            1
        } else {
            0
        };
        m[i / 8] |= bit << (i % 8);
    }
    m
}
