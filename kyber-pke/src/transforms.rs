use crate::kyber::*;
use sha3::{Shake128, Shake256};
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// Generate matrix A of size k x k with polynomial elements of order n and coefficients mod q
/// Uses seed rho to deterministically generate the matrix
/// Each element A[i][j] is generated using SHAKE256(rho || j || i)
pub fn generate_matrix_a(n: usize, k: usize, q: i32, rho: &[u8; 32]) -> Vec<Vec<Poly>> {
    let mut mat_a = vec![vec![Poly { coefs: vec![0; n] }; k]; k];
    for i in 0..k {
        for j in 0..k {
            mat_a[i][j] = generate_poly_element(n, q, rho, i as u8, j as u8);
        }
    }
    mat_a
}

/// Generates a random polynomial element for the matrix A of order n for element i, j
fn generate_poly_element(n: usize, q: i32, rho: &[u8; 32], i: u8, j: u8) -> Poly {
    let mut coefs = vec![0; n];
    let mut indices = [0u8; 2];
    indices[0] = j;
    indices[1] = i;

    let mut hasher = Shake128::default();
    hasher.update(rho);
    hasher.update(&indices);
    let mut reader = hasher.finalize_xof();

    let mut buf = [0u8; 3];
    let mut idx = 0;

    // Generate 3B array and extract up to 2 coefficients < q from every 3 bytes
    while idx < n {
        reader.read(&mut buf);
        let val0 = ((buf[0] as i32) | ((buf[1] as i32 & 0x0F) << 8)) as i32;
        if val0 < q {
            coefs[idx] = val0;
            idx += 1;
        }
        if idx < n {
            let val1 = (((buf[1] as i32) >> 4) | ((buf[2] as i32) << 4)) as i32;
            if val1 < q {
                coefs[idx] = val1;
                idx += 1;
            }
        }
    }

    Poly { coefs }
}

/// Central Binomial Distribution sampling for small coefficient polynomials
/// Samples a polynomial of degree n with coefficients in the range [-eta, eta]
/// Leverages random byte stream from PRF of at least (2*n*eta + n + eta) bits
pub fn sample_poly_cbd(n: usize, eta: usize, bytes: &[u8]) -> Poly {
    let mut coefs: Vec<i32> = vec![0; n];
    assert!(8 * bytes.len() >= 2 * n * eta + n + eta);

    for i in 0..n {
        let mut x: i32 = 0;
        let mut y: i32 = 0;

        for j in 0..n {
            let x_bit_idx = 2 * i * eta + j;
            let y_bit_idx = x_bit_idx + eta;

            x += ((bytes[x_bit_idx / 8] >> (x_bit_idx % 8)) & 1) as i32;
            y += ((bytes[y_bit_idx / 8] >> (y_bit_idx % 8)) & 1) as i32;

            coefs[i] = x - y;
        }
    }

    Poly { coefs }
}

/// Generate pseudorandom bytes using SHAKE256 with a 32-byte seed and a nonce
pub fn generate_pseudorandom_bytes(seed: &[u8; 32], num_bytes: usize, nonce: u8) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    hasher.update(&[nonce]);
    let mut reader = hasher.finalize_xof();

    let mut buf = vec![0u8; num_bytes];
    reader.read(&mut buf);
    buf
}

pub fn generate_poly_cbd_vector(n: usize, k: usize, eta: usize, seed: &[u8; 32], nonce: &mut u8) -> Vec<Poly> {
    (0..k)
        .map(|_| {
            let mut num_bytes = 2 * n * eta + n + eta; // Number of bits
            num_bytes = num_bytes / 8 + if num_bytes % 8 != 0 { 1 } else { 0 }; // Convert to bytes, round up
            let bytes = generate_pseudorandom_bytes(seed, num_bytes, *nonce);
            *nonce = nonce.wrapping_add(1); // Increment nonce for next polynomial
            sample_poly_cbd(n, eta, &bytes)
        })
        .collect()
}