use crate::kyber::*;
use crate::utils::*;
use mod_exp::mod_exp;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

pub struct NttParameters {
    /// N: Dimensionality of polynomials
    pub n: usize,
    /// Q: Modulus
    pub q: u32,
    /// Xi: Primitive n-th root of unity modulo q (xi^n mod q = 1)
    pub xi: u32,
    /// N_inv: Modular inverse of N modulo Q
    pub n_inv: u32,
    /// Xi_inv: Modular inverse of Xi modulo Q
    pub xi_inv: u32,
}

impl NttParameters {
    pub fn new(n: usize, q: u32, xi: u32) -> Self {
        Self {
            n,
            q,
            xi,
            n_inv: find_modular_inverse(n as u32, q),
            xi_inv: find_modular_inverse(xi, q),
        }
    }
}

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

/// Generate a vector of k polynomials sampled from Central Binomial Distribution with parameter eta
pub fn generate_poly_cbd_vector(
    n: usize,
    k: usize,
    eta: usize,
    seed: &[u8; 32],
    nonce: &mut u8,
) -> Vec<Poly> {
    (0..k)
        .map(|_| {
            let num_bits = 2 * n * eta + n + eta;
            let num_bytes = num_bits / 8 + if num_bits % 8 != 0 { 1 } else { 0 }; // Convert to bytes, round up
            let bytes = generate_pseudorandom_bytes(seed, num_bytes, *nonce);
            *nonce = nonce.wrapping_add(1); // Increment nonce for next polynomial
            sample_poly_cbd(n, eta, &bytes)
        })
        .collect()
}

/// Performs the Number Theoretic Transform on a given polynomial
/// Uses the long but simple O(N^2) matrix multiplication method
///
/// Parameters:
///     poly (Poly): Input polynomial
///     params (NttParameters) contains the following:
///     n (usize):   Order of the polynomial (x^0 + ... + x^(n-1))
///     q (i32):     Modulus of operations
///     xi (u32):    nth root of unity in Zq: xi^n = 1 mod q
pub fn ntt_long(poly: &Poly, params: &NttParameters) -> Poly {
    let mut out = Poly::zeros(poly.degree());
    assert!(params.n == poly.degree());

    for (j, coef) in out.coefs.iter_mut().enumerate() {
        for i in 0..params.n {
            *coef += mod_exp(params.xi, (i * j) as u32, params.q.try_into().unwrap()) as i32
                * poly.coefs[i];
            *coef %= params.q as i32;
        }
    }

    out
}

/// Performs the Inverse Number Theoretic Transform on the transformed polynomial, returning the original coefficients
/// Uses the long but simple O(N^2) matrix multiplication method
///
/// Parameters:
///     poly (Poly):  Input polynomial
///     params (NttParameters) contains the following:
///     n (usize):    Order of the polynomial (x^0 + ... + x^(n-1))
///     q (u32):      Modulus of operations
///     xi_inv (u32): Inverse nth root of unity in Zq: xi^n = 1 mod q
///     n_inv (i32):  Modular multiplicative inverse of n mod q
pub fn ntt_inv_long(poly: &Poly, params: &NttParameters) -> Poly {
    let mut out = Poly::zeros(poly.degree());
    assert!(params.n == poly.degree());

    for (j, coef) in out.coefs.iter_mut().enumerate() {
        for i in 0..params.n {
            // xi^(-1)(i*j) = (xi^(-1))^(i*j)
            let add = mod_exp(params.xi_inv, (j * i) as u32, params.q) as i32 * poly.coefs[i];
            *coef += add;
            *coef %= params.q as i32;
            println!("({}, {}): + {} % q = {}", i, j, add, coef);
        }
        print!("coef[{}] = {} -> ", j, coef);
        *coef *= params.n_inv as i32;
        *coef %= params.q as i32;
        println!("{}", coef);
    }

    out
}
