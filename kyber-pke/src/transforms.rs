use crate::kyber::*;
use sha3::Shake128;
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
