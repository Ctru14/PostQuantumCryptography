use crate::utils::*;

pub struct DomainParameters {
    pub q: i32,    // Modulus
    pub n: usize,  // Polynomial Order
    pub k: usize,  // Equation dimension
    pub eta1: i32, // Noise term for private key polynomial s
    pub eta2: i32, // Noise term for error polynomial e
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Poly {
    pub coefs: Vec<i32>,
}

impl Poly {
    pub fn degree(&self) -> usize {
        self.coefs.len()
    }

    pub fn add(&self, other: &Poly, q: i32) -> Poly {
        assert_eq!(self.degree(), other.degree());
        let coefs = self
            .coefs
            .iter()
            .zip(other.coefs.iter())
            .map(|(a, b)| {
                let mut num = (a + b) % q;
                if num < 0 {
                    num += q;
                }
                num
            })
            .collect();
        Poly { coefs }
    }

    pub fn mult(&self, num: i32) -> Poly {
        let coefs = self.coefs.iter().map(|a| a * num).collect();
        Poly { coefs }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KyberKeys {
    // t = As + e (mod q)
    pub mat_a: Vec<Vec<Poly>>, // Matrix A: Public key
    pub s: Vec<Poly>,          // Private descryption key
    pub e: Vec<Poly>,          // Error to generate t (not used afterwards)
    pub t: Vec<Poly>,          // Public encryption vector
}

impl KyberKeys {
    pub fn encrypt(&self, params: &DomainParameters, context: &EncryptionContext) -> Ciphertext {
        // Compute u Poly vector = A^T*r + e1
        let mat_a_t = poly_mat_transpose(&self.mat_a);
        let u = poly_mat_vec_mul_add_mod(&mat_a_t, &context.r, &context.e1, params.q);

        // Compute v Poly = t^T*r + e2 + encode(m)
        let mut v = poly_vec_inner_mult(&self.t, &context.r, params.q);

        // Add error term e2
        v = v.add(&context.e2, params.q);

        // Add encoded message
        let m_encoded = message_binary_to_coefs(&context.m, params.n, params.q);
        v = v.add(&m_encoded, params.q);

        Ciphertext { u, v }
    }

    pub fn decrypt(&self, params: &DomainParameters, ciphertext: Ciphertext) -> Vec<u8> {
        // Compute v - s^T * u mod q
        let s_t_u = poly_vec_inner_mult(&self.s, &ciphertext.u, params.q);
        let s_t_u_neg = s_t_u.mult(-1);
        let m_poly = ciphertext.v.add(&s_t_u_neg, params.q);

        // Convert polynomial of coefficients back to byte array message by rounding with q
        poly_coefs_to_message_binary(&m_poly, params.q)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionContext {
    pub m: Vec<u8>,    // Message as bytes
    pub r: Vec<Poly>,  // Random polynomial vector
    pub e1: Vec<Poly>, // Error polynomial vector
    pub e2: Poly,      // Error polynomial
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    pub u: Vec<Poly>, // Vector of polynomials
    pub v: Poly,      // Single polynomial
}
