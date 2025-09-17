use rand::{Rng, RngCore};
use std::ops::Range;

fn main() {
    println!("Hello, world!");

    let params = DomainParameters {
        q: 3329,
        n: 256,
        k: 3,
        eta1: 3,
        eta2: 2,
    };

    println!("Alice generates public key matrix A, secret s, error e, and computes t = As + e");
    let keys = kyber_keygen(&params);

    println!("Matrix A: {:?}", keys.mat_a);
    println!("Secret s: {:?}", keys.s);
    println!("Error e: {:?}", keys.e);
    println!("t = As + e: {:?}", keys.t);

    let message: Vec<u8> = random_bit_string(params.n); 
    println!("\nBob wants to send a message m to Alice: {:?}", message);
    let encryption_context = EncryptionContext {
        m: message.clone(),
        r: vec![
            random_poly(params.n, &(-params.eta1..params.eta1)),
            random_poly(params.n, &(-params.eta1..params.eta1)),
            random_poly(params.n, &(-params.eta1..params.eta1)),
        ],
        e1: vec![
            random_poly(params.n, &(-params.eta2..params.eta2)),
            random_poly(params.n, &(-params.eta2..params.eta2)),
            random_poly(params.n, &(-params.eta2..params.eta2)),
        ],
        e2: random_poly(params.n, &(-params.eta2..params.eta2)),
    };
    println!("Encryption Context: {:?}", encryption_context);
    let ciphertext = keys.encrypt(&params, &encryption_context);
    println!("Ciphertext: {:?}\nSend it to Alice!", ciphertext);

    println!("\nNow Alice receives the ciphertext and needs to decrypt to read the message");
    let decrypted = keys.decrypt(&params, ciphertext);
    println!("Decrypted message: {:?}", decrypted);
    assert_eq!(decrypted, message);
    println!("Decryption successful! (m = m')");
}

struct DomainParameters {
    q: i32,    // Modulus
    n: usize,  // Polynomial Order
    k: usize,  // Equation dimension
    eta1: i32, // Noise term for private key polynomial s
    eta2: i32, // Noise term for error polynomial e
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Poly {
    coefs: Vec<i32>,
}

impl Poly {
    fn degree(&self) -> usize {
        self.coefs.len()
    }

    fn add(&self, other: &Poly, q: i32) -> Poly {
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

    fn mult(&self, num: i32) -> Poly {
        let coefs = self.coefs.iter().map(|a| a * num).collect();
        Poly { coefs }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KyberKeys {
    // t = As + e (mod q)
    pub mat_a: Vec<Vec<Poly>>, // Matrix A: Public Key
    s: Vec<Poly>,
    e: Vec<Poly>,
    t: Vec<Poly>,
}

impl KyberKeys {
    fn encrypt(&self, params: &DomainParameters, context: &EncryptionContext) -> Ciphertext {
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

    fn decrypt(&self, params: &DomainParameters, ciphertext: Ciphertext) -> Vec<u8> {
        // Compute v - s^T * u mod q
        let s_t_u = poly_vec_inner_mult(&self.s, &ciphertext.u, params.q);
        let s_t_u_neg = s_t_u.mult(-1);
        let m_poly = ciphertext.v.add(&s_t_u_neg, params.q);

        // Convert polynomial of coefficients back to byte array message by rounding with q
        poly_coefs_to_message_binary(&m_poly, params.q)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EncryptionContext {
    m: Vec<u8>,    // Message as bytes
    r: Vec<Poly>,  // Random polynomial vector
    e1: Vec<Poly>, // Error polynomial vector
    e2: Poly,      // Error polynomial
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Ciphertext {
    u: Vec<Poly>, // Vector of polynomials
    v: Poly,      // Single polynomial
}

fn kyber_keygen(params: &DomainParameters) -> KyberKeys {
    // Generate random matrix A (k x k) of polynomials of degree n
    let mat_a: Vec<Vec<Poly>> = (0..params.k)
        .map(|_| {
            (0..params.k)
                .map(|_| random_poly(params.n, &(0..params.q)))
                .collect()
        })
        .collect();

    // Secret s: k polynomials
    let s: Vec<Poly> = (0..params.k)
        .map(|_| random_poly(params.n, &(-params.eta1..params.eta1)))
        .collect();

    // Error e: k polynomials
    let e: Vec<Poly> = (0..params.k)
        .map(|_| random_poly(params.n, &(-params.eta2..params.eta2)))
        .collect();

    // Compute t = As + e (mod q)
    let t = poly_mat_vec_mul_add_mod(&mat_a, &s, &e, params.q);

    KyberKeys { mat_a, s, e, t }
}

fn random_poly(n: usize, range: &Range<i32>) -> Poly {
    let mut rng = rand::rng();
    Poly {
        coefs: (0..n).map(|_| rng.random_range(range.clone())).collect(),
    }
}

fn random_bit_string(n: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    (0..(n + 7) / 8).map(|_| rng.next_u32() as u8).collect()
}

fn poly_mat_vec_mul_add_mod(
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

fn poly_mat_vec_mul_mod(mat: &Vec<Vec<Poly>>, vec: &Vec<Poly>, q: i32) -> Vec<Poly> {
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

fn poly_vec_inner_mult(v1: &Vec<Poly>, v2: &Vec<Poly>, q: i32) -> Poly {
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

fn poly_mat_transpose(mat: &Vec<Vec<Poly>>) -> Vec<Vec<Poly>> {
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

fn message_binary_to_coefs(m: &Vec<u8>, n: usize, q: i32) -> Poly {
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

fn poly_coefs_to_message_binary(poly: &Poly, q: i32) -> Vec<u8> {
    let n = poly.degree();
    let mut m = vec![0; (n + 7) / 8];
    // Range for 1 bit is [ceil(q/4), floor(3q/4)]
    let bit_1_range = (q / 4 + q % 4)..=(3 * q) / 4;
    // let one_4th_q = q / 4 + q % 4; // Round up for odd q
    // let three_4th_q = (3 * q) / 4; // Round up for odd q
    for i in 0..n {
        let bit = if bit_1_range.contains(&poly.coefs[n - i - 1]) { 1 } else { 0 };
        m[i / 8] |= bit << (i % 8);
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> KyberKeys {
        KyberKeys {
            mat_a: vec![
                vec![
                    Poly {
                        coefs: vec![21, 57, 78, 43],
                    },
                    Poly {
                        coefs: vec![126, 122, 19, 125],
                    },
                ],
                vec![
                    Poly {
                        coefs: vec![111, 9, 63, 33],
                    },
                    Poly {
                        coefs: vec![105, 61, 71, 64],
                    },
                ],
            ],
            s: vec![
                Poly {
                    coefs: vec![1, 2, -1, 2],
                },
                Poly {
                    coefs: vec![0, -1, 0, 2],
                },
            ],
            e: vec![
                Poly {
                    coefs: vec![1, 0, -1, 1],
                },
                Poly {
                    coefs: vec![0, -1, 1, 0],
                },
            ],
            t: vec![
                Poly {
                    coefs: vec![55, 96, 123, 7],
                },
                Poly {
                    coefs: vec![32, 27, 127, 100],
                },
            ],
        }
    }

    #[test]
    fn test_key_generation() {
        let toy_params = DomainParameters {
            q: 137,
            n: 4,
            k: 2,
            eta1: 2,
            eta2: 2,
        };

        let keys = test_keys();

        let t: Vec<Poly> = poly_mat_vec_mul_add_mod(&keys.mat_a, &keys.s, &keys.e, toy_params.q);

        assert_eq!(t, keys.t);
    }

    #[test]
    fn test_matrix_transpose() {
        let mat: Vec<Vec<Poly>> = vec![
            vec![
                Poly {
                    coefs: vec![1, 2, 3],
                },
                Poly {
                    coefs: vec![4, 5, 6],
                },
            ],
            vec![
                Poly {
                    coefs: vec![7, 8, 9],
                },
                Poly {
                    coefs: vec![10, 11, 12],
                },
            ],
        ];

        let transposed = poly_mat_transpose(&mat);

        assert_eq!(
            transposed,
            vec![
                vec![
                    Poly {
                        coefs: vec![1, 2, 3]
                    },
                    Poly {
                        coefs: vec![7, 8, 9]
                    },
                ],
                vec![
                    Poly {
                        coefs: vec![4, 5, 6]
                    },
                    Poly {
                        coefs: vec![10, 11, 12]
                    },
                ],
            ]
        );
    }

    #[test]
    fn test_encrypt_message() {
        let params = DomainParameters {
            q: 137,
            n: 4,
            k: 2,
            eta1: 2,
            eta2: 2,
        };

        let keys = test_keys();

        let message: Vec<u8> = vec![0b0111]; // Last 4 bits

        let encryption_context = EncryptionContext {
            m: message,
            r: vec![
                Poly {
                    coefs: vec![-2, 2, 1, -1],
                },
                Poly {
                    coefs: vec![-1, 1, 1, 0],
                },
            ],
            e1: vec![
                Poly {
                    coefs: vec![1, 0, -2, 1],
                },
                Poly {
                    coefs: vec![-1, 2, -2, 1],
                },
            ],
            e2: Poly {
                coefs: vec![2, 2, -1, 1],
            },
        };

        let encoded = keys.encrypt(&params, &encryption_context);

        assert_eq!(
            encoded,
            Ciphertext {
                u: vec![
                    Poly {
                        coefs: vec![56, 32, 77, 9]
                    },
                    Poly {
                        coefs: vec![45, 21, 2, 127]
                    },
                ],
                v: Poly {
                    coefs: vec![3, 10, 8, 123]
                },
            }
        );
    }

    #[test]
    fn test_decrypt_message() {
        let params = DomainParameters {
            q: 137,
            n: 4,
            k: 2,
            eta1: 2,
            eta2: 2,
        };

        let keys = test_keys();

        let ciphertext = Ciphertext {
            u: vec![
                Poly {
                    coefs: vec![56, 32, 77, 9],
                },
                Poly {
                    coefs: vec![45, 21, 2, 127],
                },
            ],
            v: Poly {
                coefs: vec![3, 10, 8, 123],
            },
        };

        let decrypted = keys.decrypt(&params, ciphertext);

        assert_eq!(
            decrypted,
            vec![0b0111] // Last 4 bits
        );
    }
}
