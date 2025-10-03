pub mod kyber;
pub mod transforms;
pub mod utils;

use kyber::*;
use utils::*;

fn main() {
    let params = DomainParameters {
        q: 3329,
        n: 256,
        k: 3,
        eta1: 3,
        eta2: 2,
    };

    println!("Let's demo encryption and decryption using Kyber PKE!\nWe will use the traditional domain parameters:\n{:?}\n", params);

    println!(
        "Alice generates public key generator rho, matrix A, secret s, error e, and computes t = As + e"
    );
    let keys = KyberKeys::keygen(&params);

    println!("\nGenerator rho: {}", hex_from_slice(&keys.rho));
   // Pretty-print matrix A (Vec<Vec<Poly>>)
   println!("Matrix A: [{}]", keys.mat_a.iter().map(|row| {
       let inner = row.iter().map(|p| format!("{}", p)).collect::<Vec<_>>().join(",");
       format!("[{}]", inner)
   }).collect::<Vec<_>>().join(","));

   // Pretty-print vectors of polynomials
   println!("Secret s: [{}]", keys.s.iter().map(|p| format!("{}", p)).collect::<Vec<_>>().join(","));
   println!("Error e: [{}]", keys.e.iter().map(|p| format!("{}", p)).collect::<Vec<_>>().join(","));
    println!("t = As + e: [{}]", keys.t.iter().map(|p| format!("{}", p)).collect::<Vec<_>>().join(","));

    let message: Vec<u8> = random_bit_string(params.n);
    println!("\nBob wants to send a message m to Alice: {}", hex_from_vec(&message));
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
    // Pretty-print the encryption context using Poly Display and hex for m
    println!("Encryption Context: m={} r=[{}] e1=[{}] e2={}",
        hex_from_vec(&encryption_context.m),
        encryption_context.r.iter().map(|p| format!("{}", p)).collect::<Vec<_>>().join(","),
        encryption_context.e1.iter().map(|p| format!("{}", p)).collect::<Vec<_>>().join(","),
        encryption_context.e2
    );
    let ciphertext = keys.encrypt(&params, &encryption_context);
    println!("Bob encrypts the message and sends the ciphertext to Alice:");
    println!("{}\n", ciphertext);

    println!("\nNow Alice receives the ciphertext and needs to decrypt to read the message");
    let decrypted = keys.decrypt(&params, ciphertext);
    println!("Decrypted message: {}", hex_from_vec(&decrypted));
    assert_eq!(decrypted, message);
    println!("Decryption successful! (m = m')");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> KyberKeys {
        KyberKeys {
            rho: [0u8; 32], // Unused since matrix A is hardcoded
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
