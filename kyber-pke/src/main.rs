use rand::Rng;
use std::ops::Range;

fn main() {
    println!("Hello, world!");

    let params = DomainParameters {
        q: 3329,
        n: 256,
        k: 3,
        eta1: 3,
        eta2: 2
    };

    // let toy_params = DomainParameters {
    //     q: 137,
    //     n: 4,
    //     k: 2,
    //     eta1: 2,
    //     eta2: 2,
    // };

    // Alice generates public key matrix A, secret s, error e, and computes t = As + e
    let keys = kyber_keygen(&params);

    println!("Matrix A: {:?}", keys.mat_a);
    println!("Secret s: {:?}", keys.s);
    println!("Error e: {:?}", keys.e);
    println!("t = As + e: {:?}", keys.t);
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

struct KyberKeys {
    // t = As + e (mod q)
    pub mat_a: Vec<Vec<Poly>>, // Matrix A: Public Key
    s: Vec<Poly>,
    e: Vec<Poly>,
    t: Vec<Poly>,
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
    let t = mat_vec_mul_add_mod(&mat_a, &s, &e, params.q);

    KyberKeys { mat_a, s, e, t }
}

fn random_poly(n: usize, range: &Range<i32>) -> Poly {
    let mut rng = rand::rng();
    Poly {
        coefs: (0..n).map(|_| rng.random_range(range.clone())).collect(),
    }
}

fn mat_vec_mul_add_mod(
    mat: &Vec<Vec<Poly>>,
    mult: &Vec<Poly>,
    add: &Vec<Poly>,
    q: i32,
) -> Vec<Poly> {
    // mat: k x k, vec: k, add: k, returns k polynomials
    let out = mat_vec_mul_mod(mat, mult, q);
    out.into_iter()
        .zip(add.iter())
        .map(|(mut poly, err)| {
            for (i, v) in poly.coefs.iter_mut().enumerate() {
                *v = (*v + err.coefs[i]) % q;
            }
            poly
        })
        .collect()
}

fn mat_vec_mul_mod(mat: &Vec<Vec<Poly>>, vec: &Vec<Poly>, q: i32) -> Vec<Poly> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_generation() {
        let toy_params = DomainParameters {
            q: 137,
            n: 4,
            k: 2,
            eta1: 2,
            eta2: 2,
        };

        let mat_a: Vec<Vec<Poly>> = vec![
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
        ];

        let s: Vec<Poly> = vec![
            Poly {
                coefs: vec![1, 2, -1, 2],
            },
            Poly {
                coefs: vec![0, -1, 0, 2],
            },
        ];

        let e: Vec<Poly> = vec![
            Poly {
                coefs: vec![1, 0, -1, 1],
            },
            Poly {
                coefs: vec![0, -1, 1, 0],
            },
        ];

        let t: Vec<Poly> = mat_vec_mul_add_mod(&mat_a, &s, &e, toy_params.q);

        assert_eq!(
            t,
            vec![
                Poly {
                    coefs: vec![55, 96, 123, 7]
                },
                Poly {
                    coefs: vec![32, 27, 127, 100]
                }
            ]
        );
    }
}
