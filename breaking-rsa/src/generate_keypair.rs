use rand::prelude::*;
use crate::Keypair;

pub fn generate_keypair() -> Keypair {
    println!("Welcome to this demo of breaking RSA public key cryptography!\n");

    println!("Bob wants to generate a public/private keypair. To do this, he must find a few things:");
    println!("1. Two large prime numbers, p and q, which form the large modulus N = p * q.");
    println!("2. A public exponent e, which has no common factors (\"coprime\") to (p-1)(q-1), i.e., gcd(e, (p-1)(q-1)) = 1.");
    println!("3. A private exponent d, which is the modular inverse of e modulo (p-1)(q-1), i.e., d * e ≡ 1 (mod (p-1)(q-1)).");

    println!("First, as a utility, let's generate some primes up to a certain range. To save computational resources, we will keep all calculations to 16-bit integers");
    let primes: Vec<u16> = generate_prime_range(10000);

    println!("\nOkay, let's generate some numbers! Let's pick a random two primes, p and q, from this list, and multiple them for our modulus N.");
    let mut rng: ThreadRng = rand::rng();
    let p: u16 = get_prime_of_min_size(&mut rng, &primes, 100);
    let q: u16 = get_prime_of_min_size(&mut rng, &primes, 100);
    let n: u32 = p as u32 * q as u32;

    println!("Bob picked the following primes to generate his keypair: p = {}, q = {} => N = p * q = {}", p, q, n);

    println!("\nNext, Bob needs to pick a public exponent e. This number must be coprime to (p-1)(q-1), which we call Phi(N)");
    let phi: u32 = (p as u32 - 1) * (q as u32 - 1);
    println!("Calculating (p-1)(q-1) = {}*{} = {}", p-1, q-1, phi);
    println!("\nSide note: Why (p-1)(q-1)? This is because this is the number of integers less than N=pq which share no common factors with N.");
    println!("(p-1)(q-1) = pq - p - q + 1 = [pq-1 (order of the set/number of integers between 0..pq, exclusive)] - [p-1 (multiples of q)] - [q-1 (multiples of p)]");
    println!("You can work this out by hand with p=3 and q=5 to see for yourself!");

    println!("\nFind e: Now, Bob can pick any number coprime with Phi(N)=(p-1)(q-1)={} for his public key exponent e", phi);
    println!("This requires some guessing and checking. We can efficiently check the GCD using Euler's algorithm");
    let e: u32 = pick_number_coprime_to_phi(&mut rng, phi);
    println!("Bob picked e = {}", e);

    println!("\nFind d: Bob now must find the private key exponent d such that e * d = 1 mod Phi(N)");
    println!("This means GCD(Phi, e) = 1, so this is equivalent to finding the coefficients of the equation a*Phi(N) + b*e = 1");
    let d: u32 = find_modular_inverse(e, phi);
    let check = (e as u64 * d as u64) % phi as u64;
    if check != 1 {
        panic!("Uh oh! Something went wrong calculating d. (e * d = {} * {} % {} = {}) (Expected 1)", e, d, phi, check)
    }
    println!("Bob calculated private key d = {} such that e*d mod Phi(N) = {}", d, check);

    let keypair = Keypair::new(n, e, d, p, q);
    println!("\nBob's keypair is {}", keypair);

    let m = rng.next_u32() % n;
    let c = keypair.encrypt(m);
    let m_decrypted = keypair.decrypt(c);

    if m != m_decrypted {
        panic!("Uh oh! Something went wrong decrypting the message. (m = {}, c = {}, m' = {}) (Expected m = m')", m, c, m_decrypted);
    }

    println!("\nNow, to see this key pair in action, let's say Alice wants to send Bob a secret message m = {}", m);
    println!("Alice can now encrypt this message with Bob's public key e by the ciphertext c = m^e mod N = {}", c);
    println!("After Alice sends c to Bob, Bob can decypt it with his private key by calculating m' = c^d mod N = {}", m_decrypted);

    keypair
}

fn generate_prime_range(range: u16) -> Vec<u16> {
    let mut primes: Vec<u16> = Vec::new();
    
    for num in 2..range {
        let mut is_prime = true;
        for i in 2..=((num as f64).sqrt() as u16) {
            if num % i == 0 {
                is_prime = false;
                break;
            }
        }
        if is_prime {
            primes.push(num);
        }
    }
    primes
}

fn get_prime_of_min_size(rng: &mut ThreadRng, primes: &Vec<u16>, size: u16) -> u16 {
    loop {
        let p = primes[rng.next_u32() as usize % primes.len()];
        if p >= size {
            return p;
        }
    }
}

fn pick_number_coprime_to_phi(rng: &mut ThreadRng, phi: u32) -> u32 {
    loop {
        let e = rng.next_u32() % phi;
        if gcd(e, phi) == 1 {
            return e;
        }
    }
}

fn gcd(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        let temp = b;
        b = a % b;
        a = temp;
    }
    a
}

fn find_modular_inverse(e: u32, phi: u32) -> u32 {
    let (mut x, mut y) = (0, 0);
    let (gcd, x, _y) = extended_euclidean(e as i32, phi as i32, &mut x, &mut y);
    if gcd != 1 {
        panic!("e and phi are not coprime!");
    }
    let mut d = x % phi as i32;
    if d < 0 {
        d += phi as i32;
    }
    d as u32
}

fn extended_euclidean(a: i32, b: i32, x: &mut i32, y: &mut i32) -> (i32, i32, i32) {
    if a == 0 {
        *x = 0;
        *y = 1;
        return (b, *x, *y);
    }
    let (gcd, x1, y1) = extended_euclidean(b % a, a, x, y);
    *x = y1 - (b / a) * x1;
    *y = x1;
    (gcd, *x, *y)
}