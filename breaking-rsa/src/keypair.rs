use std::fmt;
use mod_exp::mod_exp;


#[derive(Debug, Copy, Clone)]
pub struct Keypair {
    pub n: u32, // modulus
    pub e: u32, // public exponent
    
    // private!
    d: u32, // private exponent
    p: u16, 
    q: u16
}

impl fmt::Display for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keypair Public Key: (N: {}, e: {}) Private Key: (d: {})", self.n, self.e, self.d)
    }
}

impl Keypair {
    pub fn new(n: u32, e: u32, d: u32, p: u16, q: u16) -> Keypair {
        Keypair { n, e, d, p, q }
    }

    pub fn encrypt(&self, m: u32) -> u32 {
        mod_exp(m as u64, self.e as u64, self.n as u64) as u32
    }

    pub fn decrypt(&self, c: u32) -> u32 {
        mod_exp(c as u64, self.d as u64, self.n as u64) as u32
    }
}