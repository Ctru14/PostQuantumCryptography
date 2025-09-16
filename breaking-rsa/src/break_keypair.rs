use crate::Keypair;

pub fn break_keypair(keypair: &Keypair) {
    println!("\nEve is interested in the message that Alice sends to Bob! While she does not have Bob's private key, she does own a quantum computer.");
    println!("We will see how Eve is able to use Shor's algorithm on her quantum computer to find out Bob's private key.");   
}