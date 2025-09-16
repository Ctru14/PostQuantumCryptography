use crate::generate_keypair::generate_keypair;
use crate::break_keypair::break_keypair;
pub mod generate_keypair;
pub mod keypair;
pub use keypair::Keypair;
pub mod break_keypair;

fn main() {
    let keypair: Keypair = generate_keypair();
    break_keypair(&keypair);
}