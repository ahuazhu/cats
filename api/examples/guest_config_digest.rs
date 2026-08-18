//! Print the canonical guest config digest a placement policy must declare for
//! one release's GuestRuntimeProfileReceipt.
use cats_api::runtime_reconciliation::{decode_guest_runtime_profile_receipt, guest_config_digest};

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("argv[1] = profile json path");
    let bytes = std::fs::read(&path).expect("read profile");
    let receipt = decode_guest_runtime_profile_receipt(&bytes).expect("canonical profile receipt");
    let digest = guest_config_digest(&receipt).expect("digest");
    println!("{}", digest.as_str());
}
