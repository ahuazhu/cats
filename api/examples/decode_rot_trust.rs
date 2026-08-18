//! Decode one Route v2 rotation operator trust artifact and name the exact verdict.
use cats_api::route_signing_operator::decode_route_v2_rotation_operator_trust;

fn main() {
    let path = std::env::args().nth(1).expect("argv[1] = trust file");
    let bytes = std::fs::read(&path).expect("read trust file");
    println!("bytes: {}", bytes.len());
    match decode_route_v2_rotation_operator_trust(&bytes) {
        Ok(trust) => {
            println!("ACCEPTED");
            println!("  release_commit_sha = {}", trust.release_commit_sha);
            println!("  authority_id       = {}", trust.authority_id.as_str());
            println!("  threshold          = {}", trust.threshold);
            println!("  credentials        = {}", trust.credentials.len());
        }
        Err(error) => println!("REJECTED: {error}"),
    }
}
