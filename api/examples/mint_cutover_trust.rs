//! Mint the production cutover operator trust bundle with the crate's own
//! canonical encoder, so the wire shape cannot drift from the validator.
use cats_api::production_mutation_admission::{
    encode_production_cutover_operator_trust_bundle, ProductionCutoverAwsPartition,
    ProductionCutoverAwsRoleScope, ProductionCutoverOperatorCredential,
    ProductionCutoverOperatorTrustBundle,
};
use cats_api::runtime_reconciliation::{Base64UrlNoPad, ContractVersion, Id, WireU64};

fn main() {
    let mut args = std::env::args().skip(1);
    let spki = args.next().expect("argv[1] = base64url Ed25519 SPKI");
    let deployment = args.next().expect("argv[2] = deployment id");
    let release = args.next().expect("argv[3] = release id");
    let commit = args.next().expect("argv[4] = 40-hex commit");
    let account = args.next().expect("argv[5] = aws account id");
    let role = args.next().expect("argv[6] = role arn");
    let bundle = ProductionCutoverOperatorTrustBundle {
        version: ContractVersion::V1,
        deployment_id: Id::new(&deployment).expect("valid deployment id"),
        release_id: Id::new(&release).expect("valid release id"),
        source_commit_sha: commit,
        signature_threshold: WireU64::new(1).expect("threshold 1"),
        credentials: vec![ProductionCutoverOperatorCredential {
            credential_id: Id::new("cutover_operator_r1").expect("valid credential id"),
            public_key_spki: Base64UrlNoPad::new(&spki).expect("canonical Ed25519 SPKI"),
            scope: ProductionCutoverAwsRoleScope {
                aws_partition: ProductionCutoverAwsPartition::Aws,
                account_id: account,
                role_arn: role,
            },
        }],
    };
    let wire = encode_production_cutover_operator_trust_bundle(&bundle)
        .expect("bundle satisfies the validator");
    std::io::Write::write_all(&mut std::io::stdout(), &wire).expect("write");
}
