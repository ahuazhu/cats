// Temporary live probe — not for commit.
use std::time::{Duration, Instant};

use cats_object_store_aws_s3::{AwsS3BlobStore, AwsS3Config};
use cats_storage::BlobStore;

#[test]
#[ignore]
fn scratch_list_empty_volume_prefix() {
    let store = AwsS3BlobStore::new(AwsS3Config {
        endpoint: "https://s3.us-east-1.amazonaws.com".into(),
        bucket: "cats-run-prod-869621413820-us-east-1".into(),
        region: "us-east-1".into(),
        access_key: std::env::var("AWS_ACCESS_KEY_ID").unwrap(),
        secret_key: std::env::var("AWS_SECRET_ACCESS_KEY").unwrap(),
        session_token: std::env::var("AWS_SESSION_TOKEN").ok(),
        prefix: "cats-fresh".into(),
    })
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let page = store.list_for_delete_bounded_until(
        "volumes/vol_cdcf178125904c9c9cd346746030dec6/",
        100,
        deadline,
    );
    match page {
        Ok(page) => {
            let page = page.into_page();
            println!(
                "OK keys={} truncated={}",
                page.keys.len(),
                page.is_truncated
            );
        }
        Err(error) => println!("ERR: {error:#?}"),
    }
}
