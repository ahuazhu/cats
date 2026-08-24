//! Real PostgreSQL plus HTTP acceptance coverage for Node usage ingestion.
//!
//! The regression these guard is a silent one: with no producer wired to the
//! ledger, every billing read is a well-formed zero. Each test therefore ends
//! on the customer-visible number, not on an internal counter.

use std::sync::Arc;

use cats_api::metering::{
    CatUsageCheckpoint, IngestUsageCheckpointsRequest, IngestUsageCheckpointsResponse, UsageMetric,
    USAGE_CHECKPOINTS_PATH,
};
use cats_api::runtime_reconciliation::{Epoch, Id, NodeBootId, RandomId128, SessionBinding};
use cats_api::semantic_control::{NodedServiceToken, NODED_AUTHORIZATION_HEADER};
use cats_control_plane::server::{Config, Handle};
use cats_control_plane::store::DsnSource;
use cats_control_plane::testsupport::spawn_control_plane_for_test as spawn;
use cats_metering::{deterministic_event_id, SqliteUsageStore};
use reqwest::StatusCode;

const SERVICE_TOKEN: &str = "semantic-usage-service-token";
const ADMIN_TOKEN: &str = "semantic-usage-admin-token";
const NODED_TOKEN: &str = "semantic-usage-noded-token-000000";
const NODE_ID: &str = "node_metal-1";
const CAT_ID: &str = "cat_d207de919a91";
const WORKSPACE_ID: &str = "ws_usage";
const OTHER_WORKSPACE_ID: &str = "ws_usage_other";
const BILLING_ACCOUNT_ID: &str = "billing_usage";
const SOURCE_EPOCH: &str = "0f7a2c1d9b3e4f5061728394a5b6c7d8";

struct Context {
    _dir: tempfile::TempDir,
    server: Handle,
    http: reqwest::Client,
    dsn: String,
}

async fn context() -> Context {
    let dir = tempfile::tempdir().unwrap();
    let usage = Arc::new(SqliteUsageStore::open(&dir.path().join("usage.db")).unwrap());
    let dsn = cats_control_plane::testsupport::isolated_control_store_url();
    let server = spawn(Config {
        listen: "127.0.0.1:0".into(),
        control_store_dsn: DsnSource::Literal(dsn.clone()),
        control_store_ca_file: None,
        usage_store: usage.clone(),
        credit_store: usage,
        image_blob: cats_control_plane::testsupport::unavailable_image_blob(),
        default_boot_image: cats_control_plane::testsupport::test_boot_image(),
        auth_token: SERVICE_TOKEN.into(),
        noded_service_token: NODED_TOKEN.into(),
        guest_runtime_profile_receipt:
            cats_control_plane::testsupport::test_guest_runtime_profile_receipt(),
        runtime_provisioner_trust_bundle:
            cats_control_plane::testsupport::test_runtime_provisioner_trust_bundle(),
        production_cutover_operator_trust_bundle:
            cats_control_plane::testsupport::test_production_cutover_operator_trust_bundle(),
        admin_token: ADMIN_TOKEN.into(),
        workos: None,
        stripe: None,
        billing_enforcement_enabled: false,
    })
    .await
    .unwrap();
    let context = Context {
        _dir: dir,
        server,
        http: reqwest::Client::new(),
        dsn,
    };
    context.seed().await;
    context
}

impl Context {
    /// The control store client is synchronous, so every statement goes through
    /// Tokio's blocking boundary rather than holding an async worker.
    async fn with_db<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut postgres::Client) -> T + Send + 'static,
    ) -> T {
        let dsn = self.dsn.clone();
        tokio::task::spawn_blocking(move || {
            let mut client = postgres::Client::connect(&dsn, postgres::NoTls).expect("connect");
            operation(&mut client)
        })
        .await
        .expect("join control store statement")
    }

    async fn seed(&self) {
        self.with_db(|client| {
            client
                .batch_execute(&format!(
                    "INSERT INTO accounts (
                        id,slug,display_name,kind,workos_organization_id,billing_account_id,
                        personal_owner_user_id,status,created_at
                     ) VALUES (
                        'acct_usage','usage','Usage','organization','org_usage',
                        '{BILLING_ACCOUNT_ID}',NULL,'active',1
                     );
                     INSERT INTO workspaces (id,account_id,slug,display_name,is_default,created_at)
                     VALUES ('{WORKSPACE_ID}','acct_usage','default','Default',TRUE,1),
                            ('{OTHER_WORKSPACE_ID}','acct_usage','other','Other',FALSE,1);
                     INSERT INTO nodes (
                        node_id,node_name,control_endpoint,vendor,region,zone,instance_id,
                        machine_type,node_version,status,created_at,updated_at
                     ) VALUES (
                        '{NODE_ID}','metal-1','http://10.0.0.1:7301','aws','us-east-1',
                        'us-east-1a','i-usage','c5d.metal','1.0.0','running',1,1
                     );
                     INSERT INTO cats (
                        cat_id,workspace_id,cat_slug,state,node_id,cpu_count,memory_bytes,
                        boot_image,created_at,updated_at,last_running_at
                     ) VALUES (
                        '{CAT_ID}','{WORKSPACE_ID}','shell','running','{NODE_ID}',2,
                        2147483648,'sha256:image',1,1,1
                     );"
                ))
                .expect("seed billing owners and a running Cat");
        })
        .await;
    }

    async fn ingest(
        &self,
        token: &str,
        checkpoints: Vec<CatUsageCheckpoint>,
    ) -> (StatusCode, Option<IngestUsageCheckpointsResponse>) {
        self.post_usage(token, NODE_ID, checkpoints).await
    }

    /// Report as an arbitrary claimed Node, which is all the wire allows.
    async fn ingest_as(
        &self,
        claimed_node_id: &str,
        checkpoints: Vec<CatUsageCheckpoint>,
    ) -> (StatusCode, Option<IngestUsageCheckpointsResponse>) {
        self.post_usage(NODED_TOKEN, claimed_node_id, checkpoints)
            .await
    }

    async fn post_usage(
        &self,
        token: &str,
        claimed_node_id: &str,
        checkpoints: Vec<CatUsageCheckpoint>,
    ) -> (StatusCode, Option<IngestUsageCheckpointsResponse>) {
        let request = IngestUsageCheckpointsRequest {
            session: producer_for(claimed_node_id),
            node_id: claimed_node_id.to_owned(),
            checkpoints,
        };
        let response = self
            .http
            .post(format!(
                "{}{USAGE_CHECKPOINTS_PATH}",
                self.server.base_url()
            ))
            .header(
                NODED_AUTHORIZATION_HEADER,
                NodedServiceToken::new(token.to_owned())
                    .expect("service token")
                    .authorization_value(),
            )
            .json(&request)
            .send()
            .await
            .expect("usage ingestion request");
        let status = response.status();
        let body = response.json::<IngestUsageCheckpointsResponse>().await.ok();
        (status, body)
    }

    async fn usage_report(&self, workspace: &str) -> cats_api::metering::UsageReport {
        self.http
            .get(format!(
                "{}/v1/workspaces/{workspace}/billing/usage?from_ms=0&to_ms=99999999999999",
                self.server.base_url()
            ))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {ADMIN_TOKEN}"),
            )
            .send()
            .await
            .expect("usage report request")
            .json::<cats_api::metering::UsageReport>()
            .await
            .expect("usage report body")
    }

    async fn provisional_usage_nanos(&self, workspace: &str) -> u128 {
        let balance = self
            .http
            .get(format!(
                "{}/v1/workspaces/{workspace}/billing/balance",
                self.server.base_url()
            ))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {ADMIN_TOKEN}"),
            )
            .send()
            .await
            .expect("balance request")
            .json::<cats_api::billing::BillingBalance>()
            .await
            .expect("balance body");
        balance
            .provisional_usage_nanos
            .parse()
            .expect("provisional usage is an integer")
    }
}

fn producer() -> SessionBinding {
    producer_for(NODE_ID)
}

fn producer_for(node_id: &str) -> SessionBinding {
    SessionBinding {
        node_id: Id::new(node_id).expect("node id"),
        node_boot_id: NodeBootId::new("aaaaaaaabbbbbbbbccccccccdddddddd").expect("boot id"),
        agent_instance_id: RandomId128::new("11111111222222223333333344444444")
            .expect("instance id"),
        agent_session_epoch: Epoch::new(1_700_000_000).expect("session epoch"),
    }
}

fn checkpoint(
    cat_id: &str,
    source_epoch: &str,
    sequence: u64,
    metric: UsageMetric,
    cumulative_quantity: u128,
) -> CatUsageCheckpoint {
    checkpoint_from(
        NODE_ID,
        cat_id,
        source_epoch,
        sequence,
        metric,
        cumulative_quantity,
    )
}

fn checkpoint_from(
    node_id: &str,
    cat_id: &str,
    source_epoch: &str,
    sequence: u64,
    metric: UsageMetric,
    cumulative_quantity: u128,
) -> CatUsageCheckpoint {
    let mut checkpoint = CatUsageCheckpoint {
        event_id: String::new(),
        source_id: format!("node/{node_id}/cat/{cat_id}"),
        source_epoch: source_epoch.to_owned(),
        sequence,
        observed_at_unix_ms: 1_000 + (sequence as i64) * 10_000,
        cat_id: cat_id.to_owned(),
        cat_generation: 1,
        metric,
        epoch_marker: cats_api::metering::UsageEpochMarker::Open,
        cumulative_quantity,
    };
    checkpoint.event_id = deterministic_event_id(&checkpoint);
    checkpoint
}

/// One CPU-hour and one GiB-hour, so the rated total is exactly the published
/// Rate Card figures and a silent zero cannot pass.
fn one_cpu_hour_and_one_gib_hour(sequence: u64) -> Vec<CatUsageCheckpoint> {
    vec![
        checkpoint(
            CAT_ID,
            SOURCE_EPOCH,
            sequence,
            UsageMetric::CpuUsec,
            3_600_000_000,
        ),
        checkpoint(
            CAT_ID,
            SOURCE_EPOCH,
            sequence,
            UsageMetric::MemoryByteMillis,
            1_073_741_824 * 3_600_000,
        ),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_checkpoints_become_the_workspace_bill() {
    let context = context().await;
    assert_eq!(
        context.provisional_usage_nanos(WORKSPACE_ID).await,
        0,
        "a Workspace with no delivered usage starts at zero"
    );

    // The baseline checkpoint establishes the counter; it is not yet an
    // interval, so it must not move money on its own.
    let (status, body) = context
        .ingest(NODED_TOKEN, one_cpu_hour_and_one_gib_hour(0))
        .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let body = body.expect("ingest body");
    assert_eq!(body.accepted, 2);
    assert_eq!(body.rejected.len(), 0);
    assert_eq!(context.provisional_usage_nanos(WORKSPACE_ID).await, 0);

    // The next cumulative sample closes one interval of exactly one CPU-hour
    // and one GiB-hour: $0.07 + $0.045 = 115_000_000 nanos.
    let (status, body) = context
        .ingest(
            NODED_TOKEN,
            vec![
                checkpoint(
                    CAT_ID,
                    SOURCE_EPOCH,
                    1,
                    UsageMetric::CpuUsec,
                    2 * 3_600_000_000,
                ),
                checkpoint(
                    CAT_ID,
                    SOURCE_EPOCH,
                    1,
                    UsageMetric::MemoryByteMillis,
                    2 * 1_073_741_824 * 3_600_000,
                ),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body.expect("ingest body").accepted, 2);
    assert_eq!(
        context.provisional_usage_nanos(WORKSPACE_ID).await,
        115_000_000,
        "the rated bill is the Rate Card applied to the delivered interval"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replayed_checkpoints_never_bill_twice() {
    let context = context().await;
    let (status, _) = context
        .ingest(NODED_TOKEN, one_cpu_hour_and_one_gib_hour(0))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = context
        .ingest(
            NODED_TOKEN,
            vec![
                checkpoint(
                    CAT_ID,
                    SOURCE_EPOCH,
                    1,
                    UsageMetric::CpuUsec,
                    2 * 3_600_000_000,
                ),
                checkpoint(
                    CAT_ID,
                    SOURCE_EPOCH,
                    1,
                    UsageMetric::MemoryByteMillis,
                    2 * 1_073_741_824 * 3_600_000,
                ),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let billed = context.provisional_usage_nanos(WORKSPACE_ID).await;
    assert_eq!(billed, 115_000_000);

    // A durable producer redelivers an already-settled prefix after a
    // transport failure. It must settle as a replay, not as new money.
    let (status, body) = context
        .ingest(
            NODED_TOKEN,
            vec![
                checkpoint(
                    CAT_ID,
                    SOURCE_EPOCH,
                    1,
                    UsageMetric::CpuUsec,
                    2 * 3_600_000_000,
                ),
                checkpoint(
                    CAT_ID,
                    SOURCE_EPOCH,
                    1,
                    UsageMetric::MemoryByteMillis,
                    2 * 1_073_741_824 * 3_600_000,
                ),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let body = body.expect("ingest body");
    assert_eq!(body.duplicates, 2);
    assert_eq!(body.accepted, 0);
    assert_eq!(context.provisional_usage_nanos(WORKSPACE_ID).await, billed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_source_epoch_keeps_the_owner_it_was_frozen_with() {
    let context = context().await;
    let (status, _) = context
        .ingest(NODED_TOKEN, one_cpu_hour_and_one_gib_hour(0))
        .await;
    assert_eq!(status, StatusCode::OK);

    // Whatever happens to the Cat afterwards, the epoch's money stays with the
    // owner that was frozen when the epoch opened.
    context
        .with_db(|client| {
            client
                .execute(
                    "UPDATE cats SET workspace_id=$1 WHERE cat_id=$2",
                    &[&OTHER_WORKSPACE_ID, &CAT_ID],
                )
                .expect("move the Cat to another Workspace");
        })
        .await;

    let (status, body) = context
        .ingest(
            NODED_TOKEN,
            vec![checkpoint(
                CAT_ID,
                SOURCE_EPOCH,
                1,
                UsageMetric::CpuUsec,
                2 * 3_600_000_000,
            )],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body.expect("ingest body").accepted, 1);
    let frozen = context.usage_report(WORKSPACE_ID).await;
    assert_eq!(
        frozen.amount_nanos, "70000000",
        "the frozen Workspace still owns the epoch: {frozen:?}"
    );
    let moved = context.usage_report(OTHER_WORKSPACE_ID).await;
    assert_eq!(
        moved.amount_nanos, "0",
        "the Cat's new Workspace must not inherit the frozen epoch: {moved:?}"
    );
    assert!(moved.cats.is_empty(), "{moved:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unownable_checkpoint_is_named_and_does_not_block_the_batch() {
    let context = context().await;
    let (status, body) = context
        .ingest(
            NODED_TOKEN,
            vec![
                checkpoint(
                    "cat_000000000001",
                    SOURCE_EPOCH,
                    0,
                    UsageMetric::CpuUsec,
                    1_000,
                ),
                checkpoint(CAT_ID, SOURCE_EPOCH, 0, UsageMetric::CpuUsec, 3_600_000_000),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let body = body.expect("ingest body");
    assert_eq!(body.rejected.len(), 1, "{body:?}");
    assert_eq!(body.rejected[0].event_id, {
        let unknown = checkpoint(
            "cat_000000000001",
            SOURCE_EPOCH,
            0,
            UsageMetric::CpuUsec,
            1_000,
        );
        unknown.event_id
    });
    assert_eq!(body.accepted, 1, "the owned checkpoint behind it settles");
}

/// The noded service token is shared by the whole Node fleet, so authenticating
/// as *a* Node proves nothing about which Cats the caller may charge. Without a
/// placement binding, any Node could inflate any customer's bill.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_cannot_charge_a_cat_placed_on_another_node() {
    let context = context().await;
    context
        .with_db(|client| {
            client
                .batch_execute(&format!(
                    "INSERT INTO nodes (
                        node_id,node_name,control_endpoint,vendor,region,zone,instance_id,
                        machine_type,node_version,status,created_at,updated_at
                     ) VALUES (
                        'node_metal-2','metal-2','http://10.0.0.2:7301','aws','us-east-1',
                        'us-east-1b','i-usage-2','c5d.metal','1.0.0','running',1,1
                     );
                     UPDATE cats SET node_id='node_metal-2' WHERE cat_id='{CAT_ID}';"
                ))
                .expect("place the Cat on the other Node");
        })
        .await;

    let (status, body) = context
        .ingest(NODED_TOKEN, one_cpu_hour_and_one_gib_hour(0))
        .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let body = body.expect("ingest body");
    assert_eq!(body.accepted, 0);
    assert_eq!(body.rejected.len(), 2, "{body:?}");
    assert!(
        body.rejected[0]
            .reason
            .contains("not placed on the reporting Node"),
        "{body:?}"
    );
    assert_eq!(context.provisional_usage_nanos(WORKSPACE_ID).await, 0);
}

/// A fresh Cat publishes its first checkpoint about a second after the VMM
/// starts, while `cats.node_id` is still NULL and the create action holds the
/// placement. Rejecting that would silently un-bill every Cat's first seconds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cat_mid_action_on_the_reporting_node_still_bills() {
    let context = context().await;
    context
        .with_db(|client| {
            client
                .execute(
                    "UPDATE cats
                        SET state=NULL, node_id=NULL, current_action='create',
                            current_action_started_at=1, current_action_node_id=$1
                      WHERE cat_id=$2",
                    &[&NODE_ID, &CAT_ID],
                )
                .expect("leave the Cat mid-create on the reporting Node");
        })
        .await;

    let (status, body) = context
        .ingest(NODED_TOKEN, one_cpu_hour_and_one_gib_hour(0))
        .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body.expect("ingest body").accepted, 2);
}

/// The epoch's closing sample arrives after the Cat has left the Node. It must
/// still settle: the frozen attribution answers before placement is consulted,
/// which is what makes the placement check safe to add.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_final_sample_of_a_departed_cat_still_bills_its_owner() {
    let context = context().await;
    let (status, _) = context
        .ingest(NODED_TOKEN, one_cpu_hour_and_one_gib_hour(0))
        .await;
    assert_eq!(status, StatusCode::OK);
    context
        .with_db(|client| {
            client
                .execute(
                    "UPDATE cats
                        SET state='destroyed', node_id=NULL, destroyed_at=2
                      WHERE cat_id=$1",
                    &[&CAT_ID],
                )
                .expect("destroy the Cat");
        })
        .await;

    let (status, body) = context
        .ingest(
            NODED_TOKEN,
            vec![checkpoint(
                CAT_ID,
                SOURCE_EPOCH,
                1,
                UsageMetric::CpuUsec,
                2 * 3_600_000_000,
            )],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body.expect("ingest body").accepted, 1);
    assert_eq!(
        context.provisional_usage_nanos(WORKSPACE_ID).await,
        70_000_000,
        "the closed epoch's CPU interval still bills the frozen owner"
    );
}

/// Characterizes what the fleet-shared token is and is not worth, so the
/// boundary is pinned rather than assumed.
///
/// ADR-0059 identifies a Node by a body field under one shared token, the same
/// way `register` and `heartbeat` do, so a token holder can claim to be another
/// Node. Placement still bounds the claim to that Node's Cats, and everything
/// that decides money stays with Control. If a per-Node identity ever lands,
/// this test should start failing on its first assertion.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claimed_node_identity_is_bounded_by_placement_not_proven() {
    let context = context().await;
    context
        .with_db(|client| {
            client
                .batch_execute(&format!(
                    "INSERT INTO nodes (
                        node_id,node_name,control_endpoint,vendor,region,zone,instance_id,
                        machine_type,node_version,status,created_at,updated_at
                     ) VALUES (
                        'node_metal-2','metal-2','http://10.0.0.2:7301','aws','us-east-1',
                        'us-east-1b','i-usage-2','c5d.metal','1.0.0','running',1,1
                     );
                     INSERT INTO cats (
                        cat_id,workspace_id,cat_slug,state,node_id,cpu_count,memory_bytes,
                        boot_image,created_at,updated_at,last_running_at
                     ) VALUES (
                        'cat_onmetaltwo01','{OTHER_WORKSPACE_ID}','other','running',
                        'node_metal-2',2,2147483648,'sha256:image',1,1,1
                     );"
                ))
                .expect("a second Node with its own Cat");
        })
        .await;

    // Claiming to be metal-2 is accepted for metal-2's own Cat: the identity is
    // asserted, not proven.
    let (status, body) = context
        .ingest_as(
            "node_metal-2",
            vec![checkpoint_from(
                "node_metal-2",
                "cat_onmetaltwo01",
                SOURCE_EPOCH,
                0,
                UsageMetric::CpuUsec,
                3_600_000_000,
            )],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(
        body.expect("ingest body").accepted,
        1,
        "a claimed Node identity is not verified today"
    );

    // The claim buys nothing beyond that Node's placements: metal-2 still
    // cannot reach a Cat Control places on metal-1.
    let (status, body) = context
        .ingest_as(
            "node_metal-2",
            vec![checkpoint_from(
                "node_metal-2",
                CAT_ID,
                SOURCE_EPOCH,
                0,
                UsageMetric::CpuUsec,
                3_600_000_000,
            )],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let body = body.expect("ingest body");
    assert_eq!(body.accepted, 0);
    assert!(
        body.rejected[0]
            .reason
            .contains("not placed on the reporting Node"),
        "{body:?}"
    );
    assert_eq!(
        context.provisional_usage_nanos(WORKSPACE_ID).await,
        0,
        "the impersonated report never reaches another Node's Cat owner"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn usage_ingestion_requires_the_node_service_token() {
    let context = context().await;
    let (status, _) = context
        .ingest(
            "semantic-usage-wrong-token-000000",
            one_cpu_hour_and_one_gib_hour(0),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(context.provisional_usage_nanos(WORKSPACE_ID).await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_checkpoint_may_not_claim_another_producer() {
    let context = context().await;
    let request = IngestUsageCheckpointsRequest {
        session: producer(),
        node_id: NODE_ID.to_owned(),
        checkpoints: vec![checkpoint(
            CAT_ID,
            SOURCE_EPOCH,
            0,
            UsageMetric::CpuUsec,
            1_000,
        )],
    };
    let mut forged = request.clone();
    forged.checkpoints[0].source_id = format!("node/node_metal-2/cat/{CAT_ID}");
    forged.checkpoints[0].event_id = deterministic_event_id(&forged.checkpoints[0]);
    let response = context
        .http
        .post(format!(
            "{}{USAGE_CHECKPOINTS_PATH}",
            context.server.base_url()
        ))
        .header(
            NODED_AUTHORIZATION_HEADER,
            NodedServiceToken::new(NODED_TOKEN.to_owned())
                .expect("service token")
                .authorization_value(),
        )
        .json(&forged)
        .send()
        .await
        .expect("forged ingestion request");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(context.provisional_usage_nanos(WORKSPACE_ID).await, 0);
}
