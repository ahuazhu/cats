//! `query_totals` must agree with folding every interval, in PostgreSQL.
//!
//! Admission (`require_funded`) needs one fact -- whether a Billing Account has
//! anything left -- and computing it through `query` selected, sorted and
//! shipped every interval the Account had ever accrued. The window is unbounded
//! below, so the cost grew with the whole history: a no-op `exec` reached ~35 s
//! while the node agent answered the identical call in 2 ms.
//!
//! The fast path aggregates in SQL, which means it re-implements billing
//! arithmetic. A faster answer that disagrees with the slow one would silently
//! mis-bill, so equivalence -- not speed -- is what this asserts, on the cases
//! where the two could diverge: clipped windows, several metrics, filters that
//! exclude everything, and quantities past `u64`.
//!
//! `SqliteUsageStore` keeps the port's folding default instead of an override,
//! because SQLite integers are 64-bit and byte-millisecond quantities are
//! `u128`: prorating there would overflow into floating point. So this is the
//! only place the SQL aggregation can be checked, and it needs a real database.
//!
//! Set `CATS_TEST_POSTGRES_URL` to run it. Without one it skips rather than
//! passes vacuously, so a green run without that variable is not evidence.

use cats_api::metering::{CatUsageCheckpoint, UsageMetric};
use cats_api::runtime_reconciliation::{
    Epoch, Id, NodeBootId, RandomId128, Revision, SessionBinding,
};
use cats_metering::{
    deterministic_event_id, AttributedCheckpoint, RuntimeUsageSourceBinding, UsageAttribution,
    UsageQuery, UsageStore,
};
use cats_usage_store_postgres::PostgresUsageStore;

const ACCOUNT: &str = "ba-query-totals-equivalence";

fn store(schema: &str) -> Option<PostgresUsageStore> {
    let url = std::env::var("CATS_TEST_POSTGRES_URL").ok()?;
    let ca_file = std::env::var("CATS_TEST_POSTGRES_CA_FILE").ok();
    Some(
        PostgresUsageStore::connect(&url, ca_file.as_deref(), schema, 2)
            .expect("connect to the test PostgreSQL"),
    )
}

fn checkpoint(
    sequence: u64,
    observed_at_unix_ms: i64,
    cumulative_quantity: u128,
    metric: UsageMetric,
) -> AttributedCheckpoint {
    let mut checkpoint = CatUsageCheckpoint {
        event_id: String::new(),
        source_id: "node/node-a/cat/cat-a".to_string(),
        source_epoch: "epoch-a".to_string(),
        sequence,
        observed_at_unix_ms,
        cat_id: "cat-a".to_string(),
        cat_generation: 1,
        metric,
        epoch_marker: cats_api::metering::UsageEpochMarker::Open,
        cumulative_quantity,
    };
    checkpoint.event_id = deterministic_event_id(&checkpoint);
    AttributedCheckpoint {
        source_binding: RuntimeUsageSourceBinding {
            session: SessionBinding {
                node_id: Id::new("node-a").unwrap(),
                node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
                agent_instance_id: RandomId128::new("22222222222222222222222222222222").unwrap(),
                agent_session_epoch: Epoch::new(1).unwrap(),
            },
            desired_revision: Revision::new(1).unwrap(),
            runtime_incarnation: RandomId128::new("33333333333333333333333333333333").unwrap(),
        },
        attribution: UsageAttribution {
            billing_account_id: ACCOUNT.to_string(),
            workspace_id: "workspace-a".to_string(),
            resource_type: "cat".to_string(),
            resource_id: "cat-a".to_string(),
            attributed_cat_id: Some("cat-a".to_string()),
        },
        checkpoint,
    }
}

#[tokio::test]
async fn query_totals_agrees_with_folding_every_interval() {
    let schema = "cats_usage_totals_equivalence";
    let Some(store) = store(schema) else {
        eprintln!("skipped: set CATS_TEST_POSTGRES_URL to exercise the SQL aggregation");
        return;
    };

    // A byte-millisecond counter deliberately past u64, which is why the fold
    // uses u128 and why the SQL side must stay in arbitrary-precision numeric.
    let huge = u128::from(u64::MAX) + 1_000_000;
    for (metric, step) in [
        (UsageMetric::CpuUsec, 1_000_u128),
        (UsageMetric::MemoryByteMillis, huge),
    ] {
        for sequence in 0..4_u64 {
            let observed = 1_000 + i64::try_from(sequence).unwrap() * 10_000;
            let cumulative = step * u128::from(sequence);
            store
                .ingest(&checkpoint(sequence, observed, cumulative, metric))
                .await
                .expect("ingest");
        }
    }

    let windows = [
        // The admission window: unbounded below, contains everything.
        (0_i64, 1_000_000_i64),
        // Clips the leading interval, so proration and truncation must match.
        (6_000, 1_000_000),
        // Clips both ends.
        (6_000, 16_000),
        // Excludes everything.
        (500_000, 600_000),
    ];
    for (start, end) in windows {
        for (workspace, cat) in [
            (None, None),
            (Some("workspace-a".to_string()), None),
            (None, Some("cat-a".to_string())),
            (Some("workspace-absent".to_string()), None),
        ] {
            let query = UsageQuery {
                billing_account_id: ACCOUNT.to_string(),
                workspace_id: workspace.clone(),
                attributed_cat_id: cat.clone(),
                interval_start_unix_ms: start,
                interval_end_unix_ms: end,
            };
            let folded = store.query(&query).await.expect("fold every interval");
            let aggregated = store.query_totals(&query).await.expect("aggregate in SQL");
            assert_eq!(
                aggregated.totals, folded.totals,
                "totals disagree for window [{start}, {end}) workspace={workspace:?} cat={cat:?}"
            );
            assert_eq!(
                aggregated.latest_interval_end_unix_ms, folded.latest_interval_end_unix_ms,
                "visible-through disagrees for [{start}, {end}) workspace={workspace:?} cat={cat:?}"
            );
        }
    }
}
