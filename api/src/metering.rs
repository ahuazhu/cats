//! Stable usage-metering wire types.
//!
//! Producers report cumulative integer counters. They never report money or
//! choose a billing account; trusted control-plane ingestion freezes resource
//! attribution before writing immutable raw checkpoints. Usage intervals are
//! rebuildable projections of those checkpoints.

use serde::{Deserialize, Serialize};

/// Hard limit enforced by the control-plane JSON extractor. Producers should
/// target materially less than this so headers and intermediary framing never
/// put an otherwise valid checkpoint batch on the boundary.
pub const MAX_USAGE_INGEST_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Independent cardinality defense for a syntactically small request.
pub const MAX_USAGE_CHECKPOINTS_PER_REQUEST: usize = 10_000;

/// Canonical V1 meter definitions. Their units are immutable once emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageMetric {
    /// Cgroup v2 `cpu.stat usage_usec`.
    CpuUsec,
    /// Integral of cgroup v2 `memory.current` over wall-clock milliseconds.
    MemoryByteMillis,
    /// Integral of live, customer-attributable hot bytes over milliseconds.
    StorageHotByteMillis,
    /// Integral of live, customer-attributable cold bytes over milliseconds.
    StorageColdByteMillis,
    /// Public network bytes sent on behalf of a customer.
    NetworkEgressBytes,
}

impl UsageMetric {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::CpuUsec => "cats.compute.cpu.v1",
            Self::MemoryByteMillis => "cats.compute.memory.v1",
            Self::StorageHotByteMillis => "cats.storage.hot.v1",
            Self::StorageColdByteMillis => "cats.storage.cold.v1",
            Self::NetworkEgressBytes => "cats.network.egress.v1",
        }
    }

    pub const fn canonical_unit(self) -> &'static str {
        match self {
            Self::CpuUsec => "microsecond",
            Self::MemoryByteMillis | Self::StorageHotByteMillis | Self::StorageColdByteMillis => {
                "byte_millisecond"
            }
            Self::NetworkEgressBytes => "byte",
        }
    }
}

/// One cumulative counter produced by a trusted data-plane source.
///
/// `source_epoch` changes whenever the underlying counter can reset (for
/// example, a new Cat runtime cgroup). Sequence and quantity are monotonic
/// within `(source_id, source_epoch, metric)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatUsageCheckpoint {
    /// Deterministic identifier derived from source, epoch, metric and sequence.
    pub event_id: String,
    /// Stable producer identity, normally `node/<node-id>/cat/<cat-id>`.
    pub source_id: String,
    /// Opaque runtime/allocation epoch.
    pub source_epoch: String,
    pub sequence: u64,
    pub observed_at_unix_ms: i64,
    pub cat_id: String,
    pub cat_generation: i64,
    pub metric: UsageMetric,
    /// Decimal string on the wire. Byte-millisecond counters exceed `u64`
    /// for long-lived, memory-heavy runtimes.
    #[serde(with = "decimal_u128")]
    pub cumulative_quantity: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestUsageCheckpointsRequest {
    pub node_id: String,
    pub checkpoints: Vec<CatUsageCheckpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestUsageCheckpointsResponse {
    pub accepted: u64,
    pub duplicates: u64,
    /// Checkpoints the ledger will never be able to accept.
    ///
    /// A durable outbox delivers an ordered prefix, so one permanently
    /// unacceptable checkpoint used to fail the whole request and block every
    /// checkpoint behind it -- forever, because retrying could not change the
    /// answer. Naming them lets the request still succeed: the producer stops
    /// resending them and the queue drains. Empty in the ordinary case, and
    /// absent on the wire, so an older producer is unaffected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<RejectedCheckpoint>,
}

/// One checkpoint the ledger refused for good, with why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectedCheckpoint {
    pub event_id: String,
    pub reason: String,
}

/// Provisional usage line returned by the near-real-time billing API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageSummaryLine {
    pub metric: UsageMetric,
    /// Decimal string avoids losing integers above JavaScript's safe range.
    pub quantity: String,
    pub unit: String,
    /// Rated once after aggregation; absent for an unpriced meter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_nanos: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatUsageSummary {
    pub cat_id: String,
    pub items: Vec<UsageSummaryLine>,
    pub amount_nanos: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageDetailLine {
    pub interval_start_unix_ms: i64,
    pub interval_end_unix_ms: i64,
    pub resource_type: String,
    pub resource_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributed_cat_id: Option<String>,
    pub metric: UsageMetric,
    pub quantity: String,
    pub unit: String,
    pub source_id: String,
    pub source_epoch: String,
    pub end_sequence: u64,
}

/// Bounded server-side projection for an over-time billing view.
///
/// Quantities are partitioned from the same boundary-prorated ledger
/// intervals used by the report totals. Bucket amounts are display estimates;
/// the report total remains the authoritative range-level rating.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageTimeBucket {
    pub interval_start_unix_ms: i64,
    pub interval_end_unix_ms: i64,
    pub items: Vec<UsageSummaryLine>,
    pub amount_nanos: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageReport {
    pub billing_account_id: String,
    pub workspace_id: String,
    pub interval_start_unix_ms: i64,
    pub interval_end_unix_ms: i64,
    /// V1 query results are provisional until an explicit invoice close.
    pub status: String,
    pub currency: String,
    pub rate_card_id: String,
    /// Latest interval currently visible; this is not an invoice-close
    /// watermark and must not be presented as finalized coverage.
    pub latest_interval_end_unix_ms: Option<i64>,
    pub items: Vec<UsageSummaryLine>,
    pub cats: Vec<CatUsageSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub time_buckets: Vec<UsageTimeBucket>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<UsageDetailLine>,
    pub amount_nanos: String,
}

mod decimal_u128 {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(de::Error::custom(
                "cumulative_quantity must be a canonical unsigned decimal string",
            ));
        }
        value
            .parse()
            .map_err(|_| de::Error::custom("cumulative_quantity exceeds u128"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_quantity_is_an_exact_decimal_string() {
        let checkpoint = CatUsageCheckpoint {
            event_id: "usage-test".to_string(),
            source_id: "source".to_string(),
            source_epoch: "epoch".to_string(),
            sequence: 1,
            observed_at_unix_ms: 1,
            cat_id: "cat".to_string(),
            cat_generation: 1,
            metric: UsageMetric::MemoryByteMillis,
            cumulative_quantity: u128::MAX,
        };
        let json = serde_json::to_string(&checkpoint).unwrap();
        assert!(json.contains(&format!("\"cumulative_quantity\":\"{}\"", u128::MAX)));
        assert_eq!(
            serde_json::from_str::<CatUsageCheckpoint>(&json)
                .unwrap()
                .cumulative_quantity,
            u128::MAX
        );
    }

    #[test]
    fn checkpoint_quantity_rejects_json_numbers_and_noncanonical_decimals() {
        let base = r#"{
            "event_id":"usage-test","source_id":"source","source_epoch":"epoch",
            "sequence":1,"observed_at_unix_ms":1,"cat_id":"cat",
            "cat_generation":1,"metric":"memory_byte_millis",
            "cumulative_quantity":VALUE
        }"#;
        for invalid in ["1", "\"01\"", "\"-1\"", "\"1.0\""] {
            assert!(
                serde_json::from_str::<CatUsageCheckpoint>(&base.replace("VALUE", invalid))
                    .is_err()
            );
        }
    }
}
