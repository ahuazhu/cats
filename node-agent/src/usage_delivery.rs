//! One ordered, signed delivery lane for every Node usage producer.

use std::time::{Duration, Instant};

use anyhow::Context as _;
use cats_api::agent_registration::{
    Ed25519RequestSigner, JSON_CONTENT_TYPE, NODE_CREDENTIAL_ID_HEADER,
    NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER,
};
use cats_api::metering::{
    CatUsageCheckpoint, IngestUsageCheckpointsRequest, IngestUsageCheckpointsResponse,
    UsageCheckpointIngestOutcome, MAX_USAGE_CHECKPOINTS_PER_REQUEST, MAX_USAGE_INGEST_BODY_BYTES,
    USAGE_CHECKPOINTS_METHOD, USAGE_CHECKPOINTS_PATH,
};
use cats_api::runtime_reconciliation::{AgentSession, SessionBinding};
use reqwest::StatusCode;

use crate::usage_spool::UsageSpool;

/// Use half the server's explicit JSON limit. The budget covers the complete
/// serialized request and leaves room for stricter intermediaries.
const USAGE_REQUEST_TARGET_BYTES: usize = MAX_USAGE_INGEST_BODY_BYTES / 2;
const USAGE_DELIVERY_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const USAGE_DELIVERY_MAX_BACKOFF: Duration = Duration::from_secs(60);
const MAX_INGEST_ERROR_DETAIL_CHARS: usize = 512;

#[derive(Debug)]
pub(crate) struct UsageDeliveryState {
    request_budget_bytes: usize,
    max_checkpoints_per_request: usize,
    consecutive_failures: u32,
    pub(crate) retry_not_before: Option<Instant>,
}

impl Default for UsageDeliveryState {
    fn default() -> Self {
        Self {
            request_budget_bytes: USAGE_REQUEST_TARGET_BYTES,
            max_checkpoints_per_request: MAX_USAGE_CHECKPOINTS_PER_REQUEST,
            consecutive_failures: 0,
            retry_not_before: None,
        }
    }
}

impl UsageDeliveryState {
    fn retry_delay(&self, now: Instant) -> Option<Duration> {
        self.retry_not_before
            .and_then(|deadline| deadline.checked_duration_since(now))
    }

    fn record_idle(&mut self) {
        self.consecutive_failures = 0;
        self.retry_not_before = None;
    }

    fn record_success(&mut self) {
        self.record_idle();
        if self.max_checkpoints_per_request < MAX_USAGE_CHECKPOINTS_PER_REQUEST {
            let growth = (self.max_checkpoints_per_request / 8).max(1);
            self.max_checkpoints_per_request = self
                .max_checkpoints_per_request
                .saturating_add(growth)
                .min(MAX_USAGE_CHECKPOINTS_PER_REQUEST);
        }
    }

    fn record_failure(&mut self, now: Instant) -> Duration {
        let exponent = self.consecutive_failures.min(6);
        let multiplier = 1_u32 << exponent;
        let delay = USAGE_DELIVERY_INITIAL_BACKOFF
            .saturating_mul(multiplier)
            .min(USAGE_DELIVERY_MAX_BACKOFF);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.retry_not_before = now.checked_add(delay);
        delay
    }

    fn shrink_after_payload_too_large(
        &mut self,
        session: &SessionBinding,
        rejected: &[CatUsageCheckpoint],
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            rejected.len() > 1,
            "control plane rejected one usage checkpoint as payload too large; the queue head was retained"
        );
        let smaller_count = rejected.len() / 2;
        let smaller = IngestUsageCheckpointsRequest {
            session: session.clone(),
            node_id: session.node_id.to_string(),
            checkpoints: rejected[..smaller_count].to_vec(),
        };
        let smaller_bytes = serde_json::to_vec(&smaller)?.len();
        anyhow::ensure!(
            smaller_bytes < self.request_budget_bytes,
            "usage request split did not reduce the request budget"
        );
        self.request_budget_bytes = smaller_bytes;
        Ok(())
    }

    fn shrink_after_timeout(&mut self, rejected: &[CatUsageCheckpoint]) -> bool {
        if rejected.len() <= 1 {
            return false;
        }
        self.max_checkpoints_per_request = (rejected.len() / 2).max(1);
        true
    }
}

pub(crate) fn session_binding(session: &AgentSession) -> SessionBinding {
    SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    }
}

pub(crate) async fn deliver_usage_batches(
    client: &reqwest::Client,
    endpoint: &str,
    signer: &Ed25519RequestSigner,
    session: &SessionBinding,
    spool: &UsageSpool,
    delivery: &tokio::sync::Mutex<UsageDeliveryState>,
) -> anyhow::Result<()> {
    let mut delivery = delivery.lock().await;
    if spool.is_empty()? {
        delivery.record_idle();
        return Ok(());
    }
    if let Some(delay) = delivery.retry_delay(Instant::now()) {
        anyhow::bail!(
            "usage delivery is backing off for another {} ms",
            delay.as_millis()
        );
    }

    loop {
        let pending_checkpoints = match spool.peek_request_batch(
            session,
            delivery.max_checkpoints_per_request,
            delivery.request_budget_bytes,
        ) {
            Ok(checkpoints) => checkpoints,
            Err(error) => {
                let delay = delivery.record_failure(Instant::now());
                return Err(error).context(format!(
                    "build bounded usage request; retrying after {} ms",
                    delay.as_millis()
                ));
            }
        };
        if pending_checkpoints.is_empty() {
            delivery.record_idle();
            return Ok(());
        }
        let request = IngestUsageCheckpointsRequest {
            session: session.clone(),
            node_id: session.node_id.to_string(),
            checkpoints: pending_checkpoints.clone(),
        };
        let request_json = serde_json::to_vec(&request)?;
        anyhow::ensure!(
            request_json.len() <= delivery.request_budget_bytes,
            "usage request serialized to {} bytes above its {}-byte budget",
            request_json.len(),
            delivery.request_budget_bytes
        );
        let proof = signer.sign(
            USAGE_CHECKPOINTS_METHOD,
            USAGE_CHECKPOINTS_PATH,
            &request_json,
        );
        let response = match client
            .post(endpoint)
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
            .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
            .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
            .header(NODE_SIGNATURE_HEADER, proof.signature)
            .body(request_json)
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                let shrunk = error.is_timeout()
                    && !error.is_connect()
                    && delivery.shrink_after_timeout(&pending_checkpoints);
                let delay = delivery.record_failure(Instant::now());
                let capacity_detail = if shrunk {
                    format!(
                        "; reduced the next batch to at most {} checkpoints",
                        delivery.max_checkpoints_per_request
                    )
                } else {
                    String::new()
                };
                return Err(error).context(format!(
                    "send durable usage checkpoints{capacity_detail}; retrying after {} ms",
                    delay.as_millis(),
                ));
            }
        };
        if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
            if pending_checkpoints.len() == 1 {
                let delay = delivery.record_failure(Instant::now());
                anyhow::bail!(
                    "control plane rejected one usage checkpoint as payload too large; the queue head was retained and will retry after {} ms",
                    delay.as_millis()
                );
            }
            delivery.shrink_after_payload_too_large(session, &pending_checkpoints)?;
            continue;
        }
        if !response.status().is_success() {
            let status = response.status();
            let shrunk = matches!(
                status,
                StatusCode::REQUEST_TIMEOUT | StatusCode::GATEWAY_TIMEOUT
            ) && delivery.shrink_after_timeout(&pending_checkpoints);
            let detail = response.text().await.unwrap_or_default();
            let detail = detail.trim();
            let detail: String = detail.chars().take(MAX_INGEST_ERROR_DETAIL_CHARS).collect();
            let delay = delivery.record_failure(Instant::now());
            let capacity_detail = if shrunk {
                format!(
                    "; reduced the next batch to at most {} checkpoints",
                    delivery.max_checkpoints_per_request
                )
            } else {
                String::new()
            };
            if detail.is_empty() {
                anyhow::bail!(
                    "usage ingestion returned {status}{capacity_detail}; retrying after {} ms",
                    delay.as_millis()
                );
            }
            anyhow::bail!(
                "usage ingestion returned {status}: {detail}{capacity_detail}; retrying after {} ms",
                delay.as_millis()
            );
        }

        let response_body = match response.bytes().await {
            Ok(body) if body.len() <= MAX_USAGE_INGEST_BODY_BYTES => body,
            Ok(_) => {
                let delay = delivery.record_failure(Instant::now());
                anyhow::bail!(
                    "usage ingestion ACK exceeded its response limit; retaining the queue prefix for exact replay after {} ms",
                    delay.as_millis()
                );
            }
            Err(error) => {
                let delay = delivery.record_failure(Instant::now());
                return Err(error).context(format!(
                    "read usage ingestion ACK; retaining the queue prefix for exact replay after {} ms",
                    delay.as_millis()
                ));
            }
        };
        let acknowledgement: IngestUsageCheckpointsResponse = match serde_json::from_slice(
            &response_body,
        ) {
            Ok(acknowledgement) => acknowledgement,
            Err(error) => {
                let delay = delivery.record_failure(Instant::now());
                return Err(error).context(format!(
                        "decode usage ingestion ACK; retaining the queue prefix for exact replay after {} ms",
                        delay.as_millis()
                    ));
            }
        };
        if let Err(reason) = validate_exact_ack(&pending_checkpoints, &acknowledgement) {
            let delay = delivery.record_failure(Instant::now());
            anyhow::bail!(
                "usage ingestion returned an invalid ACK ({reason}); retaining the exact queue prefix for replay after {} ms",
                delay.as_millis()
            );
        }
        if let Some(first) = acknowledgement
            .results
            .iter()
            .find(|result| result.outcome == UsageCheckpointIngestOutcome::Rejected)
        {
            let delay = delivery.record_failure(Instant::now());
            anyhow::bail!(
                "usage ingestion permanently rejected event {}: {}; retaining the exact queue prefix for operator recovery after {} ms",
                first.event_id,
                first.reason.as_deref().unwrap_or("no closed reason"),
                delay.as_millis()
            );
        }

        let event_ids = pending_checkpoints
            .iter()
            .map(|checkpoint| checkpoint.event_id.clone())
            .collect::<Vec<_>>();
        spool.acknowledge(&event_ids)?;
        delivery.record_success();
    }
}

fn validate_exact_ack(
    pending: &[CatUsageCheckpoint],
    acknowledgement: &IngestUsageCheckpointsResponse,
) -> Result<(), &'static str> {
    let exact_order = acknowledgement.results.len() == pending.len()
        && acknowledgement
            .results
            .iter()
            .zip(pending)
            .all(|(result, checkpoint)| result.event_id == checkpoint.event_id);
    if !exact_order {
        return Err("results do not match the exact request order");
    }
    if acknowledgement
        .results
        .iter()
        .any(|result| match result.outcome {
            UsageCheckpointIngestOutcome::Accepted | UsageCheckpointIngestOutcome::ExactReplay => {
                result.reason.is_some()
            }
            UsageCheckpointIngestOutcome::Rejected => {
                result.reason.as_deref().is_none_or(str::is_empty)
            }
        })
    {
        return Err("result reason does not match its outcome");
    }
    let accepted = acknowledgement
        .results
        .iter()
        .filter(|result| result.outcome == UsageCheckpointIngestOutcome::Accepted)
        .count() as u64;
    let exact_replays = acknowledgement
        .results
        .iter()
        .filter(|result| result.outcome == UsageCheckpointIngestOutcome::ExactReplay)
        .count() as u64;
    let rejected = acknowledgement
        .results
        .iter()
        .filter(|result| result.outcome == UsageCheckpointIngestOutcome::Rejected)
        .collect::<Vec<_>>();
    let rejected_match = rejected.len() == acknowledgement.rejected.len()
        && rejected
            .iter()
            .zip(&acknowledgement.rejected)
            .all(|(result, legacy)| {
                result.event_id == legacy.event_id
                    && result.reason.as_deref() == Some(legacy.reason.as_str())
            });
    if acknowledgement.accepted != accepted
        || acknowledgement.duplicates != exact_replays
        || !rejected_match
    {
        return Err("aggregate diagnostics do not mirror exact results");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use cats_api::metering::{
        RejectedCheckpoint, UsageCheckpointIngestResult, UsageEpochMarker, UsageMetric,
    };

    use super::*;

    fn checkpoint(event_id: &str) -> CatUsageCheckpoint {
        CatUsageCheckpoint {
            event_id: event_id.to_owned(),
            source_id: "node/node-a/cat/cat-a".to_owned(),
            source_epoch: "epoch-a".to_owned(),
            sequence: 1,
            observed_at_unix_ms: 1_000,
            cat_id: "cat-a".to_owned(),
            cat_generation: 1,
            metric: UsageMetric::CpuUsec,
            epoch_marker: UsageEpochMarker::Open,
            cumulative_quantity: 1,
        }
    }

    #[test]
    fn exact_ack_rejects_missing_foreign_or_reordered_results() {
        let pending = vec![checkpoint("one"), checkpoint("two")];
        for event_ids in [vec!["one"], vec!["one", "foreign"], vec!["two", "one"]] {
            let acknowledgement = IngestUsageCheckpointsResponse {
                accepted: event_ids.len() as u64,
                duplicates: 0,
                rejected: Vec::new(),
                results: event_ids
                    .into_iter()
                    .map(|event_id| UsageCheckpointIngestResult {
                        event_id: event_id.to_owned(),
                        outcome: UsageCheckpointIngestOutcome::Accepted,
                        reason: None,
                    })
                    .collect(),
            };
            assert!(validate_exact_ack(&pending, &acknowledgement).is_err());
        }
    }

    #[test]
    fn exact_ack_retains_the_whole_prefix_on_any_rejection_or_count_drift() {
        let pending = vec![checkpoint("one"), checkpoint("two")];
        let rejected = IngestUsageCheckpointsResponse {
            accepted: 1,
            duplicates: 0,
            rejected: vec![RejectedCheckpoint {
                event_id: "two".to_owned(),
                reason: "closed".to_owned(),
            }],
            results: vec![
                UsageCheckpointIngestResult {
                    event_id: "one".to_owned(),
                    outcome: UsageCheckpointIngestOutcome::Accepted,
                    reason: None,
                },
                UsageCheckpointIngestResult {
                    event_id: "two".to_owned(),
                    outcome: UsageCheckpointIngestOutcome::Rejected,
                    reason: Some("closed".to_owned()),
                },
            ],
        };
        assert!(validate_exact_ack(&pending, &rejected).is_ok());
        assert!(rejected
            .results
            .iter()
            .any(|result| result.outcome == UsageCheckpointIngestOutcome::Rejected));

        let mut drift = rejected;
        drift.accepted = 2;
        assert!(validate_exact_ack(&pending, &drift).is_err());
    }
}
