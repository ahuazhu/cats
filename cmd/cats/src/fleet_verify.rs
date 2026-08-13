//! Production empty-fleet registration verifier.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::future::Future;
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use cats_api::agent_registration::JSON_CONTENT_TYPE;
use cats_api::fleet_verification::{
    decode_fleet_verification_snapshot, encode_fleet_verification_evidence, FleetExpectedKeyRing,
    FleetVerificationEvidence, FleetVerificationInventory, FleetVerificationSnapshot,
    FLEET_INVENTORY_MAX_AGE_MS, FLEET_VERIFICATION_MAX_NODES, FLEET_VERIFICATION_MAX_WIRE_BYTES,
    FLEET_VERIFICATION_PATH,
};
use cats_api::route_grant_v2::{
    decode_route_grant_v2_public_key_ring, RouteGrantV2PublicKeyRingArtifact,
};
use cats_api::runtime_reconciliation::{AgentSession, ContractVersion, Id, UnixMillis};

use crate::{auth, config, Cli};

const KEY_RING_MAX_BYTES: usize = 64 * 1024;
const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

enum RequestAuthority {
    ExplicitToken(String),
    Session(auth::FleetAdminSession),
}

impl RequestAuthority {
    fn token(&self) -> &str {
        match self {
            Self::ExplicitToken(token) => token,
            Self::Session(session) => &session.access_token,
        }
    }

    fn assert_current(&self) -> Result<()> {
        match self {
            Self::ExplicitToken(_) => Ok(()),
            Self::Session(session) => session.assert_current(),
        }
    }
}

#[derive(Clone)]
struct TrackedNode {
    session: AgentSession,
    inventory: Option<FleetVerificationInventory>,
}

struct PollState {
    expected_nodes: Vec<Id>,
    expected_ring: FleetExpectedKeyRing,
    release_commit_sha: String,
    nodes: BTreeMap<Id, TrackedNode>,
    signer_binding: Option<cats_api::fleet_verification::FleetRouteSigningAuthority>,
}

impl PollState {
    fn observe(&mut self, snapshot: &FleetVerificationSnapshot) -> Result<bool> {
        anyhow::ensure!(
            snapshot.control_release_commit_sha.as_deref()
                == Some(self.release_commit_sha.as_str()),
            "Control is not the explicitly qualified release commit {} (reported {:?})",
            self.release_commit_sha,
            snapshot.control_release_commit_sha
        );
        anyhow::ensure!(
            snapshot.desired_runtime_count.get() == 0,
            "Control still contains {} DesiredRuntimeSpec rows",
            snapshot.desired_runtime_count.get()
        );
        anyhow::ensure!(
            snapshot.current_runtime_observation_count.get() == 0,
            "Control still contains {} current runtime observation rows",
            snapshot.current_runtime_observation_count.get()
        );

        let actual_nodes = snapshot
            .nodes
            .iter()
            .map(|node| node.node_id.clone())
            .collect::<Vec<_>>();
        let extras = actual_nodes
            .iter()
            .filter(|node| self.expected_nodes.binary_search(node).is_err())
            .collect::<Vec<_>>();
        anyhow::ensure!(
            extras.is_empty(),
            "Control returned unexpected provisioned Nodes: {extras:?}"
        );
        for node_id in self.nodes.keys() {
            anyhow::ensure!(
                actual_nodes.binary_search(node_id).is_ok(),
                "provisioned Node {node_id} disappeared during verification"
            );
        }

        let Some(signer) = &snapshot.route_signing_authority else {
            bail!("Control has no persisted current Route v2 signing authority");
        };
        let active_kid = signer
            .active_kid
            .as_ref()
            .context("Control current Route v2 signing authority is disabled")?;
        anyhow::ensure!(
            signer.public_key_ring_version == self.expected_ring.ring_version
                && signer.public_key_ring_digest == self.expected_ring.key_ring_digest
                && self.expected_ring.kids.binary_search(active_kid).is_ok(),
            "Control current Route v2 signing authority does not match the expected public ring"
        );
        if let Some(previous) = &self.signer_binding {
            anyhow::ensure!(
                previous == signer,
                "Control Route v2 signing authority changed during verification"
            );
        } else {
            self.signer_binding = Some(signer.clone());
        }

        let mut all_ready = actual_nodes == self.expected_nodes;
        for expected in &self.expected_nodes {
            let Some(node) = snapshot
                .nodes
                .binary_search_by(|node| node.node_id.cmp(expected))
                .ok()
                .map(|index| &snapshot.nodes[index])
            else {
                all_ready = false;
                continue;
            };
            let Some(session) = &node.session else {
                anyhow::ensure!(
                    !self.nodes.contains_key(expected),
                    "current AgentSession for {expected} disappeared during verification"
                );
                all_ready = false;
                continue;
            };
            if let Some(previous) = self.nodes.get(expected) {
                anyhow::ensure!(
                    same_session_identity(&previous.session, session),
                    "AgentSession ABA/drift detected for {expected}"
                );
                anyhow::ensure!(
                    session.lease_deadline_unix_ms >= previous.session.lease_deadline_unix_ms,
                    "AgentSession lease regressed for {expected}"
                );
            }
            anyhow::ensure!(
                session.guest_config_digest == snapshot.approved_guest_config_digest,
                "AgentSession for {expected} is bound to a different Guest release"
            );

            let prior_inventory = self
                .nodes
                .get(expected)
                .and_then(|tracked| tracked.inventory.as_ref());
            let current_inventory = node
                .inventory
                .as_ref()
                .filter(|inventory| inventory_binds_session(inventory, session));
            anyhow::ensure!(
                !(prior_inventory.is_some() && current_inventory.is_none()),
                "complete inventory evidence for {expected} disappeared during verification"
            );
            if let (Some(previous), Some(current)) = (prior_inventory, current_inventory) {
                anyhow::ensure!(
                    current.attestation.inventory_epoch >= previous.attestation.inventory_epoch,
                    "inventory epoch regressed for {expected}"
                );
                if current.attestation.inventory_epoch == previous.attestation.inventory_epoch {
                    anyhow::ensure!(
                        current == previous,
                        "same inventory epoch changed evidence for {expected}"
                    );
                } else {
                    anyhow::ensure!(
                        current.attestation.accepted_at_unix_ms
                            > previous.attestation.accepted_at_unix_ms
                            && current.attestation.inventory_read_position
                                >= previous.attestation.inventory_read_position
                            && current.source_heartbeat_sequence
                                > previous.source_heartbeat_sequence,
                        "new inventory epoch regressed causal evidence for {expected}"
                    );
                }
            }
            self.nodes.insert(
                expected.clone(),
                TrackedNode {
                    session: session.clone(),
                    inventory: current_inventory.cloned(),
                },
            );

            if !node_ready(
                snapshot.evaluated_at_unix_ms,
                session,
                node.inventory.as_ref(),
                &self.expected_ring,
            )? {
                all_ready = false;
            }
        }
        Ok(all_ready)
    }
}

pub(crate) fn run(
    cli: &Cli,
    raw_expected_nodes: &[String],
    key_ring_path: &Path,
    release_commit_sha: &str,
    timeout_seconds: u64,
    poll_interval_ms: u64,
) -> Result<()> {
    anyhow::ensure!(
        cli.workspace.is_none(),
        "fleet verification is not Workspace-scoped; remove --workspace/CATS_WORKSPACE"
    );
    anyhow::ensure!(
        !cli.no_wait,
        "fleet verification must wait for the complete proof; remove --no-wait"
    );
    validate_release_commit(release_commit_sha)?;
    let expected_nodes = parse_expected_nodes(raw_expected_nodes)?;
    let ring = read_key_ring(key_ring_path)?;
    let expected_ring = expected_ring(&ring)?;
    let timeout = Duration::from_secs(timeout_seconds);
    let poll_interval = Duration::from_millis(poll_interval_ms);
    anyhow::ensure!(
        !timeout.is_zero() && timeout <= MAX_TIMEOUT,
        "--timeout-seconds must be from 1 through {}",
        MAX_TIMEOUT.as_secs()
    );
    anyhow::ensure!(
        !poll_interval.is_zero() && poll_interval <= timeout,
        "--poll-interval-ms must be positive and no greater than the timeout"
    );

    let (origin, authority) = request_authority(cli)?;
    let runtime = tokio::runtime::Runtime::new().context("start fleet verification runtime")?;
    let started_at = unix_millis()?;
    let deadline_at = checked_add_millis(started_at, timeout.as_millis())?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("fleet verification monotonic deadline overflow")?;
    let mut state = PollState {
        expected_nodes: expected_nodes.clone(),
        expected_ring: expected_ring.clone(),
        release_commit_sha: release_commit_sha.to_owned(),
        nodes: BTreeMap::new(),
        signer_binding: None,
    };

    let result = runtime.block_on(poll_or_cancel(
        poll(&origin, &authority, deadline, poll_interval, &mut state),
        tokio::signal::ctrl_c(),
    ));
    authority
        .assert_current()
        .context("fleet-administrator lock changed during fleet verification")?;
    let snapshot = result?;
    let completed_at = unix_millis()?;
    anyhow::ensure!(
        completed_at <= deadline_at,
        "fleet verification completed after its absolute deadline"
    );
    let evidence = FleetVerificationEvidence {
        version: ContractVersion::V1,
        release_commit_sha: release_commit_sha.to_owned(),
        started_at_unix_ms: started_at,
        deadline_unix_ms: deadline_at,
        completed_at_unix_ms: completed_at,
        expected_nodes,
        expected_key_ring: expected_ring,
        snapshot,
    };
    let bytes = encode_fleet_verification_evidence(&evidence)
        .map_err(|error| anyhow!("encode canonical fleet verification evidence: {error}"))?;
    std::io::stdout()
        .write_all(&bytes)
        .context("write canonical fleet verification evidence")?;
    std::io::stdout()
        .flush()
        .context("flush canonical fleet verification evidence")?;
    Ok(())
}

async fn poll_or_cancel<T, P, C>(poll: P, cancel: C) -> Result<T>
where
    P: Future<Output = Result<T>>,
    C: Future<Output = std::io::Result<()>>,
{
    tokio::pin!(poll);
    tokio::pin!(cancel);
    tokio::select! {
        biased;
        result = &mut poll => result,
        signal = &mut cancel => {
            signal.context("listen for fleet verification cancellation")?;
            Err(anyhow!("fleet verification cancelled"))
        }
    }
}

async fn poll(
    origin: &str,
    authority: &RequestAuthority,
    deadline: Instant,
    poll_interval: Duration,
    state: &mut PollState,
) -> Result<FleetVerificationSnapshot> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .build()
        .context("build closed fleet verification HTTP client")?;
    let url = format!("{origin}{FLEET_VERIFICATION_PATH}");
    loop {
        let request_budget = remaining(deadline)?;
        authority.assert_current()?;
        let fetched = fetch_snapshot(&client, &url, authority.token(), request_budget).await;
        let authority_after = authority.assert_current();
        authority_after.context("fleet-administrator lock changed during snapshot request")?;
        let snapshot = fetched?;
        if state.observe(&snapshot)? {
            return Ok(snapshot);
        }
        tokio::time::sleep(poll_interval.min(remaining(deadline)?)).await;
    }
}

async fn fetch_snapshot(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    timeout: Duration,
) -> Result<FleetVerificationSnapshot> {
    let mut response = client
        .get(url)
        .bearer_auth(token)
        .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .timeout(timeout)
        .send()
        .await
        .context("fleet verification HTTP response is ambiguous")?;
    anyhow::ensure!(
        response.url().as_str() == url,
        "fleet verification response URL changed"
    );
    anyhow::ensure!(
        response.status() == reqwest::StatusCode::OK,
        "fleet verification returned HTTP {}",
        response.status().as_u16()
    );
    let content_types = response
        .headers()
        .get_all(reqwest::header::CONTENT_TYPE)
        .iter()
        .map(reqwest::header::HeaderValue::as_bytes)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        content_types.as_slice() == [JSON_CONTENT_TYPE.as_bytes()],
        "fleet verification response Content-Type is not exact application/json"
    );
    anyhow::ensure!(
        response
            .headers()
            .get_all(reqwest::header::CONTENT_ENCODING)
            .iter()
            .next()
            .is_none(),
        "fleet verification response is content-encoded"
    );
    let cache_controls = response
        .headers()
        .get_all(reqwest::header::CACHE_CONTROL)
        .iter()
        .map(reqwest::header::HeaderValue::as_bytes)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        cache_controls.as_slice() == [b"no-store".as_slice()],
        "fleet verification response is not marked no-store"
    );
    if let Some(length) = response.content_length() {
        anyhow::ensure!(
            length <= FLEET_VERIFICATION_MAX_WIRE_BYTES as u64,
            "fleet verification response exceeds its wire limit"
        );
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("fleet verification response body is ambiguous")?
    {
        anyhow::ensure!(
            body.len().saturating_add(chunk.len()) <= FLEET_VERIFICATION_MAX_WIRE_BYTES,
            "fleet verification response exceeds its wire limit"
        );
        body.extend_from_slice(&chunk);
    }
    decode_fleet_verification_snapshot(&body)
        .map_err(|error| anyhow!("fleet verification response is invalid: {error}"))
}

fn node_ready(
    evaluated_at: UnixMillis,
    session: &AgentSession,
    inventory: Option<&FleetVerificationInventory>,
    expected_ring: &FleetExpectedKeyRing,
) -> Result<bool> {
    if evaluated_at >= session.lease_deadline_unix_ms {
        return Ok(false);
    }
    let Some(inventory) = inventory else {
        return Ok(false);
    };
    if !inventory_binds_session(inventory, session) {
        return Ok(false);
    }
    let accepted_at = inventory.attestation.accepted_at_unix_ms;
    let Some(fresh_until) = accepted_at.get().checked_add(FLEET_INVENTORY_MAX_AGE_MS) else {
        bail!(
            "inventory freshness timestamp overflow for {}",
            session.node_id
        );
    };
    if accepted_at > evaluated_at || evaluated_at.get() >= fresh_until {
        return Ok(false);
    }
    let empty_and_closed = inventory.complete_inventory
        && inventory.assigned_desired_count.get() == 0
        && inventory.runtime_count.get() == 0
        && inventory.residue_count.get() == 0
        && inventory.lifecycle_open_count.get() == 0
        && inventory.route_active_count.get() == 0
        && inventory.route_closed_count.get() == 0
        && inventory.active_guard_count.get() == 0
        && inventory.cancellation_pending_count.get() == 0
        && inventory.quarantined_condition_count.get() == 0;
    let exact_ack = inventory.key_ring_version == Some(expected_ring.ring_version)
        && inventory.key_ring_digest.as_ref() == Some(&expected_ring.key_ring_digest)
        && inventory.loaded_kids == expected_ring.kids;
    Ok(empty_and_closed && exact_ack)
}

fn inventory_binds_session(inventory: &FleetVerificationInventory, session: &AgentSession) -> bool {
    inventory.source_session.node_id == session.node_id
        && inventory.source_session.node_boot_id == session.node_boot_id
        && inventory.source_session.agent_instance_id == session.agent_instance_id
        && inventory.source_session.agent_session_epoch == session.agent_session_epoch
}

fn same_session_identity(left: &AgentSession, right: &AgentSession) -> bool {
    left.version == right.version
        && left.node_id == right.node_id
        && left.immutable_host_id == right.immutable_host_id
        && left.node_boot_id == right.node_boot_id
        && left.agent_instance_id == right.agent_instance_id
        && left.agent_session_epoch == right.agent_session_epoch
        && left.registration_attempt_id == right.registration_attempt_id
        && left.guest_config_digest == right.guest_config_digest
}

fn request_authority(cli: &Cli) -> Result<(String, RequestAuthority)> {
    if let Some(token) = &cli.token {
        anyhow::ensure!(!token.is_empty(), "--token is empty");
        let origin =
            config::canonical_https_origin(&auth::configured_api_url(cli.api_url.as_deref())?)
                .context("fleet verification requires one canonical HTTPS Control origin")?;
        return Ok((origin, RequestAuthority::ExplicitToken(token.clone())));
    }
    let session = auth::fleet_admin_session(cli.api_url.as_deref())?;
    let origin = config::canonical_https_origin(&session.api_url)
        .context("fleet verification requires one canonical HTTPS Control origin")?;
    Ok((origin, RequestAuthority::Session(session)))
}

fn parse_expected_nodes(raw: &[String]) -> Result<Vec<Id>> {
    anyhow::ensure!(!raw.is_empty(), "at least one --expected-node is required");
    anyhow::ensure!(
        raw.len() <= FLEET_VERIFICATION_MAX_NODES,
        "expected Node set exceeds the fleet verification bound"
    );
    let mut nodes = raw
        .iter()
        .map(|value| Id::new(value.clone()).context("invalid --expected-node"))
        .collect::<Result<Vec<_>>>()?;
    let unique = nodes.iter().cloned().collect::<BTreeSet<_>>();
    anyhow::ensure!(
        unique.len() == nodes.len(),
        "duplicate --expected-node is forbidden"
    );
    nodes.sort();
    Ok(nodes)
}

fn read_key_ring(path: &Path) -> Result<RouteGrantV2PublicKeyRingArtifact> {
    let mut file = File::open(path)
        .with_context(|| format!("open Route v2 public-key ring {}", path.display()))?;
    let mut bytes = Vec::new();
    (&mut file)
        .take((KEY_RING_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("read Route v2 public-key ring")?;
    anyhow::ensure!(
        bytes.len() <= KEY_RING_MAX_BYTES,
        "Route v2 public-key ring is too large"
    );
    decode_route_grant_v2_public_key_ring(&bytes)
        .map_err(|error| anyhow!("Route v2 public-key ring is not exact canonical input: {error}"))
}

fn expected_ring(ring: &RouteGrantV2PublicKeyRingArtifact) -> Result<FleetExpectedKeyRing> {
    anyhow::ensure!(
        !ring.keys.is_empty(),
        "expected Route v2 public-key ring is empty"
    );
    Ok(FleetExpectedKeyRing {
        ring_version: ring.ring_version,
        key_ring_digest: ring
            .digest()
            .map_err(|error| anyhow!("compute expected Route v2 key-ring digest: {error}"))?,
        kids: ring.keys.iter().map(|key| key.kid.clone()).collect(),
    })
}

fn validate_release_commit(value: &str) -> Result<()> {
    anyhow::ensure!(
        value.len() == 40
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "--release-commit must be exactly 40 lowercase hexadecimal characters"
    );
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Duration> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .context("fleet verification timed out before every expected Node was ready")?;
    Ok(remaining)
}

fn unix_millis() -> Result<UnixMillis> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before the Unix epoch")?
        .as_millis();
    let millis = u64::try_from(millis).context("system time is outside the wire range")?;
    UnixMillis::new(millis).context("system time is outside the wire range")
}

fn checked_add_millis(base: UnixMillis, addend: u128) -> Result<UnixMillis> {
    let addend = u64::try_from(addend).context("deadline duration is outside the wire range")?;
    let result = base
        .get()
        .checked_add(addend)
        .context("fleet verification wall-clock deadline overflow")?;
    UnixMillis::new(result).context("fleet verification deadline is outside the wire range")
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::fleet_verification::{FleetRouteSigningAuthority, FleetVerificationNode};
    use cats_api::runtime_reconciliation::{
        AdmissionInventoryAttestation, Epoch, KeyId, NodeBootId, RandomId128, Sequence,
        Sha256Digest, WireU64,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn random(value: char) -> RandomId128 {
        RandomId128::new(value.to_string().repeat(32)).unwrap()
    }

    fn digest(value: char) -> Sha256Digest {
        Sha256Digest::new(format!("sha256:{}", value.to_string().repeat(64))).unwrap()
    }

    fn kid(value: char) -> KeyId {
        KeyId::new(value.to_string().repeat(64)).unwrap()
    }

    fn fixture(inventory: bool) -> (PollState, FleetVerificationSnapshot) {
        let node_id = id("node_a");
        let boot = NodeBootId::new("1".repeat(32)).unwrap();
        let instance = random('2');
        let session = AgentSession {
            version: ContractVersion::V1,
            node_id: node_id.clone(),
            immutable_host_id: id("host_a"),
            node_boot_id: boot.clone(),
            agent_instance_id: instance.clone(),
            agent_session_epoch: Epoch::new(1).unwrap(),
            registration_attempt_id: random('3'),
            guest_config_digest: digest('a'),
            lease_deadline_unix_ms: UnixMillis::new(120_000).unwrap(),
        };
        let ring_version = Epoch::new(1).unwrap();
        let kids = vec![kid('c')];
        let expected_ring = FleetExpectedKeyRing {
            ring_version,
            key_ring_digest: cats_api::runtime_reconciliation::key_ring_digest(ring_version, &kids)
                .unwrap(),
            kids,
        };
        let inventory = inventory.then(|| FleetVerificationInventory {
            source_session: cats_api::runtime_reconciliation::SessionBinding {
                node_id: node_id.clone(),
                node_boot_id: boot,
                agent_instance_id: instance,
                agent_session_epoch: Epoch::new(1).unwrap(),
            },
            attestation: AdmissionInventoryAttestation {
                version: ContractVersion::V1,
                node_id: node_id.clone(),
                agent_session_epoch: Epoch::new(1).unwrap(),
                inventory_epoch: Epoch::new(1).unwrap(),
                inventory_digest: digest('d'),
                inventory_read_position: Sequence::new(1).unwrap(),
                accepted_at_unix_ms: UnixMillis::new(59_000).unwrap(),
            },
            source_observation_id: random('4'),
            source_heartbeat_sequence: Sequence::new(1).unwrap(),
            source_observed_at_unix_ms: UnixMillis::new(59_000).unwrap(),
            complete_inventory: true,
            assigned_desired_count: WireU64::new(0).unwrap(),
            runtime_count: WireU64::new(0).unwrap(),
            residue_count: WireU64::new(0).unwrap(),
            lifecycle_open_count: WireU64::new(0).unwrap(),
            route_active_count: WireU64::new(0).unwrap(),
            route_closed_count: WireU64::new(0).unwrap(),
            active_guard_count: WireU64::new(0).unwrap(),
            cancellation_pending_count: WireU64::new(0).unwrap(),
            quarantined_condition_count: WireU64::new(0).unwrap(),
            key_ring_version: Some(expected_ring.ring_version),
            key_ring_digest: Some(expected_ring.key_ring_digest.clone()),
            loaded_kids: expected_ring.kids.clone(),
        });
        let signer = FleetRouteSigningAuthority {
            deployment_id: id("deployment_a"),
            signer_revision: Epoch::new(1).unwrap(),
            signer_reference_sha256: digest('e'),
            active_kid: Some(expected_ring.kids[0].clone()),
            public_key_ring_version: expected_ring.ring_version,
            public_key_ring_digest: expected_ring.key_ring_digest.clone(),
        };
        let release = "0123456789abcdef0123456789abcdef01234567".to_owned();
        (
            PollState {
                expected_nodes: vec![node_id.clone()],
                expected_ring,
                release_commit_sha: release.clone(),
                nodes: BTreeMap::new(),
                signer_binding: None,
            },
            FleetVerificationSnapshot {
                version: ContractVersion::V1,
                control_release_commit_sha: Some(release),
                evaluated_at_unix_ms: UnixMillis::new(60_000).unwrap(),
                approved_guest_config_digest: digest('a'),
                desired_runtime_count: WireU64::new(0).unwrap(),
                current_runtime_observation_count: WireU64::new(0).unwrap(),
                route_signing_authority: Some(signer),
                nodes: vec![FleetVerificationNode {
                    node_id,
                    session: Some(session),
                    inventory,
                }],
            },
        )
    }

    async fn snapshot_server(
        listener: tokio::net::TcpListener,
        responses: Vec<Option<FleetVerificationSnapshot>>,
    ) {
        for response in responses {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 1024];
                let read = stream.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0, "request ended before headers");
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
            assert!(request.starts_with("get /v1/admin/runtime/fleet-verification http/1.1\r\n"));
            assert!(request.contains("authorization: bearer token-a\r\n"));
            assert!(request.contains("accept-encoding: identity\r\n"));
            let Some(response) = response else {
                std::future::pending::<()>().await;
                unreachable!();
            };
            let body = cats_api::fleet_verification::encode_fleet_verification_snapshot(&response)
                .unwrap();
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
            stream.shutdown().await.unwrap();
        }
    }

    #[test]
    fn poll_moves_from_not_ready_to_exact_ready() {
        let (mut state, first) = fixture(false);
        assert!(!state.observe(&first).unwrap());
        let (_, second) = fixture(true);
        assert!(state.observe(&second).unwrap());

        let (mut state, mut stale) = fixture(true);
        stale.nodes[0]
            .inventory
            .as_mut()
            .unwrap()
            .source_session
            .agent_instance_id = random('9');
        assert!(!state.observe(&stale).unwrap());
        assert!(state.nodes[&id("node_a")].inventory.is_none());
        let (_, current) = fixture(true);
        assert!(state.observe(&current).unwrap());
    }

    #[tokio::test]
    async fn http_poller_moves_from_not_ready_to_ready() {
        let (mut state, first) = fixture(false);
        let (_, second) = fixture(true);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(snapshot_server(
            listener,
            vec![Some(first), Some(second.clone())],
        ));
        let result = poll(
            &origin,
            &RequestAuthority::ExplicitToken("token-a".to_owned()),
            Instant::now() + Duration::from_secs(1),
            Duration::from_millis(1),
            &mut state,
        )
        .await
        .unwrap();
        assert_eq!(result, second);
        server.await.unwrap();
    }

    #[test]
    fn poll_rejects_session_aba_and_extra_node() {
        let (mut state, mut snapshot) = fixture(false);
        assert!(!state.observe(&snapshot).unwrap());
        snapshot.nodes[0]
            .session
            .as_mut()
            .unwrap()
            .agent_session_epoch = Epoch::new(2).unwrap();
        assert!(state
            .observe(&snapshot)
            .unwrap_err()
            .to_string()
            .contains("ABA"));

        let (mut state, mut snapshot) = fixture(true);
        let mut extra = snapshot.nodes[0].clone();
        extra.node_id = id("node_b");
        extra.session = None;
        extra.inventory = None;
        snapshot.nodes.push(extra);
        assert!(state
            .observe(&snapshot)
            .unwrap_err()
            .to_string()
            .contains("unexpected"));

        let (mut state, mut snapshot) = fixture(true);
        assert!(state.observe(&snapshot).unwrap());
        snapshot.nodes[0].inventory = None;
        assert!(state
            .observe(&snapshot)
            .unwrap_err()
            .to_string()
            .contains("disappeared"));

        let (mut state, mut snapshot) = fixture(true);
        assert!(state.observe(&snapshot).unwrap());
        snapshot.nodes[0]
            .inventory
            .as_mut()
            .unwrap()
            .attestation
            .inventory_digest = digest('f');
        assert!(state
            .observe(&snapshot)
            .unwrap_err()
            .to_string()
            .contains("same inventory epoch"));
    }

    #[test]
    fn parser_rejects_empty_duplicate_and_noncanonical_release() {
        assert!(parse_expected_nodes(&[]).is_err());
        assert!(parse_expected_nodes(&["node_a".into(), "node_a".into()]).is_err());
        assert!(validate_release_commit(&"A".repeat(40)).is_err());
        assert!(validate_release_commit("0123456789abcdef0123456789abcdef01234567").is_ok());
    }

    #[tokio::test]
    async fn elapsed_deadline_is_terminal_and_cancellation_is_prompt() {
        assert!(remaining(Instant::now()).is_err());
        let error = poll_or_cancel(
            std::future::pending::<Result<()>>(),
            std::future::ready(Ok(())),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("cancelled"));

        let (mut state, first) = fixture(false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(snapshot_server(listener, vec![Some(first), None]));
        let error = poll(
            &origin,
            &RequestAuthority::ExplicitToken("token-a".to_owned()),
            Instant::now() + Duration::from_millis(50),
            Duration::from_millis(1),
            &mut state,
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("ambiguous"));
        server.abort();
        let _ = server.await;

        let (mut state, _) = fixture(false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(snapshot_server(listener, vec![None]));
        let error = poll_or_cancel(
            poll(
                &origin,
                &RequestAuthority::ExplicitToken("token-a".to_owned()),
                Instant::now() + Duration::from_secs(1),
                Duration::from_millis(1),
                &mut state,
            ),
            async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(())
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("cancelled"));
        server.abort();
        let _ = server.await;
    }

    #[test]
    fn every_stale_nonempty_gate_and_keyring_mismatch_stays_closed() {
        let (state, mut snapshot) = fixture(true);
        let session = snapshot.nodes[0].session.as_ref().unwrap().clone();
        let expected = state.expected_ring;
        let inventory = snapshot.nodes[0].inventory.as_mut().unwrap();

        inventory.runtime_count = WireU64::new(1).unwrap();
        assert!(!node_ready(
            snapshot.evaluated_at_unix_ms,
            &session,
            Some(inventory),
            &expected
        )
        .unwrap());
        inventory.runtime_count = WireU64::new(0).unwrap();
        inventory.route_active_count = WireU64::new(1).unwrap();
        assert!(!node_ready(
            snapshot.evaluated_at_unix_ms,
            &session,
            Some(inventory),
            &expected
        )
        .unwrap());
        inventory.route_active_count = WireU64::new(0).unwrap();
        inventory.quarantined_condition_count = WireU64::new(1).unwrap();
        assert!(!node_ready(
            snapshot.evaluated_at_unix_ms,
            &session,
            Some(inventory),
            &expected
        )
        .unwrap());
        inventory.quarantined_condition_count = WireU64::new(0).unwrap();
        inventory.complete_inventory = false;
        assert!(!node_ready(
            snapshot.evaluated_at_unix_ms,
            &session,
            Some(inventory),
            &expected
        )
        .unwrap());
        inventory.complete_inventory = true;
        inventory.residue_count = WireU64::new(1).unwrap();
        assert!(!node_ready(
            snapshot.evaluated_at_unix_ms,
            &session,
            Some(inventory),
            &expected
        )
        .unwrap());
        inventory.residue_count = WireU64::new(0).unwrap();
        inventory.attestation.accepted_at_unix_ms = UnixMillis::new(0).unwrap();
        assert!(!node_ready(
            snapshot.evaluated_at_unix_ms,
            &session,
            Some(inventory),
            &expected
        )
        .unwrap());
        inventory.attestation.accepted_at_unix_ms = UnixMillis::new(59_000).unwrap();
        inventory.key_ring_version = None;
        inventory.key_ring_digest = None;
        assert!(!node_ready(
            snapshot.evaluated_at_unix_ms,
            &session,
            Some(inventory),
            &expected
        )
        .unwrap());
        inventory.key_ring_version = Some(Epoch::new(2).unwrap());
        inventory.key_ring_digest = Some(expected.key_ring_digest.clone());
        assert!(!node_ready(
            snapshot.evaluated_at_unix_ms,
            &session,
            Some(inventory),
            &expected
        )
        .unwrap());
        inventory.key_ring_version = Some(expected.ring_version);
        inventory.loaded_kids.push(kid('d'));
        assert!(!node_ready(
            snapshot.evaluated_at_unix_ms,
            &session,
            Some(inventory),
            &expected
        )
        .unwrap());
        inventory.loaded_kids.clear();
        inventory.key_ring_digest = Some(expected.key_ring_digest.clone());
        assert!(!node_ready(
            snapshot.evaluated_at_unix_ms,
            &session,
            Some(inventory),
            &expected
        )
        .unwrap());
        inventory.loaded_kids = expected.kids.clone();
        inventory.key_ring_digest = Some(digest('f'));
        assert!(!node_ready(
            snapshot.evaluated_at_unix_ms,
            &session,
            Some(inventory),
            &expected
        )
        .unwrap());

        let mut expired_session = session;
        expired_session.lease_deadline_unix_ms = snapshot.evaluated_at_unix_ms;
        assert!(!node_ready(
            snapshot.evaluated_at_unix_ms,
            &expired_session,
            Some(inventory),
            &expected
        )
        .unwrap());
    }

    #[test]
    fn evidence_encoding_is_stable_and_contains_no_key_material() {
        let (mut state, snapshot) = fixture(true);
        assert!(state.observe(&snapshot).unwrap());
        let evidence = FleetVerificationEvidence {
            version: ContractVersion::V1,
            release_commit_sha: state.release_commit_sha.clone(),
            started_at_unix_ms: UnixMillis::new(1).unwrap(),
            deadline_unix_ms: UnixMillis::new(3).unwrap(),
            completed_at_unix_ms: UnixMillis::new(2).unwrap(),
            expected_nodes: state.expected_nodes,
            expected_key_ring: state.expected_ring,
            snapshot,
        };
        let first = encode_fleet_verification_evidence(&evidence).unwrap();
        let second = encode_fleet_verification_evidence(&evidence).unwrap();
        assert_eq!(first, second);
        let rendered = String::from_utf8(first).unwrap();
        assert!(!rendered.contains("public_key_spki"));
        assert!(!rendered.contains("secret_reference"));
    }
}
