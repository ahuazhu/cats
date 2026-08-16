use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, Metadata};
use std::io::Read as _;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{AsciiText, Id, ProviderScope, RandomId128};
use cats_control_plane::store::{
    DsnSource, HostFenceProviderClaimV1, HostFenceProviderQueueClient, PgObjectWriteCutoffPort,
};
use cats_host_fence_aws::{
    AwsHostFenceConfig, AwsHostFenceProvider, AwsHostTarget, VerifiedAwsProviderBinding,
};
use cats_storage::host_fence::{HostFenceProviderError, HostFenceProviderPort};
use clap::Parser;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const AWS_BINDING_MAX_BYTES: usize = 256 * 1024;
const AWS_IDENTITY_DEADLINE: Duration = Duration::from_secs(20);

#[derive(Debug, Parser)]
#[command(
    name = "cats-host-fence-providerd",
    about = "Cats sealed Host-fence provider queue worker"
)]
struct Args {
    #[arg(long, env = "CATS_HOST_FENCE_PROVIDER_POSTGRES_URL_FILE")]
    control_store_url_file: PathBuf,
    #[arg(long, env = "CATS_CONTROL_POSTGRES_CA_FILE")]
    control_store_ca_file: PathBuf,
    #[arg(long, env = "CATS_CONTROL_POSTGRES_SCHEMA")]
    control_store_schema: String,
    #[arg(long, env = "CATS_HOST_FENCE_AWS_BINDING_FILE")]
    aws_binding_file: PathBuf,
    #[arg(long, env = "CATS_HOST_FENCE_PROVIDER_WORKER_ID")]
    worker_id: String,
    #[arg(long, default_value_t = 30_000)]
    claim_lease_ms: u64,
    #[arg(long, default_value_t = 500)]
    poll_interval_ms: u64,
    #[arg(long, default_value_t = 20_000)]
    effect_deadline_ms: u64,
    #[arg(long, default_value_t = 30_000)]
    shutdown_grace_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AwsBindingsV1 {
    version: u16,
    provider_scope: ProviderScope,
    network_quarantine_boundary_id: String,
    object_store_scope_id: String,
    #[serde(deserialize_with = "deserialize_hosts")]
    hosts: BTreeMap<String, AwsHostBindingV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AwsHostBindingV1 {
    node_id: String,
    vpc_id: String,
    network_interface_ids: Vec<String>,
    writer_authority_id: String,
    workload_principal_id: String,
}

struct ValidatedBindings {
    provider_scope: ProviderScope,
    config: AwsHostFenceConfig,
    sha256: String,
}

fn deserialize_hosts<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, AwsHostBindingV1>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct HostMapVisitor;

    impl<'de> Visitor<'de> for HostMapVisitor {
        type Value = BTreeMap<String, AwsHostBindingV1>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a Host map with unique immutable Host IDs")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut hosts = BTreeMap::new();
            while let Some((host_id, binding)) = map.next_entry()? {
                if hosts.insert(host_id, binding).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate immutable Host ID in AWS binding",
                    ));
                }
            }
            Ok(hosts)
        }
    }

    deserializer.deserialize_map(HostMapVisitor)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    validate_durations(&args)?;
    let worker_id = parse_id("worker ID", args.worker_id)?;
    let ca_file = args
        .control_store_ca_file
        .to_str()
        .context("control-store CA path is not UTF-8")?
        .to_owned();

    // This direct least-privilege identity check is deliberately the first
    // external action.  No AWS client exists if the DSN selects the schema
    // owner, the wrong role, or the wrong search path.
    let queue = HostFenceProviderQueueClient::connect_from_async(
        DsnSource::File(args.control_store_url_file),
        Some(ca_file),
        args.control_store_schema,
    )
    .await
    .context("connect dedicated Host-fence provider PostgreSQL lane")?;
    let bindings = load_bindings(&args.aws_binding_file)?;
    let sdk = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(
            bindings.provider_scope.region.as_str().to_owned(),
        ))
        .load()
        .await;
    let verified_binding = VerifiedAwsProviderBinding::establish(
        &sdk,
        &bindings.provider_scope,
        Instant::now() + AWS_IDENTITY_DEADLINE,
    )
    .await
    .map_err(|error| anyhow::anyhow!("verify AWS provider binding: {error:?}"))?;
    tracing::info!(
        binding_sha256 = %bindings.sha256,
        provider = %bindings.provider_scope.provider,
        partition = %bindings.provider_scope.partition,
        account_id = %bindings.provider_scope.account_id,
        region = %bindings.provider_scope.region,
        "Host-fence provider startup identity verified"
    );

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });
    let lease = Duration::from_millis(args.claim_lease_ms);
    let poll = Duration::from_millis(args.poll_interval_ms);
    let effect_deadline = Duration::from_millis(args.effect_deadline_ms);
    let shutdown_grace = Duration::from_millis(args.shutdown_grace_ms);

    loop {
        if *shutdown_rx.borrow() {
            break;
        }
        let claim_token = random_token();
        let claim = queue
            .claim(
                bindings.provider_scope.clone(),
                worker_id.clone(),
                claim_token,
                lease,
            )
            .await;
        let claim = match claim {
            Ok(Some(claim)) => claim,
            Ok(None) => {
                tokio::select! {
                    _ = tokio::time::sleep(poll) => {}
                    result = shutdown_rx.changed() => {
                        if result.is_err() || *shutdown_rx.borrow() { break; }
                    }
                }
                continue;
            }
            Err(error) => {
                tracing::warn!(%error, "Host-fence provider claim unavailable");
                tokio::select! {
                    _ = tokio::time::sleep(poll) => {}
                    result = shutdown_rx.changed() => {
                        if result.is_err() || *shutdown_rx.borrow() { break; }
                    }
                }
                continue;
            }
        };
        tracing::info!(
            fence_attempt_id = %claim.request.binding.fence_attempt_id,
            claim_generation = claim.claim_generation,
            "claimed sealed Host-fence provider attempt"
        );
        let attempt = process_claim(
            Arc::clone(&queue),
            claim,
            bindings.config.clone(),
            &verified_binding,
            lease,
            effect_deadline,
        );
        tokio::pin!(attempt);
        tokio::select! {
            result = &mut attempt => report_attempt(result),
            signal = shutdown_rx.changed() => {
                if signal.is_err() || *shutdown_rx.borrow() {
                    match tokio::time::timeout(shutdown_grace, &mut attempt).await {
                        Ok(result) => report_attempt(result),
                        Err(_) => tracing::warn!(
                            "shutdown grace elapsed; current claim will recover after its DB lease"
                        ),
                    }
                    break;
                }
            }
        }
    }
    queue.shutdown().await;
    Ok(())
}

async fn process_claim(
    queue: Arc<HostFenceProviderQueueClient>,
    claim: HostFenceProviderClaimV1,
    config: AwsHostFenceConfig,
    binding: &VerifiedAwsProviderBinding,
    lease: Duration,
    effect_deadline: Duration,
) -> Result<(), HostFenceProviderError> {
    let cutoff = Arc::new(PgObjectWriteCutoffPort::new(
        Arc::clone(&queue),
        claim.clone(),
    ));
    let provider = AwsHostFenceProvider::from_verified_binding(config, binding, cutoff)?;
    let (renew_stop_tx, mut renew_stop_rx) = tokio::sync::watch::channel(false);
    let (lease_lost_tx, mut lease_lost_rx) = tokio::sync::watch::channel(false);
    let renew_queue = Arc::clone(&queue);
    let renew_claim = claim.clone();
    let renew_interval = (lease / 3).max(Duration::from_millis(1));
    let renew_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(renew_interval) => {
                    let token = random_token();
                    if let Err(error) = renew_queue.renew(&renew_claim, token, lease).await {
                        tracing::warn!(%error, "lost Host-fence provider claim renewal");
                        let _ = lease_lost_tx.send(true);
                        break;
                    }
                }
                changed = renew_stop_rx.changed() => {
                    if changed.is_err() || *renew_stop_rx.borrow() { break; }
                }
            }
        }
    });

    let deadline = Instant::now() + effect_deadline;
    let evidence = tokio::select! {
        evidence = provider.establish_fence(&claim.request, deadline) => evidence,
        changed = lease_lost_rx.changed() => {
            let _ = changed;
            Err(HostFenceProviderError::ProviderUnavailable)
        }
    };
    let complete = match evidence {
        Ok(evidence) => tokio::select! {
            complete = queue.complete(&claim, &evidence) => complete
                .map(|_| ())
                .map_err(|_| HostFenceProviderError::ProviderUnavailable),
            changed = lease_lost_rx.changed() => {
                let _ = changed;
                Err(HostFenceProviderError::ProviderUnavailable)
            }
        },
        Err(error) => Err(error),
    };
    let _ = renew_stop_tx.send(true);
    let _ = renew_task.await;
    complete
}

fn report_attempt(result: Result<(), HostFenceProviderError>) {
    match result {
        Ok(()) => tracing::info!("committed terminal Host-fence provider evidence"),
        Err(error) => tracing::warn!(
            %error,
            "Host-fence provider attempt did not become terminal; DB lease recovery remains authoritative"
        ),
    }
}

fn validate_durations(args: &Args) -> anyhow::Result<()> {
    anyhow::ensure!(
        (1..=60_000).contains(&args.claim_lease_ms),
        "claim lease must be within 1..=60000ms"
    );
    anyhow::ensure!(args.poll_interval_ms > 0, "poll interval must be positive");
    anyhow::ensure!(
        args.effect_deadline_ms > 0 && args.effect_deadline_ms < args.claim_lease_ms,
        "effect deadline must be positive and shorter than the claim lease"
    );
    anyhow::ensure!(
        args.shutdown_grace_ms >= args.effect_deadline_ms,
        "shutdown grace must cover one effect deadline"
    );
    Ok(())
}

fn load_bindings(path: &Path) -> anyhow::Result<ValidatedBindings> {
    let bytes = read_bounded_stable_file(path)?;
    anyhow::ensure!(
        (2..=AWS_BINDING_MAX_BYTES).contains(&bytes.len()),
        "AWS Host-fence binding is outside its hard byte bound"
    );
    let document: AwsBindingsV1 =
        serde_json::from_slice(&bytes).context("decode strict AWS Host-fence binding v1")?;
    anyhow::ensure!(document.version == 1, "unsupported AWS binding version");
    anyhow::ensure!(
        document.provider_scope.provider.as_str() == "aws",
        "Host-fence provider binding requires provider=aws"
    );
    let quarantine = parse_id(
        "network quarantine boundary",
        document.network_quarantine_boundary_id,
    )?;
    let object_store_scope_id = AsciiText::new(document.object_store_scope_id)
        .context("object-store scope ID is invalid")?;
    let mut hosts = BTreeMap::new();
    for (host_id, host) in document.hosts {
        let immutable_host_id = parse_id("immutable Host ID", host_id)?;
        anyhow::ensure!(
            host.network_interface_ids.len() == 1,
            "AWS binding v1 requires exactly one primary network interface per Host"
        );
        let network_interface_ids = host
            .network_interface_ids
            .into_iter()
            .map(|value| parse_id("network interface ID", value))
            .collect::<anyhow::Result<BTreeSet<_>>>()?;
        anyhow::ensure!(
            network_interface_ids.len() == 1,
            "AWS binding v1 network interface list is not exact"
        );
        let previous = hosts.insert(
            immutable_host_id,
            AwsHostTarget {
                node_id: parse_id("Node ID", host.node_id)?,
                vpc_id: parse_id("VPC ID", host.vpc_id)?,
                network_interface_ids,
                writer_authority_id: parse_id(
                    "object-writer authority ID",
                    host.writer_authority_id,
                )?,
                workload_principal_id: AsciiText::new(host.workload_principal_id)
                    .context("workload principal ID is invalid")?,
            },
        );
        anyhow::ensure!(previous.is_none(), "duplicate immutable Host binding");
    }
    let provider_scope = document.provider_scope;
    let config = AwsHostFenceConfig::new(
        provider_scope.clone(),
        quarantine,
        object_store_scope_id,
        hosts,
    )
    .map_err(|error| anyhow::anyhow!("validate AWS Host-fence binding: {error}"))?;
    let sha256 = format!("sha256:{}", hex_digest(&bytes));
    Ok(ValidatedBindings {
        provider_scope,
        config,
        sha256,
    })
}

fn read_bounded_stable_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    let mut file = File::open(path)
        .with_context(|| format!("open AWS Host-fence binding {}", path.display()))?;
    let before = file
        .metadata()
        .with_context(|| format!("stat open AWS Host-fence binding {}", path.display()))?;
    anyhow::ensure!(
        before.is_file(),
        "AWS Host-fence binding must resolve to a regular file"
    );
    anyhow::ensure!(
        before.len() <= AWS_BINDING_MAX_BYTES as u64,
        "AWS Host-fence binding is outside its hard byte bound"
    );

    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take((AWS_BINDING_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read AWS Host-fence binding {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() <= AWS_BINDING_MAX_BYTES,
        "AWS Host-fence binding is outside its hard byte bound"
    );
    let after = file
        .metadata()
        .with_context(|| format!("restat open AWS Host-fence binding {}", path.display()))?;
    anyhow::ensure!(
        same_file_snapshot(&before, &after),
        "AWS Host-fence binding changed while it was read"
    );
    Ok(bytes)
}

#[cfg(unix)]
fn same_file_snapshot(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file_snapshot(before: &Metadata, after: &Metadata) -> bool {
    before.len() == after.len() && before.modified().ok() == after.modified().ok()
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_id(label: &str, value: String) -> anyhow::Result<Id> {
    Id::new(value).with_context(|| format!("Host-fence provider {label} is invalid"))
}

fn random_token() -> RandomId128 {
    RandomId128::new(uuid::Uuid::new_v4().simple().to_string())
        .expect("UUID v4 is a nonzero lowercase 128-bit token")
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        if let Ok(mut terminate) = terminate {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_binding_shape_is_accepted() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("aws-bindings.v1.json");
        std::fs::write(
            &path,
            br#"{"version":1,"provider_scope":{"provider":"aws","partition":"aws","account_id":"123456789012","region":"us-east-1"},"network_quarantine_boundary_id":"sg-0123456789abcdef0","object_store_scope_id":"arn:aws:s3:::cats-production/chunks","hosts":{"i-0123456789abcdef0":{"node_id":"node-a","vpc_id":"vpc-0123456789abcdef0","network_interface_ids":["eni-0123456789abcdef0"],"writer_authority_id":"owa1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","workload_principal_id":"arn:aws:iam::123456789012:role/cats-production-object-write-gateway"}}}"#,
        )
        .unwrap();
        let binding = load_bindings(&path).unwrap();
        assert_eq!(binding.provider_scope.region.as_str(), "us-east-1");
        assert!(binding.sha256.starts_with("sha256:"));
    }

    #[test]
    fn unknown_fields_and_multiple_interfaces_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("aws-bindings.v1.json");
        std::fs::write(
            &path,
            br#"{"version":1,"provider_scope":{"provider":"aws","partition":"aws","account_id":"123456789012","region":"us-east-1"},"network_quarantine_boundary_id":"sg-0123456789abcdef0","object_store_scope_id":"arn:aws:s3:::cats-production/chunks","hosts":{"i-0123456789abcdef0":{"node_id":"node-a","vpc_id":"vpc-0123456789abcdef0","network_interface_ids":["eni-a","eni-b"],"writer_authority_id":"owa1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","workload_principal_id":"arn:aws:iam::123456789012:role/cats-production-object-write-gateway","unexpected":true}}}"#,
        )
        .unwrap();
        assert!(load_bindings(&path).is_err());
    }

    #[test]
    fn oversized_binding_is_rejected_before_decode() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("aws-bindings.v1.json");
        std::fs::write(&path, vec![b' '; AWS_BINDING_MAX_BYTES + 1]).unwrap();
        assert!(load_bindings(&path).is_err());
    }
}
