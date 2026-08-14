use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aws_sdk_ec2::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_ec2::operation::RequestId as _;
use cats_api::runtime_reconciliation::{AsciiText, Id, ProviderScope, UnixMillis};
use cats_storage::host_fence::{
    host_fence_effect_token, host_fence_provider_attempt_id, validate_host_fence_provider_evidence,
    validate_object_write_cutoff_evidence, HostExecutionCutoffEvidence, HostFenceAttemptRequest,
    HostFencePortFuture, HostFenceProviderError, HostFenceProviderEvidence, HostFenceProviderPort,
    ObjectWriteCutoffPort, QuarantinedNetworkInterfaceEvidence, WorkloadNetworkCutoffEvidence,
    HOST_FENCE_PROVIDER_EVIDENCE_VERSION, MAX_HOST_FENCE_NETWORK_INTERFACES,
};
use sha2::{Digest, Sha256};

use crate::VerifiedAwsProviderBinding;

const OBSERVATION_POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsHostTarget {
    pub node_id: Id,
    pub vpc_id: Id,
    pub network_interface_ids: BTreeSet<Id>,
    pub writer_authority_id: Id,
    pub workload_principal_id: AsciiText,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsHostFenceConfig {
    provider_scope: ProviderScope,
    quarantine_security_group_id: Id,
    object_store_scope_id: AsciiText,
    hosts: BTreeMap<Id, AwsHostTarget>,
}

impl AwsHostFenceConfig {
    pub fn new(
        provider_scope: ProviderScope,
        quarantine_security_group_id: Id,
        object_store_scope_id: AsciiText,
        hosts: BTreeMap<Id, AwsHostTarget>,
    ) -> Result<Self, HostFenceProviderError> {
        if provider_scope.provider.as_str() != "aws" || hosts.is_empty() {
            return Err(HostFenceProviderError::InvalidRequest);
        }
        let mut node_ids = BTreeSet::new();
        let mut vpc_ids = BTreeSet::new();
        let mut writer_authority_ids = BTreeSet::new();
        let mut workload_principal_ids = BTreeSet::new();
        let mut network_interface_ids = BTreeSet::new();
        for host in hosts.values() {
            vpc_ids.insert(host.vpc_id.clone());
            if host.network_interface_ids.is_empty()
                || host.network_interface_ids.len() > MAX_HOST_FENCE_NETWORK_INTERFACES
                || !node_ids.insert(host.node_id.clone())
                || !writer_authority_ids.insert(host.writer_authority_id.clone())
                || !workload_principal_ids.insert(host.workload_principal_id.clone())
                || host
                    .network_interface_ids
                    .iter()
                    .any(|interface_id| !network_interface_ids.insert(interface_id.clone()))
            {
                return Err(HostFenceProviderError::InvalidRequest);
            }
        }
        if vpc_ids.len() != 1 {
            return Err(HostFenceProviderError::InvalidRequest);
        }
        Ok(Self {
            provider_scope,
            quarantine_security_group_id,
            object_store_scope_id,
            hosts,
        })
    }

    pub fn provider_scope(&self) -> &ProviderScope {
        &self.provider_scope
    }

    pub fn quarantine_security_group_id(&self) -> &Id {
        &self.quarantine_security_group_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ec2InstanceState {
    Pending,
    Running,
    Stopping,
    Stopped,
    ShuttingDown,
    Terminated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostObservation {
    host_id: Id,
    vpc_id: Id,
    state: Ec2InstanceState,
    network_interface_ids: BTreeSet<Id>,
    observation_id: AsciiText,
    observed_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworkInterfaceObservation {
    interface_id: Id,
    attached_host_id: Id,
    vpc_id: Id,
    security_group_ids: BTreeSet<Id>,
    observation_id: AsciiText,
    observed_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SecurityGroupObservation {
    security_group_id: Id,
    vpc_id: Id,
    ingress_rule_count: usize,
    egress_rule_count: usize,
    observation_id: AsciiText,
    observed_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MutationAcknowledgement {
    request_id: AsciiText,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ec2CallError {
    Deadline,
    Ambiguous,
    Unavailable,
    InvalidResponse,
}

type Ec2Future<'a, T> = Pin<Box<dyn Future<Output = Result<T, Ec2CallError>> + Send + 'a>>;

trait Ec2FenceApi: Send + Sync {
    fn describe_host<'a>(
        &'a self,
        host_id: &'a Id,
        deadline: Instant,
    ) -> Ec2Future<'a, HostObservation>;

    fn stop_host<'a>(
        &'a self,
        host_id: &'a Id,
        deadline: Instant,
    ) -> Ec2Future<'a, MutationAcknowledgement>;

    fn describe_network_interfaces<'a>(
        &'a self,
        interface_ids: &'a BTreeSet<Id>,
        deadline: Instant,
    ) -> Ec2Future<'a, Vec<NetworkInterfaceObservation>>;

    fn quarantine_network_interface<'a>(
        &'a self,
        interface_id: &'a Id,
        quarantine_security_group_id: &'a Id,
        deadline: Instant,
    ) -> Ec2Future<'a, MutationAcknowledgement>;

    fn describe_security_group<'a>(
        &'a self,
        security_group_id: &'a Id,
        deadline: Instant,
    ) -> Ec2Future<'a, SecurityGroupObservation>;
}

pub struct AwsHostFenceProvider {
    config: AwsHostFenceConfig,
    ec2: Arc<dyn Ec2FenceApi>,
    object_write_cutoff: Arc<dyn ObjectWriteCutoffPort>,
    observation_poll_interval: Duration,
}

impl AwsHostFenceProvider {
    pub fn from_verified_binding(
        config: AwsHostFenceConfig,
        binding: &VerifiedAwsProviderBinding,
        object_write_cutoff: Arc<dyn ObjectWriteCutoffPort>,
    ) -> Result<Self, HostFenceProviderError> {
        if binding.provider_scope() != config.provider_scope() {
            return Err(HostFenceProviderError::InvalidRequest);
        }
        Ok(Self {
            config,
            ec2: Arc::new(SdkEc2FenceApi {
                client: binding.ec2_client(),
            }),
            object_write_cutoff,
            observation_poll_interval: OBSERVATION_POLL_INTERVAL,
        })
    }

    #[cfg(test)]
    fn with_api(
        config: AwsHostFenceConfig,
        ec2: Arc<dyn Ec2FenceApi>,
        object_write_cutoff: Arc<dyn ObjectWriteCutoffPort>,
    ) -> Self {
        Self {
            config,
            ec2,
            object_write_cutoff,
            observation_poll_interval: Duration::ZERO,
        }
    }

    fn validate_request(
        &self,
        request: &HostFenceAttemptRequest,
    ) -> Result<&AwsHostTarget, HostFenceProviderError> {
        let Some(target) = self.config.hosts.get(&request.binding.immutable_host_id) else {
            return Err(HostFenceProviderError::InvalidRequest);
        };
        if request.binding.provider_scope != self.config.provider_scope
            || request.binding.node_id != target.node_id
            || request.object_writer.provider_scope != self.config.provider_scope
            || request.object_writer.writer_authority_id != target.writer_authority_id
            || request.object_writer.workload_principal_id != target.workload_principal_id
            || request.object_writer.object_store_scope_id != self.config.object_store_scope_id
            || request.network_quarantine_boundary_id.as_str()
                != self.config.quarantine_security_group_id.as_str()
        {
            return Err(HostFenceProviderError::InvalidRequest);
        }
        Ok(target)
    }

    async fn establish(
        &self,
        request: &HostFenceAttemptRequest,
        absolute_deadline: Instant,
    ) -> Result<HostFenceProviderEvidence, HostFenceProviderError> {
        let target = self.validate_request(request)?.clone();
        ensure_deadline(absolute_deadline)?;

        // This independent authority is deliberately first. EC2/ENI effects
        // cannot manufacture a successful HostFence without its closed PUT
        // prefix and visibility receipt.
        let object_write_cutoff = self
            .object_write_cutoff
            .establish_cutoff(request, absolute_deadline)
            .await?;
        validate_object_write_cutoff_evidence(request, &object_write_cutoff)?;

        let policy = self
            .ec2
            .describe_security_group(&self.config.quarantine_security_group_id, absolute_deadline)
            .await
            .map_err(map_observation_error)?;
        if policy.security_group_id != self.config.quarantine_security_group_id
            || policy.vpc_id != target.vpc_id
            || policy.ingress_rule_count != 0
            || policy.egress_rule_count != 0
        {
            return Err(HostFenceProviderError::ServingCutoffObservationAmbiguous);
        }

        let execution = self
            .ensure_execution_stopped(request, &target, absolute_deadline)
            .await?;
        let interfaces = self
            .ensure_interfaces_quarantined(request, &target, absolute_deadline)
            .await?;

        let mut aggregate = Sha256::new();
        aggregate.update(b"cats.aws-network-observation.v1");
        for observation in &interfaces {
            hash_frame(&mut aggregate, observation.interface_id.as_str().as_bytes());
            hash_frame(
                &mut aggregate,
                observation.observation_id.as_str().as_bytes(),
            );
        }
        let authoritative_observation_id = ascii_digest("awseniobs1_", aggregate.finalize())?;
        let interfaces_observed_at = interfaces
            .iter()
            .map(|observation| observation.observed_at_unix_ms)
            .max()
            .ok_or(HostFenceProviderError::ServingCutoffObservationAmbiguous)?;

        let mut interface_evidence = Vec::with_capacity(interfaces.len());
        for observation in &interfaces {
            interface_evidence.push(QuarantinedNetworkInterfaceEvidence {
                interface_id: observation.interface_id.clone(),
                effect_token: host_fence_effect_token(
                    &request.binding,
                    b"network-interface-cutoff",
                    observation.interface_id.as_str().as_bytes(),
                )?,
                provider_attempt_id: host_fence_provider_attempt_id(
                    &request.binding,
                    b"network-interface-cutoff",
                    observation.interface_id.as_str().as_bytes(),
                )?,
            });
        }

        let network_cutoff = WorkloadNetworkCutoffEvidence::WorkloadInterfacesQuarantined {
            immutable_host_id: request.binding.immutable_host_id.clone(),
            quarantine_policy_id: self.config.quarantine_security_group_id.clone(),
            boundary_effect_token: host_fence_effect_token(
                &request.binding,
                b"network-boundary-cutoff",
                self.config.quarantine_security_group_id.as_str().as_bytes(),
            )?,
            boundary_provider_attempt_id: host_fence_provider_attempt_id(
                &request.binding,
                b"network-boundary-cutoff",
                self.config.quarantine_security_group_id.as_str().as_bytes(),
            )?,
            policy_observation_id: policy.observation_id,
            policy_observed_at_unix_ms: policy.observed_at_unix_ms,
            interfaces: interface_evidence,
            authoritative_observation_id,
            observed_at_unix_ms: interfaces_observed_at,
        };
        let completed_at_unix_ms = std::cmp::max(
            execution.observed_at_unix_ms(),
            network_cutoff.observed_at_unix_ms(),
        );
        let evidence = HostFenceProviderEvidence {
            version: HOST_FENCE_PROVIDER_EVIDENCE_VERSION,
            binding: request.binding.clone(),
            object_write_cutoff,
            execution_cutoff: execution,
            network_cutoff,
            completed_at_unix_ms,
        };
        validate_host_fence_provider_evidence(request, &evidence)?;
        Ok(evidence)
    }

    async fn ensure_execution_stopped(
        &self,
        request: &HostFenceAttemptRequest,
        target: &AwsHostTarget,
        deadline: Instant,
    ) -> Result<HostExecutionCutoffEvidence, HostFenceProviderError> {
        let mut observation = self
            .ec2
            .describe_host(&request.binding.immutable_host_id, deadline)
            .await
            .map_err(map_observation_error)?;
        validate_host_observation(request, target, &observation)?;

        if matches!(
            observation.state,
            Ec2InstanceState::Pending | Ec2InstanceState::Running
        ) {
            match self
                .ec2
                .stop_host(&request.binding.immutable_host_id, deadline)
                .await
            {
                Ok(acknowledgement) => {
                    tracing::info!(
                        host_id = %request.binding.immutable_host_id,
                        aws_request_id = %acknowledgement.request_id,
                        "AWS accepted exact Host stop"
                    );
                }
                Err(Ec2CallError::Ambiguous) => {
                    tracing::warn!(
                        host_id = %request.binding.immutable_host_id,
                        "AWS Host stop response was ambiguous; rediscovering exact state"
                    );
                }
                Err(error) => return Err(map_mutation_error(error)),
            }
            // Even an acknowledgement is not the postcondition. An ambiguous
            // response is never blindly repeated; a fresh Describe decides.
            observation = self
                .ec2
                .describe_host(&request.binding.immutable_host_id, deadline)
                .await
                .map_err(map_observation_error)?;
            validate_host_observation(request, target, &observation)?;
        }

        loop {
            match observation.state {
                Ec2InstanceState::Stopped => break,
                Ec2InstanceState::Stopping => {
                    sleep_until_poll(self.observation_poll_interval, deadline).await?;
                    observation = self
                        .ec2
                        .describe_host(&request.binding.immutable_host_id, deadline)
                        .await
                        .map_err(map_observation_error)?;
                    validate_host_observation(request, target, &observation)?;
                }
                // A still-running state after one ambiguous/acknowledged stop
                // remains unresolved. Do not issue another destructive call.
                Ec2InstanceState::Pending
                | Ec2InstanceState::Running
                | Ec2InstanceState::ShuttingDown
                | Ec2InstanceState::Terminated => {
                    return Err(HostFenceProviderError::ServingCutoffObservationAmbiguous);
                }
            }
        }

        Ok(HostExecutionCutoffEvidence::HostStopped {
            immutable_host_id: request.binding.immutable_host_id.clone(),
            effect_token: host_fence_effect_token(
                &request.binding,
                b"host-execution-cutoff",
                request.binding.immutable_host_id.as_str().as_bytes(),
            )?,
            provider_attempt_id: host_fence_provider_attempt_id(
                &request.binding,
                b"host-execution-cutoff",
                request.binding.immutable_host_id.as_str().as_bytes(),
            )?,
            authoritative_observation_id: observation.observation_id,
            observed_at_unix_ms: observation.observed_at_unix_ms,
        })
    }

    async fn ensure_interfaces_quarantined(
        &self,
        request: &HostFenceAttemptRequest,
        target: &AwsHostTarget,
        deadline: Instant,
    ) -> Result<Vec<NetworkInterfaceObservation>, HostFenceProviderError> {
        let mut observations = self
            .ec2
            .describe_network_interfaces(&target.network_interface_ids, deadline)
            .await
            .map_err(map_observation_error)?;
        validate_interface_set(request, target, &observations)?;

        for index in 0..observations.len() {
            let expected_groups =
                BTreeSet::from([self.config.quarantine_security_group_id.clone()]);
            if observations[index].security_group_ids == expected_groups {
                continue;
            }
            let interface_id = observations[index].interface_id.clone();
            match self
                .ec2
                .quarantine_network_interface(
                    &interface_id,
                    &self.config.quarantine_security_group_id,
                    deadline,
                )
                .await
            {
                Ok(acknowledgement) => tracing::info!(
                    interface_id = %interface_id,
                    aws_request_id = %acknowledgement.request_id,
                    "AWS accepted exact ENI quarantine"
                ),
                Err(Ec2CallError::Ambiguous) => tracing::warn!(
                    interface_id = %interface_id,
                    "AWS ENI quarantine response was ambiguous; rediscovering exact groups"
                ),
                Err(error) => return Err(map_mutation_error(error)),
            }
            let exact = BTreeSet::from([interface_id.clone()]);
            let mut rediscovered = self
                .ec2
                .describe_network_interfaces(&exact, deadline)
                .await
                .map_err(map_observation_error)?;
            let Some(rediscovered) = rediscovered.pop() else {
                return Err(HostFenceProviderError::ServingCutoffObservationAmbiguous);
            };
            if !rediscovered.is_exact_quarantine(
                &request.binding.immutable_host_id,
                &target.vpc_id,
                &self.config.quarantine_security_group_id,
            ) {
                return Err(HostFenceProviderError::ServingCutoffObservationAmbiguous);
            }
            observations[index] = rediscovered;
        }
        observations.sort_by(|left, right| left.interface_id.cmp(&right.interface_id));
        validate_interface_set(request, target, &observations)?;
        if observations.iter().any(|observation| {
            !observation.is_exact_quarantine(
                &request.binding.immutable_host_id,
                &target.vpc_id,
                &self.config.quarantine_security_group_id,
            )
        }) {
            return Err(HostFenceProviderError::ServingCutoffObservationAmbiguous);
        }
        Ok(observations)
    }
}

impl HostFenceProviderPort for AwsHostFenceProvider {
    fn establish_fence<'a>(
        &'a self,
        request: &'a HostFenceAttemptRequest,
        absolute_deadline: Instant,
    ) -> HostFencePortFuture<'a, HostFenceProviderEvidence> {
        Box::pin(async move { self.establish(request, absolute_deadline).await })
    }
}

impl NetworkInterfaceObservation {
    fn is_exact_quarantine(&self, host_id: &Id, vpc_id: &Id, boundary: &Id) -> bool {
        self.attached_host_id == *host_id
            && self.vpc_id == *vpc_id
            && self.security_group_ids == BTreeSet::from([boundary.clone()])
    }
}

fn validate_host_observation(
    request: &HostFenceAttemptRequest,
    target: &AwsHostTarget,
    observation: &HostObservation,
) -> Result<(), HostFenceProviderError> {
    if observation.host_id != request.binding.immutable_host_id
        || observation.vpc_id != target.vpc_id
        || observation.network_interface_ids != target.network_interface_ids
    {
        return Err(HostFenceProviderError::ServingCutoffObservationAmbiguous);
    }
    Ok(())
}

fn validate_interface_set(
    request: &HostFenceAttemptRequest,
    target: &AwsHostTarget,
    observations: &[NetworkInterfaceObservation],
) -> Result<(), HostFenceProviderError> {
    let observed = observations
        .iter()
        .map(|observation| observation.interface_id.clone())
        .collect::<BTreeSet<_>>();
    if observed != target.network_interface_ids
        || observations.iter().any(|observation| {
            observation.attached_host_id != request.binding.immutable_host_id
                || observation.vpc_id != target.vpc_id
        })
    {
        return Err(HostFenceProviderError::ServingCutoffObservationAmbiguous);
    }
    Ok(())
}

fn ensure_deadline(deadline: Instant) -> Result<(), HostFenceProviderError> {
    if Instant::now() >= deadline {
        Err(HostFenceProviderError::DeadlineExceeded)
    } else {
        Ok(())
    }
}

async fn sleep_until_poll(
    interval: Duration,
    deadline: Instant,
) -> Result<(), HostFenceProviderError> {
    ensure_deadline(deadline)?;
    if interval.is_zero() {
        tokio::task::yield_now().await;
        return Ok(());
    }
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(HostFenceProviderError::DeadlineExceeded)?;
    if remaining <= interval {
        return Err(HostFenceProviderError::DeadlineExceeded);
    }
    tokio::time::sleep(interval).await;
    Ok(())
}

fn map_observation_error(error: Ec2CallError) -> HostFenceProviderError {
    match error {
        Ec2CallError::Deadline => HostFenceProviderError::DeadlineExceeded,
        Ec2CallError::Ambiguous | Ec2CallError::InvalidResponse => {
            HostFenceProviderError::ServingCutoffObservationAmbiguous
        }
        Ec2CallError::Unavailable => HostFenceProviderError::ProviderUnavailable,
    }
}

fn map_mutation_error(error: Ec2CallError) -> HostFenceProviderError {
    match error {
        Ec2CallError::Deadline => HostFenceProviderError::DeadlineExceeded,
        Ec2CallError::Ambiguous | Ec2CallError::InvalidResponse => {
            HostFenceProviderError::ServingCutoffObservationAmbiguous
        }
        Ec2CallError::Unavailable => HostFenceProviderError::ProviderUnavailable,
    }
}

fn hash_frame(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn ascii_digest(
    prefix: &str,
    digest: impl AsRef<[u8]>,
) -> Result<AsciiText, HostFenceProviderError> {
    AsciiText::new(format!("{prefix}{}", hex_lower(digest.as_ref())))
        .ok_or(HostFenceProviderError::EvidenceMismatch)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

struct SdkEc2FenceApi {
    client: aws_sdk_ec2::Client,
}

impl Ec2FenceApi for SdkEc2FenceApi {
    fn describe_host<'a>(
        &'a self,
        host_id: &'a Id,
        deadline: Instant,
    ) -> Ec2Future<'a, HostObservation> {
        Box::pin(async move {
            let output = read_with_deadline(
                self.client
                    .describe_instances()
                    .instance_ids(host_id.as_str())
                    .send(),
                deadline,
            )
            .await?;
            if output.next_token().is_some() {
                return Err(Ec2CallError::InvalidResponse);
            }
            let mut instances = output
                .reservations()
                .iter()
                .flat_map(|reservation| reservation.instances())
                .collect::<Vec<_>>();
            if instances.len() != 1 {
                return Err(Ec2CallError::InvalidResponse);
            }
            let instance = instances.pop().ok_or(Ec2CallError::InvalidResponse)?;
            let observed_host = required_id(instance.instance_id())?;
            let vpc_id = required_id(instance.vpc_id())?;
            let state = match instance.state().and_then(|state| state.name()) {
                Some(aws_sdk_ec2::types::InstanceStateName::Pending) => Ec2InstanceState::Pending,
                Some(aws_sdk_ec2::types::InstanceStateName::Running) => Ec2InstanceState::Running,
                Some(aws_sdk_ec2::types::InstanceStateName::Stopping) => Ec2InstanceState::Stopping,
                Some(aws_sdk_ec2::types::InstanceStateName::Stopped) => Ec2InstanceState::Stopped,
                Some(aws_sdk_ec2::types::InstanceStateName::ShuttingDown) => {
                    Ec2InstanceState::ShuttingDown
                }
                Some(aws_sdk_ec2::types::InstanceStateName::Terminated) => {
                    Ec2InstanceState::Terminated
                }
                _ => return Err(Ec2CallError::InvalidResponse),
            };
            let network_interface_ids = instance
                .network_interfaces()
                .iter()
                .map(|interface| required_id(interface.network_interface_id()))
                .collect::<Result<BTreeSet<_>, _>>()?;
            Ok(HostObservation {
                host_id: observed_host,
                vpc_id,
                state,
                network_interface_ids,
                observation_id: required_request_id(output.request_id())?,
                observed_at_unix_ms: now_unix_millis()?,
            })
        })
    }

    fn stop_host<'a>(
        &'a self,
        host_id: &'a Id,
        deadline: Instant,
    ) -> Ec2Future<'a, MutationAcknowledgement> {
        Box::pin(async move {
            let output = mutate_with_deadline(
                self.client
                    .stop_instances()
                    .instance_ids(host_id.as_str())
                    .send(),
                deadline,
            )
            .await?;
            Ok(MutationAcknowledgement {
                request_id: required_request_id(output.request_id())?,
            })
        })
    }

    fn describe_network_interfaces<'a>(
        &'a self,
        interface_ids: &'a BTreeSet<Id>,
        deadline: Instant,
    ) -> Ec2Future<'a, Vec<NetworkInterfaceObservation>> {
        Box::pin(async move {
            if interface_ids.is_empty() || interface_ids.len() > MAX_HOST_FENCE_NETWORK_INTERFACES {
                return Err(Ec2CallError::InvalidResponse);
            }
            let mut request = self.client.describe_network_interfaces();
            for interface_id in interface_ids {
                request = request.network_interface_ids(interface_id.as_str());
            }
            let output = read_with_deadline(request.send(), deadline).await?;
            if output.next_token().is_some() {
                return Err(Ec2CallError::InvalidResponse);
            }
            let observation_id = required_request_id(output.request_id())?;
            let observed_at_unix_ms = now_unix_millis()?;
            let mut observations = Vec::with_capacity(output.network_interfaces().len());
            for interface in output.network_interfaces() {
                observations.push(NetworkInterfaceObservation {
                    interface_id: required_id(interface.network_interface_id())?,
                    attached_host_id: required_id(
                        interface
                            .attachment()
                            .and_then(|attachment| attachment.instance_id()),
                    )?,
                    vpc_id: required_id(interface.vpc_id())?,
                    security_group_ids: interface
                        .groups()
                        .iter()
                        .map(|group| required_id(group.group_id()))
                        .collect::<Result<BTreeSet<_>, _>>()?,
                    observation_id: observation_id.clone(),
                    observed_at_unix_ms,
                });
            }
            observations.sort_by(|left, right| left.interface_id.cmp(&right.interface_id));
            Ok(observations)
        })
    }

    fn quarantine_network_interface<'a>(
        &'a self,
        interface_id: &'a Id,
        quarantine_security_group_id: &'a Id,
        deadline: Instant,
    ) -> Ec2Future<'a, MutationAcknowledgement> {
        Box::pin(async move {
            let output = mutate_with_deadline(
                self.client
                    .modify_network_interface_attribute()
                    .network_interface_id(interface_id.as_str())
                    .groups(quarantine_security_group_id.as_str())
                    .send(),
                deadline,
            )
            .await?;
            Ok(MutationAcknowledgement {
                request_id: required_request_id(output.request_id())?,
            })
        })
    }

    fn describe_security_group<'a>(
        &'a self,
        security_group_id: &'a Id,
        deadline: Instant,
    ) -> Ec2Future<'a, SecurityGroupObservation> {
        Box::pin(async move {
            let output = read_with_deadline(
                self.client
                    .describe_security_groups()
                    .group_ids(security_group_id.as_str())
                    .send(),
                deadline,
            )
            .await?;
            if output.next_token().is_some() || output.security_groups().len() != 1 {
                return Err(Ec2CallError::InvalidResponse);
            }
            let group = &output.security_groups()[0];
            Ok(SecurityGroupObservation {
                security_group_id: required_id(group.group_id())?,
                vpc_id: required_id(group.vpc_id())?,
                ingress_rule_count: group.ip_permissions().len(),
                egress_rule_count: group.ip_permissions_egress().len(),
                observation_id: required_request_id(output.request_id())?,
                observed_at_unix_ms: now_unix_millis()?,
            })
        })
    }
}

async fn read_with_deadline<T, E>(
    future: impl Future<Output = Result<T, SdkError<E>>>,
    deadline: Instant,
) -> Result<T, Ec2CallError>
where
    E: ProvideErrorMetadata,
{
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(Ec2CallError::Deadline)?;
    match tokio::time::timeout(remaining, future).await {
        Err(_) => Err(Ec2CallError::Deadline),
        Ok(Ok(output)) => Ok(output),
        Ok(Err(_)) => Err(Ec2CallError::Unavailable),
    }
}

async fn mutate_with_deadline<T, E>(
    future: impl Future<Output = Result<T, SdkError<E>>>,
    deadline: Instant,
) -> Result<T, Ec2CallError>
where
    E: ProvideErrorMetadata,
{
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(Ec2CallError::Deadline)?;
    match tokio::time::timeout(remaining, future).await {
        Err(_) => Err(Ec2CallError::Ambiguous),
        Ok(Ok(output)) => Ok(output),
        Ok(Err(SdkError::ConstructionFailure(_))) => Err(Ec2CallError::InvalidResponse),
        Ok(Err(
            SdkError::TimeoutError(_) | SdkError::DispatchFailure(_) | SdkError::ResponseError(_),
        )) => Err(Ec2CallError::Ambiguous),
        Ok(Err(SdkError::ServiceError(error))) => {
            let code = error.err().code().unwrap_or_default();
            if matches!(
                code,
                "InternalError"
                    | "RequestLimitExceeded"
                    | "ServiceUnavailable"
                    | "Unavailable"
                    | "Throttling"
                    | "ThrottlingException"
            ) {
                Err(Ec2CallError::Ambiguous)
            } else {
                Err(Ec2CallError::Unavailable)
            }
        }
        Ok(Err(_)) => Err(Ec2CallError::Ambiguous),
    }
}

fn required_id(value: Option<&str>) -> Result<Id, Ec2CallError> {
    value
        .and_then(|value| Id::new(value.to_owned()))
        .ok_or(Ec2CallError::InvalidResponse)
}

fn required_request_id(value: Option<&str>) -> Result<AsciiText, Ec2CallError> {
    value
        .and_then(|value| AsciiText::new(value.to_owned()))
        .ok_or(Ec2CallError::InvalidResponse)
}

fn now_unix_millis() -> Result<UnixMillis, Ec2CallError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Ec2CallError::InvalidResponse)?
        .as_millis();
    let millis = u64::try_from(millis).map_err(|_| Ec2CallError::InvalidResponse)?;
    UnixMillis::new(millis).ok_or(Ec2CallError::InvalidResponse)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use cats_api::runtime_reconciliation::{Epoch, NodeBootId, Sha256Digest, WireU64};
    use cats_storage::host_fence::{
        host_fence_effect_token, host_fence_provider_attempt_id, HostFenceBinding,
        ObjectWriteCutoffEvidence, ObjectWriterFenceTarget,
    };

    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn text(value: &str) -> AsciiText {
        AsciiText::new(value).unwrap()
    }

    fn scope(region: &str) -> ProviderScope {
        ProviderScope {
            provider: id("aws"),
            partition: id("aws"),
            account_id: id("123456789012"),
            region: id(region),
        }
    }

    fn request() -> HostFenceAttemptRequest {
        HostFenceAttemptRequest {
            binding: HostFenceBinding {
                provider_scope: scope("us-east-1"),
                immutable_host_id: id("i-0123456789abcdef0"),
                node_id: id("metal-1"),
                expected_node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
                expected_agent_session_epoch: Epoch::new(7).unwrap(),
                fence_attempt_id: id("fence-attempt-1"),
            },
            network_quarantine_boundary_id: text("sg-0fence000000000001"),
            object_writer: ObjectWriterFenceTarget {
                writer_authority_id: id("writer-metal-1"),
                provider_scope: scope("us-east-1"),
                workload_principal_id: text("host-writer-metal-1"),
                object_store_scope_id: text("production-chunkstore"),
            },
        }
    }

    fn config() -> AwsHostFenceConfig {
        AwsHostFenceConfig::new(
            scope("us-east-1"),
            id("sg-0fence000000000001"),
            text("production-chunkstore"),
            BTreeMap::from([(
                id("i-0123456789abcdef0"),
                AwsHostTarget {
                    node_id: id("metal-1"),
                    vpc_id: id("vpc-0123456789abcdef0"),
                    network_interface_ids: BTreeSet::from([id("eni-0123456789abcdef0")]),
                    writer_authority_id: id("writer-metal-1"),
                    workload_principal_id: text("host-writer-metal-1"),
                },
            )]),
        )
        .unwrap()
    }

    fn time(value: u64) -> UnixMillis {
        UnixMillis::new(value).unwrap()
    }

    #[test]
    fn configuration_rejects_shared_writer_or_interface_bindings() {
        let hosts = BTreeMap::from([
            (
                id("i-0123456789abcdef0"),
                AwsHostTarget {
                    node_id: id("metal-1"),
                    vpc_id: id("vpc-0123456789abcdef0"),
                    network_interface_ids: BTreeSet::from([id("eni-shared")]),
                    writer_authority_id: id("writer-shared"),
                    workload_principal_id: text("host-writer-1"),
                },
            ),
            (
                id("i-1123456789abcdef0"),
                AwsHostTarget {
                    node_id: id("metal-2"),
                    vpc_id: id("vpc-0123456789abcdef0"),
                    network_interface_ids: BTreeSet::from([id("eni-shared")]),
                    writer_authority_id: id("writer-shared"),
                    workload_principal_id: text("host-writer-2"),
                },
            ),
        ]);
        assert_eq!(
            AwsHostFenceConfig::new(
                scope("us-east-1"),
                id("sg-0fence000000000001"),
                text("production-chunkstore"),
                hosts,
            ),
            Err(HostFenceProviderError::InvalidRequest)
        );
    }

    fn host(state: Ec2InstanceState, at: u64, observation: &str) -> HostObservation {
        HostObservation {
            host_id: id("i-0123456789abcdef0"),
            vpc_id: id("vpc-0123456789abcdef0"),
            state,
            network_interface_ids: BTreeSet::from([id("eni-0123456789abcdef0")]),
            observation_id: text(observation),
            observed_at_unix_ms: time(at),
        }
    }

    fn interface(groups: &[&str], at: u64, observation: &str) -> NetworkInterfaceObservation {
        NetworkInterfaceObservation {
            interface_id: id("eni-0123456789abcdef0"),
            attached_host_id: id("i-0123456789abcdef0"),
            vpc_id: id("vpc-0123456789abcdef0"),
            security_group_ids: groups.iter().map(|group| id(group)).collect(),
            observation_id: text(observation),
            observed_at_unix_ms: time(at),
        }
    }

    fn policy() -> SecurityGroupObservation {
        SecurityGroupObservation {
            security_group_id: id("sg-0fence000000000001"),
            vpc_id: id("vpc-0123456789abcdef0"),
            ingress_rule_count: 0,
            egress_rule_count: 0,
            observation_id: text("describe-sg-1"),
            observed_at_unix_ms: time(20),
        }
    }

    struct FakeCutoff {
        calls: Mutex<usize>,
    }

    impl FakeCutoff {
        fn calls(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }

    impl ObjectWriteCutoffPort for FakeCutoff {
        fn establish_cutoff<'a>(
            &'a self,
            request: &'a HostFenceAttemptRequest,
            _deadline: Instant,
        ) -> HostFencePortFuture<'a, ObjectWriteCutoffEvidence> {
            *self.calls.lock().unwrap() += 1;
            Box::pin(async move { Ok(cutoff_evidence(request)) })
        }
    }

    fn cutoff_evidence(request: &HostFenceAttemptRequest) -> ObjectWriteCutoffEvidence {
        ObjectWriteCutoffEvidence::PrincipalCutoffWithAcceptedPutTerminalBarrier {
            binding: request.binding.clone(),
            object_writer: request.object_writer.clone(),
            effect_token: host_fence_effect_token(
                &request.binding,
                b"object-write-cutoff",
                &object_target_bytes(&request.object_writer),
            )
            .unwrap(),
            provider_attempt_id: host_fence_provider_attempt_id(
                &request.binding,
                b"object-write-cutoff",
                &object_target_bytes(&request.object_writer),
            )
            .unwrap(),
            cutoff_receipt_id: text("cutoff-receipt-1"),
            cutoff_effective_at_unix_ms: time(10),
            cutoff_sequence: WireU64::new(3).unwrap(),
            accepted_put_terminal_receipt_id: text("terminal-receipt-1"),
            accepted_puts_terminal_at_unix_ms: time(11),
            terminal_sequence: WireU64::new(3).unwrap(),
            terminal_prefix_sha256: Sha256Digest::from_bytes([7; 32]),
            successful_put_visibility_receipt_id: text("visibility-receipt-1"),
            successful_puts_visible_at_unix_ms: time(12),
        }
    }

    struct MismatchedCutoff;

    impl ObjectWriteCutoffPort for MismatchedCutoff {
        fn establish_cutoff<'a>(
            &'a self,
            request: &'a HostFenceAttemptRequest,
            _deadline: Instant,
        ) -> HostFencePortFuture<'a, ObjectWriteCutoffEvidence> {
            Box::pin(async move {
                let mut other = request.clone();
                other.object_writer.object_store_scope_id = text("other-object-store");
                Ok(cutoff_evidence(&other))
            })
        }
    }

    fn object_target_bytes(target: &ObjectWriterFenceTarget) -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in [
            target.writer_authority_id.as_str(),
            target.provider_scope.provider.as_str(),
            target.provider_scope.partition.as_str(),
            target.provider_scope.account_id.as_str(),
            target.provider_scope.region.as_str(),
            target.workload_principal_id.as_str(),
            target.object_store_scope_id.as_str(),
        ] {
            bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        bytes
    }

    struct FakeEc2 {
        hosts: Mutex<VecDeque<Result<HostObservation, Ec2CallError>>>,
        interfaces: Mutex<VecDeque<Result<Vec<NetworkInterfaceObservation>, Ec2CallError>>>,
        policies: Mutex<VecDeque<Result<SecurityGroupObservation, Ec2CallError>>>,
        stop_results: Mutex<VecDeque<Result<MutationAcknowledgement, Ec2CallError>>>,
        quarantine_results: Mutex<VecDeque<Result<MutationAcknowledgement, Ec2CallError>>>,
        stop_calls: Mutex<usize>,
        quarantine_calls: Mutex<usize>,
        read_calls: Mutex<usize>,
    }

    impl FakeEc2 {
        fn successful(stop_result: Result<MutationAcknowledgement, Ec2CallError>) -> Self {
            Self {
                hosts: Mutex::new(VecDeque::from([
                    Ok(host(Ec2InstanceState::Running, 21, "describe-host-1")),
                    Ok(host(Ec2InstanceState::Stopped, 22, "describe-host-2")),
                ])),
                interfaces: Mutex::new(VecDeque::from([
                    Ok(vec![interface(
                        &["sg-0serving0000000001"],
                        23,
                        "describe-eni-1",
                    )]),
                    Ok(vec![interface(
                        &["sg-0fence000000000001"],
                        24,
                        "describe-eni-2",
                    )]),
                ])),
                policies: Mutex::new(VecDeque::from([Ok(policy())])),
                stop_results: Mutex::new(VecDeque::from([stop_result])),
                quarantine_results: Mutex::new(VecDeque::from([Ok(MutationAcknowledgement {
                    request_id: text("modify-eni-1"),
                })])),
                stop_calls: Mutex::new(0),
                quarantine_calls: Mutex::new(0),
                read_calls: Mutex::new(0),
            }
        }

        fn no_calls() -> Self {
            Self {
                hosts: Mutex::new(VecDeque::new()),
                interfaces: Mutex::new(VecDeque::new()),
                policies: Mutex::new(VecDeque::new()),
                stop_results: Mutex::new(VecDeque::new()),
                quarantine_results: Mutex::new(VecDeque::new()),
                stop_calls: Mutex::new(0),
                quarantine_calls: Mutex::new(0),
                read_calls: Mutex::new(0),
            }
        }
    }

    impl Ec2FenceApi for FakeEc2 {
        fn describe_host<'a>(
            &'a self,
            _host_id: &'a Id,
            _deadline: Instant,
        ) -> Ec2Future<'a, HostObservation> {
            *self.read_calls.lock().unwrap() += 1;
            let result = self.hosts.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { result })
        }

        fn stop_host<'a>(
            &'a self,
            _host_id: &'a Id,
            _deadline: Instant,
        ) -> Ec2Future<'a, MutationAcknowledgement> {
            *self.stop_calls.lock().unwrap() += 1;
            let result = self.stop_results.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { result })
        }

        fn describe_network_interfaces<'a>(
            &'a self,
            _interface_ids: &'a BTreeSet<Id>,
            _deadline: Instant,
        ) -> Ec2Future<'a, Vec<NetworkInterfaceObservation>> {
            *self.read_calls.lock().unwrap() += 1;
            let result = self.interfaces.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { result })
        }

        fn quarantine_network_interface<'a>(
            &'a self,
            _interface_id: &'a Id,
            _quarantine_security_group_id: &'a Id,
            _deadline: Instant,
        ) -> Ec2Future<'a, MutationAcknowledgement> {
            *self.quarantine_calls.lock().unwrap() += 1;
            let result = self.quarantine_results.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { result })
        }

        fn describe_security_group<'a>(
            &'a self,
            _security_group_id: &'a Id,
            _deadline: Instant,
        ) -> Ec2Future<'a, SecurityGroupObservation> {
            *self.read_calls.lock().unwrap() += 1;
            let result = self.policies.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { result })
        }
    }

    #[tokio::test]
    async fn ambiguous_stop_is_settled_by_fresh_describe_without_repeating_mutation() {
        let ec2 = Arc::new(FakeEc2::successful(Err(Ec2CallError::Ambiguous)));
        let cutoff = Arc::new(FakeCutoff {
            calls: Mutex::new(0),
        });
        let provider = AwsHostFenceProvider::with_api(config(), ec2.clone(), cutoff.clone());

        let evidence = provider
            .establish_fence(&request(), Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();

        assert_eq!(*ec2.stop_calls.lock().unwrap(), 1);
        assert_eq!(*ec2.quarantine_calls.lock().unwrap(), 1);
        assert_eq!(cutoff.calls(), 1);
        assert_eq!(evidence.completed_at_unix_ms, UnixMillis::new(24).unwrap());
    }

    #[tokio::test]
    async fn wrong_region_is_rejected_before_cutoff_or_any_aws_call() {
        let ec2 = Arc::new(FakeEc2::no_calls());
        let cutoff = Arc::new(FakeCutoff {
            calls: Mutex::new(0),
        });
        let provider = AwsHostFenceProvider::with_api(config(), ec2.clone(), cutoff.clone());
        let mut wrong = request();
        wrong.binding.provider_scope.region = id("us-west-2");

        assert_eq!(
            provider
                .establish_fence(&wrong, Instant::now() + Duration::from_secs(2))
                .await,
            Err(HostFenceProviderError::InvalidRequest)
        );
        assert_eq!(cutoff.calls(), 0);
        assert_eq!(*ec2.read_calls.lock().unwrap(), 0);
        assert_eq!(*ec2.stop_calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn mismatched_writer_cutoff_evidence_prevents_all_aws_effects() {
        let ec2 = Arc::new(FakeEc2::no_calls());
        let provider =
            AwsHostFenceProvider::with_api(config(), ec2.clone(), Arc::new(MismatchedCutoff));

        assert_eq!(
            provider
                .establish_fence(&request(), Instant::now() + Duration::from_secs(2))
                .await,
            Err(HostFenceProviderError::EvidenceMismatch)
        );
        assert_eq!(*ec2.read_calls.lock().unwrap(), 0);
        assert_eq!(*ec2.stop_calls.lock().unwrap(), 0);
        assert_eq!(*ec2.quarantine_calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn ambiguous_stop_that_still_serves_fails_without_a_second_stop() {
        let ec2 = Arc::new(FakeEc2 {
            hosts: Mutex::new(VecDeque::from([
                Ok(host(Ec2InstanceState::Running, 21, "describe-host-1")),
                Ok(host(Ec2InstanceState::Running, 22, "describe-host-2")),
            ])),
            interfaces: Mutex::new(VecDeque::new()),
            policies: Mutex::new(VecDeque::from([Ok(policy())])),
            stop_results: Mutex::new(VecDeque::from([Err(Ec2CallError::Ambiguous)])),
            quarantine_results: Mutex::new(VecDeque::new()),
            stop_calls: Mutex::new(0),
            quarantine_calls: Mutex::new(0),
            read_calls: Mutex::new(0),
        });
        let cutoff = Arc::new(FakeCutoff {
            calls: Mutex::new(0),
        });
        let provider = AwsHostFenceProvider::with_api(config(), ec2.clone(), cutoff);

        assert_eq!(
            provider
                .establish_fence(&request(), Instant::now() + Duration::from_secs(2))
                .await,
            Err(HostFenceProviderError::ServingCutoffObservationAmbiguous)
        );
        assert_eq!(*ec2.stop_calls.lock().unwrap(), 1);
        assert_eq!(*ec2.quarantine_calls.lock().unwrap(), 0);
    }
}
