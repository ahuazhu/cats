//! `cats` CLI: the command-line user surface. Cat lifecycle and PersistentDisk
//! mutations call the synchronous semantic Control API using Workspace-local
//! slugs. Independent account, fleet-admin and OCI deployment tools remain in
//! the same binary; no storage or Node internals appear here.

mod auth;
#[cfg(all(test, unix))]
#[allow(dead_code)] // Retired pending-wire tests remain until the clean-slate test deletion lands.
mod cat_create_pending;
#[cfg(all(test, not(unix)))]
#[path = "cat_create_pending_unsupported.rs"]
#[allow(dead_code)]
mod cat_create_pending;
mod config;
mod credential_store;
#[cfg(unix)]
mod runtime_node_admin;
#[cfg(not(unix))]
#[path = "runtime_node_admin_unsupported.rs"]
mod runtime_node_admin;
// Compile and execute the non-Unix boundary on Unix test hosts too. This is a
// portable compile-shape oracle when a Windows standard-library target is not
// installed locally; the actual non-Unix module above uses this exact file.
#[cfg(all(test, unix))]
#[path = "runtime_node_admin_unsupported.rs"]
mod runtime_node_admin_unsupported_compile_shape;
#[cfg(unix)]
mod runtime_provisioner;
#[cfg(not(unix))]
#[path = "runtime_provisioner_unsupported.rs"]
mod runtime_provisioner;
#[cfg(all(test, unix))]
#[path = "runtime_provisioner_unsupported.rs"]
mod runtime_provisioner_unsupported_compile_shape;
#[cfg(unix)]
mod stable_unix_fs;

use std::io::Read as _;
#[cfg(test)]
use std::io::Write as _;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
#[cfg(test)]
use cats_api::cat_create::{decode_cat_create_v2_accepted_response, CatCreateV2AcceptedResponse};
#[cfg(test)]
use cats_api::persistent_disk::{
    decode_persistent_disk_binding_v2_committed_response, Disk, DiskDurability, DiskKind,
    DiskState, PersistentDiskBindingV2CommittedResponse, PersistentDiskBindingV2Request,
    PersistentDiskCreateV1Request, PERSISTENT_DISK_BINDING_CONFLICT_BODY,
    PERSISTENT_DISK_BINDING_NOT_FOUND_BODY, PERSISTENT_DISK_BINDING_PRECONDITION_BODY,
    PERSISTENT_DISK_NAME_CONFLICT_BODY,
};
use cats_api::runtime_product_reads::{
    decode_cat_operation_read_v1 as decode_product_operation,
    encode_cat_operation_read_v1 as encode_product_operation,
    CatOperationReadV1 as ProductOperation, CatOperationState as ProductOperationState, CatReadV2,
    DiskReadV2, ProductReadPage, CAT_OPERATION_READ_MAX_WIRE_BYTES as OPERATION_MAX_WIRE_BYTES,
};
use cats_api::runtime_reconciliation::Id as RuntimeId;
use clap::{Args, Parser, Subcommand};
use serde_json::json;

use cats_api::auth::{CreatedWorkspaceToken, WorkspaceToken};
use cats_api::list::ListResponse;
use cats_api::oci::{
    DeployOciRequest, OciDeployment, OciDeploymentAttempt, OciDeploymentAttemptState,
    OciRegistryAuth,
};
use cats_api::semantic_control::{
    AttachDiskRequest, CatMountRequest, CatResponse, CreateCatRequest, CreateDiskRequest,
    DetachDiskRequest, DiskResponse, PersistentMountPath, ResourceSlug, SemanticErrorBody,
};

#[derive(Parser, Debug)]
#[command(
    name = "cats",
    version,
    about = "Cats: durable, sleepable Linux microVMs"
)]
pub struct Cli {
    /// Control plane URL.
    #[arg(long, env = "CATS_API_URL", global = true)]
    pub api_url: Option<String>,
    /// Machine/admin bearer token. Users should run `cats login`.
    #[arg(long, env = "CATS_TOKEN", global = true)]
    pub token: Option<String>,
    /// Use one workspace for this command without changing the saved default.
    /// Accepts `workspace`, `account/workspace`, or a workspace ID.
    #[arg(long, env = "CATS_WORKSPACE", global = true)]
    pub workspace: Option<String>,
    /// Do not wait for operations to finish.
    #[arg(long, global = true, hide = true)]
    pub no_wait: bool,
    /// Print raw JSON instead of human-readable output.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Sign in through WorkOS in your browser.
    Login,
    /// Revoke the current CLI session and remove it from the system keychain.
    Logout,
    /// Show the signed-in user and active workspace.
    Whoami,
    /// List or select one of your workspaces.
    Workspace {
        #[command(subcommand)]
        cmd: WorkspaceCommand,
    },
    /// Manage revocable machine credentials for the selected workspace.
    Token {
        #[command(subcommand)]
        cmd: TokenCommand,
    },
    /// Create a cat (its root disk is created automatically).
    Create {
        /// Workspace-local Cat slug.
        #[arg(value_name = "CAT_SLUG")]
        name: String,
        /// Boot image understood by the Control Plane.
        #[arg(long = "boot-image", default_value = "ubuntu-24.04")]
        boot_image_digest: String,
        #[arg(long = "cpu", default_value_t = 2)]
        cpus: u32,
        #[arg(long, default_value = "2GiB")]
        memory: String,
        /// Attach `DISK_SLUG` at an absolute Guest path. May be repeated.
        #[arg(long = "mount", value_name = "DISK_SLUG:/path")]
        mounts: Vec<String>,
    },
    /// List cats.
    Ls,
    /// Show one cat by immutable ID.
    Get { id: String },
    /// Converge a Cold, Suspended, or Warm Cat to Running.
    Run {
        #[arg(value_name = "CAT_SLUG")]
        cat_id: String,
    },
    /// Pause a Cat in the Host-bound Suspended state.
    Suspend {
        #[arg(value_name = "CAT_SLUG")]
        cat_id: String,
    },
    /// Snapshot a Cat into the Host-bound Warm state.
    Warm {
        #[arg(value_name = "CAT_SLUG")]
        cat_id: String,
    },
    /// Drain and release every volume into location-independent Cold.
    Cold {
        #[arg(value_name = "CAT_SLUG")]
        cat_id: String,
    },
    /// Destroy a Cat and its RootDisk after retaining PersistentDisks safely.
    Destroy {
        #[arg(value_name = "CAT_SLUG")]
        cat_id: String,
    },
    /// Deploy a digest-pinned OCI image as a supervised service in a Cat.
    Deploy {
        /// Cat name or ID.
        name: String,
        /// Stable application and systemd service name.
        app: String,
        /// Explicit registry reference ending in `@sha256:<digest>`.
        #[arg(long)]
        image: String,
        /// NAME=VALUE lines merged over the OCI image environment.
        #[arg(long, value_name = "PATH")]
        env_file: Option<std::path::PathBuf>,
        /// Registry username. Pair with --registry-password-stdin.
        #[arg(long, requires = "registry_password_stdin")]
        registry_username: Option<String>,
        /// Read one registry password/token from stdin, keeping it out of argv.
        #[arg(long, requires = "registry_username")]
        registry_password_stdin: bool,
        /// Replace the OCI Entrypoint + Cmd, after `--`.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Disk management.
    Disk {
        #[command(subcommand)]
        cmd: DiskCommand,
    },
    /// Inspect an operation.
    Operation {
        #[command(subcommand)]
        cmd: OperationCommand,
    },
    /// Fleet administration (requires an administrator identity).
    Admin {
        #[command(subcommand)]
        cmd: AdminCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum WorkspaceCommand {
    /// List workspaces available to the signed-in user.
    List,
    /// Save the default workspace for subsequent commands.
    Use { name: String },
    /// Create a workspace beside the currently selected one.
    Create {
        slug: String,
        #[arg(long)]
        display_name: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum TokenCommand {
    /// Create a token. The secret is printed once and never stored by Cats.
    Create { label: String },
    /// List active tokens without revealing their secrets.
    List,
    /// Revoke one token by ID.
    Revoke { id: String },
}

#[derive(Subcommand, Debug)]
pub enum DiskCommand {
    Create {
        /// Workspace-local PersistentDisk slug.
        #[arg(value_name = "DISK_SLUG")]
        name: String,
        #[arg(long)]
        size: String,
    },
    Ls,
    Get {
        /// Immutable Disk ID.
        id: String,
    },
    /// Append a PersistentDisk to the immutable config of a terminal Cold Cat.
    Attach {
        /// Workspace-local PersistentDisk slug.
        #[arg(value_name = "DISK_SLUG")]
        disk: String,
        /// Workspace-local Cat slug.
        #[arg(long, value_name = "CAT_SLUG")]
        cat: String,
        /// Absolute non-root path inside the Guest.
        #[arg(long = "mount")]
        mount_path: String,
    },
    /// Remove the disk binding while the Cat remains Cold.
    Detach {
        /// Workspace-local PersistentDisk slug.
        #[arg(value_name = "DISK_SLUG")]
        disk: String,
        /// Workspace-local Cat slug.
        #[arg(long, value_name = "CAT_SLUG")]
        cat: String,
    },
    /// Destroy an unbound PersistentDisk.
    Destroy {
        #[arg(value_name = "DISK_SLUG")]
        disk: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum OperationCommand {
    Get { id: String },
    Wait { id: String },
}

#[derive(Subcommand, Debug)]
pub enum AdminCommand {
    /// Sign in to the deployment's independent fleet-administrator scope.
    Login,
    /// Remove the independent fleet-administrator session.
    Logout,
    /// Apply the signed Runtime Node identity and placement authority.
    RuntimeNode {
        /// Deployment identity whose current provisioner trust set owns this request.
        #[arg(long, global = true, conflicts_with = "token", requires_all = ["provisioner_credential_id", "provisioner_private_key_file"])]
        deployment_id: Option<String>,
        /// Current deployment-provisioner credential ID.
        #[arg(long, global = true, conflicts_with = "token", requires_all = ["deployment_id", "provisioner_private_key_file"])]
        provisioner_credential_id: Option<String>,
        /// Strict 0600, single-link PKCS#8 PEM private-key file.
        #[arg(long, global = true, conflicts_with = "token", requires_all = ["deployment_id", "provisioner_credential_id"])]
        provisioner_private_key_file: Option<std::path::PathBuf>,
        #[command(subcommand)]
        cmd: RuntimeNodeCommand,
    },
    /// Prepare and verify deployment-provisioner authority artifacts offline.
    RuntimeProvisioner {
        #[command(subcommand)]
        cmd: RuntimeProvisionerCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum RuntimeProvisionerCommand {
    /// Generate or offline-verify the central A23 trust bundle.
    Trust {
        #[command(subcommand)]
        cmd: RuntimeProvisionerTrustCommand,
    },
    /// Prepare, export or activate the fixed Host-local Node identity set.
    NodeIdentity {
        #[command(subcommand)]
        cmd: RuntimeProvisionerNodeIdentityCommand,
    },
    /// Generate or verify the closed initial Route v2 credential transaction.
    #[command(name = "route-v2-r1")]
    RouteV2R1 {
        #[command(subcommand)]
        cmd: RuntimeProvisionerRouteV2R1Command,
    },
}

#[derive(Subcommand, Debug)]
pub enum RuntimeProvisionerTrustCommand {
    /// Idempotently generate a revision-1/null-previous bundle and PKCS#8 v2 key.
    Generate {
        #[arg(long)]
        deployment_id: String,
        #[arg(long)]
        credential_id: String,
        #[arg(long)]
        private_key_out: std::path::PathBuf,
        #[arg(long)]
        trust_bundle_out: std::path::PathBuf,
    },
    /// Verify canonical bytes, strict PKCS#8 v2 and the exact SPKI binding offline.
    Verify {
        #[arg(long)]
        credential_id: String,
        #[arg(long)]
        private_key: std::path::PathBuf,
        #[arg(long)]
        trust_bundle: std::path::PathBuf,
    },
}

#[derive(Subcommand, Debug)]
pub enum RuntimeProvisionerNodeIdentityCommand {
    /// Create the durable initial recovery set without contacting Control.
    Prepare {
        #[arg(long)]
        node_id: String,
        /// Cloud provider of the Host (for example `aws`). Together with the
        /// partition, account, region and immutable Host ID this forms the
        /// complete immutable Host identity.
        #[arg(long)]
        host_provider: String,
        #[arg(long)]
        host_partition: String,
        #[arg(long)]
        host_account_id: String,
        #[arg(long)]
        host_region: String,
        #[arg(long)]
        immutable_host_id: String,
        #[arg(long)]
        state_path_id: String,
        #[arg(long)]
        credential_id: String,
    },
    /// Write the canonical public NodeIdentity recovery artifact to stdout.
    Export,
    /// Activate only after a canonical successful official-CLI apply result.
    Activate {
        #[arg(long)]
        apply_result: std::path::PathBuf,
    },
}

#[derive(Subcommand, Debug)]
pub enum RuntimeProvisionerRouteV2R1Command {
    /// Generate one root-only revision-1 candidate and provider input set.
    Generate {
        /// Absolute absent or exact-replay output directory.
        #[arg(long)]
        output: std::path::PathBuf,
        /// Every reviewed Node machine-listener DNS name (repeatable).
        #[arg(long = "node-server-dns", required = true)]
        node_server_dns: Vec<String>,
        /// Immutable Control Secret name ending in `-r1`.
        #[arg(long)]
        control_secret_name: String,
        /// Immutable Gateway Secret name ending in `-r1`.
        #[arg(long)]
        gateway_secret_name: String,
        /// Scoped Secrets Manager name ending in `-route-v2-node-r1`.
        #[arg(long)]
        node_secret_name: String,
        /// Exact lowercase source commit shared by Control and Node binaries.
        #[arg(long)]
        release_commit_sha: String,
        /// Absolute trusted OpenSSL executable used only by this offline operator.
        #[arg(long, default_value = "/usr/bin/openssl")]
        openssl: std::path::PathBuf,
    },
    /// Revalidate an existing root-only revision-1 candidate offline.
    Verify {
        /// Absolute root-only candidate directory.
        #[arg(long)]
        input: std::path::PathBuf,
        /// Every reviewed Node machine-listener DNS name (repeatable).
        #[arg(long = "node-server-dns", required = true)]
        node_server_dns: Vec<String>,
        /// Immutable Control Secret name ending in `-r1`.
        #[arg(long)]
        control_secret_name: String,
        /// Immutable Gateway Secret name ending in `-r1`.
        #[arg(long)]
        gateway_secret_name: String,
        /// Scoped Secrets Manager name ending in `-route-v2-node-r1`.
        #[arg(long)]
        node_secret_name: String,
        /// Exact lowercase source commit shared by Control and Node binaries.
        #[arg(long)]
        release_commit_sha: String,
    },
    /// Sign one canonical typed rotation command with the offline operator key.
    SignCommand {
        /// Absolute root-only revision-1 candidate directory.
        #[arg(long)]
        input: std::path::PathBuf,
        /// Absolute canonical unsigned command-payload JSON file (mode 0644).
        #[arg(long)]
        payload: std::path::PathBuf,
        /// Absolute absent or exact-replay signed command JSON file (mode 0644).
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Generate a complete r1-to-r8 rotation, disable and recovery artifact set.
    PrepareRotationRecovery {
        /// Absolute root-only revision-1 candidate directory.
        #[arg(long)]
        input: std::path::PathBuf,
        /// Absolute absent or exact-replay root-only recovery output directory.
        #[arg(long)]
        output: std::path::PathBuf,
        /// Qualification run ID embedded in the one composed command bundle.
        #[arg(long)]
        run_id: String,
    },
    /// Revalidate a complete r1-to-r8 recovery artifact set offline.
    VerifyRotationRecovery {
        /// Absolute root-only revision-1 candidate directory.
        #[arg(long)]
        input: std::path::PathBuf,
        /// Absolute root-only recovery output directory.
        #[arg(long)]
        output: std::path::PathBuf,
        /// Qualification run ID embedded in the command bundle.
        #[arg(long)]
        run_id: String,
    },
    /// Fresh-sign one prepared recovery phase into a durable replay file.
    SignRotationRecoveryPhase {
        /// Absolute root-only revision-1 candidate directory.
        #[arg(long)]
        input: std::path::PathBuf,
        /// Absolute root-only prepared recovery artifact directory.
        #[arg(long)]
        recovery: std::path::PathBuf,
        /// Exact prepared phase name.
        #[arg(long)]
        phase: String,
        /// Absolute absent or exact-replay root-only pending command file.
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Verify a restarted Control process loaded PostgreSQL current exactly.
    VerifyRotationCurrent {
        /// Absolute root-only revision-1 candidate directory.
        #[arg(long)]
        input: std::path::PathBuf,
        /// Absolute root-only prepared recovery artifact directory.
        #[arg(long)]
        recovery: std::path::PathBuf,
        /// Exact expected signer revision in the prepared recovery lineage.
        #[arg(long)]
        signer_revision: u64,
        /// Root-only canonical current-binding discovery response.
        #[arg(long)]
        discovery: std::path::PathBuf,
        /// Absolute absent or exact-replay root-only verification receipt.
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Fresh-sign one staged unsigned recovery phase without a private bundle tree.
    SignPreparedRotationPhase {
        /// Fixed root-only operator trust JSON.
        #[arg(long)]
        trust: std::path::PathBuf,
        /// Independent root-only offline operator PKCS#8 v2 PEM.
        #[arg(long)]
        operator_private_key: std::path::PathBuf,
        /// Root-only unsigned seven-phase command bundle.
        #[arg(long)]
        command_bundle: std::path::PathBuf,
        /// Exact prepared phase name.
        #[arg(long)]
        phase: String,
        /// Absolute absent or exact-replay root-only pending command file.
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Verify staged current discovery against one unsigned recovery phase.
    VerifyPreparedRotationCurrent {
        /// Fixed root-only operator trust JSON.
        #[arg(long)]
        trust: std::path::PathBuf,
        /// Root-only unsigned seven-phase command bundle.
        #[arg(long)]
        command_bundle: std::path::PathBuf,
        /// Exact expected signer revision.
        #[arg(long)]
        signer_revision: u64,
        /// Root-only canonical current-binding discovery response.
        #[arg(long)]
        discovery: std::path::PathBuf,
        /// Absolute absent or exact-replay root-only verification receipt.
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Sign one deployment-side post-apply receipt in an independent domain.
    SignControlRolloutApplyReceipt {
        /// Fixed owner-controlled operator trust JSON (release 0644 or staged 0600).
        #[arg(long)]
        trust: std::path::PathBuf,
        /// Root-only operator PKCS#8 v2 PEMs needed by the trust threshold.
        #[arg(long = "operator-private-key", required = true)]
        operator_private_keys: Vec<std::path::PathBuf>,
        /// Canonical unsigned apply-receipt payload produced after fresh discovery.
        #[arg(long)]
        payload: std::path::PathBuf,
        /// Absolute absent or exact-replay root-only signed receipt file.
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Verify one immutable deployment receipt against its exact recovery phase.
    VerifyControlRolloutApplyReceipt {
        /// Fixed owner-controlled operator trust JSON (release 0644 or staged 0600).
        #[arg(long)]
        trust: std::path::PathBuf,
        /// Root-only unsigned seven-phase command bundle.
        #[arg(long)]
        command_bundle: std::path::PathBuf,
        /// Exact prepared phase name expected next by the worker.
        #[arg(long)]
        phase: String,
        /// Exact qualification catalog digest bound by this run.
        #[arg(long)]
        qualification_catalog_sha256: String,
        /// Exact reviewed saved-plan file digest frozen for this phase.
        #[arg(long)]
        saved_plan_sha256: String,
        /// Root-only canonical signed apply receipt fetched from the inbox.
        #[arg(long)]
        receipt: std::path::PathBuf,
        /// Absolute absent or exact-replay root-only verification receipt.
        #[arg(long)]
        output: std::path::PathBuf,
    },
}

#[derive(Debug)]
pub(crate) struct RuntimeNodeAuthorityAuth<'a> {
    pub(crate) deployment_id: Option<&'a str>,
    pub(crate) provisioner_credential_id: Option<&'a str>,
    pub(crate) provisioner_private_key_file: Option<&'a std::path::Path>,
}

#[derive(Subcommand, Debug)]
pub enum RuntimeNodeCommand {
    /// Provision one identity and cordoned policy, including its trusted HTTPS transport target.
    Provision {
        #[arg(long)]
        identity: std::path::PathBuf,
        #[arg(long)]
        policy: std::path::PathBuf,
    },
    /// Apply a placement-policy mutation.
    Policy {
        #[command(subcommand)]
        cmd: RuntimeNodePolicyCommand,
    },
    /// Rotate the Node's A19 public-key credential.
    Credential {
        #[command(subcommand)]
        cmd: RuntimeNodeCredentialCommand,
    },
    /// Retire a cordoned, empty Node identity.
    Retire {
        #[arg(long)]
        request: std::path::PathBuf,
    },
    /// Issue or inspect the Node Host's one object-write writer authority.
    ObjectWriteAuthority {
        #[command(subcommand)]
        cmd: RuntimeNodeObjectWriteAuthorityCommand,
    },
}

/// The object-store side of one writer authority binding. Control derives the
/// immutable Host identity from the Node's provisioned identity, so no Host
/// fact is accepted here.
#[derive(Args, Debug)]
pub struct RuntimeNodeObjectWriteAuthorityBinding {
    /// Provisioned Node whose Host publishes through this authority.
    #[arg(long)]
    pub node: String,
    /// Object-store provider, for example `aws`.
    #[arg(long)]
    pub object_provider: String,
    /// Object-store partition, for example `aws`.
    #[arg(long)]
    pub object_partition: String,
    /// Object-store account holding the ChunkStore scope.
    #[arg(long)]
    pub object_account_id: String,
    /// Object-store region holding the ChunkStore scope.
    #[arg(long)]
    pub object_region: String,
    /// Workload principal the ObjectWrite Gateway presents to the provider.
    #[arg(long)]
    pub workload_principal_id: String,
    /// Exact ChunkStore write scope this authority may publish into.
    #[arg(long)]
    pub object_store_scope_id: String,
}

#[derive(Subcommand, Debug)]
pub enum RuntimeNodeObjectWriteAuthorityCommand {
    /// Open the one authority for this Node's Host and print its assigned ID.
    Provision {
        /// Exact current placement-policy revision this apply is bound to.
        #[arg(long)]
        expected_revision: u64,
        #[command(flatten)]
        binding: RuntimeNodeObjectWriteAuthorityBinding,
    },
    /// Print the bare authority ID that exact binding assigns, without
    /// contacting Control, so an operator can check what a binding would
    /// assign or confirm what a Node reads back from Control. It is not Node
    /// configuration: the Node reads its authority from Control.
    Id {
        #[command(flatten)]
        binding: RuntimeNodeObjectWriteAuthorityBinding,
    },
}

#[derive(Subcommand, Debug)]
pub enum RuntimeNodePolicyCommand {
    /// Apply the complete policy, including the fleet-owned HTTPS Node transport target.
    Apply {
        #[arg(long)]
        node: String,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        file: std::path::PathBuf,
    },
}

#[derive(Subcommand, Debug)]
pub enum RuntimeNodeCredentialCommand {
    Rotate {
        #[arg(long)]
        request: std::path::PathBuf,
    },
}

/// Parse "8GiB" / "512MiB" / "1024" into bytes.
pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix("GiB") {
        (n, 1u64 << 30)
    } else if let Some(n) = s.strip_suffix("MiB") {
        (n, 1u64 << 20)
    } else if let Some(n) = s.strip_suffix("KiB") {
        (n, 1u64 << 10)
    } else if let Some(n) = s.strip_suffix("B") {
        (n, 1)
    } else {
        (s, 1)
    };
    let value: u64 = num
        .trim()
        .parse()
        .with_context(|| format!("invalid size: {s}"))?;
    value
        .checked_mul(mult)
        .ok_or_else(|| anyhow!("size overflows: {s}"))
}

/// Parse the public PersistentDisk capacity syntax. V1 deliberately accepts
/// only whole binary GiB so the value sent to Control is unambiguous.
pub fn parse_gib_size(s: &str) -> Result<u64> {
    let gib = s
        .strip_suffix("GiB")
        .ok_or_else(|| anyhow!("disk size must be a whole number of GiB, for example 100GiB"))?;
    anyhow::ensure!(
        !gib.is_empty() && gib.bytes().all(|byte| byte.is_ascii_digit()),
        "disk size must be a whole number of GiB, for example 100GiB"
    );
    let gib: u64 = gib
        .parse()
        .with_context(|| format!("invalid disk size: {s}"))?;
    anyhow::ensure!(gib > 0, "disk size must be greater than zero");
    gib.checked_mul(1u64 << 30)
        .ok_or_else(|| anyhow!("disk size overflows: {s}"))
}

fn resource_slug(kind: &str, slug: &str) -> Result<ResourceSlug> {
    ResourceSlug::new(slug).with_context(|| {
        format!(
            "invalid {kind} slug {slug:?}: use 1-63 lowercase letters, digits, or '-' and start/end with a letter or digit"
        )
    })
}

fn persistent_mount_path(path: &str) -> Result<PersistentMountPath> {
    PersistentMountPath::new(path)
        .with_context(|| format!("invalid PersistentDisk mount path: {path}"))
}

fn parse_mount(value: &str) -> Result<CatMountRequest> {
    let (disk_slug, mount_path) = value
        .split_once(':')
        .ok_or_else(|| anyhow!("mount must be DISK_SLUG:/absolute/path: {value}"))?;
    anyhow::ensure!(
        !mount_path.contains(':'),
        "mount must contain exactly one ':' separator: {value}"
    );
    Ok(CatMountRequest {
        disk_slug: resource_slug("disk", disk_slug)?,
        mount_path: persistent_mount_path(mount_path)?,
    })
}

fn parse_mounts(values: &[String]) -> Result<Vec<CatMountRequest>> {
    values.iter().map(|value| parse_mount(value)).collect()
}

fn canonical_api_origin(value: &str) -> Result<String> {
    let parsed = reqwest::Url::parse(value).context("invalid Cats API origin")?;
    let has_userinfo = value.split_once("://").is_some_and(|(_, remainder)| {
        let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
        remainder[..authority_end].contains('@')
    });
    anyhow::ensure!(
        value.trim() == value
            && matches!(parsed.scheme(), "http" | "https")
            && parsed.has_host()
            && !has_userinfo
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.path() == "/"
            && parsed.query().is_none()
            && parsed.fragment().is_none(),
        "Cats API URL must be one exact HTTP(S) origin without path, query, credentials, or fragment"
    );
    Ok(parsed.origin().ascii_serialization())
}

struct Client {
    http: reqwest::blocking::Client,
    base: String,
    token: String,
    /// Immutable workspace ID; resource routes never key on a mutable slug.
    workspace_id: String,
}

impl Client {
    fn new(cli: &Cli) -> Result<Self> {
        if let Some(token) = &cli.token {
            let http = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(120))
                .redirect(reqwest::redirect::Policy::none())
                .no_gzip()
                .no_brotli()
                .no_deflate()
                .no_zstd()
                .build()?;
            let base = canonical_api_origin(&auth::configured_api_url(cli.api_url.as_deref())?)?;
            let selector = workspace_override(cli).unwrap_or_else(|| "default".to_string());
            let workspace_id = resolve_workspace_id(&http, &base, token, &selector)?;
            return Ok(Self {
                http,
                base,
                token: token.clone(),
                workspace_id,
            });
        }
        let session =
            auth::user_session(cli.api_url.as_deref(), workspace_override(cli).as_deref())?;
        Self::from_user_session(session)
    }

    fn from_user_session(session: auth::UserSession) -> Result<Self> {
        Ok(Self {
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(120))
                .redirect(reqwest::redirect::Policy::none())
                .no_gzip()
                .no_brotli()
                .no_deflate()
                .no_zstd()
                .build()?,
            base: canonical_api_origin(&session.api_url)?,
            token: session.access_token,
            workspace_id: session.workspace,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/workspaces/{}{}", self.base, self.workspace_id, path)
    }

    fn send(&self, req: reqwest::blocking::RequestBuilder) -> Result<serde_json::Value> {
        self.send_with_status(req).map(|(_, value)| value)
    }

    /// `send`, keeping the status so a caller can tell `200` (the work is done)
    /// from `202` (it is still running and named by an operation).
    fn send_with_status(
        &self,
        req: reqwest::blocking::RequestBuilder,
    ) -> Result<(reqwest::StatusCode, serde_json::Value)> {
        let (status, body) = self.send_with_status_raw(req)?;
        if body.is_empty() {
            Ok((status, serde_json::Value::Null))
        } else {
            let value = serde_json::from_slice(&body).context("malformed response")?;
            Ok((status, value))
        }
    }

    fn send_with_status_raw(
        &self,
        req: reqwest::blocking::RequestBuilder,
    ) -> Result<(reqwest::StatusCode, Vec<u8>)> {
        let resp = req
            .bearer_auth(&self.token)
            .send()
            .context("control plane unreachable")?;
        let status = resp.status();
        let body = resp
            .bytes()
            .context("read control-plane response")?
            .to_vec();
        if !status.is_success() {
            // Surface the structured error body when present.
            if let Ok(err) = serde_json::from_slice::<SemanticErrorBody>(&body) {
                bail!("{} ({:?})", err.message, err.code);
            }
            if let Ok(err) = serde_json::from_slice::<cats_api::error::ErrorBody>(&body) {
                bail!("{} ({:?})", err.message, err.code);
            }
            bail!("HTTP {status}: {}", String::from_utf8_lossy(&body));
        }
        Ok((status, body))
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn send_exact_create(
        &self,
        description: &str,
        origin: &str,
        target: &str,
        content_type: &str,
        idempotency_key: &str,
        body: Vec<u8>,
    ) -> Result<ExactCreateHttpResponse> {
        const MAX_RESPONSE_BYTES: usize = 64 * 1024;

        let exact_url = format!("{origin}{target}");
        let response = self
            .http
            .post(&exact_url)
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .header("Idempotency-Key", idempotency_key)
            .body(body)
            .send()
            .context("control plane unreachable")?;
        anyhow::ensure!(
            response.url().as_str() == exact_url,
            "{description} request did not remain on its exact canonical URL"
        );
        let status = response.status();
        let content_types = response
            .headers()
            .get_all(reqwest::header::CONTENT_TYPE)
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect();
        let content_encodings = response
            .headers()
            .get_all(reqwest::header::CONTENT_ENCODING)
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect();
        let mut body = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES.saturating_add(1) as u64)
            .read_to_end(&mut body)
            .context("read control-plane response")?;
        anyhow::ensure!(
            body.len() <= MAX_RESPONSE_BYTES,
            "{description} response exceeds its closed byte limit"
        );
        Ok(ExactCreateHttpResponse {
            status,
            content_types,
            content_encodings,
            body,
        })
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn send_cat_create(
        &self,
        pending: &cat_create_pending::PreparedCatCreate,
    ) -> Result<ExactCreateHttpResponse> {
        pending.assert_current()?;
        anyhow::ensure!(
            pending.origin() == self.base,
            "pending Cat-create request is bound to a different API origin"
        );
        self.send_exact_create(
            "Cat-create",
            pending.origin(),
            pending.target(),
            pending.content_type(),
            pending.idempotency_key(),
            pending.body()?,
        )
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn send_persistent_disk_create(
        &self,
        pending: &cat_create_pending::PreparedPersistentDiskCreate,
    ) -> Result<ExactCreateHttpResponse> {
        pending.assert_current()?;
        anyhow::ensure!(
            pending.origin() == self.base && pending.workspace_id() == self.workspace_id,
            "pending PersistentDisk-create request is bound to a different API origin or Workspace"
        );
        self.send_exact_create(
            "PersistentDisk-create",
            pending.origin(),
            pending.target(),
            pending.content_type(),
            pending.idempotency_key(),
            pending.body()?,
        )
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn send_persistent_disk_binding(
        &self,
        pending: &cat_create_pending::PreparedPersistentDiskBinding,
    ) -> Result<ExactCreateHttpResponse> {
        pending.assert_current()?;
        anyhow::ensure!(
            pending.origin() == self.base && pending.workspace_id() == self.workspace_id,
            "pending PersistentDisk-binding request is bound to a different API origin or Workspace"
        );
        self.send_exact_create(
            "PersistentDisk-binding",
            pending.origin(),
            pending.target(),
            pending.content_type(),
            pending.idempotency_key(),
            pending.body()?,
        )
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn send_cat_lifecycle(
        &self,
        pending: &cat_create_pending::PreparedCatLifecycle,
    ) -> Result<ExactCreateHttpResponse> {
        const MAX_RESPONSE_BYTES: usize = 64 * 1024;

        pending.assert_current()?;
        anyhow::ensure!(
            pending.origin() == self.base && pending.workspace_id() == self.workspace_id,
            "pending Cat-lifecycle request is bound to a different API origin or Workspace"
        );
        let exact_url = format!("{}{}", pending.origin(), pending.target());
        let response = self
            .http
            .post(&exact_url)
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "application/json")
            .header("Idempotency-Key", pending.idempotency_key())
            // This is intentionally an exact empty body. In particular, the
            // lifecycle contract forbids Content-Type on these six routes.
            .body(Vec::new())
            .send()
            .context("control plane unreachable")?;
        anyhow::ensure!(
            response.url().as_str() == exact_url,
            "Cat-lifecycle request did not remain on its exact canonical URL"
        );
        let status = response.status();
        let content_types = response
            .headers()
            .get_all(reqwest::header::CONTENT_TYPE)
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect();
        let content_encodings = response
            .headers()
            .get_all(reqwest::header::CONTENT_ENCODING)
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect();
        let mut body = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES.saturating_add(1) as u64)
            .read_to_end(&mut body)
            .context("read Cat-lifecycle response")?;
        anyhow::ensure!(
            body.len() <= MAX_RESPONSE_BYTES,
            "Cat-lifecycle response exceeds its closed byte limit"
        );
        Ok(ExactCreateHttpResponse {
            status,
            content_types,
            content_encodings,
            body,
        })
    }

    fn get(&self, path: &str) -> Result<serde_json::Value> {
        self.send(self.http.get(self.url(path)))
    }

    fn get_all_product_pages<T: serde::de::DeserializeOwned>(
        &self,
        collection: &str,
    ) -> Result<Vec<T>> {
        let mut items = Vec::new();
        let mut cursor = None;
        let mut seen = std::collections::BTreeSet::new();
        loop {
            let path = match cursor.as_deref() {
                Some(cursor) => format!("{collection}?limit=100&cursor={cursor}"),
                None => format!("{collection}?limit=100"),
            };
            let page: ProductReadPage<T> = serde_json::from_value(self.get(&path)?)?;
            anyhow::ensure!(
                page.next_cursor.is_none() || !page.items.is_empty(),
                "product collection returned a cursor without an item"
            );
            items.extend(page.items);
            let Some(next) = page.next_cursor else {
                return Ok(items);
            };
            anyhow::ensure!(
                seen.insert(next.clone()),
                "product collection cursor repeated"
            );
            cursor = Some(next);
        }
    }

    fn post(&self, path: &str, body: Option<serde_json::Value>) -> Result<serde_json::Value> {
        let mut req = self
            .http
            .post(self.url(path))
            .header(reqwest::header::ACCEPT, "application/json");
        req = match body {
            Some(b) => req.json(&b),
            None => req.header("content-length", "0"),
        };
        self.send(req)
    }

    fn get_runtime_operation(&self, operation_id: &str) -> Result<ProductOperation> {
        self.get_runtime_operation_with_timeout(operation_id, None)
    }

    fn get_runtime_operation_with_timeout(
        &self,
        operation_id: &str,
        request_timeout: Option<Duration>,
    ) -> Result<ProductOperation> {
        let workspace_id = RuntimeId::new(self.workspace_id.clone())
            .ok_or_else(|| anyhow!("selected workspace ID is not valid for runtime operations"))?;
        let operation_id = RuntimeId::new(operation_id.to_owned())
            .ok_or_else(|| anyhow!("invalid runtime operation ID"))?;
        let exact_url = self.url(&format!("/operations/{operation_id}"));
        let mut request = self
            .http
            .get(&exact_url)
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::ACCEPT_ENCODING, "identity");
        if let Some(request_timeout) = request_timeout {
            request = request.timeout(request_timeout);
        }
        let response = request.send().context("control plane unreachable")?;
        anyhow::ensure!(
            response.url().as_str() == exact_url,
            "Operation request did not remain on its exact canonical URL"
        );
        let status = response.status();
        let content_types: Vec<Vec<u8>> = response
            .headers()
            .get_all(reqwest::header::CONTENT_TYPE)
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect();
        let content_encodings: Vec<Vec<u8>> = response
            .headers()
            .get_all(reqwest::header::CONTENT_ENCODING)
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect();
        let mut body = Vec::new();
        response
            .take(OPERATION_MAX_WIRE_BYTES.saturating_add(1) as u64)
            .read_to_end(&mut body)
            .context("read Operation response")?;
        anyhow::ensure!(
            body.len() <= OPERATION_MAX_WIRE_BYTES,
            "Operation response exceeds its closed byte limit"
        );
        if status != reqwest::StatusCode::OK {
            if let Ok(error) = serde_json::from_slice::<cats_api::error::ErrorBody>(&body) {
                bail!("{} ({:?})", error.message, error.code);
            }
            bail!("HTTP {status}: {}", String::from_utf8_lossy(&body));
        }
        anyhow::ensure!(
            content_types.as_slice() == [b"application/json"],
            "Operation response must have exactly Content-Type: application/json"
        );
        anyhow::ensure!(
            content_encodings.is_empty(),
            "Operation response must not have Content-Encoding"
        );
        let operation = decode_product_operation(&body).context("invalid Operation response")?;
        anyhow::ensure!(
            encode_product_operation(&operation).context("invalid decoded Operation response")?
                == body,
            "Operation response is not canonical"
        );
        anyhow::ensure!(
            operation.workspace_id == workspace_id && operation.operation_id == operation_id,
            "Operation response identity does not match the request"
        );
        Ok(operation)
    }

    fn wait_runtime_operation(&self, operation_id: &str) -> Result<ProductOperation> {
        self.wait_runtime_operation_for(operation_id, Duration::from_secs(120))
    }

    fn wait_runtime_operation_for(
        &self,
        operation_id: &str,
        wait_timeout: Duration,
    ) -> Result<ProductOperation> {
        let deadline = Instant::now() + wait_timeout;
        loop {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                bail!("operation {operation_id} did not finish in time");
            };
            if remaining.is_zero() {
                bail!("operation {operation_id} did not finish in time");
            }
            let operation =
                match self.get_runtime_operation_with_timeout(operation_id, Some(remaining)) {
                    Ok(operation) => operation,
                    Err(error)
                        if Instant::now() >= deadline
                            || error
                                .downcast_ref::<reqwest::Error>()
                                .is_some_and(reqwest::Error::is_timeout) =>
                    {
                        bail!("operation {operation_id} did not finish in time");
                    }
                    Err(error) => return Err(error),
                };
            match &operation.state {
                ProductOperationState::InProgress => {
                    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                        bail!("operation {operation_id} did not finish in time");
                    };
                    if remaining.is_zero() {
                        bail!("operation {operation_id} did not finish in time");
                    }
                    std::thread::sleep(remaining.min(Duration::from_millis(150)));
                }
                ProductOperationState::Succeeded => return Ok(operation),
                ProductOperationState::Failed => bail!(
                    "{} operation {operation_id} failed",
                    format!("{:?}", operation.action).to_lowercase()
                ),
            }
        }
    }
}

fn workspace_override(cli: &Cli) -> Option<String> {
    cli.workspace.clone()
}

/// Machine tokens have no WorkOS identity to enumerate workspaces from, so a
/// non-ID selector is resolved through the admin workspace directory.
fn resolve_workspace_id(
    http: &reqwest::blocking::Client,
    base: &str,
    token: &str,
    selector: &str,
) -> Result<String> {
    if selector.starts_with("ws_") {
        return Ok(selector.to_string());
    }
    let response = http
        .get(format!("{base}/v1/admin/workspaces"))
        .bearer_auth(token)
        .send()
        .context("control plane unreachable")?;
    anyhow::ensure!(
        response.status().is_success(),
        "could not resolve workspace {selector}: the token must be an admin token, \
         or pass --workspace with a workspace ID"
    );
    let listed: ListResponse<cats_api::auth::Workspace> = response
        .json()
        .context("invalid workspace directory response")?;
    let matched = listed
        .items
        .iter()
        .find(|workspace| workspace.locator == selector)
        .or_else(|| {
            let mut slug_matches = listed
                .items
                .iter()
                .filter(|workspace| workspace.slug == selector);
            let first = slug_matches.next()?;
            slug_matches.next().is_none().then_some(first)
        })
        .with_context(|| format!("unknown or ambiguous workspace {selector}"))?;
    Ok(matched.id.clone())
}

fn print_runtime_cat(cat: &CatReadV2, json_mode: bool) {
    if json_mode {
        println!("{}", serde_json::to_string_pretty(cat).unwrap());
    } else {
        let lifecycle = cat
            .lifecycle
            .stable_state
            .map(|state| format!("{state:?}").to_lowercase())
            .unwrap_or_else(|| "unknown".to_owned());
        let (physical, node) = cat.observed.as_ref().map_or_else(
            || ("unknown".to_owned(), "-".to_owned()),
            |observed| {
                (
                    format!("{:?}", observed.physical_state).to_lowercase(),
                    observed.node_id.to_string(),
                )
            },
        );
        println!(
            "{:<16} id={:<38} lifecycle={:<9} physical={:<22} node={} config={}",
            cat.name, cat.id, lifecycle, physical, node, cat.current_runtime_config_id,
        );
    }
}

fn runtime_product_item_id<'a>(value: &'a str, prefix: &str, resource: &str) -> Result<&'a str> {
    anyhow::ensure!(
        RuntimeId::new(value.to_owned()).is_some() && value.starts_with(prefix),
        "{resource} item key must be an immutable {prefix} ID"
    );
    Ok(value)
}

/// Run the CLI; returns the process exit code.
pub fn run(cli: Cli) -> Result<()> {
    match &cli.command {
        Command::Login => {
            let config = auth::login(cli.api_url.as_deref())?;
            let user = config.user.as_ref().context("WorkOS returned no user")?;
            println!("Logged in as {}", user.email);
            if let Some(workspace) = &config.current_workspace {
                println!("Current workspace: {workspace}");
            }
            return Ok(());
        }
        Command::Logout => {
            auth::logout(cli.api_url.as_deref())?;
            println!("Logged out");
            return Ok(());
        }
        Command::Whoami => {
            let session =
                auth::user_session(cli.api_url.as_deref(), workspace_override(&cli).as_deref())?;
            let client = Client::from_user_session(session)?;
            let value = client.send(client.http.get(format!("{}/v1/me", client.base)))?;
            let me: cats_api::auth::MeResponse = serde_json::from_value(value)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&me)?);
            } else {
                println!("{}", me.user.email);
                println!("User: {}", me.user.id);
                let label = me
                    .workspaces
                    .iter()
                    .find(|workspace| workspace.id == client.workspace_id)
                    .map(|workspace| workspace.locator.clone())
                    .unwrap_or_else(|| client.workspace_id.clone());
                println!("Workspace: {label}");
            }
            return Ok(());
        }
        Command::Workspace { cmd } => {
            match cmd {
                WorkspaceCommand::List => {
                    let mut session = auth::user_session(
                        cli.api_url.as_deref(),
                        workspace_override(&cli).as_deref(),
                    )?;
                    let workspaces = auth::sync_workspaces(&mut session)?;
                    if cli.json {
                        println!("{}", serde_json::to_string_pretty(&workspaces)?);
                    } else {
                        for workspace in workspaces {
                            let selected = if session.config.current_workspace.as_deref()
                                == Some(workspace.selector())
                            {
                                "*"
                            } else {
                                " "
                            };
                            println!(
                                "{selected} {:<24} {}",
                                workspace.selector(),
                                workspace.display_name
                            );
                        }
                    }
                }
                WorkspaceCommand::Use { name } => {
                    let workspace = auth::switch_workspace(cli.api_url.as_deref(), name)?;
                    println!("Current workspace: {}", workspace.selector());
                }
                WorkspaceCommand::Create { slug, display_name } => {
                    let session = auth::user_session(
                        cli.api_url.as_deref(),
                        workspace_override(&cli).as_deref(),
                    )?;
                    let account_id = session
                        .config
                        .workspaces
                        .iter()
                        .find(|workspace| workspace.id == session.workspace)
                        .map(|workspace| workspace.account_id.clone())
                        .context("selected workspace disappeared from the login session")?;
                    let client = Client::from_user_session(session)?;
                    let value = client.send(
                        client
                            .http
                            .post(format!(
                                "{}/v1/accounts/{}/workspaces",
                                client.base, account_id
                            ))
                            .json(&cats_api::auth::CreateWorkspaceRequest {
                                slug: slug.clone(),
                                display_name: display_name.clone().unwrap_or_else(|| slug.clone()),
                            }),
                    )?;
                    let workspace: cats_api::auth::Workspace = serde_json::from_value(value)?;
                    println!("{}", workspace.selector());
                }
            }
            return Ok(());
        }
        Command::Admin {
            cmd: AdminCommand::Login,
        } => {
            anyhow::ensure!(
                cli.token.is_none(),
                "fleet administrator login acquires its own WorkOS session; remove --token"
            );
            anyhow::ensure!(
                cli.workspace.is_none(),
                "fleet administrator login is not Workspace-scoped; remove --workspace/CATS_WORKSPACE"
            );
            let identity = auth::fleet_admin_login(cli.api_url.as_deref())?;
            println!("Fleet administrator signed in as {}", identity.email);
            return Ok(());
        }
        Command::Admin {
            cmd: AdminCommand::Logout,
        } => {
            anyhow::ensure!(
                cli.token.is_none(),
                "fleet administrator logout uses its own WorkOS session; remove --token"
            );
            anyhow::ensure!(
                cli.workspace.is_none(),
                "fleet administrator logout is not Workspace-scoped; remove --workspace/CATS_WORKSPACE"
            );
            auth::fleet_admin_logout(cli.api_url.as_deref())?;
            println!("Fleet administrator logged out");
            return Ok(());
        }
        Command::Admin {
            cmd:
                AdminCommand::RuntimeNode {
                    deployment_id,
                    provisioner_credential_id,
                    provisioner_private_key_file,
                    cmd,
                },
        } => {
            let authority = RuntimeNodeAuthorityAuth {
                deployment_id: deployment_id.as_deref(),
                provisioner_credential_id: provisioner_credential_id.as_deref(),
                provisioner_private_key_file: provisioner_private_key_file.as_deref(),
            };
            return runtime_node_admin::run(&cli, &authority, cmd);
        }
        Command::Admin {
            cmd: AdminCommand::RuntimeProvisioner { cmd },
        } => return runtime_provisioner::run(&cli, cmd),
        _ => {}
    }
    let client = Client::new(&cli)?;

    match &cli.command {
        Command::Login | Command::Logout | Command::Whoami | Command::Workspace { .. } => {
            unreachable!("handled before API client construction")
        }
        Command::Token { cmd } => match cmd {
            TokenCommand::Create { label } => {
                let value = client.post("/tokens", Some(json!({ "label": label })))?;
                let created: CreatedWorkspaceToken = serde_json::from_value(value)?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&created)?);
                } else {
                    println!("Token ID: {}", created.access_token.id);
                    println!("Token: {}", created.token);
                    println!("Save it now; Cats will not show it again.");
                }
                Ok(())
            }
            TokenCommand::List => {
                let list: ListResponse<WorkspaceToken> =
                    serde_json::from_value(client.get("/tokens")?)?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&list.items)?);
                } else {
                    for token in list.items {
                        println!("{}  {}", token.id, token.label);
                    }
                }
                Ok(())
            }
            TokenCommand::Revoke { id } => {
                client.send(client.http.delete(client.url(&format!("/tokens/{id}"))))?;
                println!("revoked {id}");
                Ok(())
            }
        },
        Command::Create {
            name,
            boot_image_digest,
            cpus,
            memory,
            mounts,
        } => {
            let request = CreateCatRequest {
                cat_slug: resource_slug("cat", name)?,
                cpu: *cpus,
                memory_bytes: parse_size(memory)?,
                boot_image: boot_image_digest.clone(),
                mounts: parse_mounts(mounts)?,
            };
            request.validate().context("invalid Cat create request")?;
            let response = client.post("/cats", Some(serde_json::to_value(request)?))?;
            let response: CatResponse =
                serde_json::from_value(response).context("invalid semantic Cat response")?;
            response.cat.validate().context("invalid Cat response")?;
            print_cat_response(&response, cli.json)
        }
        Command::Ls => {
            let cats: Vec<CatReadV2> = client.get_all_product_pages("/cats")?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&cats).unwrap());
            } else {
                for cat in &cats {
                    print_runtime_cat(cat, false);
                }
            }
            Ok(())
        }
        Command::Get { id } => {
            let id = runtime_product_item_id(id, "cat_", "Cat")?;
            let cat: CatReadV2 = serde_json::from_value(client.get(&format!("/cats/{id}"))?)?;
            print_runtime_cat(&cat, cli.json);
            Ok(())
        }
        Command::Run { cat_id } => run_semantic_cat_action(&client, &cli, cat_id, "run"),
        Command::Suspend { cat_id } => run_semantic_cat_action(&client, &cli, cat_id, "suspend"),
        Command::Warm { cat_id } => run_semantic_cat_action(&client, &cli, cat_id, "warm"),
        Command::Cold { cat_id } => run_semantic_cat_action(&client, &cli, cat_id, "cold"),
        Command::Destroy { cat_id } => run_semantic_cat_action(&client, &cli, cat_id, "destroy"),
        Command::Deploy {
            name,
            app,
            image,
            env_file,
            registry_username,
            registry_password_stdin,
            command,
        } => {
            let env = env_file
                .as_deref()
                .map(read_exec_env_file)
                .transpose()?
                .unwrap_or_default();
            let registry_auth = if *registry_password_stdin {
                use std::io::Read as _;
                let mut password = String::new();
                std::io::stdin()
                    .read_to_string(&mut password)
                    .context("read registry password from stdin")?;
                let password = password.trim_end_matches(['\r', '\n']).to_string();
                anyhow::ensure!(!password.is_empty(), "registry password stdin was empty");
                Some(OciRegistryAuth {
                    username: registry_username
                        .clone()
                        .expect("clap requires a registry username"),
                    password,
                })
            } else {
                None
            };
            let body = DeployOciRequest {
                app: app.clone(),
                image: image.clone(),
                command: command.clone(),
                env,
                registry_auth,
            };
            let (status, value) = client.send_with_status(
                client
                    .http
                    .post(client.url(&format!("/cats/{name}/oci-deployments")))
                    .timeout(Duration::from_secs(3_615))
                    .json(&body),
            )?;
            // A deploy long enough to outrun the control plane's synchronous
            // wait is named by an OCI attempt. Both are successes; poll that
            // independent authority without consulting lifecycle Operations.
            let deployment: OciDeployment = if status == reqwest::StatusCode::ACCEPTED {
                let accepted: OciDeploymentAttempt = serde_json::from_value(value)?;
                follow_oci_deployment(&client, accepted.attempt_id.as_str(), name)?
            } else {
                serde_json::from_value(value)?
            };
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&deployment)?);
            } else {
                println!(
                    "deployed {} {} as {} ({})",
                    deployment.app,
                    deployment.manifest_digest,
                    deployment.service,
                    if deployment.active {
                        "active"
                    } else {
                        "installed"
                    }
                );
            }
            Ok(())
        }
        Command::Disk { cmd } => run_disk(&client, &cli, cmd),
        Command::Operation { cmd } => match cmd {
            OperationCommand::Get { id } => {
                let operation = client.get_runtime_operation(id)?;
                println!("{}", serde_json::to_string_pretty(&operation)?);
                Ok(())
            }
            OperationCommand::Wait { id } => {
                let operation = client.wait_runtime_operation(id)?;
                print_runtime_operation_terminal(&operation, cli.json)
            }
        },
        Command::Admin { .. } => {
            unreachable!("fleet administrator commands bypass workspace API construction")
        }
    }
}

/// Follow an accepted OCI deployment to its outcome.
///
/// Polls the exact OCI attempt. The deploy is durable
/// and keyed on `(cat, app, digest)`, so interrupting this wait loses only the
/// waiting: re-running the same deploy replays the result rather than
/// redeploying.
fn follow_oci_deployment(client: &Client, attempt_id: &str, cat: &str) -> Result<OciDeployment> {
    loop {
        let attempt: OciDeploymentAttempt = serde_json::from_value(
            client.get(&format!("/cats/{cat}/oci-deployment-attempts/{attempt_id}"))?,
        )?;
        anyhow::ensure!(
            attempt.attempt_id.as_str() == attempt_id,
            "OCI deployment attempt response identity changed"
        );
        match attempt.state {
            OciDeploymentAttemptState::Succeeded => {
                return attempt
                    .deployment
                    .context("succeeded OCI deployment attempt did not include its deployment");
            }
            OciDeploymentAttemptState::Failed => {
                let message = attempt
                    .error
                    .map(|error| error.message)
                    .unwrap_or_else(|| "deployment failed".to_string());
                bail!("{message}");
            }
            OciDeploymentAttemptState::Running => {
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

fn read_exec_env_file(
    path: &std::path::Path,
) -> Result<std::collections::BTreeMap<String, String>> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("read exec environment file {}", path.display()))?;
    let mut env = std::collections::BTreeMap::new();
    for (index, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line.split_once('=').with_context(|| {
            format!(
                "{}:{} must be NAME=VALUE",
                path.display(),
                index.saturating_add(1)
            )
        })?;
        anyhow::ensure!(
            valid_env_name(name),
            "{}:{} has invalid environment name",
            path.display(),
            index.saturating_add(1)
        );
        env.insert(name.to_string(), value.to_string());
    }
    Ok(env)
}

fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn run_semantic_cat_action(client: &Client, cli: &Cli, cat_slug: &str, action: &str) -> Result<()> {
    resource_slug("cat", cat_slug)?;
    let response = client.post(&format!("/cats/{cat_slug}/actions/{action}"), None)?;
    let response: CatResponse =
        serde_json::from_value(response).context("invalid semantic Cat response")?;
    response.cat.validate().context("invalid Cat response")?;
    print_cat_response(&response, cli.json)
}

fn print_cat_response(response: &CatResponse, json_mode: bool) -> Result<()> {
    if json_mode {
        println!("{}", serde_json::to_string_pretty(response)?);
        return Ok(());
    }
    let state = response
        .cat
        .state
        .map(|state| format!("{state:?}").to_lowercase())
        .unwrap_or_else(|| "creating".to_owned());
    let node = response
        .cat
        .node_name
        .as_ref()
        .map_or("-", |name| name.as_str());
    let code = serde_json::to_value(response.code)?;
    let code = code
        .as_str()
        .context("semantic success code was not a string")?;
    println!(
        "{}: cat={} id={} state={} node={}",
        code, response.cat.cat_slug, response.cat.cat_id, state, node
    );
    Ok(())
}

fn print_disk_response(response: &DiskResponse, json_mode: bool) -> Result<()> {
    if json_mode {
        println!("{}", serde_json::to_string_pretty(response)?);
    } else {
        let code = serde_json::to_value(response.code)?;
        let code = code
            .as_str()
            .context("semantic success code was not a string")?;
        println!(
            "{}: disk={} id={} status={}",
            code,
            response.disk.disk_slug,
            response.disk.disk_id,
            format!("{:?}", response.disk.status).to_lowercase()
        );
    }
    Ok(())
}

fn run_disk(client: &Client, cli: &Cli, cmd: &DiskCommand) -> Result<()> {
    match cmd {
        DiskCommand::Create { name, size } => {
            let request = CreateDiskRequest {
                disk_slug: resource_slug("disk", name)?,
                size_bytes: parse_gib_size(size)?,
            };
            request
                .validate()
                .context("invalid PersistentDisk create request")?;
            let response = client.post("/disks", Some(serde_json::to_value(request)?))?;
            let response: DiskResponse = serde_json::from_value(response)
                .context("invalid semantic PersistentDisk response")?;
            response
                .disk
                .validate()
                .context("invalid PersistentDisk response")?;
            print_disk_response(&response, cli.json)
        }
        DiskCommand::Ls => {
            let disks: Vec<DiskReadV2> = client.get_all_product_pages("/disks")?;
            if cli.json {
                println!("{}", runtime_disk_list_json(&disks)?);
            } else {
                for disk in &disks {
                    print_runtime_disk(disk, false);
                }
            }
            Ok(())
        }
        DiskCommand::Get { id } => {
            let id = runtime_product_item_id(id, "disk_", "Disk")?;
            let disk: DiskReadV2 = serde_json::from_value(client.get(&format!("/disks/{id}"))?)?;
            print_runtime_disk(&disk, cli.json);
            Ok(())
        }
        DiskCommand::Attach {
            disk,
            cat,
            mount_path,
        } => {
            resource_slug("disk", disk)?;
            let request = AttachDiskRequest {
                cat_slug: resource_slug("cat", cat)?,
                mount_path: persistent_mount_path(mount_path)?,
            };
            let response = client.post(
                &format!("/disks/{disk}/actions/attach"),
                Some(serde_json::to_value(request)?),
            )?;
            let response: DiskResponse = serde_json::from_value(response)
                .context("invalid semantic PersistentDisk response")?;
            response
                .disk
                .validate()
                .context("invalid PersistentDisk response")?;
            print_disk_response(&response, cli.json)
        }
        DiskCommand::Detach { disk, cat } => {
            resource_slug("disk", disk)?;
            let request = DetachDiskRequest {
                cat_slug: resource_slug("cat", cat)?,
            };
            let response = client.post(
                &format!("/disks/{disk}/actions/detach"),
                Some(serde_json::to_value(request)?),
            )?;
            let response: DiskResponse = serde_json::from_value(response)
                .context("invalid semantic PersistentDisk response")?;
            response
                .disk
                .validate()
                .context("invalid PersistentDisk response")?;
            print_disk_response(&response, cli.json)
        }
        DiskCommand::Destroy { disk } => {
            resource_slug("disk", disk)?;
            let response = client.post(&format!("/disks/{disk}/actions/destroy"), None)?;
            let response: DiskResponse = serde_json::from_value(response)
                .context("invalid semantic PersistentDisk response")?;
            response
                .disk
                .validate()
                .context("invalid PersistentDisk response")?;
            print_disk_response(&response, cli.json)
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
fn run_persistent_disk_binding(
    client: &Client,
    cli: &Cli,
    disk: &str,
    cat: &str,
    mount_path: &str,
    action: cat_create_pending::PersistentDiskBindingAction,
) -> Result<()> {
    let disk = runtime_product_item_id(disk, "disk_", "Disk")?;
    let cat = runtime_product_item_id(cat, "cat_", "Cat")?;
    let request = PersistentDiskBindingV2Request {
        cat_id: RuntimeId::new(cat.to_owned()).context("invalid immutable Cat ID")?,
        mount_path: cats_api::runtime_reconciliation::HostPath::new(mount_path.to_owned())
            .context("invalid absolute Guest mount path")?,
    };
    request
        .validate()
        .context("invalid PersistentDisk-binding request")?;
    let request_body = serde_json::to_vec(&request)?;
    let pending = cat_create_pending::PreparedPersistentDiskBinding::prepare(
        &client.base,
        &client.workspace_id,
        disk,
        action,
        &request_body,
    )
    .with_context(|| {
        format!(
            "could not durably prepare PersistentDisk-{} recovery state; no HTTP request was sent",
            action.as_str()
        )
    })?;
    anyhow::ensure!(
        pending.disk_id().as_str() == disk
            && pending.action() == action
            && pending.request()? == request,
        "persisted PersistentDisk-binding request changed before send"
    );
    let response = client
        .send_persistent_disk_binding(&pending)
        .with_context(|| {
            format!(
                "PersistentDisk-{} response is ambiguous; the exact path, body, and Idempotency-Key remain pending at {}",
                action.as_str(),
                pending.pending_path().display()
            )
        })?;
    match classify_persistent_disk_binding_response(&response) {
        PersistentDiskBindingResponseClassification::Committed(committed) => {
            anyhow::ensure!(
                persistent_disk_binding_response_matches_target(&committed, disk, cat),
                "PersistentDisk-{} response carried a different Cat or Disk identity; replay the same command to reuse the pending Idempotency-Key at {}",
                action.as_str(),
                pending.pending_path().display()
            );
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&committed)?);
            } else {
                println!(
                    "PersistentDisk {disk} {} committed for Cat {cat} at {mount_path} (runtime config {}, {})",
                    action.as_str(),
                    committed.runtime_config_id,
                    committed.runtime_config_digest,
                );
            }
            std::io::stdout().flush().with_context(|| {
                format!(
                    "flush committed PersistentDisk-{} config before cleanup",
                    action.as_str()
                )
            })?;
            pending.clear().with_context(|| {
                format!(
                    "PersistentDisk-{} committed and was reported, but its pending recovery state could not be durably cleared",
                    action.as_str()
                )
            })?;
            Ok(())
        }
        PersistentDiskBindingResponseClassification::NotFound => {
            pending.clear().with_context(|| {
                format!(
                    "PersistentDisk-{} not-found result is terminal, but its pending recovery state could not be durably cleared",
                    action.as_str()
                )
            })?;
            bail!("Cat or PersistentDisk was not found (NotFound)")
        }
        PersistentDiskBindingResponseClassification::Conflict => {
            pending.clear().with_context(|| {
                format!(
                    "PersistentDisk-{} conflict is terminal, but its pending recovery state could not be durably cleared",
                    action.as_str()
                )
            })?;
            bail!(
                "PersistentDisk {} does not have the exact requested Cat and mount-path binding (Conflict)",
                action.as_str()
            )
        }
        PersistentDiskBindingResponseClassification::FailedPrecondition => {
            pending.clear().with_context(|| {
                format!(
                    "PersistentDisk-{} failed precondition is terminal, but its pending recovery state could not be durably cleared",
                    action.as_str()
                )
            })?;
            bail!(
                "PersistentDisk {} requires an exact settled Cold Cat and unowned disk (FailedPrecondition)",
                action.as_str()
            )
        }
        PersistentDiskBindingResponseClassification::Nonterminal => {
            let detail = serde_json::from_slice::<cats_api::error::ErrorBody>(&response.body)
                .map(|error| format!("{} ({:?})", error.message, error.code))
                .unwrap_or_else(|_| {
                    format!(
                        "HTTP {}: {}",
                        response.status,
                        String::from_utf8_lossy(&response.body)
                    )
                });
            bail!(
                "PersistentDisk-{} response was not an exact terminal result ({detail}); replay the same command to reuse the pending Idempotency-Key at {}",
                action.as_str(),
                pending.pending_path().display()
            )
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
fn print_disk(d: &Disk, json_mode: bool) {
    if json_mode {
        println!("{}", serde_json::to_string_pretty(d).unwrap());
    } else {
        println!(
            "{:<16} {:>8} MiB  kind={:<10} state={:<10} durability={:<7} cat={}",
            d.name,
            d.size_bytes >> 20,
            format!("{:?}", d.kind).to_lowercase(),
            format!("{:?}", d.state).to_lowercase(),
            d.durability.as_str(),
            d.bound_cat_id.as_deref().unwrap_or("-")
        );
    }
}

fn runtime_disk_list_json(disks: &[DiskReadV2]) -> serde_json::Result<String> {
    serde_json::to_string_pretty(disks)
}

fn print_runtime_disk(disk: &DiskReadV2, json_mode: bool) {
    if json_mode {
        println!("{}", serde_json::to_string_pretty(disk).unwrap());
    } else {
        let kind = match disk.kind {
            cats_api::runtime_product_reads::DiskReadKind::Root { .. } => "root",
            cats_api::runtime_product_reads::DiskReadKind::Persistent => "persistent",
        };
        let bound_cat = disk
            .binding
            .as_ref()
            .map(|binding| binding.cat_id.as_str())
            .unwrap_or("-");
        println!(
            "{:<16} id={:<38} {:>8} MiB kind={:<10} admin={:<8} durability={:<7} cat={}",
            disk.name,
            disk.id,
            disk.size_bytes >> 20,
            kind,
            format!("{:?}", disk.admin_state).to_lowercase(),
            format!("{:?}", disk.durability).to_lowercase(),
            bound_cat,
        );
    }
}

#[cfg(test)]
const CAT_CREATE_NAME_CONFLICT_BODY: &[u8] =
    br#"{"code":"already_exists","message":"cat name already exists"}"#;

#[cfg(test)]
struct ExactCreateHttpResponse {
    status: reqwest::StatusCode,
    content_types: Vec<Vec<u8>>,
    content_encodings: Vec<Vec<u8>>,
    body: Vec<u8>,
}

#[cfg(test)]
#[allow(dead_code)]
enum CatCreateResponseClassification {
    Accepted(CatCreateV2AcceptedResponse),
    NameConflict,
    Nonterminal,
}

#[cfg(test)]
fn classify_cat_create_response(
    response: &ExactCreateHttpResponse,
) -> CatCreateResponseClassification {
    let exact_json_identity = response.content_types.as_slice() == [b"application/json"]
        && response.content_encodings.is_empty();
    if !exact_json_identity {
        return CatCreateResponseClassification::Nonterminal;
    }
    if response.status == reqwest::StatusCode::ACCEPTED {
        if let Ok(accepted) = decode_cat_create_v2_accepted_response(&response.body) {
            if serde_json::to_vec(&accepted).ok().as_deref() == Some(response.body.as_slice()) {
                return CatCreateResponseClassification::Accepted(accepted);
            }
        }
    } else if response.status == reqwest::StatusCode::CONFLICT
        && response.body == CAT_CREATE_NAME_CONFLICT_BODY
    {
        return CatCreateResponseClassification::NameConflict;
    }
    CatCreateResponseClassification::Nonterminal
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(test)]
#[allow(dead_code)]
struct CatLifecycleAcceptedResponse {
    operation_id: RuntimeId,
}

#[cfg(test)]
#[allow(dead_code)]
enum CatLifecycleResponseClassification {
    Accepted(CatLifecycleAcceptedResponse),
    DefinitiveError(cats_api::error::ErrorBody),
    Nonterminal,
}

#[cfg(test)]
#[allow(dead_code)]
fn decode_exact_json<T>(body: &[u8]) -> Option<T>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let decoded = T::deserialize(&mut decoder).ok()?;
    decoder.end().ok()?;
    (serde_json::to_vec(&decoded).ok()?.as_slice() == body).then_some(decoded)
}

#[cfg(test)]
#[allow(dead_code)]
fn classify_cat_lifecycle_response(
    response: &ExactCreateHttpResponse,
) -> CatLifecycleResponseClassification {
    let exact_json_identity = response.content_types.as_slice() == [b"application/json"]
        && response.content_encodings.is_empty();
    if !exact_json_identity {
        return CatLifecycleResponseClassification::Nonterminal;
    }
    if response.status == reqwest::StatusCode::ACCEPTED {
        if let Some(accepted) = decode_exact_json::<CatLifecycleAcceptedResponse>(&response.body) {
            if accepted.operation_id.as_str().starts_with("op_") {
                return CatLifecycleResponseClassification::Accepted(accepted);
            }
        }
    } else if response.status.is_client_error() {
        if let Some(error) = decode_exact_json::<cats_api::error::ErrorBody>(&response.body) {
            if error.code.http_status() == response.status.as_u16() {
                return CatLifecycleResponseClassification::DefinitiveError(error);
            }
        }
    }
    CatLifecycleResponseClassification::Nonterminal
}

fn print_runtime_operation_terminal(operation: &ProductOperation, json_mode: bool) -> Result<()> {
    if json_mode {
        println!("{}", serde_json::to_string_pretty(operation)?);
    } else {
        println!(
            "completed: {} {}",
            format!("{:?}", operation.action).to_lowercase(),
            format!("{:?}", operation.state).to_lowercase()
        );
    }
    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
fn run_cat_lifecycle_mutation(
    client: &Client,
    cli: &Cli,
    cat_id: &str,
    action: cat_create_pending::CatLifecycleAction,
) -> Result<()> {
    runtime_product_item_id(cat_id, "cat_", "Cat")?;
    let pending = cat_create_pending::PreparedCatLifecycle::prepare(
        &client.base,
        &client.workspace_id,
        cat_id,
        action,
    )
    .context("could not durably prepare Cat-lifecycle recovery state; no HTTP request was sent")?;
    anyhow::ensure!(
        pending.cat_id().as_str() == cat_id && pending.action() == action,
        "pending Cat-lifecycle state does not bind the requested Cat and action"
    );
    let response = client.send_cat_lifecycle(&pending).with_context(|| {
        format!(
            "Cat-lifecycle response is ambiguous; the exact empty-body request and Idempotency-Key remain pending at {}",
            pending.pending_path().display()
        )
    })?;
    match classify_cat_lifecycle_response(&response) {
        CatLifecycleResponseClassification::Accepted(accepted) => {
            let operation_id = accepted.operation_id.to_string();
            if cli.no_wait {
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&accepted)?);
                } else {
                    println!("operation {operation_id} accepted");
                }
                std::io::stdout()
                    .flush()
                    .context("flush accepted Operation identity before cleanup")?;
            }
            pending.clear().with_context(|| {
                format!(
                    "Cat {} was accepted as operation {operation_id}, but its pending recovery state could not be durably cleared",
                    action.as_str()
                )
            })?;
            if cli.no_wait {
                return Ok(());
            }
            let operation = client.wait_runtime_operation(&operation_id)?;
            print_runtime_operation_terminal(&operation, cli.json)
        }
        CatLifecycleResponseClassification::DefinitiveError(error) => {
            pending.clear().context(
                "the Cat-lifecycle rejection is definitive, but its pending recovery state could not be durably cleared",
            )?;
            bail!("{} ({:?})", error.message, error.code)
        }
        CatLifecycleResponseClassification::Nonterminal => {
            let detail = serde_json::from_slice::<cats_api::error::ErrorBody>(&response.body)
                .map(|error| format!("{} ({:?})", error.message, error.code))
                .unwrap_or_else(|_| {
                    format!(
                        "HTTP {}: {}",
                        response.status,
                        String::from_utf8_lossy(&response.body)
                    )
                });
            bail!(
                "Cat-lifecycle response was not an exact terminal result ({detail}); replay the same command to reuse the pending Idempotency-Key at {}",
                pending.pending_path().display()
            )
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
enum PersistentDiskCreateResponseClassification {
    Created(Disk),
    NameConflict,
    Nonterminal,
}

#[cfg(test)]
#[allow(dead_code)]
enum PersistentDiskBindingResponseClassification {
    Committed(PersistentDiskBindingV2CommittedResponse),
    NotFound,
    Conflict,
    FailedPrecondition,
    Nonterminal,
}

#[cfg(test)]
fn persistent_disk_binding_response_matches_target(
    response: &PersistentDiskBindingV2CommittedResponse,
    disk_id: &str,
    cat_id: &str,
) -> bool {
    response.disk_id.as_str() == disk_id && response.cat_id.as_str() == cat_id
}

#[cfg(test)]
fn classify_persistent_disk_binding_response(
    response: &ExactCreateHttpResponse,
) -> PersistentDiskBindingResponseClassification {
    let exact_json_identity = response.content_types.as_slice() == [b"application/json"]
        && response.content_encodings.is_empty();
    if !exact_json_identity {
        return PersistentDiskBindingResponseClassification::Nonterminal;
    }
    if response.status == reqwest::StatusCode::OK {
        if let Ok(committed) = decode_persistent_disk_binding_v2_committed_response(&response.body)
        {
            if serde_json::to_vec(&committed).ok().as_deref() == Some(response.body.as_slice()) {
                return PersistentDiskBindingResponseClassification::Committed(committed);
            }
        }
    } else if response.status == reqwest::StatusCode::NOT_FOUND
        && response.body == PERSISTENT_DISK_BINDING_NOT_FOUND_BODY
    {
        return PersistentDiskBindingResponseClassification::NotFound;
    } else if response.status == reqwest::StatusCode::CONFLICT
        && response.body == PERSISTENT_DISK_BINDING_CONFLICT_BODY
    {
        return PersistentDiskBindingResponseClassification::Conflict;
    } else if response.status == reqwest::StatusCode::PRECONDITION_FAILED
        && response.body == PERSISTENT_DISK_BINDING_PRECONDITION_BODY
    {
        return PersistentDiskBindingResponseClassification::FailedPrecondition;
    }
    PersistentDiskBindingResponseClassification::Nonterminal
}

#[cfg(test)]
fn classify_persistent_disk_create_response(
    response: &ExactCreateHttpResponse,
    pending: &cat_create_pending::PreparedPersistentDiskCreate,
) -> Result<PersistentDiskCreateResponseClassification> {
    let exact_json_identity = response.content_types.as_slice() == [b"application/json"]
        && response.content_encodings.is_empty();
    if !exact_json_identity {
        return Ok(PersistentDiskCreateResponseClassification::Nonterminal);
    }
    if response.status == reqwest::StatusCode::CREATED {
        let Ok(disk) = serde_json::from_slice::<Disk>(&response.body) else {
            return Ok(PersistentDiskCreateResponseClassification::Nonterminal);
        };
        if serde_json::to_vec(&disk).ok().as_deref() != Some(response.body.as_slice()) {
            return Ok(PersistentDiskCreateResponseClassification::Nonterminal);
        }
        let request = pending.request()?;
        let exact = disk.workspace_id == pending.workspace_id()
            && disk.name == request.name.as_str()
            && disk.kind == DiskKind::Persistent
            && disk.size_bytes == request.size_bytes
            && disk.state == DiskState::Available
            && disk.durability == request.durability
            && disk.bound_cat_id.is_none()
            && disk.created_at_unix >= 0
            && exact_product_identity(&disk.id, "disk_")
            && exact_product_identity(&disk.volume_id, "vol_");
        if exact {
            return Ok(PersistentDiskCreateResponseClassification::Created(disk));
        }
    } else if response.status == reqwest::StatusCode::CONFLICT
        && response.body == PERSISTENT_DISK_NAME_CONFLICT_BODY
    {
        return Ok(PersistentDiskCreateResponseClassification::NameConflict);
    }
    Ok(PersistentDiskCreateResponseClassification::Nonterminal)
}

#[cfg(test)]
fn exact_product_identity(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|random| {
        random.len() == 32
            && random
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::runtime_product_reads::CatOperationAction;

    const TEST_BOOT_IMAGE: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn size_parsing() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("8GiB").unwrap(), 8 << 30);
        assert_eq!(parse_size("512MiB").unwrap(), 512 << 20);
        assert_eq!(parse_size("4KiB").unwrap(), 4096);
        assert!(parse_size("abc").is_err());
        assert_eq!(parse_gib_size("100GiB").unwrap(), 100 << 30);
        for invalid in ["0GiB", "1GB", "1.5GiB", "GiB", " 1GiB"] {
            assert!(parse_gib_size(invalid).is_err(), "accepted {invalid:?}");
        }
        assert_eq!(
            parse_mount("data-disk:/srv/data").unwrap(),
            CatMountRequest {
                disk_slug: ResourceSlug::new("data-disk").unwrap(),
                mount_path: PersistentMountPath::new("/srv/data").unwrap(),
            }
        );
        for invalid in ["data", "DATA:/data", "data:relative", "data:/proc"] {
            assert!(parse_mount(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn cli_parses_typical_commands() {
        use clap::Parser;
        assert!(matches!(
            Cli::parse_from(["cats", "login"]).command,
            Command::Login
        ));
        let workspace = Cli::parse_from(["cats", "workspace", "use", "acme-dev"]);
        assert!(matches!(
            workspace.command,
            Command::Workspace {
                cmd: WorkspaceCommand::Use { .. }
            }
        ));
        let override_workspace = Cli::parse_from(["cats", "--workspace", "other", "ls"]);
        assert_eq!(override_workspace.workspace.as_deref(), Some("other"));
        let cli = Cli::parse_from([
            "cats",
            "create",
            "dev",
            "--boot-image",
            "ubuntu-24.04",
            "--cpu",
            "4",
            "--memory",
            "8GiB",
            "--mount",
            "data:/data",
        ]);
        match cli.command {
            Command::Create {
                name,
                cpus,
                boot_image_digest,
                ..
            } => {
                assert_eq!(name, "dev");
                assert_eq!(cpus, 4);
                assert_eq!(boot_image_digest, "ubuntu-24.04");
            }
            _ => panic!("wrong parse"),
        }
        assert!(Cli::try_parse_from(["cats", "create", "x"]).is_ok());
        assert!(Cli::try_parse_from([
            "cats",
            "create",
            "x",
            "--boot-image",
            TEST_BOOT_IMAGE,
            "--disk",
            "legacy",
        ])
        .is_err());
        for action in ["run", "suspend", "warm", "cold", "destroy"] {
            let parsed = Cli::try_parse_from(["cats", action, "cat_01"])
                .unwrap_or_else(|error| panic!("{action} did not parse: {error}"));
            let parsed_id = match parsed.command {
                Command::Run { cat_id }
                | Command::Suspend { cat_id }
                | Command::Warm { cat_id }
                | Command::Cold { cat_id }
                | Command::Destroy { cat_id } => cat_id,
                other => panic!("{action} parsed as {other:?}"),
            };
            assert_eq!(parsed_id, "cat_01");
        }
        for retired in ["start", "stop", "delete", "resume"] {
            assert!(Cli::try_parse_from(["cats", retired, "cat_01"]).is_err());
        }
        let deploy = Cli::parse_from([
            "cats",
            "deploy",
            "preview",
            "server",
            "--image",
            "ghcr.io/paperboy/server@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--",
            "/app/server",
        ]);
        match deploy.command {
            Command::Deploy {
                name,
                app,
                command,
                registry_password_stdin,
                ..
            } => {
                assert_eq!(name, "preview");
                assert_eq!(app, "server");
                assert_eq!(command, vec!["/app/server"]);
                assert!(!registry_password_stdin);
            }
            other => panic!("expected deploy, got {other:?}"),
        }
        let cli = Cli::parse_from([
            "cats",
            "disk",
            "attach",
            "data",
            "--cat",
            "app",
            "--mount",
            "/srv/data",
        ]);
        assert!(matches!(
            cli.command,
            Command::Disk {
                cmd: DiskCommand::Attach {
                    disk,
                    cat,
                    mount_path,
                }
            } if disk == "data" && cat == "app" && mount_path == "/srv/data"
        ));
        let cli = Cli::parse_from(["cats", "disk", "detach", "data", "--cat", "app"]);
        assert!(matches!(
            cli.command,
            Command::Disk {
                cmd: DiskCommand::Detach { .. }
            }
        ));
        assert!(Cli::try_parse_from(["cats", "disk", "destroy", "data"]).is_ok());
        let cli = Cli::parse_from([
            "cats",
            "admin",
            "runtime-node",
            "provision",
            "--identity",
            "identity.json",
            "--policy",
            "policy.json",
        ]);
        assert!(matches!(
            cli.command,
            Command::Admin {
                cmd: AdminCommand::RuntimeNode {
                    cmd: RuntimeNodeCommand::Provision { .. },
                    ..
                }
            }
        ));
        let cli = Cli::parse_from([
            "cats",
            "admin",
            "runtime-node",
            "policy",
            "apply",
            "--node",
            "node_a",
            "--expected-revision",
            "1",
            "--file",
            "policy.json",
        ]);
        assert!(matches!(
            cli.command,
            Command::Admin {
                cmd: AdminCommand::RuntimeNode {
                    cmd: RuntimeNodeCommand::Policy {
                        cmd: RuntimeNodePolicyCommand::Apply { .. }
                    },
                    ..
                }
            }
        ));
        let writer = Cli::parse_from([
            "cats",
            "admin",
            "runtime-node",
            "object-write-authority",
            "provision",
            "--node",
            "node_a",
            "--expected-revision",
            "1",
            "--object-provider",
            "aws",
            "--object-partition",
            "aws",
            "--object-account-id",
            "123456789012",
            "--object-region",
            "us-east-1",
            "--workload-principal-id",
            "arn:aws:iam::123456789012:role/cats-gateway",
            "--object-store-scope-id",
            "arn:aws:s3:::cats-production/chunks",
        ]);
        let Command::Admin {
            cmd:
                AdminCommand::RuntimeNode {
                    cmd:
                        RuntimeNodeCommand::ObjectWriteAuthority {
                            cmd:
                                RuntimeNodeObjectWriteAuthorityCommand::Provision {
                                    expected_revision,
                                    binding,
                                },
                        },
                    ..
                },
        } = writer.command
        else {
            panic!("writer authority provision must parse")
        };
        assert_eq!(expected_revision, 1);
        assert_eq!(binding.node, "node_a");
        assert_eq!(binding.object_region, "us-east-1");
        assert_eq!(
            binding.object_store_scope_id,
            "arn:aws:s3:::cats-production/chunks"
        );
        // The Host side of the binding is never an operator argument.
        assert!(Cli::try_parse_from([
            "cats",
            "admin",
            "runtime-node",
            "object-write-authority",
            "provision",
            "--node",
            "node_a",
            "--expected-revision",
            "1",
            "--immutable-host-id",
            "i-0123456789abcdef0",
        ])
        .is_err());
        assert!(matches!(
            Cli::parse_from([
                "cats",
                "admin",
                "runtime-node",
                "object-write-authority",
                "id",
                "--node",
                "node_a",
                "--object-provider",
                "aws",
                "--object-partition",
                "aws",
                "--object-account-id",
                "123456789012",
                "--object-region",
                "us-east-1",
                "--workload-principal-id",
                "arn:aws:iam::123456789012:role/cats-gateway",
                "--object-store-scope-id",
                "arn:aws:s3:::cats-production/chunks",
            ])
            .command,
            Command::Admin {
                cmd: AdminCommand::RuntimeNode {
                    cmd: RuntimeNodeCommand::ObjectWriteAuthority {
                        cmd: RuntimeNodeObjectWriteAuthorityCommand::Id { .. }
                    },
                    ..
                }
            }
        ));
        assert!(matches!(
            Cli::parse_from(["cats", "admin", "login"]).command,
            Command::Admin {
                cmd: AdminCommand::Login
            }
        ));
        assert!(matches!(
            Cli::parse_from(["cats", "admin", "logout"]).command,
            Command::Admin {
                cmd: AdminCommand::Logout
            }
        ));
        let machine = Cli::parse_from([
            "cats",
            "admin",
            "runtime-node",
            "provision",
            "--identity",
            "identity.json",
            "--policy",
            "policy.json",
            "--deployment-id",
            "deployment_a",
            "--provisioner-credential-id",
            "provisioner_a",
            "--provisioner-private-key-file",
            "provisioner.pem",
        ]);
        assert!(matches!(
            machine.command,
            Command::Admin {
                cmd: AdminCommand::RuntimeNode {
                    deployment_id: Some(_),
                    provisioner_credential_id: Some(_),
                    provisioner_private_key_file: Some(_),
                    ..
                }
            }
        ));
        assert!(Cli::try_parse_from([
            "cats",
            "admin",
            "runtime-node",
            "--deployment-id",
            "deployment_a",
            "provision",
            "--identity",
            "identity.json",
            "--policy",
            "policy.json",
        ])
        .is_err());
    }

    #[test]
    fn cli_exposes_the_closed_route_v2_revision_one_credential_workflow() {
        use clap::Parser;

        assert!(Cli::try_parse_from([
            "cats",
            "admin",
            "runtime-provisioner",
            "route-v2-r1",
            "generate",
            "--output",
            "/approved/route-v2-r1",
            "--node-server-dns",
            "metal-1.internal",
            "--control-secret-name",
            "cats-route-v2-control-r1",
            "--gateway-secret-name",
            "cats-route-v2-gateway-r1",
            "--node-secret-name",
            "cats-production-route-v2-node-r1",
            "--release-commit-sha",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--openssl",
            "/usr/bin/openssl",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "cats",
            "admin",
            "runtime-provisioner",
            "route-v2-r1",
            "sign-command",
            "--input",
            "/approved/route-v2-r1",
            "--payload",
            "/approved/command-payload.json",
            "--output",
            "/approved/signed-command.json",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "cats",
            "admin",
            "runtime-provisioner",
            "route-v2-r1",
            "prepare-rotation-recovery",
            "--input",
            "/approved/route-v2-r1",
            "--output",
            "/approved/route-v2-recovery",
            "--run-id",
            "qualification_run_a",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "cats",
            "admin",
            "runtime-provisioner",
            "route-v2-r1",
            "sign-rotation-recovery-phase",
            "--input",
            "/approved/route-v2-r1",
            "--recovery",
            "/approved/route-v2-recovery",
            "--phase",
            "disable",
            "--output",
            "/approved/pending/disable.command.json",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "cats",
            "admin",
            "runtime-provisioner",
            "route-v2-r1",
            "verify-rotation-current",
            "--input",
            "/approved/route-v2-r1",
            "--recovery",
            "/approved/route-v2-recovery",
            "--signer-revision",
            "8",
            "--discovery",
            "/approved/current-r8.json",
            "--output",
            "/approved/current-r8.receipt.json",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "cats",
            "admin",
            "runtime-provisioner",
            "route-v2-r1",
            "sign-prepared-rotation-phase",
            "--trust",
            "/etc/cats/route-v2/rotation-operator-trust.v1.json",
            "--operator-private-key",
            "/approved/rotation-operator-private-key.pem",
            "--command-bundle",
            "/approved/rotation-recovery-command-bundle.v1.json",
            "--phase",
            "disable",
            "--output",
            "/approved/pending/disable.command.json",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "cats",
            "admin",
            "runtime-provisioner",
            "route-v2-r1",
            "verify-prepared-rotation-current",
            "--trust",
            "/etc/cats/route-v2/rotation-operator-trust.v1.json",
            "--command-bundle",
            "/approved/rotation-recovery-command-bundle.v1.json",
            "--signer-revision",
            "8",
            "--discovery",
            "/approved/current-r8.json",
            "--output",
            "/approved/current-r8.receipt.json",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "cats",
            "admin",
            "runtime-provisioner",
            "route-v2-r1",
            "sign-control-rollout-apply-receipt",
            "--trust",
            "/etc/cats/route-v2/rotation-operator-trust.v1.json",
            "--operator-private-key",
            "/approved/operator-a.pem",
            "--operator-private-key",
            "/approved/operator-b.pem",
            "--payload",
            "/approved/apply/publish_overlap.payload.json",
            "--output",
            "/approved/apply/publish_overlap.signed.json",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "cats",
            "admin",
            "runtime-provisioner",
            "route-v2-r1",
            "verify-control-rollout-apply-receipt",
            "--trust",
            "/etc/cats/route-v2/rotation-operator-trust.v1.json",
            "--command-bundle",
            "/approved/rotation-recovery-command-bundle.v1.json",
            "--phase",
            "publish_overlap",
            "--qualification-catalog-sha256",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--saved-plan-sha256",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--receipt",
            "/approved/inbox/publish_overlap.signed.json",
            "--output",
            "/approved/verified/publish_overlap.receipt.json",
        ])
        .is_ok());
    }

    fn read_request(stream: &mut std::net::TcpStream) -> (String, Vec<u8>) {
        use std::io::Read;

        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        let header_end = loop {
            let mut chunk = [0_u8; 1024];
            let count = stream.read(&mut chunk).unwrap();
            assert_ne!(count, 0, "request ended before its headers");
            bytes.extend_from_slice(&chunk[..count]);
            if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        while bytes.len() - header_end < content_length {
            let mut chunk = [0_u8; 1024];
            let count = stream.read(&mut chunk).unwrap();
            assert_ne!(count, 0, "request ended before its body");
            bytes.extend_from_slice(&chunk[..count]);
        }
        (
            headers,
            bytes[header_end..header_end + content_length].to_vec(),
        )
    }

    fn request_header(headers: &str, expected_name: &str) -> String {
        headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case(expected_name)
                    .then(|| value.trim().to_owned())
            })
            .unwrap_or_else(|| panic!("missing request header {expected_name}"))
    }

    fn product_operation(state: ProductOperationState) -> ProductOperation {
        use cats_api::runtime_reconciliation::{ContractVersion, UnixMillis};

        ProductOperation {
            version: ContractVersion::V1,
            operation_id: RuntimeId::new("op_01").unwrap(),
            workspace_id: RuntimeId::new("ws_01").unwrap(),
            cat_id: RuntimeId::new("cat_01").unwrap(),
            action: CatOperationAction::Run,
            state,
            created_at_unix_ms: UnixMillis::new(1).unwrap(),
            terminal_at_unix_ms: (state != ProductOperationState::InProgress)
                .then(|| UnixMillis::new(2).unwrap()),
        }
    }

    fn pending_runtime_operation() -> ProductOperation {
        product_operation(ProductOperationState::InProgress)
    }

    fn succeeded_runtime_operation() -> ProductOperation {
        product_operation(ProductOperationState::Succeeded)
    }

    fn failed_runtime_operation() -> ProductOperation {
        product_operation(ProductOperationState::Failed)
    }

    fn runtime_test_client(base: String) -> Client {
        Client {
            http: reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_gzip()
                .no_brotli()
                .no_deflate()
                .no_zstd()
                .build()
                .unwrap(),
            base,
            token: "test-token".to_owned(),
            workspace_id: "ws_01".to_owned(),
        }
    }

    fn write_runtime_operation_response(
        stream: &mut std::net::TcpStream,
        body: &[u8],
        content_encoding: Option<&str>,
    ) {
        use std::io::Write as _;

        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n"
        )
        .unwrap();
        if let Some(content_encoding) = content_encoding {
            write!(stream, "Content-Encoding: {content_encoding}\r\n").unwrap();
        }
        write!(
            stream,
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
        stream.flush().unwrap();
    }

    #[test]
    fn runtime_operation_get_uses_workspace_path_and_strict_canonical_decoder() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let expected = pending_runtime_operation();
        let body = encode_product_operation(&expected).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let (headers, request_body) = read_request(&mut stream);
            assert!(request_body.is_empty());
            assert_eq!(
                headers.lines().next().unwrap(),
                "GET /v1/workspaces/ws_01/operations/op_01 HTTP/1.1"
            );
            assert_eq!(
                request_header(&headers, "authorization"),
                "Bearer test-token"
            );
            assert_eq!(request_header(&headers, "accept"), "application/json");
            assert_eq!(request_header(&headers, "accept-encoding"), "identity");
            write_runtime_operation_response(&mut stream, &body, None);
        });

        let operation = runtime_test_client(base)
            .get_runtime_operation("op_01")
            .unwrap();
        assert_eq!(operation, expected);
        server.join().unwrap();
    }

    #[test]
    fn accepted_oci_deploy_polls_its_workspace_scoped_attempt() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let body = br#"{"version":1,"attempt_id":"oci_attempt_01","state":"succeeded","deployment":{"app":"web","image_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","manifest_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","service":"web.service","active":true}}"#;
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let (headers, request_body) = read_request(&mut stream);
            assert!(request_body.is_empty());
            assert_eq!(
                headers.lines().next().unwrap(),
                "GET /v1/workspaces/ws_01/cats/cat_01/oci-deployment-attempts/oci_attempt_01 HTTP/1.1"
            );
            assert_eq!(
                request_header(&headers, "authorization"),
                "Bearer test-token"
            );
            write_runtime_operation_response(&mut stream, body, None);
        });

        let deployment =
            follow_oci_deployment(&runtime_test_client(base), "oci_attempt_01", "cat_01").unwrap();
        assert_eq!(deployment.app, "web");
        assert_eq!(deployment.service, "web.service");
        server.join().unwrap();
    }

    #[test]
    fn disk_ls_json_is_one_parseable_document_after_two_pages() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            for (expected_path, body) in [
                (
                    "GET /v1/workspaces/ws_01/disks?limit=100 HTTP/1.1",
                    br#"{"items":[{"version":1,"id":"disk_01","workspace_id":"ws_01","name":"one","size_bytes":1048576,"durability":"strict","created_at_unix_ms":1,"kind":{"kind":"persistent"},"admin_state":"active","binding":null}],"next_cursor":"cursor_01"}"#.as_slice(),
                ),
                (
                    "GET /v1/workspaces/ws_01/disks?limit=100&cursor=cursor_01 HTTP/1.1",
                    br#"{"items":[{"version":1,"id":"disk_02","workspace_id":"ws_01","name":"two","size_bytes":2097152,"durability":"relaxed","created_at_unix_ms":2,"kind":{"kind":"persistent"},"admin_state":"deleting","binding":null}],"next_cursor":null}"#.as_slice(),
                ),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let (headers, request_body) = read_request(&mut stream);
                assert!(request_body.is_empty());
                assert_eq!(headers.lines().next().unwrap(), expected_path);
                assert_eq!(
                    request_header(&headers, "authorization"),
                    "Bearer test-token"
                );
                write_runtime_operation_response(&mut stream, body, None);
            }
        });

        let items: Vec<DiskReadV2> = runtime_test_client(base)
            .get_all_product_pages("/disks")
            .unwrap();
        assert_eq!(items.len(), 2);
        let document = runtime_disk_list_json(&items).unwrap();
        let reparsed: Vec<DiskReadV2> = serde_json::from_str(&document).unwrap();
        assert_eq!(reparsed, items);
        server.join().unwrap();
    }

    #[test]
    fn product_item_keys_are_resource_typed_immutable_ids() {
        assert_eq!(
            runtime_product_item_id("cat_01", "cat_", "Cat").unwrap(),
            "cat_01"
        );
        assert!(runtime_product_item_id("demo", "cat_", "Cat").is_err());
        assert!(runtime_product_item_id("disk_01", "cat_", "Cat").is_err());
        assert!(runtime_product_item_id("cat_01/operations", "cat_", "Cat").is_err());
    }

    #[test]
    fn runtime_operation_get_rejects_encoded_response_without_auto_decompression() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let body = encode_product_operation(&pending_runtime_operation()).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let (headers, _) = read_request(&mut stream);
            assert_eq!(request_header(&headers, "accept-encoding"), "identity");
            write_runtime_operation_response(&mut stream, &body, Some("gzip"));
        });

        let error = runtime_test_client(base)
            .get_runtime_operation("op_01")
            .unwrap_err();
        assert!(error.to_string().contains("must not have Content-Encoding"));
        server.join().unwrap();
    }

    #[test]
    fn runtime_operation_wait_polls_pending_until_succeeded() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let pending = encode_product_operation(&pending_runtime_operation()).unwrap();
        let succeeded = succeeded_runtime_operation();
        let succeeded_body = encode_product_operation(&succeeded).unwrap();
        let server = std::thread::spawn(move || {
            for body in [&pending, &succeeded_body] {
                let (mut stream, _) = listener.accept().unwrap();
                let (headers, _) = read_request(&mut stream);
                assert_eq!(
                    headers.lines().next().unwrap(),
                    "GET /v1/workspaces/ws_01/operations/op_01 HTTP/1.1"
                );
                write_runtime_operation_response(&mut stream, body, None);
            }
        });

        let operation = runtime_test_client(base)
            .wait_runtime_operation("op_01")
            .unwrap();
        assert_eq!(operation, succeeded);
        server.join().unwrap();
    }

    #[test]
    fn runtime_operation_wait_bounds_slow_second_response_by_absolute_deadline() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let pending = encode_product_operation(&pending_runtime_operation()).unwrap();
        let (second_request_tx, second_request_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            let _ = read_request(&mut first);
            write_runtime_operation_response(&mut first, &pending, None);

            let (mut second, _) = listener.accept().unwrap();
            let _ = read_request(&mut second);
            second_request_tx.send(()).unwrap();
            // Keep the response open longer than the client's total wait
            // budget. The test releases this promptly once the bounded wait
            // returns; an unbounded second GET instead stalls here.
            let _ = release_rx.recv_timeout(cats_test_support::poll_bound());
        });

        let started = Instant::now();
        let error = runtime_test_client(base)
            .wait_runtime_operation_for("op_01", Duration::from_millis(400))
            .unwrap_err();
        let elapsed = started.elapsed();
        let _ = release_tx.send(());

        assert!(
            second_request_rx
                .recv_timeout(cats_test_support::poll_bound())
                .is_ok(),
            "wait did not issue the expected second GET"
        );
        assert!(
            error.to_string().contains("did not finish in time"),
            "unexpected timeout error: {error}"
        );
        assert!(
            elapsed < Duration::from_millis(1_500),
            "wait exceeded its absolute deadline by too much: {elapsed:?}"
        );
        server.join().unwrap();
    }

    #[test]
    fn runtime_operation_wait_reports_closed_product_failure() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let body = encode_product_operation(&failed_runtime_operation()).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_request(&mut stream);
            write_runtime_operation_response(&mut stream, &body, None);
        });

        let error = runtime_test_client(base)
            .wait_runtime_operation("op_01")
            .unwrap_err();
        assert_eq!(error.to_string(), "run operation op_01 failed");
        server.join().unwrap();
    }

    #[test]
    fn semantic_create_sends_slug_mounts_and_no_idempotency_key() {
        use clap::Parser;
        use std::io::Write;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let captured = read_request(&mut stream);
            let response = br#"{"status":"ok","code":"cat_created","cat":{"cat_id":"cat_01","workspace_id":"ws_01","cat_slug":"app","state":"running","current_action":null,"node_id":"node_01","node_name":"worker-a","cpu":3,"memory_bytes":2147483648,"boot_image":"ubuntu-24.04","mounts":[],"last_error":null,"created_at_unix_ms":1,"updated_at_unix_ms":2,"destroyed_at_unix_ms":null}}"#;
            write!(
                stream,
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .unwrap();
            stream.write_all(response).unwrap();
            stream.flush().unwrap();
            drop(stream);
            listener.set_nonblocking(true).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            assert!(matches!(
                listener.accept(),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
            ));
            captured
        });
        let base = format!("http://{address}");
        let cli = Cli::parse_from([
            "cats",
            "--api-url",
            &base,
            "--token",
            "test-token",
            "--workspace",
            "ws_01",
            "create",
            "app",
            "--boot-image",
            "ubuntu-24.04",
            "--cpu",
            "3",
            "--memory",
            "2GiB",
            "--mount",
            "data:/srv/data",
            "--mount",
            "logs:/srv/logs",
        ]);
        run(cli).unwrap();
        let (headers, body) = server.join().unwrap();
        assert!(headers.starts_with("POST /v1/workspaces/ws_01/cats HTTP/1.1\r\n"));
        assert!(headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case("content-type: application/json")));
        assert!(!headers
            .lines()
            .any(|line| line.to_ascii_lowercase().starts_with("idempotency-key:")));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            json!({
                "cat_slug": "app",
                "cpu": 3,
                "memory_bytes": 2_147_483_648_u64,
                "boot_image": "ubuntu-24.04",
                "mounts": [
                    {"disk_slug": "data", "mount_path": "/srv/data"},
                    {"disk_slug": "logs", "mount_path": "/srv/logs"},
                ],
            })
        );
    }

    #[test]
    fn every_semantic_lifecycle_command_sends_one_sync_empty_body_request() {
        use clap::Parser as _;
        use std::io::Write as _;

        for action in ["run", "suspend", "warm", "cold", "destroy"] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let captured = read_request(&mut stream);
                let response = br#"{"status":"ok","code":"cat_running","cat":{"cat_id":"cat_01","workspace_id":"ws_01","cat_slug":"app","state":"running","current_action":null,"node_id":"node_01","node_name":"worker-a","cpu":2,"memory_bytes":2147483648,"boot_image":"ubuntu-24.04","mounts":[],"last_error":null,"created_at_unix_ms":1,"updated_at_unix_ms":2,"destroyed_at_unix_ms":null}}"#;
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                )
                .unwrap();
                stream.write_all(response).unwrap();
                stream.flush().unwrap();
                captured
            });
            let base = format!("http://{address}");
            run(Cli::parse_from([
                "cats",
                "--api-url",
                &base,
                "--token",
                "test-token",
                "--workspace",
                "ws_01",
                action,
                "app",
            ]))
            .unwrap();
            let (headers, body) = server.join().unwrap();
            assert_eq!(
                headers.lines().next().unwrap(),
                format!("POST /v1/workspaces/ws_01/cats/app/actions/{action} HTTP/1.1")
            );
            assert_eq!(
                request_header(&headers, "authorization"),
                "Bearer test-token"
            );
            assert_eq!(request_header(&headers, "accept"), "application/json");
            assert!(!headers
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("idempotency-key:")));
            assert!(
                !headers
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("content-type:")),
                "{action} incorrectly sent Content-Type: {headers}"
            );
            assert!(body.is_empty());
        }
    }

    #[test]
    fn semantic_disk_create_sends_exact_gib_bytes_without_idempotency_key() {
        use clap::Parser as _;
        use std::io::Write as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let captured = read_request(&mut stream);
            let response = br#"{"status":"ok","code":"disk_created","disk":{"disk_id":"disk_01","workspace_id":"ws_01","disk_slug":"data","size_bytes":107374182400,"status":"normal","binding":null,"created_at_unix_ms":1,"deleted_at_unix_ms":null}}"#;
            write!(
                stream,
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .unwrap();
            stream.write_all(response).unwrap();
            stream.flush().unwrap();
            captured
        });
        let base = format!("http://{address}");
        let cli = Cli::parse_from([
            "cats",
            "--api-url",
            &base,
            "--token",
            "test-token",
            "--workspace",
            "ws_01",
            "disk",
            "create",
            "data",
            "--size",
            "100GiB",
        ]);
        run(cli).unwrap();
        let (headers, body) = server.join().unwrap();
        assert!(headers.starts_with("POST /v1/workspaces/ws_01/disks HTTP/1.1\r\n"));
        assert_eq!(request_header(&headers, "content-type"), "application/json");
        assert!(!headers
            .lines()
            .any(|line| line.to_ascii_lowercase().starts_with("idempotency-key:")));
        assert_eq!(body, br#"{"disk_slug":"data","size_bytes":107374182400}"#);
    }

    #[test]
    fn semantic_disk_binding_sends_slug_requests() {
        use clap::Parser as _;
        use std::io::Write as _;

        for (verb, expected_body) in [
            (
                "attach",
                br#"{"cat_slug":"app","mount_path":"/srv/data"}"#.as_slice(),
            ),
            ("detach", br#"{"cat_slug":"app"}"#.as_slice()),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let captured = read_request(&mut stream);
                let response = br#"{"status":"ok","code":"disk_attached","disk":{"disk_id":"disk_01","workspace_id":"ws_01","disk_slug":"data","size_bytes":1073741824,"status":"normal","binding":null,"created_at_unix_ms":1,"deleted_at_unix_ms":null}}"#;
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                )
                .unwrap();
                stream.write_all(response).unwrap();
                stream.flush().unwrap();
                captured
            });
            let base = format!("http://{address}");
            let mut args = vec![
                "cats",
                "--api-url",
                &base,
                "--token",
                "test-token",
                "--workspace",
                "ws_01",
                "disk",
                verb,
                "data",
                "--cat",
                "app",
            ];
            if verb == "attach" {
                args.extend(["--mount", "/srv/data"]);
            }
            let cli = Cli::parse_from(args);
            run(cli).unwrap();
            let (headers, body) = server.join().unwrap();
            assert_eq!(
                headers.lines().next().unwrap(),
                format!("POST /v1/workspaces/ws_01/disks/data/actions/{verb} HTTP/1.1")
            );
            assert_eq!(request_header(&headers, "content-type"), "application/json");
            assert!(!headers
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("idempotency-key:")));
            assert_eq!(body, expected_body);
        }
    }

    #[test]
    fn semantic_disk_destroy_sends_empty_request_without_idempotency_key() {
        use clap::Parser as _;
        use std::io::Write as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let captured = read_request(&mut stream);
            let response = br#"{"status":"ok","code":"disk_deleted","disk":{"disk_id":"disk_01","workspace_id":"ws_01","disk_slug":"data","size_bytes":1073741824,"status":"deleted","binding":null,"created_at_unix_ms":1,"deleted_at_unix_ms":2}}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .unwrap();
            stream.write_all(response).unwrap();
            stream.flush().unwrap();
            captured
        });
        let base = format!("http://{address}");
        run(Cli::parse_from([
            "cats",
            "--api-url",
            &base,
            "--token",
            "test-token",
            "--workspace",
            "ws_01",
            "disk",
            "destroy",
            "data",
        ]))
        .unwrap();
        let (headers, body) = server.join().unwrap();
        assert_eq!(
            headers.lines().next().unwrap(),
            "POST /v1/workspaces/ws_01/disks/data/actions/destroy HTTP/1.1"
        );
        assert!(body.is_empty());
        assert!(!headers
            .lines()
            .any(|line| line.to_ascii_lowercase().starts_with("idempotency-key:")));
    }

    #[cfg(unix)]
    #[test]
    fn cat_create_restart_process_helper() {
        use clap::Parser as _;

        let Some(mode) = std::env::var_os("CATS_TEST_CAT_CREATE_HELPER_MODE") else {
            return;
        };
        let base = std::env::var("CATS_TEST_CAT_CREATE_HELPER_BASE").unwrap();
        let cli = Cli::parse_from([
            "cats",
            "--api-url",
            &base,
            "--token",
            "test-token",
            "--workspace",
            "ws_01",
            "create",
            "app",
            "--boot-image-digest",
            TEST_BOOT_IMAGE,
            "--cpus",
            "3",
            "--memory",
            "2GiB",
            "--root-size",
            "4GiB",
            "--durability",
            "relaxed",
        ]);
        match mode.to_string_lossy().as_ref() {
            "lost" => {
                let error = run(cli).expect_err("the committed response is deliberately dropped");
                assert!(error.to_string().contains("ambiguous"), "{error:#}");
            }
            "replay" => run(cli).unwrap(),
            unexpected => panic!("unexpected helper mode {unexpected}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn persistent_disk_create_restart_process_helper() {
        use clap::Parser as _;

        let Some(mode) = std::env::var_os("CATS_TEST_PERSISTENT_DISK_CREATE_HELPER_MODE") else {
            return;
        };
        let base = std::env::var("CATS_TEST_PERSISTENT_DISK_CREATE_HELPER_BASE").unwrap();
        let cli = Cli::parse_from([
            "cats",
            "--api-url",
            &base,
            "--token",
            "test-token",
            "--workspace",
            "ws_01",
            "disk",
            "create",
            "data",
            "--size",
            "1GiB",
            "--durability",
            "strict",
        ]);
        match mode.to_string_lossy().as_ref() {
            "lost" => {
                let error = run(cli).expect_err("the committed response is deliberately dropped");
                assert!(error.to_string().contains("ambiguous"), "{error:#}");
            }
            "replay" => run(cli).unwrap(),
            unexpected => panic!("unexpected helper mode {unexpected}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn persistent_disk_binding_restart_process_helper() {
        use clap::Parser as _;

        let Some(mode) = std::env::var_os("CATS_TEST_PERSISTENT_DISK_BINDING_HELPER_MODE") else {
            return;
        };
        let base = std::env::var("CATS_TEST_PERSISTENT_DISK_BINDING_HELPER_BASE").unwrap();
        let cli = Cli::parse_from([
            "cats",
            "--api-url",
            &base,
            "--token",
            "test-token",
            "--workspace",
            "ws_01",
            "disk",
            "attach",
            "disk_01",
            "--cat",
            "cat_01",
            "--mount-path",
            "/srv/data",
        ]);
        match mode.to_string_lossy().as_ref() {
            "lost" => {
                let error = run(cli).expect_err("the committed response is deliberately dropped");
                assert!(error.to_string().contains("ambiguous"), "{error:#}");
            }
            "replay" => run(cli).unwrap(),
            unexpected => panic!("unexpected helper mode {unexpected}"),
        }
    }

    #[cfg(unix)]
    #[cfg(any())]
    #[test]
    fn committed_response_loss_process_restart_replays_one_cat_and_operation_exactly() {
        use std::collections::{HashMap, HashSet};
        use std::io::Write as _;
        use std::process::Command as ProcessCommand;

        let state_directory = tempfile::tempdir().unwrap();
        let state_root = state_directory.path().canonicalize().unwrap().join("state");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server_state_root = state_root.clone();
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            let mut cats = HashSet::new();
            let mut operations = HashMap::new();
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let (headers, body) = read_request(&mut stream);
                assert!(std::fs::read_dir(&server_state_root).unwrap().any(|entry| {
                    entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .ends_with(".pending.json")
                }));
                let first_line = headers.lines().next().unwrap().to_owned();
                let key = request_header(&headers, "Idempotency-Key");
                requests.push((first_line, body.clone(), key.clone()));
                let response = operations.entry(key).or_insert_with(|| {
                    cats.insert("cat_01".to_owned());
                    br#"{"cat_id":"cat_01","operation_id":"op_01"}"#.to_vec()
                });
                if attempt == 0 {
                    // The server-side Cat/Operation commit above is complete;
                    // close before any status line to model an ambiguous
                    // post-commit transport loss.
                    drop(stream);
                    continue;
                }
                write!(
                    stream,
                    "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                )
                .unwrap();
                stream.write_all(response).unwrap();
                stream.flush().unwrap();
            }
            (requests, cats.len(), operations.len())
        });

        let helper = "tests::cat_create_restart_process_helper";
        let executable = std::env::current_exe().unwrap();
        let invoke = |mode: &str| {
            ProcessCommand::new(&executable)
                .args(["--exact", helper, "--nocapture"])
                .env("CATS_TEST_CAT_CREATE_HELPER_MODE", mode)
                .env("CATS_TEST_CAT_CREATE_HELPER_BASE", &base)
                .env("CATS_TEST_CAT_CREATE_STATE_ROOT", &state_root)
                .output()
                .unwrap()
        };
        let lost = invoke("lost");
        assert!(
            lost.status.success(),
            "lost-response helper failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&lost.stdout),
            String::from_utf8_lossy(&lost.stderr)
        );
        let replay = invoke("replay");
        assert!(
            replay.status.success(),
            "replay helper failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&replay.stdout),
            String::from_utf8_lossy(&replay.stderr)
        );
        assert!(String::from_utf8_lossy(&replay.stdout)
            .contains("Cat cat_01 accepted (operation op_01)"));

        let (requests, cat_count, operation_count) = server.join().unwrap();
        assert_eq!(cat_count, 1);
        assert_eq!(operation_count, 1);
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0], requests[1]);
        assert_eq!(requests[0].0, "POST /v1/workspaces/ws_01/cats HTTP/1.1");
        assert_eq!(
            requests[0].1,
            br#"{"name":"app","boot_image_digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","vcpus":3,"memory_bytes":2147483648,"root_size_bytes":4294967296,"durability":"relaxed"}"#
        );
        assert!(requests[0].2.starts_with("cli-"));
        assert!(std::fs::read_dir(&state_root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".pending.json")
        }));
    }

    #[cfg(unix)]
    #[cfg(any())]
    #[test]
    fn persistent_disk_response_loss_process_restart_replays_one_disk_exactly() {
        use std::collections::HashMap;
        use std::io::Write as _;
        use std::process::Command as ProcessCommand;

        let state_directory = tempfile::tempdir().unwrap();
        let state_root = state_directory.path().canonicalize().unwrap().join("state");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server_state_root = state_root.clone();
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            let mut results = HashMap::new();
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let (headers, body) = read_request(&mut stream);
                assert!(std::fs::read_dir(&server_state_root).unwrap().any(|entry| {
                    entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .ends_with(".pending.json")
                }));
                let first_line = headers.lines().next().unwrap().to_owned();
                let key = request_header(&headers, "Idempotency-Key");
                requests.push((first_line, body, key.clone()));
                let response = results.entry(key).or_insert_with(|| {
                    br#"{"id":"disk_11111111111111111111111111111111","workspace_id":"ws_01","name":"data","kind":"persistent","size_bytes":1073741824,"state":"available","durability":"strict","volume_id":"vol_22222222222222222222222222222222","created_at_unix":1720000000}"#.to_vec()
                });
                if attempt == 0 {
                    // The authoritative Disk+Volume+result transaction is
                    // complete, but the client sees no response bytes.
                    drop(stream);
                    continue;
                }
                write!(
                    stream,
                    "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                )
                .unwrap();
                stream.write_all(response).unwrap();
                stream.flush().unwrap();
            }
            (requests, results.len())
        });

        let helper = "tests::persistent_disk_create_restart_process_helper";
        let executable = std::env::current_exe().unwrap();
        let invoke = |mode: &str| {
            ProcessCommand::new(&executable)
                .args(["--exact", helper, "--nocapture"])
                .env("CATS_TEST_PERSISTENT_DISK_CREATE_HELPER_MODE", mode)
                .env("CATS_TEST_PERSISTENT_DISK_CREATE_HELPER_BASE", &base)
                .env("CATS_TEST_PERSISTENT_DISK_CREATE_STATE_ROOT", &state_root)
                .output()
                .unwrap()
        };
        let lost = invoke("lost");
        assert!(
            lost.status.success(),
            "lost-response helper failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&lost.stdout),
            String::from_utf8_lossy(&lost.stderr)
        );
        let replay = invoke("replay");
        assert!(
            replay.status.success(),
            "replay helper failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&replay.stdout),
            String::from_utf8_lossy(&replay.stderr)
        );
        assert!(String::from_utf8_lossy(&replay.stdout).contains("data"));

        let (requests, result_count) = server.join().unwrap();
        assert_eq!(result_count, 1);
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0], requests[1]);
        assert_eq!(requests[0].0, "POST /v1/workspaces/ws_01/disks HTTP/1.1");
        assert_eq!(
            requests[0].1,
            br#"{"durability":"strict","name":"data","size_bytes":1073741824}"#
        );
        assert!(requests[0].2.starts_with("cli-"));
        assert!(std::fs::read_dir(&state_root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".pending.json")
        }));
    }

    #[cfg(unix)]
    #[cfg(any())]
    #[test]
    fn persistent_disk_binding_response_loss_replays_one_config_result_exactly() {
        use std::collections::HashMap;
        use std::io::Write as _;
        use std::process::Command as ProcessCommand;

        let state_directory = tempfile::tempdir().unwrap();
        let state_root = state_directory.path().canonicalize().unwrap().join("state");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server_state_root = state_root.clone();
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            let mut results = HashMap::new();
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let (headers, body) = read_request(&mut stream);
                assert!(std::fs::read_dir(&server_state_root).unwrap().any(|entry| {
                    entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .ends_with(".pending.json")
                }));
                let first_line = headers.lines().next().unwrap().to_owned();
                let key = request_header(&headers, "Idempotency-Key");
                requests.push((first_line, body, key.clone()));
                let response = results.entry(key).or_insert_with(|| {
                    br#"{"cat_id":"cat_01","disk_id":"disk_01","runtime_config_id":"cfg_02","runtime_config_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}"#.to_vec()
                });
                if attempt == 0 {
                    // Config pointer plus stored response committed; no
                    // response bytes reach the first process.
                    drop(stream);
                    continue;
                }
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                )
                .unwrap();
                stream.write_all(response).unwrap();
                stream.flush().unwrap();
            }
            (requests, results.len())
        });

        let helper = "tests::persistent_disk_binding_restart_process_helper";
        let executable = std::env::current_exe().unwrap();
        let invoke = |mode: &str| {
            ProcessCommand::new(&executable)
                .args(["--exact", helper, "--nocapture"])
                .env("CATS_TEST_PERSISTENT_DISK_BINDING_HELPER_MODE", mode)
                .env("CATS_TEST_PERSISTENT_DISK_BINDING_HELPER_BASE", &base)
                .env("CATS_TEST_PERSISTENT_DISK_BINDING_STATE_ROOT", &state_root)
                .output()
                .unwrap()
        };
        let lost = invoke("lost");
        assert!(
            lost.status.success(),
            "lost-response helper failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&lost.stdout),
            String::from_utf8_lossy(&lost.stderr)
        );
        let replay = invoke("replay");
        assert!(
            replay.status.success(),
            "replay helper failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&replay.stdout),
            String::from_utf8_lossy(&replay.stderr)
        );
        assert!(String::from_utf8_lossy(&replay.stdout)
            .contains("runtime config cfg_02, sha256:1111111111111111111111111111111111111111111111111111111111111111"));

        let (requests, result_count) = server.join().unwrap();
        assert_eq!(result_count, 1);
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0], requests[1]);
        assert_eq!(
            requests[0].0,
            "POST /v1/workspaces/ws_01/disks/disk_01/actions/attach HTTP/1.1"
        );
        assert_eq!(
            requests[0].1,
            br#"{"cat_id":"cat_01","mount_path":"/srv/data"}"#
        );
        assert!(requests[0].2.starts_with("cli-"));
        assert!(std::fs::read_dir(&state_root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".pending.json")
        }));
    }

    #[cfg(unix)]
    #[cfg(any())]
    #[test]
    fn exact_name_conflict_is_terminal_and_durably_clears_pending_state() {
        use clap::Parser as _;
        use std::io::Write as _;

        let state_directory = tempfile::tempdir().unwrap();
        let state_root = state_directory.path().canonicalize().unwrap().join("state");
        let _state_guard = cat_create_pending::TestStateRootGuard::set(state_root.clone());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _request = read_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                CAT_CREATE_NAME_CONFLICT_BODY.len()
            )
            .unwrap();
            stream.write_all(CAT_CREATE_NAME_CONFLICT_BODY).unwrap();
            stream.flush().unwrap();
        });
        let cli = Cli::parse_from([
            "cats",
            "--api-url",
            &base,
            "--token",
            "test-token",
            "--workspace",
            "ws_01",
            "create",
            "app",
            "--boot-image-digest",
            TEST_BOOT_IMAGE,
        ]);
        let error = run(cli).unwrap_err().to_string();
        assert!(error.contains("cat name already exists"));
        server.join().unwrap();
        assert!(std::fs::read_dir(state_root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".pending.json")
        }));
    }

    #[cfg(unix)]
    #[cfg(any())]
    #[test]
    fn exact_disk_binding_fixed_results_clear_but_nonterminal_response_stays_pending() {
        use clap::Parser as _;
        use std::io::Write as _;

        let invoke = |base: &str| {
            Cli::parse_from([
                "cats",
                "--api-url",
                base,
                "--token",
                "test-token",
                "--workspace",
                "ws_01",
                "disk",
                "attach",
                "disk_01",
                "--cat",
                "cat_01",
                "--mount-path",
                "/srv/data",
            ])
        };

        for (status_line, body, expected_error) in [
            (
                "409 Conflict",
                PERSISTENT_DISK_BINDING_CONFLICT_BODY,
                "Conflict",
            ),
            (
                "412 Precondition Failed",
                PERSISTENT_DISK_BINDING_PRECONDITION_BODY,
                "FailedPrecondition",
            ),
        ] {
            let state_directory = tempfile::tempdir().unwrap();
            let state_root = state_directory.path().canonicalize().unwrap().join("state");
            let _state_guard = cat_create_pending::TestPersistentDiskBindingStateRootGuard::set(
                state_root.clone(),
            );
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let _ = read_request(&mut stream);
                write!(
                    stream,
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(body).unwrap();
                stream.flush().unwrap();
            });
            let error = run(invoke(&base)).unwrap_err().to_string();
            assert!(error.contains(expected_error), "{error}");
            server.join().unwrap();
            assert!(std::fs::read_dir(&state_root).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".pending.json")
            }));
        }

        let state_directory = tempfile::tempdir().unwrap();
        let state_root = state_directory.path().canonicalize().unwrap().join("state");
        let _state_guard =
            cat_create_pending::TestPersistentDiskBindingStateRootGuard::set(state_root.clone());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_request(&mut stream);
            let body = br#"{"code":"unavailable","message":"retry"}"#;
            write!(
                stream,
                "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
            stream.flush().unwrap();
        });
        let error = run(invoke(&base)).unwrap_err().to_string();
        assert!(error.contains("not an exact terminal result"), "{error}");
        server.join().unwrap();
        assert!(std::fs::read_dir(&state_root).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".pending.json")
        }));
    }

    #[test]
    fn cat_create_response_classification_is_exact_and_closed() {
        let response = |status, body: &[u8]| ExactCreateHttpResponse {
            status,
            content_types: vec![b"application/json".to_vec()],
            content_encodings: Vec::new(),
            body: body.to_vec(),
        };
        assert!(matches!(
            classify_cat_create_response(&response(
                reqwest::StatusCode::ACCEPTED,
                br#"{"cat_id":"cat_01","operation_id":"op_01"}"#,
            )),
            CatCreateResponseClassification::Accepted(_)
        ));
        assert!(matches!(
            classify_cat_create_response(&response(
                reqwest::StatusCode::CONFLICT,
                CAT_CREATE_NAME_CONFLICT_BODY,
            )),
            CatCreateResponseClassification::NameConflict
        ));
        for closed in [
            response(
                reqwest::StatusCode::OK,
                br#"{"cat_id":"cat_01","operation_id":"op_01"}"#,
            ),
            response(
                reqwest::StatusCode::ACCEPTED,
                br#"{ "cat_id":"cat_01","operation_id":"op_01"}"#,
            ),
            response(
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                br#"{"code":"unavailable","message":"retry"}"#,
            ),
        ] {
            assert!(matches!(
                classify_cat_create_response(&closed),
                CatCreateResponseClassification::Nonterminal
            ));
        }
        let mut compressed = response(
            reqwest::StatusCode::ACCEPTED,
            br#"{"cat_id":"cat_01","operation_id":"op_01"}"#,
        );
        compressed.content_encodings.push(b"gzip".to_vec());
        assert!(matches!(
            classify_cat_create_response(&compressed),
            CatCreateResponseClassification::Nonterminal
        ));
    }

    #[test]
    fn persistent_disk_binding_response_classification_is_exact_and_closed() {
        let response = |status, body: &[u8]| ExactCreateHttpResponse {
            status,
            content_types: vec![b"application/json".to_vec()],
            content_encodings: Vec::new(),
            body: body.to_vec(),
        };
        let committed = br#"{"cat_id":"cat_01","disk_id":"disk_01","runtime_config_id":"cfg_02","runtime_config_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}"#.as_slice();
        assert!(matches!(
            classify_persistent_disk_binding_response(&response(
                reqwest::StatusCode::OK,
                committed,
            )),
            PersistentDiskBindingResponseClassification::Committed(_)
        ));
        let parsed = decode_persistent_disk_binding_v2_committed_response(committed).unwrap();
        assert!(persistent_disk_binding_response_matches_target(
            &parsed, "disk_01", "cat_01"
        ));
        assert!(!persistent_disk_binding_response_matches_target(
            &parsed,
            "disk_other",
            "cat_01"
        ));
        assert!(!persistent_disk_binding_response_matches_target(
            &parsed,
            "disk_01",
            "cat_other"
        ));
        assert!(matches!(
            classify_persistent_disk_binding_response(&response(
                reqwest::StatusCode::NOT_FOUND,
                PERSISTENT_DISK_BINDING_NOT_FOUND_BODY,
            )),
            PersistentDiskBindingResponseClassification::NotFound
        ));
        assert!(matches!(
            classify_persistent_disk_binding_response(&response(
                reqwest::StatusCode::CONFLICT,
                PERSISTENT_DISK_BINDING_CONFLICT_BODY,
            )),
            PersistentDiskBindingResponseClassification::Conflict
        ));
        assert!(matches!(
            classify_persistent_disk_binding_response(&response(
                reqwest::StatusCode::PRECONDITION_FAILED,
                PERSISTENT_DISK_BINDING_PRECONDITION_BODY,
            )),
            PersistentDiskBindingResponseClassification::FailedPrecondition
        ));
        for closed in [
            response(reqwest::StatusCode::ACCEPTED, committed),
            response(
                reqwest::StatusCode::OK,
                br#"{ "cat_id":"cat_01","disk_id":"disk_01","runtime_config_id":"cfg_02","runtime_config_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}"#,
            ),
            response(
                reqwest::StatusCode::CONFLICT,
                br#"{"code":"conflict","message":"different"}"#,
            ),
            response(
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                br#"{"code":"unavailable","message":"retry"}"#,
            ),
        ] {
            assert!(matches!(
                classify_persistent_disk_binding_response(&closed),
                PersistentDiskBindingResponseClassification::Nonterminal
            ));
        }
        let mut compressed = response(reqwest::StatusCode::OK, committed);
        compressed.content_encodings.push(b"gzip".to_vec());
        assert!(matches!(
            classify_persistent_disk_binding_response(&compressed),
            PersistentDiskBindingResponseClassification::Nonterminal
        ));
    }

    #[cfg(unix)]
    #[test]
    fn persistent_disk_response_classification_is_exact_and_closed() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap().join("state");
        let _state_guard = cat_create_pending::TestPersistentDiskStateRootGuard::set(root.clone());
        let request = PersistentDiskCreateV1Request {
            durability: DiskDurability::Strict,
            name: cats_api::runtime_reconciliation::Id::new("data").unwrap(),
            size_bytes: 1 << 30,
        };
        let pending = cat_create_pending::PreparedPersistentDiskCreate::prepare(
            "https://control.example",
            "ws_01",
            &serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();
        let response = |status, body: &[u8]| ExactCreateHttpResponse {
            status,
            content_types: vec![b"application/json".to_vec()],
            content_encodings: Vec::new(),
            body: body.to_vec(),
        };
        let exact = br#"{"id":"disk_11111111111111111111111111111111","workspace_id":"ws_01","name":"data","kind":"persistent","size_bytes":1073741824,"state":"available","durability":"strict","volume_id":"vol_22222222222222222222222222222222","created_at_unix":1720000000}"#;
        assert!(matches!(
            classify_persistent_disk_create_response(
                &response(reqwest::StatusCode::CREATED, exact),
                &pending,
            )
            .unwrap(),
            PersistentDiskCreateResponseClassification::Created(_)
        ));
        assert!(matches!(
            classify_persistent_disk_create_response(
                &response(
                    reqwest::StatusCode::CONFLICT,
                    PERSISTENT_DISK_NAME_CONFLICT_BODY,
                ),
                &pending,
            )
            .unwrap(),
            PersistentDiskCreateResponseClassification::NameConflict
        ));
        for closed in [
            response(reqwest::StatusCode::OK, exact),
            response(
                reqwest::StatusCode::CREATED,
                br#"{ "id":"disk_11111111111111111111111111111111","workspace_id":"ws_01","name":"data","kind":"persistent","size_bytes":1073741824,"state":"available","durability":"strict","volume_id":"vol_22222222222222222222222222222222","created_at_unix":1720000000}"#,
            ),
            response(
                reqwest::StatusCode::CREATED,
                br#"{"id":"disk_11111111111111111111111111111111","workspace_id":"ws_02","name":"data","kind":"persistent","size_bytes":1073741824,"state":"available","durability":"strict","volume_id":"vol_22222222222222222222222222222222","created_at_unix":1720000000}"#,
            ),
        ] {
            assert!(matches!(
                classify_persistent_disk_create_response(&closed, &pending).unwrap(),
                PersistentDiskCreateResponseClassification::Nonterminal
            ));
        }
    }

    #[test]
    fn retired_product_commands_are_not_parseable() {
        use clap::Parser;

        let commands: &[&[&str]] = &[
            &["sync", "app"],
            &["exec", "app", "--", "true"],
            &["shell", "app"],
            &["sleep", "on", "app"],
            &["sleep", "off", "app"],
            &["sleep", "status", "app"],
            &["expiry", "app"],
            &["disk", "delete", "data"],
            &["disk", "snapshot", "data"],
            &["mount", "data", "--cat", "app"],
            &["unmount", "data"],
            &["expose", "app", "8080"],
            &["endpoint", "ls", "app"],
            &["operation", "ls"],
            &["admin", "monitoring"],
            &["admin", "nodes"],
            &["admin", "node", "get", "node_01"],
            &["admin", "node", "cordon", "node_01"],
            &["admin", "node", "uncordon", "node_01"],
            &["admin", "node", "drain", "node_01"],
            &[
                "admin",
                "node",
                "fence",
                "node_01",
                "--confirm-host-stopped-or-isolated",
            ],
            &["admin", "node", "delete", "node_01"],
        ];
        for command in commands {
            let mut argv = vec!["cats"];
            argv.extend_from_slice(command);
            assert!(
                Cli::try_parse_from(argv).is_err(),
                "retired command {command:?} remains in the CLI grammar"
            );
        }
    }

    #[test]
    fn disk_resize_is_not_a_cli_command() {
        use clap::Parser;

        let parsed = Cli::try_parse_from(["cats", "disk", "resize", "data", "--size", "2GiB"]);
        assert!(
            parsed.is_err(),
            "immutable volume capacity still has a CLI mutation"
        );
    }

    #[test]
    fn shipped_help_exposes_atomic_lifecycle_and_hides_closed_authority_commands() {
        use clap::CommandFactory;

        let mut root = Cli::command();
        let root_help = root.render_long_help().to_string();
        for command in [
            "start", "stop", "delete", "resume", "sync", "exec", "shell", "sleep", "expiry",
            "mount", "unmount", "expose", "endpoint",
        ] {
            assert!(
                !root_help.contains(&format!("\n  {command} ")),
                "retired command {command:?} remains visible in root help"
            );
        }
        for supported in [
            "ls", "get", "deploy", "disk", "run", "suspend", "warm", "cold", "destroy",
        ] {
            assert!(
                root_help.contains(&format!("\n  {supported} ")),
                "production command {supported:?} is hidden from root help"
            );
        }
        assert!(root_help.contains("\n  operation "));
        assert!(!root_help.contains("--no-wait"));

        let mut disk = Cli::command()
            .find_subcommand("disk")
            .expect("Disk command")
            .clone();
        let disk_help = disk.render_long_help().to_string();
        for supported in ["create", "ls", "get", "attach", "detach", "destroy"] {
            assert!(disk_help.contains(&format!("\n  {supported} ")));
        }
        for retired in ["resize", "delete", "snapshot"] {
            assert!(!disk_help.contains(&format!("\n  {retired} ")));
        }

        let mut operation = Cli::command()
            .find_subcommand("operation")
            .expect("Operation command")
            .clone();
        let operation_help = operation.render_long_help().to_string();
        assert!(operation_help.contains("\n  get "));
        assert!(operation_help.contains("\n  wait "));
        assert!(!operation_help.contains("\n  ls "));

        let mut create = Cli::command()
            .find_subcommand("create")
            .expect("create command")
            .clone();
        let create_help = create.render_long_help().to_string();
        for flag in ["--boot-image", "--cpu", "--memory", "--mount"] {
            assert!(
                create_help.contains(flag),
                "missing semantic create flag {flag}"
            );
        }
        assert!(!create_help.contains("--boot-image-digest"));
        for retired in ["--image", "--disk", "--no-auto-suspend", "--expires-in"] {
            assert!(
                !create_help.contains(retired),
                "legacy create flag {retired:?}"
            );
        }

        let mut admin = Cli::command()
            .find_subcommand("admin")
            .expect("admin command")
            .clone();
        let admin_help = admin.render_long_help().to_string();
        for retired in ["monitoring", "nodes", "node"] {
            assert!(
                !admin_help.contains(&format!("\n  {retired} ")),
                "legacy admin command {retired:?} remains visible"
            );
        }
        assert!(admin_help.contains("runtime-node"));
    }

    #[test]
    #[cfg(any())]
    fn served_getting_started_examples_are_accepted_by_the_shipped_parser() {
        use clap::Parser;

        const CREATE: &str = "cats create dev --boot-image-digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --cpus 2 --memory 2GiB --root-size 1GiB --durability strict";
        let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for relative in [
            "control-plane/ui/public/docs/en/getting-started.md",
            "control-plane/ui/public/docs/en/getting-started.html",
            "control-plane/ui/public/docs/zh-CN/getting-started.md",
            "control-plane/ui/public/docs/zh-CN/getting-started.html",
        ] {
            let path = workspace.join(relative);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            assert!(
                source.contains(CREATE),
                "served documentation {relative} lost the copyable create command"
            );
            Cli::try_parse_from(CREATE.split_whitespace()).unwrap_or_else(|error| {
                panic!("served documentation {relative} has an invalid create command: {error}")
            });
        }
    }

    #[test]
    fn fleet_admin_commands_reject_workspace_scope_before_authentication() {
        for arguments in [
            vec!["cats", "--workspace", "ordinary", "admin", "login"],
            vec!["cats", "--workspace", "ordinary", "admin", "logout"],
            vec![
                "cats",
                "--workspace",
                "ordinary",
                "admin",
                "runtime-node",
                "provision",
                "--identity",
                "missing-identity.json",
                "--policy",
                "missing-policy.json",
            ],
        ] {
            let error = run(Cli::parse_from(arguments)).unwrap_err().to_string();
            assert!(error.contains("not Workspace-scoped"), "{error}");
        }

        let error = run(Cli::parse_from([
            "cats",
            "--token",
            "must-not-be-ignored",
            "admin",
            "login",
        ]))
        .unwrap_err()
        .to_string();
        assert!(error.contains("remove --token"), "{error}");
    }
}
