//! `cats` CLI: the command-line user surface. Cat lifecycle and PersistentDisk
//! mutations call the synchronous semantic Control API using Workspace-local
//! slugs. Independent account, fleet-admin and OCI deployment tools remain in
//! the same binary; no storage or Node internals appear here.

mod auth;
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
mod workos_client;

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use serde_json::json;

use cats_api::auth::{CreatedWorkspaceToken, WorkspaceToken};
use cats_api::list::ListResponse;
use cats_api::oci::{
    DeployOciRequest, OciDeployment, OciDeploymentAttempt, OciDeploymentAttemptState,
    OciRegistryAuth,
};
use cats_api::semantic_control::{
    AttachDiskRequest, CatMountRequest, CatResponse, CatView, CreateCatRequest, CreateDiskRequest,
    DetachDiskRequest, DiskResponse, DiskView, PersistentMountPath, ResourceSlug,
    SemanticErrorBody,
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
    /// Show the current Cat selected by its Workspace-local slug.
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
        /// Workspace-local PersistentDisk slug.
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

    /// `send`, keeping the status for callers whose synchronous endpoint has
    /// more than one successful HTTP result.
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

    fn get(&self, path: &str) -> Result<serde_json::Value> {
        self.send(self.http.get(self.url(path)))
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

fn print_semantic_cat(cat: &CatView, json_mode: bool) {
    if json_mode {
        println!("{}", serde_json::to_string_pretty(cat).unwrap());
    } else {
        let state = cat
            .state
            .map(|state| format!("{state:?}").to_lowercase())
            .unwrap_or_else(|| "creating".to_owned());
        let node = cat.node_name.as_ref().map_or("-", |name| name.as_str());
        println!(
            "{:<16} id={:<38} state={:<9} node={} disks={}",
            cat.cat_slug,
            cat.cat_id,
            state,
            node,
            cat.mounts.len(),
        );
    }
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
            cpus,
            memory,
            mounts,
        } => {
            let request = CreateCatRequest {
                cat_slug: resource_slug("cat", name)?,
                cpu: *cpus,
                memory_bytes: parse_size(memory)?,
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
            let cats: Vec<CatView> = serde_json::from_value(client.get("/cats")?)
                .context("invalid semantic Cat list response")?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&cats)?);
            } else {
                for cat in &cats {
                    cat.validate().context("invalid Cat list item")?;
                    print_semantic_cat(cat, false);
                }
            }
            Ok(())
        }
        Command::Get { id } => {
            let slug = resource_slug("cat", id)?;
            let cat: CatView = serde_json::from_value(client.get(&format!("/cats/{slug}"))?)
                .context("invalid semantic Cat response")?;
            cat.validate().context("invalid Cat response")?;
            print_semantic_cat(&cat, cli.json);
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
            let disks: Vec<DiskView> = serde_json::from_value(client.get("/disks")?)
                .context("invalid semantic PersistentDisk list response")?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&disks)?);
            } else {
                for disk in &disks {
                    disk.validate()
                        .context("invalid PersistentDisk list item")?;
                    print_semantic_disk(disk, false);
                }
            }
            Ok(())
        }
        DiskCommand::Get { id } => {
            let slug = resource_slug("disk", id)?;
            let disk: DiskView = serde_json::from_value(client.get(&format!("/disks/{slug}"))?)
                .context("invalid semantic PersistentDisk response")?;
            disk.validate().context("invalid PersistentDisk response")?;
            print_semantic_disk(&disk, cli.json);
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

fn print_semantic_disk(disk: &DiskView, json_mode: bool) {
    if json_mode {
        println!("{}", serde_json::to_string_pretty(disk).unwrap());
    } else {
        let bound_cat = disk
            .binding
            .as_ref()
            .map(|binding| binding.cat_slug.as_str())
            .unwrap_or("-");
        println!(
            "{:<16} id={:<38} {:>8} MiB status={:<8} cat={}",
            disk.disk_slug,
            disk.disk_id,
            disk.size_bytes >> 20,
            format!("{:?}", disk.status).to_lowercase(),
            bound_cat,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn create_rejects_a_user_boot_image_override() {
        use clap::Parser as _;

        let error = Cli::try_parse_from(["cats", "create", "app", "--boot-image", "ubuntu-24.04"])
            .expect_err("the Control-owned boot image cannot be overridden");
        assert!(error
            .to_string()
            .contains("unexpected argument '--boot-image'"));
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
            "--cpu",
            "4",
            "--memory",
            "8GiB",
            "--mount",
            "data:/data",
        ]);
        match cli.command {
            Command::Create { name, cpus, .. } => {
                assert_eq!(name, "dev");
                assert_eq!(cpus, 4);
            }
            _ => panic!("wrong parse"),
        }
        assert!(Cli::try_parse_from(["cats", "create", "x"]).is_ok());
        assert!(Cli::try_parse_from(["cats", "create", "x", "--disk", "legacy",]).is_err());
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

    fn write_json_response(stream: &mut std::net::TcpStream, body: &[u8]) {
        use std::io::Write as _;

        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n"
        )
        .unwrap();
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
            write_json_response(&mut stream, body);
        });

        let deployment =
            follow_oci_deployment(&runtime_test_client(base), "oci_attempt_01", "cat_01").unwrap();
        assert_eq!(deployment.app, "web");
        assert_eq!(deployment.service, "web.service");
        server.join().unwrap();
    }

    #[test]
    fn semantic_reads_use_current_slugs_and_unpaged_collections() {
        use clap::Parser as _;

        for (args, expected_path, response) in [
            (
                vec!["get", "app"],
                "GET /v1/workspaces/ws_01/cats/app HTTP/1.1",
                br#"{"cat_id":"cat_01","workspace_id":"ws_01","cat_slug":"app","state":"running","current_action":null,"node_id":"node_01","node_name":"worker-a","cpu":1,"memory_bytes":536870912,"boot_image":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","mounts":[],"last_error":null,"created_at_unix_ms":1,"updated_at_unix_ms":2,"destroyed_at_unix_ms":null}"#.as_slice(),
            ),
            (
                vec!["disk", "ls"],
                "GET /v1/workspaces/ws_01/disks HTTP/1.1",
                br#"[{"disk_id":"disk_01","workspace_id":"ws_01","disk_slug":"data","size_bytes":1073741824,"status":"normal","binding":null,"created_at_unix_ms":1,"deleted_at_unix_ms":null}]"#.as_slice(),
            ),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let (headers, request_body) = read_request(&mut stream);
                assert!(request_body.is_empty());
                assert_eq!(headers.lines().next().unwrap(), expected_path);
                assert_eq!(
                    request_header(&headers, "authorization"),
                    "Bearer test-token"
                );
                write_json_response(&mut stream, response);
            });
            let mut argv = vec![
                "cats",
                "--api-url",
                &base,
                "--token",
                "test-token",
                "--workspace",
                "ws_01",
                "--json",
            ];
            argv.extend(args);
            run(Cli::parse_from(argv)).unwrap();
            server.join().unwrap();
        }
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
            &["operation", "get", "op_01"],
            &["operation", "wait", "op_01"],
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
    fn shipped_help_exposes_semantic_lifecycle_and_hides_retired_commands() {
        use clap::CommandFactory;

        let mut root = Cli::command();
        let root_help = root.render_long_help().to_string();
        for command in [
            "start",
            "stop",
            "delete",
            "resume",
            "sync",
            "exec",
            "shell",
            "sleep",
            "expiry",
            "mount",
            "unmount",
            "expose",
            "endpoint",
            "operation",
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

        let mut create = Cli::command()
            .find_subcommand("create")
            .expect("create command")
            .clone();
        let create_help = create.render_long_help().to_string();
        for flag in ["--cpu", "--memory", "--mount"] {
            assert!(
                create_help.contains(flag),
                "missing semantic create flag {flag}"
            );
        }
        for retired in [
            "--boot-image",
            "--boot-image-digest",
            "--image",
            "--disk",
            "--no-auto-suspend",
            "--expires-in",
        ] {
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
