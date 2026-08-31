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
mod shell;
#[cfg(unix)]
mod stable_unix_fs;
mod term;
mod view;
mod workos_client;

use std::time::{Duration, Instant, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;

use cats_api::auth::{CreatedWorkspaceToken, WorkspaceToken};
use cats_api::list::ListResponse;
use cats_protocol::oci::{
    DeployOciRequest, OciDeployment, OciDeploymentAttempt, OciDeploymentAttemptState,
    OciRegistryAuth,
};
use cats_protocol::semantic_control::{
    AttachDiskRequest, CatMountRequest, CatResponse, CatView, CreateCatRequest, CreateDiskRequest,
    DetachDiskRequest, DiskResponse, DiskView, PersistentMountPath, ResourceSlug,
    SemanticErrorBody,
};
use cats_protocol::sessions::{
    ExecRequest, ExecResponse, DEFAULT_EXEC_TIMEOUT_MS, MAX_EXEC_ENV_BYTES,
    MAX_EXEC_RESPONSE_JSON_BYTES, MAX_EXEC_STDIN_BYTES, MAX_EXEC_TIMEOUT_MS,
};

pub use term::ColorChoice;
use term::{format_bytes, format_clock, truncate_visible, Align, Cell, Style, Table, Term};
use view::UsageOutcome;

/// A successfully dispatched remote process reported a non-zero exit. Keeping
/// it typed lets the binary preserve a conventional 1..=255 code while every
/// transport, protocol, validation, and local I/O error remains process exit 1.
#[derive(Debug)]
struct RemoteExitCode {
    subject: &'static str,
    code: i32,
}

impl std::fmt::Display for RemoteExitCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} exited with {}", self.subject, self.code)
    }
}

impl std::error::Error for RemoteExitCode {}

#[derive(Debug)]
struct SignalExitCode {
    signal: &'static str,
    code: i32,
}

impl std::fmt::Display for SignalExitCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "interactive shell interrupted by {}",
            self.signal
        )
    }
}

impl std::error::Error for SignalExitCode {}

fn exact_process_exit_code(code: i32) -> i32 {
    if (1..=255).contains(&code) {
        code
    } else {
        1
    }
}

fn remote_exit(subject: &'static str, code: i32) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(RemoteExitCode { subject, code }.into())
    }
}

/// Converts the CLI result into its OS process status without flattening an
/// exact remote command result. Unknown/invalid statuses and ordinary errors
/// are one; a successful command is zero.
pub fn process_exit_code(result: &Result<()>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(error) => error.downcast_ref::<RemoteExitCode>().map_or_else(
            || {
                error
                    .downcast_ref::<SignalExitCode>()
                    .map_or(1, |signal| exact_process_exit_code(signal.code))
            },
            |remote| exact_process_exit_code(remote.code),
        ),
    }
}

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
    /// Colorize human-readable output.
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto, global = true)]
    pub color: ColorChoice,

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
    /// Show one Cat in detail.
    Show {
        /// Workspace-local Cat slug.
        #[arg(value_name = "CAT_SLUG")]
        cat_id: String,
        /// Redraw as the Cat changes instead of printing once and exiting.
        #[arg(long, short = 'w')]
        watch: bool,
        /// Poll interval while watching: `500ms`, `2s` or `1m`.
        #[arg(long, value_name = "DURATION", default_value = "1s")]
        interval: String,
        /// Add the metered usage block. Costs one extra billing read.
        #[arg(long)]
        usage: bool,
    },
    /// Deprecated alias for `cats show`.
    #[command(hide = true)]
    Get {
        /// Workspace-local Cat slug.
        #[arg(value_name = "CAT_SLUG")]
        id: String,
    },
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
    /// Run one argv command inside a Cat, waking it if necessary.
    Exec {
        #[arg(value_name = "CAT_SLUG")]
        cat_id: String,
        /// How long the command may run, in seconds (default 120, maximum 3600).
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
        /// Read newline-delimited NAME=VALUE entries for the child process.
        #[arg(long, value_name = "PATH")]
        env_file: Option<std::path::PathBuf>,
        /// Connect the contents of PATH to the command's standard input.
        #[arg(long, value_name = "PATH")]
        stdin_file: Option<std::path::PathBuf>,
        /// Command argv, after `--`; it is never interpreted by a shell.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Open an interactive login shell inside a Cat, waking it if necessary.
    Shell {
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

#[derive(Debug)]
pub(crate) struct RuntimeNodeAuthorityAuth<'a> {
    pub(crate) deployment_id: Option<&'a str>,
    pub(crate) provisioner_credential_id: Option<&'a str>,
    pub(crate) provisioner_private_key_file: Option<&'a std::path::Path>,
}

#[derive(Subcommand, Debug)]
pub enum RuntimeNodeCommand {
    /// Provision one identity and cordoned policy.
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
}

#[derive(Subcommand, Debug)]
pub enum RuntimeNodePolicyCommand {
    /// Apply the complete placement policy.
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
    /// `account/workspace` when this invocation knows it, for display only.
    /// Never used to address a route.
    workspace_label: Option<String>,
}

const MAX_EXEC_ERROR_RESPONSE_BYTES: usize = 16 * 1024;
// Control may use T + 30 seconds for Node execution and result delivery. The
// CLI stays outside that envelope so Control, rather than the public HTTP
// client, owns the terminal timeout reported to the user.
const EXEC_CONTROL_NODE_ENVELOPE_MARGIN: Duration = Duration::from_secs(30);
const EXEC_PUBLIC_RESPONSE_MARGIN: Duration = Duration::from_secs(15);

fn read_bounded_http_body(
    response: reqwest::blocking::Response,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>> {
    use std::io::Read as _;

    if let Some(content_length) = response.content_length() {
        anyhow::ensure!(
            content_length <= u64::try_from(max_bytes).unwrap_or(u64::MAX),
            "{label} body exceeds the {max_bytes}-byte limit"
        );
    }
    let mut body = Vec::new();
    response
        .take(
            u64::try_from(max_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut body)
        .with_context(|| format!("read {label} body"))?;
    anyhow::ensure!(
        body.len() <= max_bytes,
        "{label} body exceeds the {max_bytes}-byte limit"
    );
    Ok(body)
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
            let workspace_label = (selector != workspace_id).then_some(selector);
            return Ok(Self {
                http,
                base,
                token: token.clone(),
                workspace_id,
                workspace_label,
            });
        }
        let session =
            auth::user_session(cli.api_url.as_deref(), workspace_override(cli).as_deref())?;
        Self::from_user_session(session)
    }

    fn from_user_session(session: auth::UserSession) -> Result<Self> {
        let workspace_label =
            session_workspace_label(&session.config.workspaces, &session.workspace);
        Ok(Self {
            workspace_label,
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

    /// The transport result, without turning an unsuccessful status into an
    /// error. `--watch` has to tell "this Cat is gone" apart from "this request
    /// failed", and the shared error path flattens both into one message.
    fn send_raw(
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
        Ok((status, body))
    }

    fn send_with_status_raw(
        &self,
        req: reqwest::blocking::RequestBuilder,
    ) -> Result<(reqwest::StatusCode, Vec<u8>)> {
        let (status, body) = self.send_raw(req)?;
        if !status.is_success() {
            // Surface the structured error body when present.
            if let Ok(err) = serde_json::from_slice::<SemanticErrorBody>(&body) {
                bail!("{} ({:?})", err.message, err.code);
            }
            if let Ok(err) = serde_json::from_slice::<cats_protocol::error::ErrorBody>(&body) {
                bail!("{} ({:?})", err.message, err.code);
            }
            bail!("HTTP {status}: {}", String::from_utf8_lossy(&body));
        }
        Ok((status, body))
    }

    fn send_exec(&self, request: reqwest::blocking::RequestBuilder) -> Result<ExecResponse> {
        let response = request
            .bearer_auth(&self.token)
            .send()
            .context("control plane unreachable")?;
        let status = response.status();
        let (max_bytes, label) = if status.is_success() {
            (MAX_EXEC_RESPONSE_JSON_BYTES, "exec response")
        } else {
            (MAX_EXEC_ERROR_RESPONSE_BYTES, "exec error response")
        };
        let body = read_bounded_http_body(response, max_bytes, label)?;
        if !status.is_success() {
            if let Ok(error) = serde_json::from_slice::<SemanticErrorBody>(&body) {
                bail!("{} ({:?})", error.message, error.code);
            }
            if let Ok(error) = serde_json::from_slice::<cats_protocol::error::ErrorBody>(&body) {
                bail!("{} ({:?})", error.message, error.code);
            }
            bail!("HTTP {status}: {}", String::from_utf8_lossy(&body));
        }
        let response: ExecResponse =
            serde_json::from_slice(&body).context("invalid exec response")?;
        response.validate().context("invalid exec response")?;
        Ok(response)
    }

    fn get(&self, path: &str) -> Result<serde_json::Value> {
        self.send(self.http.get(self.url(path)))
    }

    /// `get`, mapping an absent resource to `None` instead of an error.
    fn get_optional(&self, path: &str) -> Result<Option<serde_json::Value>> {
        let (status, body) = self.send_raw(self.http.get(self.url(path)))?;
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            if let Ok(err) = serde_json::from_slice::<SemanticErrorBody>(&body) {
                bail!("{} ({:?})", err.message, err.code);
            }
            bail!("HTTP {status}: {}", String::from_utf8_lossy(&body));
        }
        serde_json::from_slice(&body)
            .map(Some)
            .context("malformed response")
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

/// Display label for the Workspace this invocation is actually addressing.
///
/// It must be looked up by the resolved ID, not read from the saved default:
/// `--workspace OTHER` changes what every route addresses while
/// `config.current_workspace` still names the default, so labelling from the
/// default would put another Workspace's name on this Cat's card. An
/// unresolvable ID yields no label at all -- omitting the line is honest, a
/// wrong one is not.
fn session_workspace_label(
    workspaces: &[cats_api::auth::Workspace],
    workspace_id: &str,
) -> Option<String> {
    workspaces
        .iter()
        .find(|workspace| workspace.id == workspace_id)
        .map(|workspace| workspace.locator.clone())
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

/// Wall-clock milliseconds, for ages and durations against wire timestamps.
///
/// A clock before the epoch yields 0 rather than an error: every consumer
/// clamps, and a skewed clock must not stop the CLI from printing.
fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
        })
}

fn list_cats(client: &Client) -> Result<Vec<CatView>> {
    let cats: Vec<CatView> = serde_json::from_value(client.get("/cats")?)
        .context("invalid semantic Cat list response")?;
    for cat in &cats {
        cat.validate().context("invalid Cat list item")?;
    }
    Ok(cats)
}

fn list_disks(client: &Client) -> Result<Vec<DiskView>> {
    let disks: Vec<DiskView> = serde_json::from_value(client.get("/disks")?)
        .context("invalid semantic PersistentDisk list response")?;
    for disk in &disks {
        disk.validate()
            .context("invalid PersistentDisk list item")?;
    }
    Ok(disks)
}

/// One Cat, or `None` once it no longer exists.
fn fetch_cat(client: &Client, slug: &ResourceSlug) -> Result<Option<CatView>> {
    let Some(value) = client.get_optional(&format!("/cats/{slug}"))? else {
        return Ok(None);
    };
    let cat: CatView = serde_json::from_value(value).context("invalid semantic Cat response")?;
    cat.validate().context("invalid Cat response")?;
    Ok(Some(cat))
}

/// The Disk reads behind a Cat's mounts, for their sizes.
///
/// Skipped entirely when the Cat has no mounts, which is the common case and
/// saves a request on every `cats show`.
fn mounted_disks(client: &Client, cat: &CatView) -> Result<Vec<DiskView>> {
    if cat.mounts.is_empty() {
        return Ok(Vec::new());
    }
    list_disks(client)
}

/// Trailing usage window shown by `--usage`.
const USAGE_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
const USAGE_WINDOW_LABEL: &str = "last 24h";

/// Reads one Cat's metered usage, rendering any failure instead of returning
/// it: a workspace without a billing ledger, or a metering outage, must not
/// stop `cats show` from reporting lifecycle state.
fn fetch_usage(client: &Client, cat: &CatView, now_ms: i64) -> UsageOutcome {
    let from_ms =
        now_ms.saturating_sub(i64::try_from(USAGE_WINDOW.as_millis()).unwrap_or(i64::MAX));
    let path = format!(
        "/billing/usage?cat_id={}&from_ms={from_ms}&to_ms={now_ms}",
        cat.cat_id
    );
    match client.get(&path).and_then(|value| {
        serde_json::from_value::<cats_protocol::metering::UsageReport>(value)
            .context("invalid usage report")
    }) {
        Ok(report) => UsageOutcome::Report {
            window_label: USAGE_WINDOW_LABEL.to_owned(),
            report: Box::new(report),
        },
        Err(error) => UsageOutcome::Unavailable {
            window_label: USAGE_WINDOW_LABEL.to_owned(),
            reason: error.to_string(),
        },
    }
}

/// PersistentDisks as a table.
///
/// `STATUS` folds the admin status together with whether the Disk is bound,
/// because "normal" alone does not answer the question a reader has. `ATTACHED
/// TO` shows the single RWO binding, which is the only attachment V1 allows.
fn disks_table(term: Term, disks: &[DiskView]) -> String {
    let mut table = Table::new(
        term,
        vec![
            ("NAME", Align::Left),
            ("SIZE", Align::Right),
            ("STATUS", Align::Left),
            ("ATTACHED TO", Align::Left),
            ("ID", Align::Left),
        ],
    );
    let mut ordered: Vec<&DiskView> = disks.iter().collect();
    ordered.sort_by(|left, right| left.disk_slug.as_str().cmp(right.disk_slug.as_str()));
    for disk in ordered {
        let (status, style) = match disk.status {
            cats_protocol::semantic_control::DiskStatus::Normal => {
                if disk.binding.is_some() {
                    ("attached", Style::Green)
                } else {
                    ("available", Style::Plain)
                }
            }
            cats_protocol::semantic_control::DiskStatus::Deleted => ("deleted", Style::Dim),
        };
        let attached = disk.binding.as_ref().map_or_else(
            || "-".to_owned(),
            |binding| format!("{} {}", binding.cat_slug, binding.mount_path),
        );
        table.push(vec![
            Cell::plain(disk.disk_slug.as_str()),
            Cell::plain(format_bytes(disk.size_bytes)),
            Cell::styled(term, status, style),
            Cell::plain(attached),
            Cell::styled(term, disk.disk_id.as_str(), Style::Dim),
        ]);
    }
    table.render()
}

/// Shortest accepted `--interval`.
///
/// The control plane serializes its PostgreSQL work, so a fast poll from many
/// clients is spent on the store rather than on the transitions it is trying to
/// catch. Sub-second lifecycle transitions are not reliably observable by
/// polling at any rate; catching them needs an operation read, not a shorter
/// interval.
const MIN_WATCH_INTERVAL: Duration = Duration::from_millis(250);
const MAX_WATCH_INTERVAL: Duration = Duration::from_secs(300);

fn parse_interval(value: &str) -> Result<Duration> {
    let trimmed = value.trim();
    let (digits, unit_millis) = if let Some(digits) = trimmed.strip_suffix("ms") {
        (digits, 1)
    } else if let Some(digits) = trimmed.strip_suffix('s') {
        (digits, 1_000)
    } else if let Some(digits) = trimmed.strip_suffix('m') {
        (digits, 60_000)
    } else {
        bail!("interval {value:?} needs a unit: 500ms, 2s or 1m");
    };
    let amount: u64 = digits
        .trim()
        .parse()
        .with_context(|| format!("interval {value:?} is not a whole number with a unit"))?;
    let interval = Duration::from_millis(
        amount
            .checked_mul(unit_millis)
            .context("interval overflows")?,
    );
    if interval < MIN_WATCH_INTERVAL || interval > MAX_WATCH_INTERVAL {
        bail!(
            "interval must be between {}ms and {}s",
            MIN_WATCH_INTERVAL.as_millis(),
            MAX_WATCH_INTERVAL.as_secs()
        );
    }
    Ok(interval)
}

/// How long a watch tolerates consecutive failed polls before giving up.
const WATCH_FAILURE_GRACE: Duration = Duration::from_secs(30);
/// How often a watch refreshes the usage block, which is far more expensive
/// than a Cat read and changes far more slowly.
const WATCH_USAGE_REFRESH: Duration = Duration::from_secs(30);
/// Transitions kept under the card.
const WATCH_HISTORY: usize = 5;

/// Polls one Cat and redraws it in place.
///
/// There is no push transport to prefer: the control plane serves no WebSocket
/// or SSE route, so this polls. It is written as fetch-then-render so adding a
/// push transport later replaces the fetch and leaves the rendering alone.
fn watch_cat(
    client: &Client,
    cli: &Cli,
    slug: &ResourceSlug,
    interval: Duration,
    usage: bool,
) -> Result<()> {
    let mut history: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    let mut signature: Option<String> = None;
    let mut printed_lines = 0usize;
    let mut last_success = Instant::now();
    let mut cached_usage: Option<(Instant, UsageOutcome)> = None;
    let mut disks: Vec<DiskView> = Vec::new();
    // Mount sizes come from a second request that can fail on its own. Retry it
    // until it succeeds rather than once per signature change.
    let mut disks_are_stale = false;
    // The last snapshot that was read successfully. A failed poll keeps drawing
    // it under a stale banner rather than freezing or clearing the screen.
    let mut last_cat: Option<CatView> = None;

    loop {
        // Re-read capabilities every pass so a resized window keeps redrawing
        // correctly.
        let term = Term::stdout(cli.color);
        let now_ms = unix_now_ms();
        // `Some(reason)` when this pass could not refresh, which turns the
        // frame's header into a stale banner over the previous snapshot.
        let stale = match fetch_cat(client, slug) {
            Ok(Some(cat)) => {
                last_success = Instant::now();
                let current = watch_signature(&cat);
                if signature.as_ref() != Some(&current) {
                    if signature.is_some() {
                        // The first observation is the starting point, not a
                        // change.
                        history.push_back(format!(
                            "{}  {}",
                            format_clock(now_ms),
                            view::state_summary(term, &cat),
                        ));
                        while history.len() > WATCH_HISTORY {
                            history.pop_front();
                        }
                    }
                    signature = Some(current);
                    disks_are_stale = true;
                }
                if disks_are_stale {
                    (disks, disks_are_stale) = refresh_disks(disks, mounted_disks(client, &cat));
                }
                if usage
                    && cached_usage
                        .as_ref()
                        .is_none_or(|(fetched, _)| fetched.elapsed() >= WATCH_USAGE_REFRESH)
                {
                    cached_usage = Some((Instant::now(), fetch_usage(client, &cat, now_ms)));
                }
                last_cat = Some(cat);
                None
            }
            // A destroyed Cat is a terminal answer, not a failure.
            Ok(None) => {
                println!("cat {slug} no longer exists");
                return Ok(());
            }
            Err(error) => {
                if last_cat.is_none() {
                    // Nothing has ever been drawn, so there is no watch to
                    // degrade: report the failure the way a plain read would.
                    return Err(error);
                }
                if last_success.elapsed() >= WATCH_FAILURE_GRACE {
                    return Err(error.context(format!(
                        "watch gave up after {}s without a successful poll",
                        WATCH_FAILURE_GRACE.as_secs()
                    )));
                }
                Some(error.to_string())
            }
        };

        if let Some(cat) = &last_cat {
            let card = view::cat_card(
                term,
                cat,
                client.workspace_label.as_deref(),
                &disks,
                cached_usage.as_ref().map(|(_, usage)| usage),
                now_ms,
            );
            let frame = watch_frame(term, &card, &history, stale.as_deref(), interval, now_ms);
            printed_lines = draw_frame(term, &frame, printed_lines);
        }
        std::thread::sleep(interval);
    }
}

/// Applies a mounted-disk refresh, keeping the previous set when it failed.
///
/// Returns the set to display and whether it still needs a refresh. Replacing
/// the cache with an empty vector on a transient `/disks` error would print `-`
/// for every mount size for the rest of the watch, with nothing on screen
/// saying the sizes are missing rather than absent.
fn refresh_disks(previous: Vec<DiskView>, fetched: Result<Vec<DiskView>>) -> (Vec<DiskView>, bool) {
    match fetched {
        Ok(disks) => (disks, false),
        Err(_) => (previous, true),
    }
}

/// The fields whose change is worth recording in the transition history.
fn watch_signature(cat: &CatView) -> String {
    format!(
        "{:?}/{:?}/{}/{}",
        cat.state,
        cat.current_action,
        cat.updated_at_unix_ms,
        cat.mounts.len()
    )
}

fn watch_frame(
    term: Term,
    card: &str,
    history: &std::collections::VecDeque<String>,
    error: Option<&str>,
    interval: Duration,
    now_ms: i64,
) -> String {
    let mut frame = String::new();
    let status = match error {
        Some(error) => term.paint(&format!("stale: {error}"), Style::Red),
        None => term.paint(
            &format!(
                "watching every {}ms  {}",
                interval.as_millis(),
                format_clock(now_ms)
            ),
            Style::Dim,
        ),
    };
    frame.push_str(&status);
    frame.push('\n');
    frame.push_str(card);
    if !history.is_empty() {
        frame.push_str(&format!("\n\n  {}", term.paint("changes", Style::Dim)));
        for entry in history {
            frame.push_str(&format!("\n    {entry}"));
        }
    }
    frame
}

/// Reprints `frame` over the previous one and returns the line count it wrote.
///
/// Every line is truncated to the terminal width so one logical line is exactly
/// one physical row; otherwise a wrapped line makes the cursor-up count wrong
/// and the redraw walks up the scrollback. `\x1b[0J` erases forward from the
/// cursor only, so completed output above stays in the scrollback -- unlike a
/// full-screen clear or the alternate screen.
fn draw_frame(term: Term, frame: &str, previous_lines: usize) -> usize {
    let (text, lines) = compose_redraw(term, frame, previous_lines);
    println!("{text}");
    lines
}

/// The bytes of one redraw and the number of rows it will occupy.
///
/// Split out from the write so the rewind arithmetic is testable: an off-by-one
/// here walks the cursor into finished output.
fn compose_redraw(term: Term, frame: &str, previous_lines: usize) -> (String, usize) {
    let Some(width) = term.width() else {
        // Not a terminal: append instead of redrawing, so a redirected watch is
        // a readable log rather than a pile of escape sequences.
        return (frame.to_owned(), 0);
    };
    let mut lines: Vec<String> = frame
        .lines()
        .map(|line| truncate_visible(line, width))
        .collect();
    if let Some(height) = term.height() {
        // Keep the frame shorter than the window: a frame taller than the
        // window scrolls, and then cursor-up lands in the wrong place.
        lines.truncate(height.saturating_sub(1).max(1));
    }
    let mut out = String::new();
    if previous_lines > 0 {
        out.push_str(&format!("\x1b[{previous_lines}A\x1b[0J"));
    }
    out.push_str(&lines.join("\n"));
    (out, lines.len())
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
            print_cat_response(&response, &cli)
        }
        Command::Ls => {
            let cats = list_cats(&client)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&cats)?);
                return Ok(());
            }
            if cats.is_empty() {
                println!("No cats yet. Create one with:\n  cats create NAME");
                return Ok(());
            }
            println!(
                "{}",
                view::cats_table(Term::stdout(cli.color), &cats, unix_now_ms())
            );
            Ok(())
        }
        Command::Show {
            cat_id,
            watch,
            interval,
            usage,
        } => {
            let slug = resource_slug("cat", cat_id)?;
            if *watch {
                if cli.json {
                    bail!("--watch has no --json form; poll `cats show --json` instead");
                }
                return watch_cat(&client, &cli, &slug, parse_interval(interval)?, *usage);
            }
            let cat =
                fetch_cat(&client, &slug)?.with_context(|| format!("cat {slug} does not exist"))?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&cat)?);
                return Ok(());
            }
            let disks = mounted_disks(&client, &cat)?;
            let usage = usage.then(|| fetch_usage(&client, &cat, unix_now_ms()));
            println!(
                "{}",
                view::cat_card(
                    Term::stdout(cli.color),
                    &cat,
                    client.workspace_label.as_deref(),
                    &disks,
                    usage.as_ref(),
                    unix_now_ms(),
                )
            );
            Ok(())
        }
        Command::Get { id } => {
            eprintln!("warning: `cats get` is deprecated and will be removed; use `cats show`");
            run(Cli {
                command: Command::Show {
                    cat_id: id.clone(),
                    watch: false,
                    interval: "1s".to_owned(),
                    usage: false,
                },
                api_url: cli.api_url.clone(),
                token: cli.token.clone(),
                workspace: cli.workspace.clone(),
                json: cli.json,
                color: cli.color,
            })
        }
        Command::Run { cat_id } => run_semantic_cat_action(&client, &cli, cat_id, "run"),
        Command::Suspend { cat_id } => run_semantic_cat_action(&client, &cli, cat_id, "suspend"),
        Command::Warm { cat_id } => run_semantic_cat_action(&client, &cli, cat_id, "warm"),
        Command::Cold { cat_id } => run_semantic_cat_action(&client, &cli, cat_id, "cold"),
        Command::Destroy { cat_id } => run_semantic_cat_action(&client, &cli, cat_id, "destroy"),
        Command::Exec {
            cat_id,
            timeout,
            env_file,
            stdin_file,
            command,
        } => {
            resource_slug("cat", cat_id)?;
            let env = env_file
                .as_deref()
                .map(read_exec_env_file)
                .transpose()?
                .unwrap_or_default();
            let stdin = stdin_file
                .as_deref()
                .map(read_exec_stdin_file)
                .transpose()?
                .unwrap_or_default();
            let timeout_ms = timeout.map(exec_timeout_ms).transpose()?;
            let body = ExecRequest {
                command: command.clone(),
                timeout_ms,
                env,
                stdin,
            };
            body.validate().context("invalid exec request")?;

            // Exec is not idempotent. This is deliberately one HTTP attempt:
            // an ambiguous transport response is reported, never replayed.
            let response = client.send_exec(
                client
                    .http
                    .post(client.url(&format!("/cats/{cat_id}/exec")))
                    .timeout(exec_http_timeout(timeout_ms))
                    .json(&body),
            )?;
            use std::io::Write as _;
            std::io::stdout()
                .write_all(response.stdout.as_bytes())
                .context("write command stdout")?;
            std::io::stdout().flush().context("flush command stdout")?;
            std::io::stderr()
                .write_all(response.stderr.as_bytes())
                .context("write command stderr")?;
            std::io::stderr().flush().context("flush command stderr")?;
            remote_exit("remote command", response.exit_code)
        }
        Command::Shell { cat_id } => {
            resource_slug("cat", cat_id)?;
            match shell::run(&client.base, &client.workspace_id, &client.token, cat_id)? {
                shell::ShellExit::Remote(code) => remote_exit("remote shell", code),
                shell::ShellExit::Interrupted {
                    signal,
                    process_exit_code,
                } => Err(SignalExitCode {
                    signal,
                    code: process_exit_code,
                }
                .into()),
            }
        }
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
    let contents = read_bounded_file(path, MAX_EXEC_ENV_BYTES, "exec environment")?;
    let contents = String::from_utf8(contents)
        .with_context(|| format!("exec environment file {} is not UTF-8", path.display()))?;
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

fn read_exec_stdin_file(path: &std::path::Path) -> Result<Vec<u8>> {
    read_bounded_file(path, MAX_EXEC_STDIN_BYTES, "exec stdin")
}

fn read_bounded_file(path: &std::path::Path, max_bytes: usize, label: &str) -> Result<Vec<u8>> {
    use std::io::Read as _;

    let file = std::fs::File::open(path)
        .with_context(|| format!("open {label} file {}", path.display()))?;
    let mut contents = Vec::new();
    file.take(
        u64::try_from(max_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1),
    )
    .read_to_end(&mut contents)
    .with_context(|| format!("read {label} file {}", path.display()))?;
    anyhow::ensure!(
        contents.len() <= max_bytes,
        "{label} file {} exceeds the {max_bytes}-byte limit",
        path.display()
    );
    Ok(contents)
}

fn exec_timeout_ms(seconds: u64) -> Result<u64> {
    let timeout_ms = seconds
        .checked_mul(1_000)
        .context("exec timeout overflows milliseconds")?;
    anyhow::ensure!(
        timeout_ms > 0 && timeout_ms <= MAX_EXEC_TIMEOUT_MS,
        "exec timeout must be between 1 and {} seconds",
        MAX_EXEC_TIMEOUT_MS / 1_000
    );
    Ok(timeout_ms)
}

fn exec_http_timeout(timeout_ms: Option<u64>) -> Duration {
    Duration::from_millis(timeout_ms.unwrap_or(DEFAULT_EXEC_TIMEOUT_MS))
        .saturating_add(EXEC_CONTROL_NODE_ENVELOPE_MARGIN)
        .saturating_add(EXEC_PUBLIC_RESPONSE_MARGIN)
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
    print_cat_response(&response, cli)
}

fn print_cat_response(response: &CatResponse, cli: &Cli) -> Result<()> {
    if cli.json {
        println!("{}", serde_json::to_string_pretty(response)?);
        return Ok(());
    }
    let code = serde_json::to_value(response.code)?;
    let code = code
        .as_str()
        .context("semantic success code was not a string")?;
    println!(
        "{code}: cat={} id={} state={}",
        response.cat.cat_slug,
        response.cat.cat_id,
        view::state_summary(Term::stdout(cli.color), &response.cat),
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
            let disks = list_disks(client)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&disks)?);
                return Ok(());
            }
            if disks.is_empty() {
                println!("No disks yet. Create one with:\n  cats disk create NAME --size 100GiB");
                return Ok(());
            }
            println!("{}", disks_table(Term::stdout(cli.color), &disks));
            Ok(())
        }
        DiskCommand::Get { id } => {
            let slug = resource_slug("disk", id)?;
            let disk: DiskView = serde_json::from_value(client.get(&format!("/disks/{slug}"))?)
                .context("invalid semantic PersistentDisk response")?;
            disk.validate().context("invalid PersistentDisk response")?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&disk)?);
                return Ok(());
            }
            println!(
                "{}",
                disks_table(Term::stdout(cli.color), std::slice::from_ref(&disk))
            );
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
mod tests {
    use super::*;

    #[test]
    fn the_workspace_label_names_the_workspace_being_addressed() {
        let workspaces = vec![
            workspace_entry("ws_default", "acct/default"),
            workspace_entry("ws_other", "acct/other"),
        ];
        // `--workspace acct/other` resolves into the session's workspace while
        // the saved default is unchanged. Labelling from the default would put
        // another Workspace's name on this Cat's card.
        assert_eq!(
            session_workspace_label(&workspaces, "ws_other").as_deref(),
            Some("acct/other")
        );
        assert_eq!(
            session_workspace_label(&workspaces, "ws_default").as_deref(),
            Some("acct/default")
        );
        assert_eq!(
            session_workspace_label(&workspaces, "ws_vanished"),
            None,
            "an unresolvable workspace is left unlabelled, never mislabelled"
        );
    }

    #[test]
    fn a_failed_disk_refresh_keeps_the_last_sizes_and_stays_due() {
        let disks = vec![disk_view("data", 20 << 30)];
        let (kept, stale) = refresh_disks(disks.clone(), Err(anyhow!("control plane unreachable")));
        assert_eq!(
            kept.len(),
            1,
            "a transient /disks failure must not blank the sizes"
        );
        assert!(stale, "and must leave the refresh due for the next tick");

        let (replaced, stale) = refresh_disks(disks, Ok(vec![disk_view("data", 40 << 30)]));
        assert_eq!(replaced[0].size_bytes, 40 << 30);
        assert!(!stale);
    }

    fn workspace_entry(id: &str, locator: &str) -> cats_api::auth::Workspace {
        cats_api::auth::Workspace {
            id: id.to_owned(),
            account_id: "acct_01".to_owned(),
            account_slug: "acct".to_owned(),
            account_display_name: "Acct".to_owned(),
            slug: locator.rsplit('/').next().unwrap_or(locator).to_owned(),
            locator: locator.to_owned(),
            display_name: "Workspace".to_owned(),
            kind: cats_api::auth::AccountKind::Organization,
            organization_id: "org_01".to_owned(),
            role: None,
            is_default: false,
        }
    }

    fn disk_view(slug: &str, size_bytes: u64) -> DiskView {
        DiskView {
            disk_id: cats_protocol::runtime_reconciliation::Id::new(format!("disk_{slug}"))
                .unwrap(),
            workspace_id: cats_protocol::runtime_reconciliation::Id::new("ws_01").unwrap(),
            disk_slug: ResourceSlug::new(slug).unwrap(),
            size_bytes,
            status: cats_protocol::semantic_control::DiskStatus::Normal,
            binding: None,
            created_at_unix_ms: 1,
            deleted_at_unix_ms: None,
        }
    }

    #[test]
    fn watch_intervals_reject_unbounded_and_unitless_values() {
        assert_eq!(parse_interval("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_interval("2s").unwrap(), Duration::from_secs(2));
        assert_eq!(parse_interval(" 1m ").unwrap(), Duration::from_secs(60));
        for rejected in ["1", "0.5s", "s", "-1s", ""] {
            assert!(
                parse_interval(rejected).is_err(),
                "interval {rejected:?} must not parse"
            );
        }
        // Faster polling cannot catch a sub-second transition and only moves
        // load onto the control plane's serialized store.
        assert!(parse_interval("100ms").is_err());
        assert!(parse_interval("10m").is_err());
    }

    #[test]
    fn a_watch_signature_changes_on_every_settled_or_in_flight_move() {
        let mut cat: CatView = serde_json::from_value(json!({
            "cat_id": "cat_01",
            "workspace_id": "ws_01",
            "cat_slug": "web",
            "state": "cold",
            "current_action": null,
            "node_id": null,
            "node_name": null,
            "cpu": 2,
            "memory_bytes": 2147483648u64,
            "boot_image": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "mounts": [],
            "last_error": null,
            "created_at_unix_ms": 1,
            "updated_at_unix_ms": 2,
            "destroyed_at_unix_ms": null,
        }))
        .expect("Cat");
        let cold = watch_signature(&cat);
        cat.current_action = Some(cats_protocol::semantic_control::CatAction::Run);
        cat.updated_at_unix_ms = 3;
        let starting = watch_signature(&cat);
        cat.current_action = None;
        cat.state = Some(cats_protocol::semantic_control::CatState::Running);
        cat.updated_at_unix_ms = 4;
        let running = watch_signature(&cat);
        assert_ne!(cold, starting);
        assert_ne!(starting, running);
        assert_eq!(running, watch_signature(&cat), "a stable Cat is stable");
    }

    #[test]
    fn a_watch_frame_reports_staleness_instead_of_hiding_it() {
        let term = Term::stdout(ColorChoice::Never);
        let history = std::collections::VecDeque::from(["09:41:00  running".to_owned()]);
        let live = watch_frame(
            term,
            "card",
            &history,
            None,
            Duration::from_millis(500),
            1_700_000_000_000,
        );
        assert!(live.starts_with("watching every 500ms"), "{live}");
        assert!(live.contains("changes"), "{live}");
        assert!(live.contains("09:41:00  running"), "{live}");

        let stale = watch_frame(
            term,
            "card",
            &history,
            Some("control plane unreachable"),
            Duration::from_secs(1),
            1_700_000_000_000,
        );
        assert!(
            stale.starts_with("stale: control plane unreachable"),
            "a failed poll must say so rather than silently freeze: {stale}"
        );
        assert!(stale.contains("card"), "the last snapshot stays drawn");
    }

    #[test]
    fn a_redraw_rewinds_exactly_the_lines_it_last_printed() {
        let term = Term::fixed(false, Some(20));
        let (first, first_lines) = compose_redraw(term, "one\ntwo\nthree", 0);
        assert_eq!(first_lines, 3);
        assert!(
            !first.contains('\x1b'),
            "the first frame must not rewind into scrollback: {first:?}"
        );
        let (second, second_lines) = compose_redraw(term, "one\ntwo", first_lines);
        assert!(
            second.starts_with("\x1b[3A\x1b[0J"),
            "a redraw rewinds the previous line count and erases forward only: {second:?}"
        );
        assert_eq!(second_lines, 2);

        // A line longer than the window is truncated, so one logical line stays
        // one physical row and the rewind count keeps matching.
        let (wide, wide_lines) = compose_redraw(term, &"x".repeat(80), 0);
        assert_eq!(wide_lines, 1);
        assert_eq!(wide.lines().next().map(str::len), Some(20));
    }

    #[test]
    fn a_redraw_appends_when_stdout_is_not_a_terminal() {
        let term = Term::fixed(false, None);
        let (framed, lines) = compose_redraw(term, "one\ntwo", 7);
        assert_eq!(
            lines, 0,
            "a pipe has no cursor to rewind, so nothing is claimed"
        );
        assert_eq!(framed, "one\ntwo");
        assert!(!framed.contains('\x1b'));
    }

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
    fn exec_timeout_is_bounded_and_converted_without_overflow() {
        assert_eq!(exec_timeout_ms(1).unwrap(), 1_000);
        assert_eq!(exec_timeout_ms(3_600).unwrap(), MAX_EXEC_TIMEOUT_MS);
        for rejected in [0, 3_601, u64::MAX] {
            assert!(
                exec_timeout_ms(rejected).is_err(),
                "accepted invalid exec timeout {rejected}"
            );
        }
    }

    #[test]
    fn exec_http_timeout_strictly_contains_the_control_node_envelope() {
        for execution_ms in [DEFAULT_EXEC_TIMEOUT_MS, MAX_EXEC_TIMEOUT_MS] {
            let execution = Duration::from_millis(execution_ms);
            let control_deadline = execution + EXEC_CONTROL_NODE_ENVELOPE_MARGIN;
            let cli_deadline = exec_http_timeout(Some(execution_ms));

            assert_eq!(cli_deadline, control_deadline + EXEC_PUBLIC_RESPONSE_MARGIN);
            assert!(cli_deadline > control_deadline);
        }
        assert_eq!(
            exec_http_timeout(None),
            Duration::from_millis(DEFAULT_EXEC_TIMEOUT_MS)
                + EXEC_CONTROL_NODE_ENVELOPE_MARGIN
                + EXEC_PUBLIC_RESPONSE_MARGIN
        );
    }

    #[test]
    fn process_exit_preserves_only_valid_exact_remote_codes() {
        assert_eq!(process_exit_code(&Ok(())), 0);
        assert_eq!(process_exit_code(&remote_exit("remote command", 0)), 0);
        assert_eq!(process_exit_code(&remote_exit("remote command", 1)), 1);
        assert_eq!(process_exit_code(&remote_exit("remote command", 7)), 7);
        assert_eq!(process_exit_code(&remote_exit("remote shell", 255)), 255);
        for invalid in [-9, -1, 256, i32::MAX] {
            assert_eq!(
                process_exit_code(&remote_exit("remote command", invalid)),
                1
            );
        }
        assert_eq!(process_exit_code(&Err(anyhow!("transport failed"))), 1);
        assert_eq!(
            process_exit_code(&Err(SignalExitCode {
                signal: "SIGTERM",
                code: 143,
            }
            .into())),
            143
        );
    }

    #[test]
    fn exec_stdin_file_is_read_through_the_protocol_bound() {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file()
            .set_len(u64::try_from(MAX_EXEC_STDIN_BYTES + 1).unwrap())
            .unwrap();
        let error = read_exec_stdin_file(file.path()).unwrap_err();
        assert!(
            error.to_string().contains("exceeds the"),
            "unexpected oversized-input error: {error:#}"
        );
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
        let exec = Cli::parse_from([
            "cats",
            "exec",
            "dev",
            "--timeout",
            "900",
            "--env-file",
            "build.env",
            "--stdin-file",
            "request.bin",
            "--",
            "cargo",
            "test",
            "--workspace",
        ]);
        match exec.command {
            Command::Exec {
                cat_id,
                timeout,
                env_file,
                stdin_file,
                command,
            } => {
                assert_eq!(cat_id, "dev");
                assert_eq!(timeout, Some(900));
                assert_eq!(env_file.unwrap(), std::path::PathBuf::from("build.env"));
                assert_eq!(stdin_file.unwrap(), std::path::PathBuf::from("request.bin"));
                assert_eq!(command, ["cargo", "test", "--workspace"]);
            }
            other => panic!("expected exec, got {other:?}"),
        }
        assert!(
            Cli::try_parse_from(["cats", "exec", "dev"]).is_err(),
            "exec without argv must fail before contacting Control"
        );
        assert!(matches!(
            Cli::parse_from(["cats", "shell", "dev"]).command,
            Command::Shell { cat_id } if cat_id == "dev"
        ));
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
            workspace_label: None,
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
    fn a_list_from_a_control_without_the_run_clocks_still_renders() {
        use clap::Parser as _;

        // The skew a merged CLI hits before its Control is deployed: the new
        // observations are absent, and a Running Cat must still list. Rejecting
        // the shape here would fail the whole command, not one column.
        let body = br#"[{"cat_id":"cat_01","workspace_id":"ws_01","cat_slug":"app","state":"running","current_action":null,"node_id":"node_01","node_name":"worker-a","cpu":1,"memory_bytes":536870912,"boot_image":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","mounts":[],"last_error":null,"created_at_unix_ms":1,"updated_at_unix_ms":2,"destroyed_at_unix_ms":null}]"#;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let (headers, _) = read_request(&mut stream);
            assert_eq!(
                headers.lines().next().unwrap(),
                "GET /v1/workspaces/ws_01/cats HTTP/1.1"
            );
            write_json_response(&mut stream, body.as_slice());
        });
        run(Cli::parse_from([
            "cats",
            "--api-url",
            &base,
            "--token",
            "test-token",
            "--workspace",
            "ws_01",
            "--color",
            "never",
            "ls",
        ]))
        .expect("an older Control's list must render, not fail");
        server.join().unwrap();
    }

    #[test]
    fn usage_is_read_for_one_cat_over_a_bounded_window() {
        use clap::Parser as _;

        let cat = br#"{"cat_id":"cat_01","workspace_id":"ws_01","cat_slug":"app","state":"running","current_action":null,"node_id":"node_01","node_name":"worker-a","cpu":1,"memory_bytes":536870912,"boot_image":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","mounts":[],"last_error":null,"created_at_unix_ms":1,"updated_at_unix_ms":2,"destroyed_at_unix_ms":null,"current_action_started_at_unix_ms":null,"last_running_at_unix_ms":2}"#;
        let report = br#"{"billing_account_id":"ba_01","workspace_id":"ws_01","interval_start_unix_ms":1,"interval_end_unix_ms":2,"status":"provisional","currency":"usd","rate_card_id":"rc_01","latest_interval_end_unix_ms":2,"items":[{"metric":"cpu_usec","quantity":"3600000000","unit":"microsecond","amount_nanos":"42100000"}],"cats":[],"amount_nanos":"42100000"}"#;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let mut requested = Vec::new();
            for body in [cat.as_slice(), report.as_slice()] {
                let (mut stream, _) = listener.accept().unwrap();
                let (headers, request_body) = read_request(&mut stream);
                assert!(request_body.is_empty());
                requested.push(headers.lines().next().unwrap().to_owned());
                write_json_response(&mut stream, body);
            }
            requested
        });
        run(Cli::parse_from([
            "cats",
            "--api-url",
            &base,
            "--token",
            "test-token",
            "--workspace",
            "ws_01",
            "--color",
            "never",
            "show",
            "app",
            "--usage",
        ]))
        .unwrap();
        let requested = server.join().unwrap();
        assert_eq!(requested[0], "GET /v1/workspaces/ws_01/cats/app HTTP/1.1");
        let usage = &requested[1];
        assert!(
            usage.starts_with("GET /v1/workspaces/ws_01/billing/usage?cat_id=cat_01&from_ms="),
            // The immutable ID, not the slug: a renamed or recreated slug must
            // not silently bill someone else's history into this card.
            "usage must be scoped to this Cat by ID: {usage}"
        );
        let window: Vec<&str> = usage.split(['=', '&', ' ']).collect();
        let from: i64 = window[4].parse().expect("from_ms");
        let to: i64 = window[6].parse().expect("to_ms");
        assert_eq!(
            to - from,
            i64::try_from(USAGE_WINDOW.as_millis()).unwrap(),
            "the usage window must be bounded, not open-ended: {usage}"
        );
    }

    #[test]
    fn semantic_reads_use_current_slugs_and_unpaged_collections() {
        use clap::Parser as _;

        for (args, expected_path, response) in [
            (
                vec!["get", "app"],
                "GET /v1/workspaces/ws_01/cats/app HTTP/1.1",
                br#"{"cat_id":"cat_01","workspace_id":"ws_01","cat_slug":"app","state":"running","current_action":null,"node_id":"node_01","node_name":"worker-a","cpu":1,"memory_bytes":536870912,"boot_image":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","mounts":[],"last_error":null,"created_at_unix_ms":1,"updated_at_unix_ms":2,"destroyed_at_unix_ms":null,"current_action_started_at_unix_ms":null,"last_running_at_unix_ms":2}"#.as_slice(),
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
            let response = br#"{"status":"ok","code":"cat_created","cat":{"cat_id":"cat_01","workspace_id":"ws_01","cat_slug":"app","state":"running","current_action":null,"node_id":"node_01","node_name":"worker-a","cpu":3,"memory_bytes":2147483648,"boot_image":"ubuntu-24.04","mounts":[],"last_error":null,"created_at_unix_ms":1,"updated_at_unix_ms":2,"destroyed_at_unix_ms":null,"current_action_started_at_unix_ms":null,"last_running_at_unix_ms":2}}"#;
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
                let response = br#"{"status":"ok","code":"cat_running","cat":{"cat_id":"cat_01","workspace_id":"ws_01","cat_slug":"app","state":"running","current_action":null,"node_id":"node_01","node_name":"worker-a","cpu":2,"memory_bytes":2147483648,"boot_image":"ubuntu-24.04","mounts":[],"last_error":null,"created_at_unix_ms":1,"updated_at_unix_ms":2,"destroyed_at_unix_ms":null,"current_action_started_at_unix_ms":null,"last_running_at_unix_ms":2}}"#;
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
    fn exec_sends_one_workspace_scoped_argv_request() {
        use clap::Parser as _;

        let files = tempfile::tempdir().unwrap();
        let env_path = files.path().join("exec.env");
        let stdin_path = files.path().join("stdin.bin");
        std::fs::write(&env_path, "# private input\nMODE=test\n").unwrap();
        std::fs::write(&stdin_path, b"request bytes").unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let captured = read_request(&mut stream);
            write_json_response(&mut stream, br#"{"exit_code":0,"stdout":"","stderr":""}"#);
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
        let argv = vec![
            "cats".to_owned(),
            "--api-url".to_owned(),
            base,
            "--token".to_owned(),
            "test-token".to_owned(),
            "--workspace".to_owned(),
            "ws_01".to_owned(),
            "exec".to_owned(),
            "app".to_owned(),
            "--timeout".to_owned(),
            "7".to_owned(),
            "--env-file".to_owned(),
            env_path.display().to_string(),
            "--stdin-file".to_owned(),
            stdin_path.display().to_string(),
            "--".to_owned(),
            "/usr/bin/printf".to_owned(),
            "%s".to_owned(),
            "literal argument".to_owned(),
        ];
        run(Cli::parse_from(argv)).unwrap();

        let (headers, body) = server.join().unwrap();
        assert_eq!(
            headers.lines().next().unwrap(),
            "POST /v1/workspaces/ws_01/cats/app/exec HTTP/1.1"
        );
        assert_eq!(
            request_header(&headers, "authorization"),
            "Bearer test-token"
        );
        let request: ExecRequest = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            request.command,
            ["/usr/bin/printf", "%s", "literal argument"]
        );
        assert_eq!(request.timeout_ms, Some(7_000));
        assert_eq!(request.env.get("MODE").map(String::as_str), Some("test"));
        assert_eq!(request.stdin, b"request bytes");
    }

    fn minimal_exec_request() -> ExecRequest {
        ExecRequest {
            command: vec!["true".to_owned()],
            timeout_ms: None,
            env: std::collections::BTreeMap::new(),
            stdin: Vec::new(),
        }
    }

    #[test]
    fn exec_rejects_oversized_declared_success_before_reading_its_body() {
        use std::io::Write as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_EXEC_RESPONSE_JSON_BYTES + 1
            )
            .unwrap();
            stream.flush().unwrap();
        });
        let client = runtime_test_client(base);
        let error = client
            .send_exec(
                client
                    .http
                    .post(client.url("/cats/app/exec"))
                    .json(&minimal_exec_request()),
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("exec response body exceeds"),
            "unexpected declared-length error: {error:#}"
        );
        server.join().unwrap();
    }

    #[test]
    fn exec_reads_an_exactly_maximum_declared_success_before_parsing_it() {
        use std::io::Write as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {MAX_EXEC_RESPONSE_JSON_BYTES}\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            stream
                .write_all(&vec![b' '; MAX_EXEC_RESPONSE_JSON_BYTES])
                .unwrap();
            stream.flush().unwrap();
        });
        let client = runtime_test_client(base);
        let error = client
            .send_exec(
                client
                    .http
                    .post(client.url("/cats/app/exec"))
                    .json(&minimal_exec_request()),
            )
            .unwrap_err();
        let error_chain = format!("{error:#}");
        assert!(
            error_chain.contains("invalid exec response"),
            "exact-cap body did not reach JSON parsing: {error_chain}"
        );
        assert!(
            !error_chain.contains("body exceeds"),
            "exact-cap body was rejected by the body limit: {error_chain}"
        );
        server.join().unwrap();
    }

    #[test]
    fn exec_rejects_oversized_chunked_success_at_the_stream_bound() {
        use std::io::Write as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:X}\r\n",
                MAX_EXEC_RESPONSE_JSON_BYTES + 1
            )
            .unwrap();
            let oversized = vec![b' '; MAX_EXEC_RESPONSE_JSON_BYTES + 1];
            stream.write_all(&oversized).unwrap();
            let _ = stream.write_all(b"\r\n0\r\n\r\n");
            let _ = stream.flush();
        });
        let client = runtime_test_client(base);
        let error = client
            .send_exec(
                client
                    .http
                    .post(client.url("/cats/app/exec"))
                    .json(&minimal_exec_request()),
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("exec response body exceeds"),
            "unexpected chunked-length error: {error:#}"
        );
        server.join().unwrap();
    }

    #[test]
    fn exec_error_body_uses_its_independent_small_cap() {
        use std::io::Write as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_EXEC_ERROR_RESPONSE_BYTES + 1
            )
            .unwrap();
            stream.flush().unwrap();
        });
        let client = runtime_test_client(base);
        let error = client
            .send_exec(
                client
                    .http
                    .post(client.url("/cats/app/exec"))
                    .json(&minimal_exec_request()),
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("exec error response body exceeds the 16384-byte limit"),
            "unexpected error-body cap: {error:#}"
        );
        server.join().unwrap();
    }

    #[test]
    fn exec_validates_output_after_the_bounded_json_read() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_request(&mut stream);
            let response = serde_json::to_vec(&ExecResponse {
                exit_code: 0,
                stdout: "x".repeat(cats_protocol::sessions::MAX_EXEC_OUTPUT_BYTES + 1),
                stderr: String::new(),
            })
            .unwrap();
            write_json_response(&mut stream, &response);
        });
        let client = runtime_test_client(base);
        let error = client
            .send_exec(
                client
                    .http
                    .post(client.url("/cats/app/exec"))
                    .json(&minimal_exec_request()),
            )
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("stdout and stderr exceed"),
            "ExecResponse validation was skipped: {error:#}"
        );
        server.join().unwrap();
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
            "ls", "show", "exec", "shell", "deploy", "disk", "run", "suspend", "warm", "cold",
            "destroy",
        ] {
            assert!(
                root_help.contains(&format!("\n  {supported} ")),
                "production command {supported:?} is hidden from root help"
            );
        }
        assert!(!root_help.contains("--no-wait"));
        // `get` is a deprecated alias for `show`: still accepted so existing
        // scripts keep working, but no longer advertised.
        assert!(
            !root_help.contains("\n  get "),
            "the deprecated `get` alias must not be advertised"
        );
        assert!(matches!(
            Cli::parse_from(["cats", "get", "web"]).command,
            Command::Get { .. }
        ));
        let show = Cli::parse_from(["cats", "show", "web"]);
        assert!(matches!(
            show.command,
            Command::Show {
                watch: false,
                usage: false,
                ..
            }
        ));
        assert_eq!(
            show.color,
            ColorChoice::Auto,
            "color must default to following the terminal"
        );

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
