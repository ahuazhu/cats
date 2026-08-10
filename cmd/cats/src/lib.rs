//! `cats` CLI: the command-line user surface. Commands express intent against
//! the same versioned API as the web consoles; mutations return operations
//! that the CLI waits on by default (`--no-wait` to skip). No storage/node
//! internals ever appear here.

mod auth;
#[cfg(unix)]
mod cat_create_pending;
#[cfg(not(unix))]
#[path = "cat_create_pending_unsupported.rs"]
mod cat_create_pending;
#[cfg(all(test, unix))]
#[path = "cat_create_pending_unsupported.rs"]
#[allow(dead_code)] // Compile-shape oracle: production selects exactly one implementation.
mod cat_create_pending_unsupported_compile_shape;
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
mod shell;
#[cfg(unix)]
mod stable_unix_fs;

use std::io::{Read as _, Write as _};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use cats_api::cat_create::{
    decode_cat_create_v2_accepted_response, CatCreateV2AcceptedResponse, CatCreateV2Request,
};
use clap::{Args, Parser, Subcommand};
use serde_json::json;

use cats_api::oci::{DeployOciRequest, OciDeployment, OciRegistryAuth};
use cats_api::requests::*;
use cats_api::resources::*;

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
        name: String,
        /// Content-addressed boot image manifest (`sha256:<64 lowercase hex>`).
        #[arg(long)]
        boot_image_digest: String,
        #[arg(long, default_value_t = 2)]
        cpus: u32,
        #[arg(long, default_value = "2GiB")]
        memory: String,
        #[arg(long, default_value = "1GiB")]
        root_size: String,
        /// What an fsync inside the Cat promises, for the disks this command
        /// creates. `strict`: fsync returns once the data is durable in the
        /// object store and survives losing the host. `relaxed`: fsync
        /// returns after a local commit and the data reaches the object store
        /// asynchronously; an unclean host loss may drop recent acknowledged
        /// writes, so choose `strict` when that is not acceptable.
        #[arg(long, default_value = "strict", value_parser = ["strict", "relaxed"])]
        durability: String,
    },
    /// List cats.
    #[command(hide = true)]
    Ls,
    /// Show one cat.
    #[command(hide = true)]
    Get { name: String },
    /// Start (or wake) a cat.
    #[command(hide = true)]
    Start { name: String },
    /// Stop a cat (release compute; disks stay durable).
    #[command(hide = true)]
    Stop { name: String },
    /// Suspend a cat (pause + page-out; host-bound).
    #[command(hide = true)]
    Suspend { name: String },
    /// Resume a suspended/warm cat.
    #[command(hide = true)]
    Resume { name: String },
    /// Demote a cat to Warm (snapshot + VMM exit; host-bound).
    #[command(hide = true)]
    Warm { name: String },
    /// Force everything written inside the cat to durable storage now.
    /// On relaxed disks this is the escape hatch that buys one strict
    /// moment on demand; on strict disks it is a cheap no-op.
    #[command(hide = true)]
    Sync { name: String },
    /// Destroy a cat and its root disk (persistent disks survive).
    #[command(hide = true)]
    Destroy { name: String },
    /// Run a command inside the cat (wakes it if needed).
    #[command(hide = true)]
    Exec {
        name: String,
        /// How long the command may run, in seconds. The API accepts up to an
        /// hour; without this the default is 120 s, which a build or a test suite
        /// can exceed.
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
        /// Read newline-delimited NAME=VALUE entries and pass them only to the
        /// child process. This avoids putting deploy secrets in argv.
        #[arg(long, value_name = "PATH")]
        env_file: Option<std::path::PathBuf>,
        /// Connect the contents of PATH to the command's standard input.
        #[arg(long, value_name = "PATH")]
        stdin_file: Option<std::path::PathBuf>,
        /// Command argv, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Deploy a digest-pinned OCI image as a supervised service in a Cat.
    #[command(hide = true)]
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
    /// Open an interactive login shell inside the cat.
    #[command(hide = true)]
    Shell { name: String },
    /// Configure or explain work-driven auto-suspend.
    #[command(hide = true)]
    Sleep {
        #[command(subcommand)]
        cmd: SleepCommand,
    },
    /// Show or change a cat's absolute expiry (automatic deletion time).
    #[command(hide = true)]
    Expiry {
        name: String,
        /// Expire SECONDS from now.
        #[arg(long, value_name = "SECONDS", conflicts_with_all = ["at", "never"])]
        r#in: Option<u64>,
        /// Expire at an absolute unix timestamp (seconds).
        #[arg(long, value_name = "UNIX", conflicts_with_all = ["in", "never"])]
        at: Option<i64>,
        /// Clear the expiry so the cat never expires.
        #[arg(long, conflicts_with_all = ["in", "at"])]
        never: bool,
    },
    /// Disk management.
    #[command(hide = true)]
    Disk {
        #[command(subcommand)]
        cmd: DiskCommand,
    },
    /// Mount a persistent disk into a cat.
    #[command(hide = true)]
    Mount {
        disk: String,
        #[arg(long)]
        cat: String,
        #[arg(long, default_value = "/data")]
        at: String,
    },
    /// Unmount a persistent disk.
    #[command(hide = true)]
    Unmount { disk: String },
    /// Expose a guest port through a stable endpoint.
    #[command(hide = true)]
    Expose {
        cat: String,
        port: u16,
        #[arg(long, default_value = "web")]
        name: String,
        #[arg(long, default_value = "http")]
        protocol: String,
        /// Disable wake-on-request for this endpoint.
        #[arg(long)]
        no_wake: bool,
    },
    /// List endpoints of a cat.
    #[command(hide = true)]
    Endpoint {
        #[command(subcommand)]
        cmd: EndpointCommand,
    },
    /// Inspect an operation.
    #[command(hide = true)]
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
pub enum SleepCommand {
    On { name: String },
    Off { name: String },
    Status { name: String },
}

#[derive(Subcommand, Debug)]
pub enum DiskCommand {
    Create {
        name: String,
        #[arg(long)]
        size: String,
        /// See `cats create --durability`.
        #[arg(long, default_value = "strict", value_parser = ["strict", "relaxed"])]
        durability: String,
    },
    Ls,
    Get {
        name: String,
    },
    Resize {
        name: String,
        #[arg(long)]
        size: String,
    },
    Delete {
        name: String,
    },
    Snapshot(SnapshotArgs),
}

#[derive(Args, Debug)]
pub struct SnapshotArgs {
    pub name: String,
}

#[derive(Subcommand, Debug)]
pub enum EndpointCommand {
    Ls { cat: String },
}

#[derive(Subcommand, Debug)]
pub enum OperationCommand {
    Ls,
    Get { id: String },
    Wait { id: String },
}

#[derive(Subcommand, Debug)]
pub enum AdminCommand {
    /// Sign in to the deployment's independent fleet-administrator scope.
    Login,
    /// Remove the independent fleet-administrator session.
    Logout,
    /// Show fleet health, lifecycle and capacity counters.
    #[command(hide = true)]
    Monitoring,
    /// List worker nodes with assignments and last telemetry.
    #[command(hide = true)]
    Nodes,
    /// Inspect or manage one worker node.
    #[command(hide = true)]
    Node {
        #[command(subcommand)]
        cmd: AdminNodeCommand,
    },
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
}

#[derive(Debug)]
pub(crate) struct RuntimeNodeAuthorityAuth<'a> {
    pub(crate) deployment_id: Option<&'a str>,
    pub(crate) provisioner_credential_id: Option<&'a str>,
    pub(crate) provisioner_private_key_file: Option<&'a std::path::Path>,
}

#[derive(Subcommand, Debug)]
pub enum RuntimeNodeCommand {
    /// Atomically provision one Node identity and its initial cordoned policy.
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

#[derive(Subcommand, Debug)]
pub enum AdminNodeCommand {
    Get {
        id: String,
    },
    Cordon {
        id: String,
    },
    Uncordon {
        id: String,
    },
    /// Stop and reschedule every Cat, then leave the node cordoned.
    Drain {
        id: String,
    },
    /// Revoke claims on a lost node after external Host fencing is proven.
    Fence {
        id: String,
        /// Confirm the old Host is powered off or isolated from execution.
        #[arg(long)]
        confirm_host_stopped_or_isolated: bool,
    },
    /// Remove an empty cordoned/lost/fenced node from the registry.
    Delete {
        id: String,
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
                .build()?;
            let base = cat_create_pending::canonical_api_origin(&auth::configured_api_url(
                cli.api_url.as_deref(),
            )?)?;
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
                .build()?,
            base: cat_create_pending::canonical_api_origin(&session.api_url)?,
            token: session.access_token,
            workspace_id: session.workspace,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/workspaces/{}{}", self.base, self.workspace_id, path)
    }

    fn admin_url(&self, path: &str) -> String {
        format!("{}/v1/admin{}", self.base, path)
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
            if let Ok(err) = serde_json::from_slice::<cats_api::error::ErrorBody>(&body) {
                bail!("{} ({:?})", err.message, err.code);
            }
            bail!("HTTP {status}: {}", String::from_utf8_lossy(&body));
        }
        Ok((status, body))
    }

    fn send_cat_create(
        &self,
        pending: &cat_create_pending::PreparedCatCreate,
    ) -> Result<CatCreateHttpResponse> {
        const MAX_RESPONSE_BYTES: usize = 64 * 1024;

        pending.assert_current()?;
        anyhow::ensure!(
            pending.origin() == self.base,
            "pending Cat-create request is bound to a different API origin"
        );
        let exact_url = format!("{}{}", pending.origin(), pending.target());
        let response = self
            .http
            .post(&exact_url)
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::CONTENT_TYPE, pending.content_type())
            .header("Idempotency-Key", pending.idempotency_key())
            .body(pending.body()?)
            .send()
            .context("control plane unreachable")?;
        anyhow::ensure!(
            response.url().as_str() == exact_url,
            "Cat-create request did not remain on its exact canonical URL"
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
            "Cat-create response exceeds its closed byte limit"
        );
        Ok(CatCreateHttpResponse {
            status,
            content_types,
            content_encodings,
            body,
        })
    }

    fn get(&self, path: &str) -> Result<serde_json::Value> {
        self.send(self.http.get(self.url(path)))
    }

    fn post(&self, path: &str, body: Option<serde_json::Value>) -> Result<serde_json::Value> {
        let mut req = self.http.post(self.url(path));
        req = match body {
            Some(b) => req.json(&b),
            None => req.header("content-length", "0"),
        };
        self.send(req)
    }

    fn put(&self, path: &str, body: serde_json::Value) -> Result<serde_json::Value> {
        self.send(self.http.put(self.url(path)).json(&body))
    }

    fn wait_operation(&self, op_id: &str) -> Result<Operation> {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let v = self.send(
                self.http
                    .get(format!("{}/v1/operations/{op_id}", self.base)),
            )?;
            let op: Operation = serde_json::from_value(v)?;
            if op.phase.is_terminal() {
                if let Some(err) = &op.error {
                    bail!("operation {op_id} failed: {}", err.message);
                }
                return Ok(op);
            }
            if Instant::now() > deadline {
                bail!("operation {op_id} did not finish in time");
            }
            std::thread::sleep(Duration::from_millis(150));
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
    let listed: cats_api::requests::ListResponse<cats_api::auth::Workspace> = response
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

/// Time left before the control plane deletes this cat, shortest readable
/// form. Every listing carries it: an expiry destroys data on its own, so it
/// must not be something you only see when you go looking for it.
fn expires_in(cat: &Cat) -> String {
    match cat.expires_at_unix {
        None => "never".to_string(),
        Some(at) => time_left(at - unix_now()),
    }
}

/// Shortest readable form of a countdown, `overdue` once it has run out.
fn time_left(secs: i64) -> String {
    if secs <= 0 {
        return "overdue".to_string();
    }
    let (days, hours, minutes) = (secs / 86_400, secs % 86_400 / 3_600, secs % 3_600 / 60);
    if days > 0 {
        format!("{days}d{hours}h")
    } else if hours > 0 {
        format!("{hours}h{minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m")
    } else {
        format!("{secs}s")
    }
}

fn print_cat(cat: &Cat, json_mode: bool) {
    if json_mode {
        println!("{}", serde_json::to_string_pretty(cat).unwrap());
    } else {
        println!(
            "{:<16} {:>4} cpu {:>6} MiB  desired={:<9} observed={:<9} expires={:<8} \
             auto-suspend={} node={}",
            cat.name,
            cat.spec.cpus,
            cat.spec.memory_mib,
            format!("{:?}", cat.desired_state).to_lowercase(),
            format!("{:?}", cat.observed_state).to_lowercase(),
            expires_in(cat),
            if cat.auto_suspend { "on" } else { "off" },
            cat.node_id.as_deref().unwrap_or("-")
        );
    }
}

const RUNTIME_CUTOVER_UNSUPPORTED: &str =
    "is unavailable until its signed runtime-authority projection lands; no HTTP request was sent";

/// Retired product-authority commands stay parseable for a clear local error,
/// but are hidden from shipped help and rejected before Client construction.
/// This prevents even workspace resolution or authentication refresh from
/// turning an unsupported invocation into outbound traffic.
fn runtime_cutover_unsupported(command: &Command) -> Option<&'static str> {
    match command {
        Command::Ls | Command::Get { .. } => Some("Cat read/list"),
        Command::Start { .. }
        | Command::Stop { .. }
        | Command::Suspend { .. }
        | Command::Resume { .. }
        | Command::Warm { .. }
        | Command::Sync { .. }
        | Command::Destroy { .. }
        | Command::Exec { .. }
        | Command::Deploy { .. }
        | Command::Shell { .. }
        | Command::Sleep { .. }
        | Command::Expiry { .. } => Some("Cat lifecycle"),
        Command::Disk { .. } | Command::Mount { .. } | Command::Unmount { .. } => {
            Some("PersistentDisk")
        }
        Command::Expose { .. } | Command::Endpoint { .. } => Some("Endpoint"),
        Command::Operation { .. } => Some("Operation"),
        Command::Admin {
            cmd: AdminCommand::Monitoring | AdminCommand::Nodes | AdminCommand::Node { .. },
        } => Some("legacy fleet administration"),
        Command::Login
        | Command::Logout
        | Command::Whoami
        | Command::Workspace { .. }
        | Command::Token { .. }
        | Command::Create { .. }
        | Command::Admin {
            cmd: AdminCommand::Login | AdminCommand::Logout | AdminCommand::RuntimeNode { .. },
        } => None,
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
        _ => {}
    }
    if let Some(surface) = runtime_cutover_unsupported(&cli.command) {
        bail!("{surface} {RUNTIME_CUTOVER_UNSUPPORTED}");
    }
    let client = Client::new(&cli)?;

    let mutate = |resp: serde_json::Value| -> Result<()> {
        let parsed: CatOperationResponse = serde_json::from_value(resp.clone())
            .map_err(|e| anyhow!("unexpected response: {e}; body {resp}"))?;
        if cli.no_wait {
            println!("operation {} accepted", parsed.operation.id);
            return Ok(());
        }
        client.wait_operation(&parsed.operation.id)?;
        let v = client.get(&format!("/cats/{}", parsed.cat.name));
        match v {
            Ok(v) => {
                let cat: Cat = serde_json::from_value(v)?;
                print_cat(&cat, cli.json);
            }
            // The resource may legitimately be gone (destroy).
            Err(_) => println!("done"),
        }
        Ok(())
    };

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
            root_size,
            durability,
        } => {
            let durability = match durability.as_str() {
                "strict" => cats_api::runtime_reconciliation::Durability::Strict,
                "relaxed" => cats_api::runtime_reconciliation::Durability::Relaxed,
                _ => unreachable!("clap validates --durability"),
            };
            let body = CatCreateV2Request::new(
                name.clone(),
                boot_image_digest.clone(),
                *cpus,
                parse_size(memory)?,
                parse_size(root_size)?,
                durability,
            )
            .context("invalid Cat-create request")?;
            let request_body = serde_json::to_vec(&body)?;
            let pending = cat_create_pending::PreparedCatCreate::prepare(
                &client.base,
                &client.workspace_id,
                &request_body,
            )
            .context(
                "could not durably prepare Cat-create recovery state; no HTTP request was sent",
            )?;
            let response = client.send_cat_create(&pending).with_context(|| {
                format!(
                    "Cat-create response is ambiguous; the exact path, body, and Idempotency-Key remain pending at {}",
                    pending.pending_path().display()
                )
            })?;
            match classify_cat_create_response(&response) {
                CatCreateResponseClassification::Accepted(accepted) => {
                    // Report the durable identity before acknowledging local
                    // state. A crash before this output leaves the exact
                    // request replayable; a crash after it can only repeat the
                    // same accepted identity.
                    if cli.json {
                        println!("{}", serde_json::to_string_pretty(&accepted)?);
                    } else {
                        println!(
                            "Cat {} accepted (operation {})",
                            accepted.cat_id, accepted.operation_id
                        );
                    }
                    std::io::stdout()
                        .flush()
                        .context("flush accepted Cat/Operation identity before cleanup")?;
                    pending.clear().context(
                        "Cat-create was accepted and reported, but its pending recovery state could not be durably cleared",
                    )?;
                    Ok(())
                }
                CatCreateResponseClassification::NameConflict => {
                    pending.clear().context(
                        "Cat name conflict is terminal, but its pending recovery state could not be durably cleared",
                    )?;
                    bail!("cat name already exists (AlreadyExists)")
                }
                CatCreateResponseClassification::Nonterminal => {
                    let detail =
                        serde_json::from_slice::<cats_api::error::ErrorBody>(&response.body)
                            .map(|error| format!("{} ({:?})", error.message, error.code))
                            .unwrap_or_else(|_| {
                                format!(
                                    "HTTP {}: {}",
                                    response.status,
                                    String::from_utf8_lossy(&response.body)
                                )
                            });
                    bail!(
                        "Cat-create response was not an exact terminal result ({detail}); replay the same command to reuse the pending Idempotency-Key at {}",
                        pending.pending_path().display()
                    )
                }
            }
        }
        Command::Ls => {
            let v = client.get("/cats")?;
            let list: ListResponse<Cat> = serde_json::from_value(v)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&list.items).unwrap());
            } else {
                for cat in &list.items {
                    print_cat(cat, false);
                }
            }
            Ok(())
        }
        Command::Get { name } => {
            let cat: Cat = serde_json::from_value(client.get(&format!("/cats/{name}"))?)?;
            print_cat(&cat, cli.json);
            if !cli.json {
                let endpoints: ListResponse<Endpoint> =
                    serde_json::from_value(client.get(&format!("/cats/{name}/endpoints"))?)?;
                if let Some(endpoint) = endpoints.items.iter().find(|ep| ep.name == "web") {
                    println!("URL: https://{}", endpoint.hostname);
                }
            }
            Ok(())
        }
        Command::Start { name } => {
            mutate(client.post(&format!("/cats/{name}/actions/start"), None)?)
        }
        Command::Stop { name } => mutate(client.post(&format!("/cats/{name}/actions/stop"), None)?),
        Command::Suspend { name } => {
            mutate(client.post(&format!("/cats/{name}/actions/suspend"), None)?)
        }
        Command::Resume { name } => {
            mutate(client.post(&format!("/cats/{name}/actions/resume"), None)?)
        }
        Command::Warm { name } => mutate(client.post(&format!("/cats/{name}/actions/warm"), None)?),
        Command::Sync { name } => {
            client.post(&format!("/cats/{name}/actions/sync"), None)?;
            println!("synced {name}: all acknowledged writes are durable");
            Ok(())
        }
        Command::Destroy { name } => {
            let resp = client.send(client.http.delete(client.url(&format!("/cats/{name}"))))?;
            let parsed: CatOperationResponse = serde_json::from_value(resp)?;
            if cli.no_wait {
                println!("operation {} accepted", parsed.operation.id);
                return Ok(());
            }
            client.wait_operation(&parsed.operation.id)?;
            println!("destroyed {name}");
            Ok(())
        }
        Command::Exec {
            name,
            timeout,
            env_file,
            stdin_file,
            command,
        } => {
            let env = env_file
                .as_deref()
                .map(read_exec_env_file)
                .transpose()?
                .unwrap_or_default();
            let stdin = stdin_file
                .as_deref()
                .map(std::fs::read)
                .transpose()
                .context("read exec stdin file")?
                .unwrap_or_default();
            let mut body = json!({ "command": command, "env": env, "stdin": stdin });
            if let Some(seconds) = timeout {
                body["timeout_ms"] = json!(seconds * 1000);
            }
            let request_timeout = Duration::from_secs(timeout.unwrap_or(120).saturating_add(15));
            let v = client.send(
                client
                    .http
                    .post(client.url(&format!("/cats/{name}/exec")))
                    .timeout(request_timeout)
                    .json(&body),
            )?;
            let out: ExecResponse = serde_json::from_value(v)?;
            print!("{}", out.stdout);
            eprint!("{}", out.stderr);
            if out.exit_code != 0 {
                bail!("command exited with {}", out.exit_code);
            }
            Ok(())
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
            // wait is named by an operation instead of being answered inline.
            // Both are successes; follow the operation and read the result.
            let deployment: OciDeployment = if status == reqwest::StatusCode::ACCEPTED {
                let accepted: OciDeploymentOperationResponse = serde_json::from_value(value)?;
                follow_oci_deployment(&client, &accepted.operation.id, name, app)?
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
        Command::Shell { name } => {
            shell::run(&client.base, &client.workspace_id, &client.token, name)
        }
        Command::Sleep { cmd } => {
            let response = match cmd {
                SleepCommand::On { name } => client.put(
                    &format!("/cats/{name}/auto-suspend"),
                    json!({ "enabled": true }),
                )?,
                SleepCommand::Off { name } => client.put(
                    &format!("/cats/{name}/auto-suspend"),
                    json!({ "enabled": false }),
                )?,
                SleepCommand::Status { name } => {
                    let work: CatWorkStatus =
                        serde_json::from_value(client.get(&format!("/cats/{name}/work"))?)?;
                    if cli.json {
                        println!("{}", serde_json::to_string_pretty(&work)?);
                    } else {
                        print_work_status(&work);
                    }
                    return Ok(());
                }
            };
            let response: AutoSuspendResponse = serde_json::from_value(response)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                print_work_status(&response.work);
            }
            Ok(())
        }
        Command::Expiry {
            name,
            r#in,
            at,
            never,
        } => {
            let cat: Cat = if r#in.is_none() && at.is_none() && !never {
                serde_json::from_value(client.get(&format!("/cats/{name}/expiry"))?)?
            } else {
                let expires_at_unix = match (r#in, at, never) {
                    (Some(secs), None, false) => Some(unix_now() + *secs as i64),
                    (None, Some(unix), false) => Some(*unix),
                    (None, None, true) => None,
                    _ => unreachable!("clap conflicts_with_all"),
                };
                serde_json::from_value(client.put(
                    &format!("/cats/{name}/expiry"),
                    json!({ "expires_at_unix": expires_at_unix }),
                )?)?
            };
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&cat)?);
            } else {
                match cat.expires_at_unix {
                    Some(unix) if unix <= unix_now() => println!(
                        "{} expires at unix {unix}, already past; the control plane \
                         deletes it on the next tick",
                        cat.name
                    ),
                    Some(unix) => println!(
                        "{} expires at unix {unix} (in {})",
                        cat.name,
                        expires_in(&cat)
                    ),
                    None => println!("{} never expires", cat.name),
                }
            }
            Ok(())
        }
        Command::Disk { cmd } => run_disk(&client, &cli, cmd),
        Command::Mount { disk, cat, at } => {
            client.post(
                &format!("/disks/{disk}/actions/mount"),
                Some(json!({ "cat_id": cat, "mount_at": at })),
            )?;
            println!("mounted {disk} into {cat} at {at}");
            Ok(())
        }
        Command::Unmount { disk } => {
            client.post(&format!("/disks/{disk}/actions/unmount"), Some(json!({})))?;
            println!("unmounted {disk}");
            Ok(())
        }
        Command::Expose {
            cat,
            port,
            name,
            protocol,
            no_wake,
        } => {
            let v = client.post(
                &format!("/cats/{cat}/endpoints"),
                Some(json!({
                    "name": name,
                    "target_port": port,
                    "protocol": protocol,
                    "wake_policy": if *no_wake { "no_wake" } else { "wake_on_request" },
                })),
            )?;
            let resp: EndpointResponse = serde_json::from_value(v)?;
            println!("https://{}", resp.endpoint.hostname);
            Ok(())
        }
        Command::Endpoint { cmd } => match cmd {
            EndpointCommand::Ls { cat } => {
                let v = client.get(&format!("/cats/{cat}/endpoints"))?;
                let list: ListResponse<Endpoint> = serde_json::from_value(v)?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&list.items)?);
                    return Ok(());
                }
                for ep in list.items {
                    println!(
                        "{:<12} {:<40} port={} wake={:?}",
                        ep.name,
                        format!("https://{}", ep.hostname),
                        ep.target_port,
                        ep.wake_policy
                    );
                }
                Ok(())
            }
        },
        Command::Operation { cmd } => match cmd {
            OperationCommand::Ls => {
                let v = client.get("/operations")?;
                let list: ListResponse<Operation> = serde_json::from_value(v)?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&list.items).unwrap());
                } else {
                    for operation in list.items {
                        println!(
                            "{:<18} {:<18} phase={:<10} resource={}",
                            operation.id,
                            operation.kind,
                            format!("{:?}", operation.phase).to_lowercase(),
                            operation.resource_id
                        );
                    }
                }
                Ok(())
            }
            OperationCommand::Get { id } => {
                let v = client.send(
                    client
                        .http
                        .get(format!("{}/v1/operations/{id}", client.base)),
                )?;
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
                Ok(())
            }
            OperationCommand::Wait { id } => {
                let op = client.wait_operation(id)?;
                println!("{:?}", op.phase);
                Ok(())
            }
        },
        Command::Admin { cmd } => run_admin(&client, &cli, cmd),
    }
}

/// Follow an accepted OCI deployment to its outcome.
///
/// Polls the operation, then reads the deployment back. The deploy is durable
/// and keyed on `(cat, app, digest)`, so interrupting this wait loses only the
/// waiting: re-running the same deploy replays the result rather than
/// redeploying.
fn follow_oci_deployment(
    client: &Client,
    operation_id: &str,
    cat: &str,
    app: &str,
) -> Result<OciDeployment> {
    loop {
        let operation: Operation = serde_json::from_value(
            client.send(
                client
                    .http
                    .get(format!("{}/v1/operations/{operation_id}", client.base)),
            )?,
        )?;
        match operation.phase {
            OperationPhase::Succeeded => break,
            OperationPhase::Failed => {
                let message = operation
                    .error
                    .map(|error| error.message)
                    .unwrap_or_else(|| "deployment failed".to_string());
                bail!("{message}");
            }
            OperationPhase::Pending | OperationPhase::Running => {
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
    let listed: ListResponse<OciDeployment> =
        serde_json::from_value(client.get(&format!("/cats/{cat}/oci-deployments"))?)?;
    listed
        .items
        .into_iter()
        .find(|deployment| deployment.app == app)
        .with_context(|| format!("deployment of {app} succeeded but is not listed"))
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

fn print_work_status(work: &CatWorkStatus) {
    println!(
        "auto-suspend={} work={} guest-signal={} eligible={} reason={}",
        if work.auto_suspend { "on" } else { "off" },
        work.active_work_count,
        if work.guest_signal_fresh {
            "fresh"
        } else {
            "stale"
        },
        work.can_suspend_now,
        work.reason
    );
    for lease in &work.leases {
        println!(
            "  {:?} {} label={} expires_at_ms={}",
            lease.kind, lease.id, lease.label, lease.expires_at_unix_ms
        );
    }
}

fn run_admin(client: &Client, cli: &Cli, cmd: &AdminCommand) -> Result<()> {
    match cmd {
        AdminCommand::Monitoring => {
            let value = client.send(client.http.get(client.admin_url("/monitoring")))?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&value).unwrap());
            } else {
                let overview: MonitoringOverview = serde_json::from_value(value)?;
                println!(
                    "cats total={} running={} suspended={} warm={} cold={} failed/unknown={}",
                    overview.cats.total,
                    overview.cats.running,
                    overview.cats.suspended,
                    overview.cats.warm,
                    overview.cats.cold,
                    overview.cats.failed_or_unknown
                );
                println!(
                    "nodes total={} ready={} cordoned={} draining={} lost={} fenced={} orphans={}",
                    overview.nodes.total,
                    overview.nodes.ready,
                    overview.nodes.cordoned,
                    overview.nodes.draining,
                    overview.nodes.lost,
                    overview.nodes.fenced,
                    overview.orphan_cats
                );
                println!(
                    "capacity cpu={}/{} memory={}MiB/{}MiB",
                    overview.capacity.assigned_cpus,
                    overview.capacity.total_cpus,
                    overview.capacity.assigned_memory_mib,
                    overview.capacity.total_memory_mib
                );
                println!(
                    "operations pending={} running={} succeeded={} failed={}",
                    overview.operations.pending,
                    overview.operations.running,
                    overview.operations.succeeded,
                    overview.operations.failed
                );
            }
            Ok(())
        }
        AdminCommand::Nodes => {
            let value = client.send(client.http.get(client.admin_url("/nodes")))?;
            let list: ListResponse<NodeSummary> = serde_json::from_value(value)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&list.items).unwrap());
            } else {
                for node in &list.items {
                    print_node(node);
                }
            }
            Ok(())
        }
        AdminCommand::Node { cmd } => {
            let (id, action, fence_request) = match cmd {
                AdminNodeCommand::Get { id } => (id, None, None),
                AdminNodeCommand::Cordon { id } => (id, Some("cordon"), None),
                AdminNodeCommand::Uncordon { id } => (id, Some("uncordon"), None),
                AdminNodeCommand::Drain { id } => (id, Some("drain"), None),
                AdminNodeCommand::Fence {
                    id,
                    confirm_host_stopped_or_isolated,
                } => {
                    anyhow::ensure!(
                        confirm_host_stopped_or_isolated,
                        "refusing to fence without --confirm-host-stopped-or-isolated"
                    );
                    (
                        id,
                        Some("fence"),
                        Some(FenceNodeRequest {
                            confirm_host_stopped_or_isolated: true,
                        }),
                    )
                }
                AdminNodeCommand::Delete { id } => {
                    client.send(
                        client
                            .http
                            .delete(client.admin_url(&format!("/nodes/{id}"))),
                    )?;
                    println!("deleted {id}");
                    return Ok(());
                }
            };
            let request = if let Some(action) = action {
                let request = client
                    .http
                    .post(client.admin_url(&format!("/nodes/{id}/actions/{action}")));
                if let Some(body) = fence_request {
                    request.json(&body)
                } else {
                    request.header("content-length", "0")
                }
            } else {
                client.http.get(client.admin_url(&format!("/nodes/{id}")))
            };
            let value = client.send(request)?;
            let summary: NodeSummary = serde_json::from_value(value)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&summary).unwrap());
            } else {
                print_node(&summary);
            }
            Ok(())
        }
        AdminCommand::RuntimeNode { .. } => {
            unreachable!("Runtime Node authority commands bypass workspace API construction")
        }
        AdminCommand::Login | AdminCommand::Logout => {
            unreachable!("fleet administrator login commands bypass workspace API construction")
        }
    }
}

fn print_node(summary: &NodeSummary) {
    let telemetry = summary.node.telemetry.as_ref();
    println!(
        "{:<18} state={:<9} cats={} orphans={} cpu={}/{} memory={}MiB/{}MiB heartbeat={}s load={}",
        summary.node.id,
        format!("{:?}", summary.node.state).to_lowercase(),
        summary.assigned_cats,
        summary.orphan_cats,
        summary.assigned_cpus,
        summary.node.capacity.cpus,
        summary.assigned_memory_mib,
        summary.node.capacity.memory_mib,
        summary.heartbeat_age_seconds,
        telemetry
            .and_then(|sample| sample.load_average_1m)
            .map(|value| format!("{value:.2}"))
            .unwrap_or_else(|| "-".to_string())
    );
}

fn run_disk(client: &Client, cli: &Cli, cmd: &DiskCommand) -> Result<()> {
    match cmd {
        DiskCommand::Create {
            name,
            size,
            durability,
        } => {
            let v = client.post(
                "/disks",
                Some(json!({
                    "name": name,
                    "size_bytes": parse_size(size)?,
                    "durability": durability,
                })),
            )?;
            let disk: Disk = serde_json::from_value(v)?;
            print_disk(&disk, cli.json);
            Ok(())
        }
        DiskCommand::Ls => {
            let v = client.get("/disks")?;
            let list: ListResponse<Disk> = serde_json::from_value(v)?;
            for d in &list.items {
                print_disk(d, cli.json);
            }
            Ok(())
        }
        DiskCommand::Get { name } => {
            let disk: Disk = serde_json::from_value(client.get(&format!("/disks/{name}"))?)?;
            print_disk(&disk, cli.json);
            Ok(())
        }
        DiskCommand::Resize { name, size } => {
            let v = client.post(
                &format!("/disks/{name}/actions/resize"),
                Some(json!({ "size_bytes": parse_size(size)? })),
            )?;
            let disk: Disk = serde_json::from_value(v)?;
            print_disk(&disk, cli.json);
            Ok(())
        }
        DiskCommand::Delete { name } => {
            client.send(client.http.delete(client.url(&format!("/disks/{name}"))))?;
            println!("deleted {name}");
            Ok(())
        }
        DiskCommand::Snapshot(args) => {
            let v = client.post(&format!("/disks/{}/snapshots", args.name), Some(json!({})))?;
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
            Ok(())
        }
    }
}

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

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

const CAT_CREATE_NAME_CONFLICT_BODY: &[u8] =
    br#"{"code":"already_exists","message":"cat name already exists"}"#;

struct CatCreateHttpResponse {
    status: reqwest::StatusCode,
    content_types: Vec<Vec<u8>>,
    content_encodings: Vec<Vec<u8>>,
    body: Vec<u8>,
}

enum CatCreateResponseClassification {
    Accepted(CatCreateV2AcceptedResponse),
    NameConflict,
    Nonterminal,
}

fn classify_cat_create_response(
    response: &CatCreateHttpResponse,
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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_BOOT_IMAGE: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn size_parsing() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("8GiB").unwrap(), 8 << 30);
        assert_eq!(parse_size("512MiB").unwrap(), 512 << 20);
        assert_eq!(parse_size("4KiB").unwrap(), 4096);
        assert!(parse_size("abc").is_err());
    }

    #[test]
    fn countdown_formatting() {
        assert_eq!(time_left(0), "overdue");
        assert_eq!(time_left(-5), "overdue");
        assert_eq!(time_left(45), "45s");
        assert_eq!(time_left(90), "1m");
        assert_eq!(time_left(3_600), "1h0m");
        assert_eq!(time_left(28_800), "8h0m");
        assert_eq!(time_left(90_000), "1d1h");
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
            "--boot-image-digest",
            TEST_BOOT_IMAGE,
            "--cpus",
            "4",
            "--memory",
            "8GiB",
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
                assert_eq!(boot_image_digest, TEST_BOOT_IMAGE);
            }
            _ => panic!("wrong parse"),
        }
        let cli = Cli::parse_from([
            "cats",
            "create",
            "ci",
            "--boot-image-digest",
            TEST_BOOT_IMAGE,
            "--durability",
            "relaxed",
        ]);
        match cli.command {
            Command::Create { durability, .. } => assert_eq!(durability, "relaxed"),
            _ => panic!("wrong parse"),
        }
        // No flag means strict: the honest default.
        let cli = Cli::parse_from([
            "cats",
            "create",
            "db",
            "--boot-image-digest",
            TEST_BOOT_IMAGE,
        ]);
        match cli.command {
            Command::Create { durability, .. } => assert_eq!(durability, "strict"),
            _ => panic!("wrong parse"),
        }
        assert!(Cli::try_parse_from([
            "cats",
            "create",
            "x",
            "--boot-image-digest",
            TEST_BOOT_IMAGE,
            "--durability",
            "fast",
        ])
        .is_err());
        assert!(Cli::try_parse_from(["cats", "create", "x"]).is_err());
        assert!(Cli::try_parse_from([
            "cats",
            "create",
            "x",
            "--boot-image-digest",
            TEST_BOOT_IMAGE,
            "--disk",
            "legacy",
        ])
        .is_err());
        assert!(matches!(
            Cli::parse_from(["cats", "sync", "dev"]).command,
            Command::Sync { name } if name == "dev"
        ));
        let with_timeout = Cli::parse_from([
            "cats",
            "exec",
            "dev",
            "--timeout",
            "900",
            "--",
            "cargo",
            "build",
        ]);
        match with_timeout.command {
            Command::Exec {
                timeout, command, ..
            } => {
                assert_eq!(
                    timeout,
                    Some(900),
                    "a long build needs more than the default"
                );
                assert_eq!(command, vec!["cargo", "build"]);
            }
            other => panic!("expected exec, got {other:?}"),
        }
        let cli = Cli::parse_from(["cats", "exec", "dev", "--", "git", "status"]);
        match cli.command {
            Command::Exec {
                command, timeout, ..
            } => {
                assert_eq!(command, vec!["git", "status"]);
                assert_eq!(timeout, None, "no flag means the API default");
            }
            _ => panic!("wrong parse"),
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
        assert!(matches!(
            Cli::parse_from(["cats", "shell", "dev"]).command,
            Command::Shell { name } if name == "dev"
        ));
        let cli = Cli::parse_from(["cats", "mount", "data", "--cat", "dev", "--at", "/data"]);
        assert!(matches!(cli.command, Command::Mount { .. }));
        let cli = Cli::parse_from(["cats", "admin", "node", "drain", "node-a"]);
        assert!(matches!(
            cli.command,
            Command::Admin {
                cmd: AdminCommand::Node {
                    cmd: AdminNodeCommand::Drain { .. }
                }
            }
        ));
        let cli = Cli::parse_from([
            "cats",
            "admin",
            "node",
            "fence",
            "node-a",
            "--confirm-host-stopped-or-isolated",
        ]);
        assert!(matches!(
            cli.command,
            Command::Admin {
                cmd: AdminCommand::Node {
                    cmd: AdminNodeCommand::Fence {
                        confirm_host_stopped_or_isolated: true,
                        ..
                    }
                }
            }
        ));
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
            .expect("JSON request has Content-Length");
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

    #[cfg(unix)]
    #[test]
    fn create_sends_one_exact_v2_request_and_accepts_only_the_flat_202() {
        use clap::Parser;
        use std::io::Write;

        let state_directory = tempfile::tempdir().unwrap();
        let state_root = state_directory.path().canonicalize().unwrap().join("state");
        let _state_guard = cat_create_pending::TestStateRootGuard::set(state_root.clone());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let captured = read_request(&mut stream);
            let response = br#"{"cat_id":"cat_01","operation_id":"op_01"}"#;
            write!(
                stream,
                "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
        run(cli).unwrap();
        let (headers, body) = server.join().unwrap();
        assert!(headers.starts_with("POST /v1/workspaces/ws_01/cats HTTP/1.1\r\n"));
        assert!(headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case("content-type: application/json")));
        assert!(headers.lines().any(|line| line
            .to_ascii_lowercase()
            .starts_with("idempotency-key: cli-")));
        assert_eq!(
            body,
            br#"{"name":"app","boot_image_digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","vcpus":3,"memory_bytes":2147483648,"root_size_bytes":4294967296,"durability":"relaxed"}"#
        );
        assert!(std::fs::read_dir(state_root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".pending.json")
        }));
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

    #[test]
    fn cat_create_response_classification_is_exact_and_closed() {
        let response = |status, body: &[u8]| CatCreateHttpResponse {
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
    fn every_retired_product_command_fails_before_any_outbound_request() {
        use clap::Parser;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let commands: &[&[&str]] = &[
            &["ls"],
            &["get", "app"],
            &["start", "app"],
            &["stop", "app"],
            &["suspend", "app"],
            &["resume", "app"],
            &["warm", "app"],
            &["sync", "app"],
            &["destroy", "app"],
            &["exec", "app", "--", "true"],
            &[
                "deploy",
                "app",
                "service",
                "--image",
                "registry.example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ],
            &["shell", "app"],
            &["sleep", "on", "app"],
            &["sleep", "off", "app"],
            &["sleep", "status", "app"],
            &["expiry", "app"],
            &["disk", "create", "data", "--size", "1GiB"],
            &["disk", "ls"],
            &["disk", "get", "data"],
            &["disk", "resize", "data", "--size", "2GiB"],
            &["disk", "delete", "data"],
            &["disk", "snapshot", "data"],
            &["mount", "data", "--cat", "app"],
            &["unmount", "data"],
            &["expose", "app", "8080"],
            &["endpoint", "ls", "app"],
            &["operation", "ls"],
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
            let mut argv = vec![
                "cats",
                "--api-url",
                base.as_str(),
                "--token",
                "test-token",
                "--workspace",
                "ws_01",
            ];
            argv.extend_from_slice(command);
            let cli = Cli::try_parse_from(argv).unwrap_or_else(|error| {
                panic!("retired command {command:?} stopped parsing: {error}")
            });
            let error = run(cli).expect_err("retired command must fail locally");
            assert!(
                error.to_string().contains(RUNTIME_CUTOVER_UNSUPPORTED),
                "unexpected error for {command:?}: {error}"
            );
            assert!(matches!(
                listener.accept(),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
            ));
        }
    }

    #[test]
    fn shipped_help_hides_every_closed_authority_command_and_legacy_create_flag() {
        use clap::CommandFactory;

        let mut root = Cli::command();
        let root_help = root.render_long_help().to_string();
        for command in [
            "ls",
            "get",
            "start",
            "stop",
            "suspend",
            "resume",
            "warm",
            "sync",
            "destroy",
            "exec",
            "deploy",
            "shell",
            "sleep",
            "expiry",
            "disk",
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
        assert!(!root_help.contains("--no-wait"));

        let mut create = Cli::command()
            .find_subcommand("create")
            .expect("create command")
            .clone();
        let create_help = create.render_long_help().to_string();
        assert!(create_help.contains("--boot-image-digest"));
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
