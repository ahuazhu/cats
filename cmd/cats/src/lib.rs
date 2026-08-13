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

use std::io::{Read as _, Write as _};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use cats_api::cat_create::{
    decode_cat_create_v2_accepted_response, CatCreateV2AcceptedResponse, CatCreateV2Request,
};
use cats_api::persistent_disk::{
    PersistentDiskCreateV1Request, PERSISTENT_DISK_NAME_CONFLICT_BODY,
};
use cats_api::runtime_product_reads::{CatReadV2, DiskReadV2, ProductReadPage};
use cats_api::runtime_reconciliation::{
    decode_operation as decode_runtime_operation, encode_operation as encode_runtime_operation,
    Id as RuntimeId, Operation as RuntimeOperation, OperationPhase as RuntimeOperationPhase,
    OperationTerminal as RuntimeOperationTerminal, OPERATION_MAX_WIRE_BYTES,
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
    Ls,
    /// Show one cat by immutable ID.
    Get { id: String },
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
        /// Immutable Disk ID.
        id: String,
    },
    Delete {
        name: String,
    },
    #[command(hide = true)]
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
    #[command(hide = true)]
    Ls,
    Get {
        id: String,
    },
    Wait {
        id: String,
    },
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
                .no_gzip()
                .no_brotli()
                .no_deflate()
                .no_zstd()
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
                .no_gzip()
                .no_brotli()
                .no_deflate()
                .no_zstd()
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

    fn get_runtime_operation(&self, operation_id: &str) -> Result<RuntimeOperation> {
        self.get_runtime_operation_with_timeout(operation_id, None)
    }

    fn get_runtime_operation_with_timeout(
        &self,
        operation_id: &str,
        request_timeout: Option<Duration>,
    ) -> Result<RuntimeOperation> {
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
        let operation = decode_runtime_operation(&body).context("invalid Operation response")?;
        anyhow::ensure!(
            encode_runtime_operation(&operation).context("invalid decoded Operation response")?
                == body,
            "Operation response is not canonical"
        );
        anyhow::ensure!(
            operation.workspace_id == workspace_id && operation.operation_id == operation_id,
            "Operation response identity does not match the request"
        );
        Ok(operation)
    }

    fn wait_runtime_operation(&self, operation_id: &str) -> Result<RuntimeOperation> {
        self.wait_runtime_operation_for(operation_id, Duration::from_secs(120))
    }

    fn wait_runtime_operation_for(
        &self,
        operation_id: &str,
        wait_timeout: Duration,
    ) -> Result<RuntimeOperation> {
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
            match operation.phase {
                RuntimeOperationPhase::Pending => {
                    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                        bail!("operation {operation_id} did not finish in time");
                    };
                    if remaining.is_zero() {
                        bail!("operation {operation_id} did not finish in time");
                    }
                    std::thread::sleep(remaining.min(Duration::from_millis(150)));
                }
                RuntimeOperationPhase::Succeeded => return Ok(operation),
                RuntimeOperationPhase::Failed => {
                    let Some(RuntimeOperationTerminal::Failed { error, .. }) = &operation.terminal
                    else {
                        bail!("operation {operation_id} returned an invalid failed state");
                    };
                    bail!("operation {operation_id} failed: {error:?}");
                }
                RuntimeOperationPhase::Superseded => {
                    let Some(RuntimeOperationTerminal::Superseded {
                        superseded_by_revision,
                        superseded_by_operation_id,
                        ..
                    }) = &operation.terminal
                    else {
                        bail!("operation {operation_id} returned an invalid superseded state");
                    };
                    bail!(
                        "operation {operation_id} was superseded by operation \
                         {superseded_by_operation_id} at revision {}",
                        superseded_by_revision.get()
                    );
                }
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

fn print_runtime_cat(cat: &CatReadV2, json_mode: bool) {
    if json_mode {
        println!("{}", serde_json::to_string_pretty(cat).unwrap());
    } else {
        let observed = cat
            .observed
            .as_ref()
            .and_then(|observed| observed.stable_state)
            .map(|state| format!("{state:?}").to_lowercase())
            .unwrap_or_else(|| "unknown".to_owned());
        println!(
            "{:<16} id={:<38} {:>4} cpu {:>6} MiB desired={:<9} observed={:<9} node={}",
            cat.name,
            cat.id,
            cat.desired.vcpus,
            cat.desired.memory_bytes >> 20,
            format!("{:?}", cat.desired.target).to_lowercase(),
            observed,
            cat.desired.node_id,
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

const RUNTIME_CUTOVER_UNSUPPORTED: &str =
    "is unavailable until its signed runtime-authority projection lands; no HTTP request was sent";

/// Retired product-authority commands stay parseable for a clear local error,
/// but are hidden from shipped help and rejected before Client construction.
/// This prevents even workspace resolution or authentication refresh from
/// turning an unsupported invocation into outbound traffic.
fn runtime_cutover_unsupported(command: &Command) -> Option<&'static str> {
    match command {
        Command::Ls | Command::Get { .. } => None,
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
        Command::Disk {
            cmd: DiskCommand::Create { .. },
        } => None,
        Command::Disk {
            cmd: DiskCommand::Ls | DiskCommand::Get { .. },
        } => None,
        Command::Disk { .. } | Command::Mount { .. } | Command::Unmount { .. } => {
            Some("PersistentDisk")
        }
        Command::Expose { .. } | Command::Endpoint { .. } => Some("Endpoint"),
        Command::Operation {
            cmd: OperationCommand::Ls,
        } => Some("Operation list"),
        Command::Operation {
            cmd: OperationCommand::Get { .. } | OperationCommand::Wait { .. },
        } => None,
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
            cmd:
                AdminCommand::Login
                | AdminCommand::Logout
                | AdminCommand::RuntimeNode { .. }
                | AdminCommand::RuntimeProvisioner { .. },
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
        Command::Admin {
            cmd: AdminCommand::RuntimeProvisioner { cmd },
        } => return runtime_provisioner::run(&cli, cmd),
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
            OperationCommand::Ls => bail!("Operation list {RUNTIME_CUTOVER_UNSUPPORTED}"),
            OperationCommand::Get { id } => {
                let operation = client.get_runtime_operation(id)?;
                println!("{}", serde_json::to_string_pretty(&operation)?);
                Ok(())
            }
            OperationCommand::Wait { id } => {
                let operation = client.wait_runtime_operation(id)?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&operation)?);
                } else {
                    println!("succeeded");
                }
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
        AdminCommand::RuntimeProvisioner { .. } => {
            unreachable!("Runtime provisioner commands bypass workspace API construction")
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
            let request = PersistentDiskCreateV1Request {
                durability: DiskDurability::parse(durability)
                    .context("invalid PersistentDisk durability")?,
                name: cats_api::runtime_reconciliation::Id::new(name.clone())
                    .context("invalid PersistentDisk name")?,
                size_bytes: parse_size(size)?,
            };
            request
                .validate()
                .context("invalid PersistentDisk-create request")?;
            let request_body = serde_json::to_vec(&request)?;
            let pending = cat_create_pending::PreparedPersistentDiskCreate::prepare(
                &client.base,
                &client.workspace_id,
                &request_body,
            )
            .context(
                "could not durably prepare PersistentDisk-create recovery state; no HTTP request was sent",
            )?;
            let response = client
                .send_persistent_disk_create(&pending)
                .with_context(|| {
                    format!(
                        "PersistentDisk-create response is ambiguous; the exact path, body, and Idempotency-Key remain pending at {}",
                        pending.pending_path().display()
                    )
                })?;
            match classify_persistent_disk_create_response(&response, &pending)? {
                PersistentDiskCreateResponseClassification::Created(disk) => {
                    print_disk(&disk, cli.json);
                    std::io::stdout()
                        .flush()
                        .context("flush created PersistentDisk identity before cleanup")?;
                    pending.clear().context(
                        "PersistentDisk-create committed and was reported, but its pending recovery state could not be durably cleared",
                    )?;
                    Ok(())
                }
                PersistentDiskCreateResponseClassification::NameConflict => {
                    pending.clear().context(
                        "PersistentDisk name conflict is terminal, but its pending recovery state could not be durably cleared",
                    )?;
                    bail!("disk name already exists (AlreadyExists)")
                }
                PersistentDiskCreateResponseClassification::Nonterminal => {
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
                        "PersistentDisk-create response was not an exact terminal result ({detail}); replay the same command to reuse the pending Idempotency-Key at {}",
                        pending.pending_path().display()
                    )
                }
            }
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

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

const CAT_CREATE_NAME_CONFLICT_BODY: &[u8] =
    br#"{"code":"already_exists","message":"cat name already exists"}"#;

struct ExactCreateHttpResponse {
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

enum PersistentDiskCreateResponseClassification {
    Created(Disk),
    NameConflict,
    Nonterminal,
}

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

    fn pending_runtime_operation() -> RuntimeOperation {
        use cats_api::runtime_reconciliation::{
            AssignedKind, AssignedPlacement, ContractVersion, Epoch, OperationPhase, Revision,
            RuntimeTarget, Sha256Digest, UnixMillis,
        };

        RuntimeOperation {
            version: ContractVersion::V1,
            operation_id: RuntimeId::new("op_01").unwrap(),
            workspace_id: RuntimeId::new("ws_01").unwrap(),
            cat_id: RuntimeId::new("cat_01").unwrap(),
            desired_revision: Revision::new(1).unwrap(),
            desired_spec_digest: Sha256Digest::from_bytes([7; 32]),
            placement: AssignedPlacement {
                kind: AssignedKind::Assigned,
                node_id: RuntimeId::new("node_01").unwrap(),
                placement_epoch: Epoch::new(1).unwrap(),
            },
            target: RuntimeTarget::Running,
            phase: OperationPhase::Pending,
            terminal: None,
            created_at_unix_ms: UnixMillis::new(1).unwrap(),
            updated_at_unix_ms: UnixMillis::new(1).unwrap(),
        }
    }

    fn succeeded_runtime_operation() -> RuntimeOperation {
        use cats_api::runtime_reconciliation::{
            Epoch, OperationPhase, OperationSuccess, OperationTerminal, RandomId128, Sequence,
            UnixMillis,
        };

        let mut operation = pending_runtime_operation();
        let completed_at = UnixMillis::new(2).unwrap();
        operation.phase = OperationPhase::Succeeded;
        operation.updated_at_unix_ms = completed_at;
        operation.terminal = Some(OperationTerminal::Succeeded {
            result: OperationSuccess {
                observation_id: RandomId128::new("11111111111111111111111111111111").unwrap(),
                node_id: operation.placement.node_id.clone(),
                agent_session_epoch: Epoch::new(1).unwrap(),
                heartbeat_sequence: Sequence::new(1).unwrap(),
                observed_target: operation.target,
                runtime_incarnation: Some(
                    RandomId128::new("22222222222222222222222222222222").unwrap(),
                ),
            },
            completed_at_unix_ms: completed_at,
        });
        operation
    }

    fn failed_runtime_operation() -> RuntimeOperation {
        use cats_api::runtime_reconciliation::{
            Epoch, OperationFailure, OperationPhase, OperationTerminal, UnixMillis,
        };

        let mut operation = pending_runtime_operation();
        let completed_at = UnixMillis::new(2).unwrap();
        operation.phase = OperationPhase::Failed;
        operation.updated_at_unix_ms = completed_at;
        operation.terminal = Some(OperationTerminal::Failed {
            error: Box::new(OperationFailure::HostLost {
                node_id: operation.placement.node_id.clone(),
                agent_session_epoch: Epoch::new(1).unwrap(),
                host_fence_event_id: RuntimeId::new("fence_01").unwrap(),
            }),
            completed_at_unix_ms: completed_at,
        });
        operation
    }

    fn superseded_runtime_operation() -> RuntimeOperation {
        use cats_api::runtime_reconciliation::{
            OperationPhase, OperationTerminal, Revision, UnixMillis,
        };

        let mut operation = pending_runtime_operation();
        let completed_at = UnixMillis::new(2).unwrap();
        operation.phase = OperationPhase::Superseded;
        operation.updated_at_unix_ms = completed_at;
        operation.terminal = Some(OperationTerminal::Superseded {
            superseded_by_revision: Revision::new(2).unwrap(),
            superseded_by_operation_id: RuntimeId::new("op_02").unwrap(),
            completed_at_unix_ms: completed_at,
        });
        operation
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
        let body = encode_runtime_operation(&expected).unwrap();
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
        let body = encode_runtime_operation(&pending_runtime_operation()).unwrap();
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
        let pending = encode_runtime_operation(&pending_runtime_operation()).unwrap();
        let succeeded = succeeded_runtime_operation();
        let succeeded_body = encode_runtime_operation(&succeeded).unwrap();
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
        let pending = encode_runtime_operation(&pending_runtime_operation()).unwrap();
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
            let _ = release_rx.recv_timeout(Duration::from_secs(3));
        });

        let started = Instant::now();
        let error = runtime_test_client(base)
            .wait_runtime_operation_for("op_01", Duration::from_millis(400))
            .unwrap_err();
        let elapsed = started.elapsed();
        let _ = release_tx.send(());

        assert!(
            second_request_rx
                .recv_timeout(Duration::from_secs(1))
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
    fn runtime_operation_wait_reports_failed_and_superseded_terminals() {
        for (operation, expected_error) in [
            (failed_runtime_operation(), "failed: HostLost"),
            (
                superseded_runtime_operation(),
                "superseded by operation op_02 at revision 2",
            ),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let body = encode_runtime_operation(&operation).unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let _ = read_request(&mut stream);
                write_runtime_operation_response(&mut stream, &body, None);
            });

            let error = runtime_test_client(base)
                .wait_runtime_operation("op_01")
                .unwrap_err();
            assert!(
                error.to_string().contains(expected_error),
                "unexpected terminal error: {error}"
            );
            server.join().unwrap();
        }
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
    fn persistent_disk_create_sends_one_exact_covered_request() {
        use clap::Parser as _;
        use std::io::Write as _;

        let state_directory = tempfile::tempdir().unwrap();
        let state_root = state_directory.path().canonicalize().unwrap().join("state");
        let _state_guard =
            cat_create_pending::TestPersistentDiskStateRootGuard::set(state_root.clone());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let captured = read_request(&mut stream);
            let response = br#"{"id":"disk_11111111111111111111111111111111","workspace_id":"ws_01","name":"data","kind":"persistent","size_bytes":1073741824,"state":"available","durability":"strict","volume_id":"vol_22222222222222222222222222222222","created_at_unix":1720000000}"#;
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
            "1GiB",
            "--durability",
            "strict",
        ]);
        run(cli).unwrap();
        let (headers, body) = server.join().unwrap();
        assert!(headers.starts_with("POST /v1/workspaces/ws_01/disks HTTP/1.1\r\n"));
        assert_eq!(request_header(&headers, "content-type"), "application/json");
        assert!(request_header(&headers, "idempotency-key").starts_with("cli-"));
        assert_eq!(
            body,
            br#"{"durability":"strict","name":"data","size_bytes":1073741824}"#
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
    fn every_retired_product_command_fails_before_any_outbound_request() {
        use clap::Parser;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let commands: &[&[&str]] = &[
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
    fn disk_resize_is_not_a_cli_command() {
        use clap::Parser;

        let parsed = Cli::try_parse_from(["cats", "disk", "resize", "data", "--size", "2GiB"]);
        assert!(
            parsed.is_err(),
            "immutable volume capacity still has a CLI mutation"
        );
    }

    #[test]
    fn shipped_help_hides_every_closed_authority_command_and_legacy_create_flag() {
        use clap::CommandFactory;

        let mut root = Cli::command();
        let root_help = root.render_long_help().to_string();
        for command in [
            "start", "stop", "suspend", "resume", "warm", "sync", "destroy", "exec", "deploy",
            "shell", "sleep", "expiry", "mount", "unmount", "expose", "endpoint",
        ] {
            assert!(
                !root_help.contains(&format!("\n  {command} ")),
                "retired command {command:?} remains visible in root help"
            );
        }
        for read in ["ls", "get", "disk"] {
            assert!(
                root_help.contains(&format!("\n  {read} ")),
                "production read command {read:?} is hidden from root help"
            );
        }
        assert!(root_help.contains("\n  operation "));
        assert!(!root_help.contains("--no-wait"));

        let mut disk = Cli::command()
            .find_subcommand("disk")
            .expect("Disk command")
            .clone();
        let disk_help = disk.render_long_help().to_string();
        for supported in ["create", "ls", "get"] {
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
