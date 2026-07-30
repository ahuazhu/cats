//! `cats` CLI: the command-line user surface. Commands express intent against
//! the same versioned API as the web consoles; mutations return operations
//! that the CLI waits on by default (`--no-wait` to skip). No storage/node
//! internals ever appear here.

mod auth;
mod config;
mod credential_store;
mod shell;

use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use serde_json::json;

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
    #[arg(long, global = true)]
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
        #[arg(long, default_value = "ubuntu-24.04")]
        image: String,
        #[arg(long, default_value_t = 2)]
        cpus: u32,
        #[arg(long, default_value = "2GiB")]
        memory: String,
        #[arg(long, default_value = "1GiB")]
        root_size: String,
        /// Optional persistent disk to create and mount: NAME
        #[arg(long)]
        disk: Option<String>,
        #[arg(long, default_value = "1GiB")]
        disk_size: String,
        #[arg(long, default_value = "/data")]
        mount_at: String,
        /// Keep this Cat running when the distributed work count reaches 0.
        #[arg(long)]
        no_auto_suspend: bool,
        /// Delete this Cat automatically after SECONDS from now.
        #[arg(long, value_name = "SECONDS")]
        expires_in: Option<u64>,
        /// What an fsync inside the Cat promises, for the disks this command
        /// creates. `strict`: fsync returns once the data is durable in the
        /// object store and survives losing the host. `relaxed`: fsync
        /// returns after a local commit and the data reaches the object store
        /// within ~5 s; an unclean host loss may drop those last seconds, so
        /// use `cats sync` before promising the outside world anything.
        #[arg(long, default_value = "strict", value_parser = ["strict", "relaxed"])]
        durability: String,
    },
    /// List cats.
    Ls,
    /// Show one cat.
    Get { name: String },
    /// Start (or wake) a cat.
    Start { name: String },
    /// Stop a cat (release compute; disks stay durable).
    Stop { name: String },
    /// Suspend a cat (pause + page-out; host-bound).
    Suspend { name: String },
    /// Resume a suspended/warm cat.
    Resume { name: String },
    /// Demote a cat to Warm (snapshot + VMM exit; host-bound).
    Warm { name: String },
    /// Force everything written inside the cat to durable storage now.
    /// On relaxed disks this is the escape hatch that buys one strict
    /// moment on demand; on strict disks it is a cheap no-op.
    Sync { name: String },
    /// Destroy a cat and its root disk (persistent disks survive).
    Destroy { name: String },
    /// Run a command inside the cat (wakes it if needed).
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
    /// Open an interactive login shell inside the cat.
    Shell { name: String },
    /// Configure or explain work-driven auto-suspend.
    Sleep {
        #[command(subcommand)]
        cmd: SleepCommand,
    },
    /// Show or change a cat's absolute expiry (automatic deletion time).
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
    Mount {
        disk: String,
        #[arg(long)]
        cat: String,
        #[arg(long, default_value = "/data")]
        at: String,
    },
    /// Unmount a persistent disk.
    Unmount { disk: String },
    /// Expose a guest port through a stable endpoint.
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
    /// Show fleet health, lifecycle and capacity counters.
    Monitoring,
    /// List worker nodes with assignments and last telemetry.
    Nodes,
    /// Inspect or manage one worker node.
    Node {
        #[command(subcommand)]
        cmd: AdminNodeCommand,
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
    /// Remove an empty cordoned/lost node from the registry.
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
                .build()?;
            let base = auth::configured_api_url(cli.api_url.as_deref())?;
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
                .build()?,
            base: session.api_url,
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
        let resp = req
            .bearer_auth(&self.token)
            .send()
            .context("control plane unreachable")?;
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        if !status.is_success() {
            // Surface the structured error body when present.
            if let Ok(err) = serde_json::from_str::<cats_api::error::ErrorBody>(&text) {
                bail!("{} ({:?})", err.message, err.code);
            }
            bail!("HTTP {status}: {text}");
        }
        if text.is_empty() {
            Ok(serde_json::Value::Null)
        } else {
            serde_json::from_str(&text).context("malformed response")
        }
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
    let listed: cats_api::requests::ListResponse<cats_api::auth::Workspace> =
        response.json().context("invalid workspace directory response")?;
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
        _ => {}
    }
    let client = Client::new(&cli)?;
    let idem = uuid_like();

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
            image,
            cpus,
            memory,
            root_size,
            disk,
            disk_size,
            mount_at,
            no_auto_suspend,
            expires_in,
            durability,
        } => {
            let body = CreateCatRequest {
                name: name.clone(),
                image: image.clone(),
                cpus: *cpus,
                memory_mib: parse_size(memory)? >> 20,
                root_size_bytes: parse_size(root_size)?,
                auto_suspend: !no_auto_suspend,
                disk: disk.as_ref().map(|d| CreateCatDisk {
                    name: d.clone(),
                    size_bytes: parse_size(disk_size).unwrap_or(1 << 30),
                    mount_at: mount_at.clone(),
                }),
                expires_at_unix: expires_in.map(|secs| unix_now() + secs as i64),
                durability: DiskDurability::parse(durability)
                    .expect("clap validated the value"),
            };
            let resp = client.send(
                client
                    .http
                    .post(client.url("/cats"))
                    .header("Idempotency-Key", &idem)
                    .json(&body),
            )?;
            mutate(resp)?;
            if !cli.json {
                let endpoints: ListResponse<Endpoint> =
                    serde_json::from_value(client.get(&format!("/cats/{name}/endpoints"))?)?;
                if let Some(endpoint) = endpoints.items.iter().find(|ep| ep.name == "web") {
                    println!("URL: https://{}", endpoint.hostname);
                }
            }
            Ok(())
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
            let request_timeout =
                Duration::from_secs(timeout.unwrap_or(120).saturating_add(15));
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
                    "nodes total={} ready={} cordoned={} draining={} lost={}",
                    overview.nodes.total,
                    overview.nodes.ready,
                    overview.nodes.cordoned,
                    overview.nodes.draining,
                    overview.nodes.lost
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
            let (id, action) = match cmd {
                AdminNodeCommand::Get { id } => (id, None),
                AdminNodeCommand::Cordon { id } => (id, Some("cordon")),
                AdminNodeCommand::Uncordon { id } => (id, Some("uncordon")),
                AdminNodeCommand::Drain { id } => (id, Some("drain")),
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
                client
                    .http
                    .post(client.admin_url(&format!("/nodes/{id}/actions/{action}")))
                    .header("content-length", "0")
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
    }
}

fn print_node(summary: &NodeSummary) {
    let telemetry = summary.node.telemetry.as_ref();
    println!(
        "{:<18} state={:<9} cats={} cpu={}/{} memory={}MiB/{}MiB heartbeat={}s load={}",
        summary.node.id,
        format!("{:?}", summary.node.state).to_lowercase(),
        summary.assigned_cats,
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

/// Random idempotency key without pulling a uuid dependency.
fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("cli-{nanos}-{}", std::process::id())
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
        let cli = Cli::parse_from(["cats", "create", "dev", "--cpus", "4", "--memory", "8GiB"]);
        match cli.command {
            Command::Create {
                name,
                cpus,
                no_auto_suspend,
                ..
            } => {
                assert_eq!(name, "dev");
                assert_eq!(cpus, 4);
                assert!(!no_auto_suspend);
            }
            _ => panic!("wrong parse"),
        }
        let cli = Cli::parse_from(["cats", "create", "always-on", "--no-auto-suspend"]);
        assert!(matches!(
            cli.command,
            Command::Create {
                no_auto_suspend: true,
                ..
            }
        ));
        let cli = Cli::parse_from(["cats", "create", "ci", "--durability", "relaxed"]);
        match cli.command {
            Command::Create { durability, .. } => assert_eq!(durability, "relaxed"),
            _ => panic!("wrong parse"),
        }
        // No flag means strict: the honest default.
        let cli = Cli::parse_from(["cats", "create", "db"]);
        match cli.command {
            Command::Create { durability, .. } => assert_eq!(durability, "strict"),
            _ => panic!("wrong parse"),
        }
        assert!(Cli::try_parse_from(["cats", "create", "x", "--durability", "fast"]).is_err());
        assert!(matches!(
            Cli::parse_from(["cats", "sync", "dev"]).command,
            Command::Sync { name } if name == "dev"
        ));
        let with_timeout =
            Cli::parse_from(["cats", "exec", "dev", "--timeout", "900", "--", "cargo", "build"]);
        match with_timeout.command {
            Command::Exec {
                timeout, command, ..
            } => {
                assert_eq!(timeout, Some(900), "a long build needs more than the default");
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
    }
}
