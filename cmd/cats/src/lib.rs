//! `cats` CLI: the only user-facing surface. Commands express intent against
//! the versioned API; mutations return operations that the CLI waits on by
//! default (`--no-wait` to skip). No storage/node internals ever appear here.

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
    #[arg(
        long,
        env = "CATS_API_URL",
        default_value = "http://127.0.0.1:7300",
        global = true
    )]
    pub api_url: String,
    /// API token.
    #[arg(long, env = "CATS_TOKEN", default_value = "dev-token", global = true)]
    pub token: String,
    /// Project name.
    #[arg(long, env = "CATS_PROJECT", default_value = "default", global = true)]
    pub project: String,
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
    /// Destroy a cat and its root disk (persistent disks survive).
    Destroy { name: String },
    /// Run a command inside the cat (wakes it if needed).
    Exec {
        name: String,
        /// Command argv, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
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
}

#[derive(Subcommand, Debug)]
pub enum DiskCommand {
    Create {
        name: String,
        #[arg(long)]
        size: String,
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
    Get { id: String },
    Wait { id: String },
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
    project: String,
}

impl Client {
    fn new(cli: &Cli) -> Result<Self> {
        Ok(Self {
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(120))
                .build()?,
            base: cli.api_url.trim_end_matches('/').to_string(),
            token: cli.token.clone(),
            project: cli.project.clone(),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/projects/{}{}", self.base, self.project, path)
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

fn print_cat(cat: &Cat, json_mode: bool) {
    if json_mode {
        println!("{}", serde_json::to_string_pretty(cat).unwrap());
    } else {
        println!(
            "{:<16} {:>4} cpu {:>6} MiB  desired={:<9} observed={:<9} node={}",
            cat.name,
            cat.spec.cpus,
            cat.spec.memory_mib,
            format!("{:?}", cat.desired_state).to_lowercase(),
            format!("{:?}", cat.observed_state).to_lowercase(),
            cat.node_id.as_deref().unwrap_or("-")
        );
    }
}

/// Run the CLI; returns the process exit code.
pub fn run(cli: Cli) -> Result<()> {
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
        Command::Create {
            name,
            image,
            cpus,
            memory,
            root_size,
            disk,
            disk_size,
            mount_at,
        } => {
            let body = CreateCatRequest {
                name: name.clone(),
                image: image.clone(),
                cpus: *cpus,
                memory_mib: parse_size(memory)? >> 20,
                root_size_bytes: parse_size(root_size)?,
                disk: disk.as_ref().map(|d| CreateCatDisk {
                    name: d.clone(),
                    size_bytes: parse_size(disk_size).unwrap_or(1 << 30),
                    mount_at: mount_at.clone(),
                }),
            };
            let resp = client.send(
                client
                    .http
                    .post(client.url("/cats"))
                    .header("Idempotency-Key", &idem)
                    .json(&body),
            )?;
            mutate(resp)
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
        Command::Exec { name, command } => {
            let v = client.post(
                &format!("/cats/{name}/exec"),
                Some(json!({ "command": command })),
            )?;
            let out: ExecResponse = serde_json::from_value(v)?;
            print!("{}", out.stdout);
            eprint!("{}", out.stderr);
            if out.exit_code != 0 {
                bail!("command exited with {}", out.exit_code);
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
            println!("{}", resp.endpoint.hostname);
            Ok(())
        }
        Command::Endpoint { cmd } => match cmd {
            EndpointCommand::Ls { cat } => {
                let v = client.get(&format!("/cats/{cat}/endpoints"))?;
                let list: ListResponse<Endpoint> = serde_json::from_value(v)?;
                for ep in list.items {
                    println!(
                        "{:<12} {:<40} port={} wake={:?}",
                        ep.name, ep.hostname, ep.target_port, ep.wake_policy
                    );
                }
                Ok(())
            }
        },
        Command::Operation { cmd } => match cmd {
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
    }
}

fn run_disk(client: &Client, cli: &Cli, cmd: &DiskCommand) -> Result<()> {
    match cmd {
        DiskCommand::Create { name, size } => {
            let v = client.post(
                "/disks",
                Some(json!({ "name": name, "size_bytes": parse_size(size)? })),
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
            "{:<16} {:>8} MiB  kind={:<10} state={:<10} cat={}",
            d.name,
            d.size_bytes >> 20,
            format!("{:?}", d.kind).to_lowercase(),
            format!("{:?}", d.state).to_lowercase(),
            d.bound_cat_id.as_deref().unwrap_or("-")
        );
    }
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
    fn cli_parses_typical_commands() {
        use clap::Parser;
        let cli = Cli::parse_from(["cats", "create", "dev", "--cpus", "4", "--memory", "8GiB"]);
        match cli.command {
            Command::Create { name, cpus, .. } => {
                assert_eq!(name, "dev");
                assert_eq!(cpus, 4);
            }
            _ => panic!("wrong parse"),
        }
        let cli = Cli::parse_from(["cats", "exec", "dev", "--", "git", "status"]);
        match cli.command {
            Command::Exec { command, .. } => assert_eq!(command, vec!["git", "status"]),
            _ => panic!("wrong parse"),
        }
        let cli = Cli::parse_from(["cats", "mount", "data", "--cat", "dev", "--at", "/data"]);
        assert!(matches!(cli.command, Command::Mount { .. }));
    }
}
