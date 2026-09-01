//! Digest-pinned OCI application deployment inside a Cat.
//!
//! This deliberately implements "flatten and chroot", not a container
//! runtime. OCI supplies immutable distribution, layer and process metadata;
//! Cats' RootDisk supplies the writable filesystem and systemd supplies
//! process supervision. No Docker daemon or OverlayFS is involved.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use cats_protocol::oci::{DeployOciRequest, OciDeployment, OciRegistryAuth};
use flate2::read::MultiGzDecoder;
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, CONTENT_TYPE, WWW_AUTHENTICATE};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::GuestMode;

const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const DOCKER_INDEX: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const MANIFEST_ACCEPT: &str = concat!(
    "application/vnd.oci.image.index.v1+json,",
    "application/vnd.oci.image.manifest.v1+json,",
    "application/vnd.docker.distribution.manifest.list.v2+json,",
    "application/vnd.docker.distribution.manifest.v2+json"
);
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_LAYER_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_UNPACKED_LAYER_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_UNPACKED_IMAGE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_LAYERS: usize = 1_024;
const MAX_LAYER_ENTRIES: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImageReference {
    registry: String,
    repository: String,
    digest: String,
    scheme: &'static str,
}

impl ImageReference {
    fn parse(value: &str) -> Result<Self> {
        if value.contains("://") {
            bail!("OCI image must be registry/repository@sha256:digest without a URL scheme");
        }
        let (name, digest) = value
            .rsplit_once('@')
            .context("OCI image must be pinned by @sha256:<64 hex>")?;
        validate_sha256(digest)?;
        let (registry, repository) = name
            .split_once('/')
            .context("OCI image must include an explicit registry host")?;
        if registry.is_empty()
            || repository.is_empty()
            || repository.starts_with('/')
            || repository.ends_with('/')
        {
            bail!("OCI registry and repository must be non-empty");
        }
        if repository.split('/').any(|part| {
            part.is_empty()
                || !part.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
                || !part
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !part
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        }) {
            bail!("OCI repository contains an invalid path component");
        }
        let registry_url =
            reqwest::Url::parse(&format!("https://{registry}/")).context("invalid OCI registry")?;
        if registry_url.host_str().is_none()
            || !registry_url.username().is_empty()
            || registry_url.password().is_some()
            || registry_url.query().is_some()
            || registry_url.fragment().is_some()
            || registry_url.path() != "/"
        {
            bail!("OCI registry must be a host with an optional port");
        }
        let registry = if registry.eq_ignore_ascii_case("docker.io")
            || registry.eq_ignore_ascii_case("index.docker.io")
        {
            "registry-1.docker.io".to_string()
        } else {
            registry.to_string()
        };
        let scheme = if registry_url.host_str().is_some_and(is_loopback_host) {
            "http"
        } else {
            "https"
        };
        Ok(Self {
            registry,
            repository: repository.to_string(),
            digest: digest.to_ascii_lowercase(),
            scheme,
        })
    }

    fn base(&self) -> String {
        format!("{}://{}/v2/{}", self.scheme, self.registry, self.repository)
    }
}

fn validate_sha256(value: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        bail!("only sha256 OCI digests are supported");
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("OCI sha256 digest must contain exactly 64 hexadecimal characters");
    }
    Ok(())
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn verify_digest(bytes: &[u8], expected: &str, what: &str) -> Result<()> {
    let actual = digest_bytes(bytes);
    if actual != expected.to_ascii_lowercase() {
        bail!("{what} digest mismatch: expected {expected}, got {actual}");
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    media_type: String,
    digest: String,
    size: u64,
    #[serde(default)]
    platform: Option<Platform>,
}

#[derive(Debug, Clone, Deserialize)]
struct Platform {
    architecture: String,
    os: String,
    #[serde(default)]
    variant: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ImageIndex {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    manifests: Vec<Descriptor>,
}

#[derive(Debug, Deserialize)]
struct ImageManifest {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    config: Descriptor,
    layers: Vec<Descriptor>,
}

#[derive(Debug, Deserialize)]
struct ImageConfigEnvelope {
    architecture: String,
    os: String,
    #[serde(default)]
    config: ImageConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ImageConfig {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    env: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    entrypoint: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    cmd: Vec<String>,
    #[serde(default)]
    working_dir: String,
    #[serde(default)]
    user: String,
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Option::<T>::deserialize(deserializer).map(Option::unwrap_or_default)
}

struct Registry {
    reference: ImageReference,
    client: Client,
    auth: Option<OciRegistryAuth>,
    bearer: Option<String>,
}

impl Registry {
    fn new(reference: ImageReference, auth: Option<OciRegistryAuth>) -> Result<Self> {
        let client = Client::builder()
            .connect_timeout(std::time::Duration::from_secs(15))
            .timeout(std::time::Duration::from_secs(300))
            .user_agent(concat!("cats-guest-agent/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build OCI registry client")?;
        Ok(Self {
            reference,
            client,
            auth,
            bearer: None,
        })
    }

    fn get(&mut self, url: &str, accept: Option<&str>) -> Result<Response> {
        let send = |bearer: Option<&str>| {
            let mut request = self.client.get(url);
            if let Some(value) = accept {
                request = request.header(ACCEPT, value);
            }
            if let Some(token) = bearer {
                request = request.bearer_auth(token);
            } else if let Some(auth) = &self.auth {
                request = request.basic_auth(&auth.username, Some(&auth.password));
            }
            request.send()
        };
        let mut response = send(self.bearer.as_deref()).context("contact OCI registry")?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            let challenge = response
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok())
                .context("registry returned 401 without WWW-Authenticate")?
                .to_string();
            let token = self.exchange_bearer(&challenge)?;
            self.bearer = Some(token);
            response = send(self.bearer.as_deref()).context("retry OCI registry request")?;
        }
        if !response.status().is_success() {
            let status = response.status();
            let body = read_limited(response, 64 * 1024)
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .unwrap_or_default();
            bail!("OCI registry request failed ({status}): {}", body.trim());
        }
        Ok(response)
    }

    fn exchange_bearer(&self, challenge: &str) -> Result<String> {
        let fields = parse_bearer_challenge(challenge)?;
        let realm = fields
            .get("realm")
            .context("registry Bearer challenge has no realm")?;
        let mut url = reqwest::Url::parse(realm).context("invalid registry token realm")?;
        let local_insecure_realm = url.scheme() == "http"
            && self.reference.scheme == "http"
            && url.host_str().is_some_and(is_loopback_host);
        if url.scheme() != "https" && !local_insecure_realm {
            bail!("registry token realm must use HTTPS");
        }
        {
            let mut query = url.query_pairs_mut();
            if let Some(service) = fields.get("service") {
                query.append_pair("service", service);
            }
            if let Some(scope) = fields.get("scope") {
                query.append_pair("scope", scope);
            } else {
                query.append_pair(
                    "scope",
                    &format!("repository:{}:pull", self.reference.repository),
                );
            }
        }
        let mut request = self.client.get(url);
        if let Some(auth) = &self.auth {
            request = request.basic_auth(&auth.username, Some(&auth.password));
        }
        let response = request
            .send()
            .context("request OCI registry bearer token")?;
        let status = response.status();
        let bytes = read_limited(response, 1024 * 1024)?;
        if !status.is_success() {
            bail!(
                "OCI registry token request failed ({status}): {}",
                String::from_utf8_lossy(&bytes).trim()
            );
        }
        #[derive(Deserialize)]
        struct TokenResponse {
            #[serde(default)]
            token: String,
            #[serde(default)]
            access_token: String,
        }
        let body: TokenResponse =
            serde_json::from_slice(&bytes).context("decode OCI registry token response")?;
        let token = if body.token.is_empty() {
            body.access_token
        } else {
            body.token
        };
        if token.is_empty() {
            bail!("OCI registry token response did not contain a token");
        }
        Ok(token)
    }

    fn manifest(&mut self, digest: &str) -> Result<(String, Vec<u8>)> {
        validate_sha256(digest)?;
        let url = format!("{}/manifests/{digest}", self.reference.base());
        let response = self.get(&url, Some(MANIFEST_ACCEPT))?;
        let mut media_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        let bytes = read_limited(response, MAX_MANIFEST_BYTES)?;
        verify_digest(&bytes, digest, "OCI manifest")?;
        if media_type.is_empty() || media_type == "application/octet-stream" {
            let value: serde_json::Value =
                serde_json::from_slice(&bytes).context("decode OCI manifest envelope")?;
            media_type = value
                .get("mediaType")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
                .or_else(|| value.get("manifests").map(|_| OCI_INDEX.to_string()))
                .or_else(|| value.get("config").map(|_| OCI_MANIFEST.to_string()))
                .context("OCI manifest response has no recognizable media type")?;
        }
        Ok((media_type, bytes))
    }

    fn blob_bytes(&mut self, descriptor: &Descriptor, limit: u64, what: &str) -> Result<Vec<u8>> {
        validate_descriptor(descriptor, limit, what)?;
        let url = format!("{}/blobs/{}", self.reference.base(), descriptor.digest);
        let bytes = read_limited(self.get(&url, None)?, limit)?;
        if bytes.len() as u64 != descriptor.size {
            bail!(
                "{what} size mismatch: manifest says {}, registry returned {}",
                descriptor.size,
                bytes.len()
            );
        }
        verify_digest(&bytes, &descriptor.digest, what)?;
        Ok(bytes)
    }

    fn blob_file(&mut self, descriptor: &Descriptor, path: &Path) -> Result<()> {
        validate_descriptor(descriptor, MAX_LAYER_BYTES, "OCI layer")?;
        let url = format!("{}/blobs/{}", self.reference.base(), descriptor.digest);
        let mut response = self.get(&url, None)?;
        let mut output = File::create(path).context("create OCI layer staging file")?;
        let mut hasher = Sha256::new();
        let mut written = 0u64;
        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            let read = response.read(&mut buffer).context("read OCI layer")?;
            if read == 0 {
                break;
            }
            written = written
                .checked_add(read as u64)
                .context("OCI layer size overflow")?;
            if written > descriptor.size || written > MAX_LAYER_BYTES {
                bail!("OCI layer exceeds its declared or platform size limit");
            }
            hasher.update(&buffer[..read]);
            output
                .write_all(&buffer[..read])
                .context("write OCI layer staging file")?;
        }
        output.sync_all().context("sync OCI layer staging file")?;
        if written != descriptor.size {
            bail!(
                "OCI layer size mismatch: manifest says {}, registry returned {written}",
                descriptor.size
            );
        }
        let actual = format!("sha256:{}", hex::encode(hasher.finalize()));
        if actual != descriptor.digest.to_ascii_lowercase() {
            bail!(
                "OCI layer digest mismatch: expected {}, got {actual}",
                descriptor.digest
            );
        }
        Ok(())
    }
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn parse_bearer_challenge(value: &str) -> Result<BTreeMap<String, String>> {
    let (scheme, value) = value
        .split_once(' ')
        .context("invalid registry authentication challenge")?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        bail!("registry authentication scheme is not Bearer");
    }
    let mut fields = BTreeMap::new();
    for field in value.split(',') {
        let (name, raw) = field
            .trim()
            .split_once('=')
            .context("invalid registry Bearer challenge")?;
        let raw = raw.trim();
        let decoded = raw
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(raw)
            .replace("\\\"", "\"");
        fields.insert(name.trim().to_ascii_lowercase(), decoded);
    }
    Ok(fields)
}

fn read_limited(response: Response, max: u64) -> Result<Vec<u8>> {
    if response.content_length().is_some_and(|len| len > max) {
        bail!("registry response exceeds the {max}-byte limit");
    }
    let mut bytes = Vec::new();
    response
        .take(max + 1)
        .read_to_end(&mut bytes)
        .context("read OCI registry response")?;
    if bytes.len() as u64 > max {
        bail!("registry response exceeds the {max}-byte limit");
    }
    Ok(bytes)
}

fn validate_descriptor(descriptor: &Descriptor, max: u64, what: &str) -> Result<()> {
    validate_sha256(&descriptor.digest)?;
    if descriptor.size > max {
        bail!("{what} exceeds the {max}-byte limit");
    }
    Ok(())
}

fn guest_architecture() -> Result<(&'static str, Option<&'static str>)> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(("amd64", None)),
        "aarch64" => Ok(("arm64", Some("v8"))),
        arch => bail!("OCI deployment is unsupported on Guest architecture {arch}"),
    }
}

fn select_platform(index: ImageIndex) -> Result<Descriptor> {
    if index.schema_version != 2 {
        bail!("OCI image index schemaVersion must be 2");
    }
    let (architecture, variant) = guest_architecture()?;
    index
        .manifests
        .into_iter()
        .find(|manifest| {
            manifest.platform.as_ref().is_some_and(|platform| {
                platform.os == "linux"
                    && platform.architecture == architecture
                    && (variant.is_none()
                        || platform.variant.as_deref().is_none()
                        || platform.variant.as_deref() == variant)
            })
        })
        .with_context(|| format!("OCI index has no linux/{architecture} image"))
}

fn is_index(media_type: &str, bytes: &[u8]) -> bool {
    matches!(media_type, OCI_INDEX | DOCKER_INDEX)
        || serde_json::from_slice::<serde_json::Value>(bytes)
            .ok()
            .and_then(|value| value.get("manifests").cloned())
            .is_some()
}

fn validate_app_name(app: &str) -> Result<()> {
    if app.is_empty()
        || app.len() > 63
        || !app
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || app.starts_with('-')
        || app.ends_with('-')
    {
        bail!("OCI app name must be 1-63 lowercase letters, digits, or internal hyphens");
    }
    Ok(())
}

fn clean_relative(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        bail!("OCI layer contains an absolute path");
    }
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            _ => bail!("OCI layer path escapes the release root"),
        }
    }
    Ok(clean)
}

fn clean_absolute(value: &str, what: &str) -> Result<PathBuf> {
    if value.contains('\0') || value.contains('\n') || value.contains('\r') {
        bail!("{what} contains a NUL or newline");
    }
    let path = Path::new(value);
    if !path.is_absolute() {
        bail!("{what} must be an absolute path");
    }
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => clean.push(part),
            _ => bail!("{what} escapes the OCI release root"),
        }
    }
    Ok(clean)
}

fn ensure_parent_inside(root: &Path, relative: &Path) -> Result<()> {
    let canonical_root = root
        .canonicalize()
        .context("canonicalize OCI release root")?;
    let mut existing = relative.parent().unwrap_or_else(|| Path::new(""));
    while !existing.as_os_str().is_empty() && !root.join(existing).exists() {
        existing = existing.parent().unwrap_or_else(|| Path::new(""));
    }
    let canonical = root
        .join(existing)
        .canonicalize()
        .context("canonicalize OCI layer parent")?;
    if !canonical.starts_with(&canonical_root) {
        bail!("OCI layer path follows a symlink outside the release root");
    }
    Ok(())
}

fn remove_path(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(path).with_context(|| format!("remove {}", path.display()))
        }
        Ok(_) => fs::remove_file(path).with_context(|| format!("remove {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn apply_layer(
    root: &Path,
    blob: &Path,
    media_type: &str,
    work: &Path,
    preserve_metadata: bool,
) -> Result<u64> {
    if !(media_type.contains("image.layer") || media_type.contains("rootfs.diff")) {
        bail!("unsupported OCI layer media type {media_type}");
    }
    let tar_path = work.join("layer.tar");
    let input = File::open(blob).context("open OCI layer")?;
    let mut output = File::create(&tar_path).context("create uncompressed OCI layer")?;
    let unpacked_tar_bytes = if media_type.ends_with("+gzip") || media_type.ends_with(".gzip") {
        std::io::copy(
            &mut MultiGzDecoder::new(input).take(MAX_UNPACKED_LAYER_BYTES + 1),
            &mut output,
        )
        .context("decompress gzip OCI layer")?
    } else if media_type.ends_with("+zstd") {
        std::io::copy(
            &mut zstd::stream::read::Decoder::new(input)
                .context("open zstd OCI layer")?
                .take(MAX_UNPACKED_LAYER_BYTES + 1),
            &mut output,
        )
        .context("decompress zstd OCI layer")?
    } else {
        std::io::copy(
            &mut BufReader::new(input).take(MAX_UNPACKED_LAYER_BYTES + 1),
            &mut output,
        )
        .context("stage OCI tar layer")?
    };
    if unpacked_tar_bytes > MAX_UNPACKED_LAYER_BYTES {
        bail!("unpacked OCI layer exceeds the {MAX_UNPACKED_LAYER_BYTES}-byte limit");
    }
    output.sync_all().context("sync uncompressed OCI layer")?;

    // Whiteouts are layer-wide removals and must be applied before additions,
    // independent of their order in the tar stream.
    let mut archive = tar::Archive::new(File::open(&tar_path)?);
    let mut whiteouts = Vec::new();
    for (index, entry) in archive
        .entries()
        .context("read OCI layer entries")?
        .enumerate()
    {
        if index >= MAX_LAYER_ENTRIES {
            bail!("OCI layer exceeds the {MAX_LAYER_ENTRIES}-entry limit");
        }
        let entry = entry.context("read OCI layer entry")?;
        let relative = clean_relative(&entry.path().context("decode OCI layer path")?)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let name = relative
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if name == ".wh..wh..opq" || name.starts_with(".wh.") {
            whiteouts.push(relative);
        }
    }
    for relative in &whiteouts {
        ensure_parent_inside(root, relative)?;
        let name = relative.file_name().and_then(|name| name.to_str()).unwrap();
        let parent = root.join(relative.parent().unwrap_or_else(|| Path::new("")));
        if name == ".wh..wh..opq" {
            if parent.exists() {
                let canonical_root = root.canonicalize()?;
                let canonical_parent = parent.canonicalize()?;
                if !canonical_parent.starts_with(&canonical_root) {
                    bail!("OCI opaque whiteout follows a symlink outside the release root");
                }
                for child in fs::read_dir(&canonical_parent)? {
                    remove_path(&child?.path())?;
                }
            }
        } else {
            remove_path(&parent.join(name.trim_start_matches(".wh.")))?;
        }
    }

    let whiteouts: HashSet<PathBuf> = whiteouts.into_iter().collect();
    let mut archive = tar::Archive::new(File::open(&tar_path)?);
    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    archive.set_preserve_ownerships(preserve_metadata);
    archive.set_unpack_xattrs(preserve_metadata);
    let mut unpacked_entry_bytes = 0u64;
    for (index, entry) in archive
        .entries()
        .context("read OCI layer entries")?
        .enumerate()
    {
        if index >= MAX_LAYER_ENTRIES {
            bail!("OCI layer exceeds the {MAX_LAYER_ENTRIES}-entry limit");
        }
        let mut entry = entry.context("read OCI layer entry")?;
        let relative = clean_relative(&entry.path().context("decode OCI layer path")?)?;
        let kind = entry.header().entry_type();
        if relative.as_os_str().is_empty() {
            if kind.is_dir() {
                continue;
            }
            bail!("OCI layer contains a non-directory root entry");
        }
        if whiteouts.contains(&relative) {
            continue;
        }
        ensure_parent_inside(root, &relative)?;
        if !(kind.is_file() || kind.is_dir() || kind.is_symlink() || kind.is_hard_link()) {
            bail!(
                "OCI layer contains unsupported special file {}",
                relative.display()
            );
        }
        unpacked_entry_bytes = unpacked_entry_bytes
            .checked_add(entry.header().size().context("read OCI entry size")?)
            .context("unpacked OCI layer size overflow")?;
        if unpacked_entry_bytes > MAX_UNPACKED_LAYER_BYTES {
            bail!("unpacked OCI entries exceed the {MAX_UNPACKED_LAYER_BYTES}-byte limit");
        }
        if kind.is_hard_link() {
            let target = entry
                .link_name()
                .context("decode OCI hard-link target")?
                .context("OCI hard link has no target")?;
            let target = clean_relative(&target)?;
            if target.as_os_str().is_empty() {
                bail!("OCI hard link has an empty target");
            }
            ensure_parent_inside(root, &target)?;
        }
        if !entry
            .unpack_in(root)
            .with_context(|| format!("unpack OCI path {}", relative.display()))?
        {
            bail!("OCI layer path escapes the release root");
        }
    }
    Ok(unpacked_entry_bytes)
}

fn parse_environment(values: &[String]) -> Result<BTreeMap<String, String>> {
    values
        .iter()
        .map(|value| {
            let (name, value) = value
                .split_once('=')
                .context("OCI environment entry must be NAME=VALUE")?;
            Ok((name.to_string(), value.to_string()))
        })
        .collect()
}

fn valid_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn unit_quote(value: &str) -> Result<String> {
    if value.contains('\0') || value.contains('\n') || value.contains('\r') {
        bail!("OCI process metadata contains a NUL or newline");
    }
    let escaped = value
        .replace('%', "%%")
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    Ok(format!("\"{escaped}\""))
}

fn unit_path_value(value: &str) -> Result<String> {
    if !value.starts_with('/') {
        bail!("systemd path value must be absolute");
    }
    if value.contains('\0') || value.contains('\n') || value.contains('\r') {
        bail!("OCI process metadata contains a NUL or newline");
    }
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'.' | b'_' | b'-' => {
                escaped.push(char::from(byte))
            }
            b'%' => escaped.push_str("%%"),
            _ => {
                escaped.push_str("\\x");
                escaped.push_str(&hex::encode([byte]));
            }
        }
    }
    Ok(escaped)
}

fn unit_exec_quote(value: &str) -> Result<String> {
    if value.contains('\0') || value.contains('\n') || value.contains('\r') {
        bail!("OCI process metadata contains a NUL or newline");
    }
    let escaped = value
        .replace('%', "%%")
        .replace('$', "$$")
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    Ok(format!("\"{escaped}\""))
}

fn root_entry_exists(root: &Path, relative: &Path) -> bool {
    ensure_parent_inside(root, relative).is_ok()
        && fs::symlink_metadata(root.join(relative))
            .is_ok_and(|metadata| metadata.is_file() || metadata.file_type().is_symlink())
}

fn resolve_command(
    root: &Path,
    config: &ImageConfig,
    override_command: &[String],
    working_dir: &Path,
) -> Result<Vec<String>> {
    let mut command = if override_command.is_empty() {
        let mut command = config.entrypoint.clone();
        command.extend(config.cmd.clone());
        command
    } else {
        override_command.to_vec()
    };
    let executable = command
        .first_mut()
        .context("OCI image has no Entrypoint/Cmd; pass an argv after `--`")?;
    if executable.starts_with('/') {
        let relative = clean_absolute(executable, "OCI executable")?;
        *executable = format!("/{}", relative.display());
    } else if executable.contains('/') {
        let relative = clean_relative(Path::new(executable))?;
        if relative.as_os_str().is_empty() {
            bail!("OCI executable path is empty");
        }
        let resolved = working_dir.join(relative);
        if !root_entry_exists(root, &resolved) {
            bail!("OCI executable {executable} does not exist under WorkingDir");
        }
        *executable = format!("/{}", resolved.display());
    } else {
        let environment = parse_environment(&config.env)?;
        let path = environment
            .get("PATH")
            .map(String::as_str)
            .unwrap_or("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
        let mut resolved = None;
        for part in path.split(':') {
            let directory = if part.is_empty() {
                working_dir.to_path_buf()
            } else if part.starts_with('/') {
                clean_absolute(part, "OCI PATH entry")?
            } else {
                working_dir.join(clean_relative(Path::new(part))?)
            };
            let candidate = directory.join(executable.as_str());
            if root_entry_exists(root, &candidate) {
                resolved = Some(candidate);
                break;
            }
        }
        let resolved = resolved
            .with_context(|| format!("OCI executable {executable} was not found in PATH"))?;
        *executable = format!("/{}", resolved.display());
    }
    let relative = Path::new(executable.trim_start_matches('/'));
    if !root_entry_exists(root, relative) {
        bail!("OCI executable {executable} does not exist in the image");
    }
    Ok(command)
}

fn resolve_user(root: &Path, configured: &str) -> Result<Option<(u32, u32)>> {
    if configured.is_empty() {
        return Ok(None);
    }
    let (user, explicit_group) = configured
        .split_once(':')
        .map_or((configured, None), |(user, group)| (user, Some(group)));
    let passwd = fs::read_to_string(root.join("etc/passwd")).unwrap_or_default();
    let user_row = passwd.lines().find_map(|line| {
        let fields: Vec<_> = line.split(':').collect();
        (fields.len() >= 4 && fields[0] == user).then_some(fields)
    });
    let uid = user
        .parse::<u32>()
        .ok()
        .or_else(|| user_row.as_ref()?.get(2)?.parse().ok())
        .with_context(|| {
            format!("OCI user {user} is neither numeric nor present in /etc/passwd")
        })?;
    let default_gid = user_row
        .as_ref()
        .and_then(|fields| fields.get(3))
        .and_then(|gid| gid.parse().ok())
        .unwrap_or(uid);
    let gid = match explicit_group {
        None | Some("") => default_gid,
        Some(group) => group
            .parse::<u32>()
            .ok()
            .or_else(|| {
                fs::read_to_string(root.join("etc/group"))
                    .ok()?
                    .lines()
                    .find_map(|line| {
                        let fields: Vec<_> = line.split(':').collect();
                        (fields.len() >= 3 && fields[0] == group)
                            .then(|| fields[2].parse().ok())
                            .flatten()
                    })
            })
            .with_context(|| {
                format!("OCI group {group} is neither numeric nor present in /etc/group")
            })?,
    };
    Ok(Some((uid, gid)))
}

fn install_guest_network_files(root: &Path) -> Result<()> {
    let etc = root.join("etc");
    match fs::symlink_metadata(&etc) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => bail!("OCI /etc must be a directory, not a symlink or file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&etc).context("create OCI /etc")?;
        }
        Err(error) => return Err(error).context("inspect OCI /etc"),
    }
    for name in ["resolv.conf", "hosts"] {
        let source = Path::new("/etc").join(name);
        let target = root.join("etc").join(name);
        ensure_parent_inside(root, &Path::new("etc").join(name))?;
        remove_path(&target)?;
        fs::copy(&source, &target)
            .with_context(|| format!("install Guest {name} in OCI rootfs"))?;
    }
    Ok(())
}

fn render_unit(
    app: &str,
    release_root: &Path,
    service_root: &Path,
    config: &ImageConfig,
    request: &DeployOciRequest,
) -> Result<String> {
    install_guest_network_files(release_root)?;
    let working_dir = if config.working_dir.is_empty() {
        "/"
    } else {
        config.working_dir.as_str()
    };
    let working_dir_relative = clean_absolute(working_dir, "OCI WorkingDir")?;
    ensure_parent_inside(release_root, &working_dir_relative)?;
    fs::create_dir_all(release_root.join(&working_dir_relative))
        .context("create OCI working directory")?;
    let working_dir = if working_dir_relative.as_os_str().is_empty() {
        "/".to_string()
    } else {
        format!("/{}", working_dir_relative.display())
    };
    let command = resolve_command(
        release_root,
        config,
        &request.command,
        &working_dir_relative,
    )?;

    let mut environment = parse_environment(&config.env)?;
    environment.extend(request.env.clone());
    if environment.keys().any(|name| !valid_environment_name(name)) {
        bail!("OCI environment contains an invalid variable name");
    }

    let mut unit = format!(
        "[Unit]\nDescription=Cats OCI application {app}\nAfter=network.target\n\n\
         [Service]\nType=simple\nRootDirectory={}\nMountAPIVFS=yes\nPrivateTmp=yes\n\
         WorkingDirectory={}\nRestart=always\nRestartSec=1\nKillMode=mixed\n",
        unit_path_value(&service_root.display().to_string())?,
        unit_path_value(&working_dir)?,
    );
    if let Some((uid, gid)) = resolve_user(release_root, &config.user)? {
        unit.push_str(&format!("User={uid}\nGroup={gid}\n"));
    }
    for (name, value) in environment {
        unit.push_str(&format!(
            "Environment={}\n",
            unit_quote(&format!("{name}={value}"))?
        ));
    }
    let command = command
        .iter()
        .map(|argument| unit_exec_quote(argument))
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    unit.push_str(&format!(
        "ExecStart={command}\n\n[Install]\nWantedBy=multi-user.target\n"
    ));
    Ok(unit)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("atomic file has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".tmp-{}", Uuid::new_v4().simple()));
    let mut file = File::create(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn systemctl(args: &[&str]) -> Result<()> {
    let output = Command::new("systemctl")
        .args(args)
        .output()
        .with_context(|| format!("run systemctl {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "systemctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

pub(super) struct OciDeployer {
    root: PathBuf,
    unit_dir: PathBuf,
    systemd: bool,
    preserve_metadata: bool,
}

impl OciDeployer {
    pub(super) fn for_mode(mode: &GuestMode, disk_map_path: &Path) -> Self {
        match mode {
            GuestMode::Vm => Self {
                root: PathBuf::from("/var/lib/cats/oci"),
                unit_dir: PathBuf::from("/etc/systemd/system"),
                systemd: true,
                preserve_metadata: true,
            },
            GuestMode::Fake => {
                let state = disk_map_path.parent().unwrap_or_else(|| Path::new("."));
                Self {
                    root: state.join("oci"),
                    unit_dir: state.join("oci-units"),
                    systemd: false,
                    preserve_metadata: false,
                }
            }
        }
    }

    #[cfg(test)]
    fn for_test(root: PathBuf, unit_dir: PathBuf) -> Self {
        Self {
            root,
            unit_dir,
            systemd: false,
            preserve_metadata: false,
        }
    }

    pub(super) fn deploy(&mut self, request: DeployOciRequest) -> Result<OciDeployment> {
        validate_app_name(&request.app)?;
        let reference = ImageReference::parse(&request.image)?;
        if request.env.keys().any(|name| !valid_environment_name(name)) {
            bail!("OCI environment contains an invalid variable name");
        }
        for value in request.env.values() {
            unit_quote(value)?;
        }
        for argument in &request.command {
            unit_exec_quote(argument)?;
        }
        let requested_digest = reference.digest.clone();
        let app_root = self.root.join(&request.app);
        let releases = app_root.join("releases");
        fs::create_dir_all(&releases).context("create OCI release directory")?;
        let work = app_root.join(format!(".work-{}", Uuid::new_v4().simple()));
        fs::create_dir_all(&work).context("create OCI staging directory")?;

        let result = (|| {
            let mut registry = Registry::new(reference, request.registry_auth.clone())?;
            let (mut media_type, mut manifest_bytes) = registry.manifest(&requested_digest)?;
            let manifest_digest = if is_index(&media_type, &manifest_bytes) {
                let descriptor = select_platform(
                    serde_json::from_slice(&manifest_bytes).context("decode OCI image index")?,
                )?;
                validate_descriptor(&descriptor, MAX_MANIFEST_BYTES, "OCI platform manifest")?;
                let digest = descriptor.digest.clone();
                (media_type, manifest_bytes) = registry.manifest(&digest)?;
                if manifest_bytes.len() as u64 != descriptor.size {
                    bail!(
                        "OCI platform manifest size mismatch: index says {}, registry returned {}",
                        descriptor.size,
                        manifest_bytes.len()
                    );
                }
                digest
            } else {
                requested_digest.clone()
            };
            if !matches!(media_type.as_str(), OCI_MANIFEST | DOCKER_MANIFEST) {
                bail!("registry returned unsupported OCI manifest media type {media_type}");
            }
            let manifest: ImageManifest =
                serde_json::from_slice(&manifest_bytes).context("decode OCI image manifest")?;
            if manifest.schema_version != 2 {
                bail!("OCI image manifest schemaVersion must be 2");
            }
            if manifest.layers.len() > MAX_LAYERS {
                bail!("OCI image exceeds the {MAX_LAYERS}-layer limit");
            }
            validate_descriptor(&manifest.config, MAX_CONFIG_BYTES, "OCI image config")?;
            let total_size = manifest.layers.iter().try_fold(0u64, |total, layer| {
                total
                    .checked_add(layer.size)
                    .context("OCI image size overflow")
            })?;
            if total_size > MAX_IMAGE_BYTES {
                bail!("OCI image layers exceed the {MAX_IMAGE_BYTES}-byte limit");
            }
            let config_bytes =
                registry.blob_bytes(&manifest.config, MAX_CONFIG_BYTES, "OCI image config")?;
            let config: ImageConfigEnvelope =
                serde_json::from_slice(&config_bytes).context("decode OCI image config")?;
            let (guest_arch, _) = guest_architecture()?;
            if config.os != "linux" || config.architecture != guest_arch {
                bail!(
                    "OCI image config is {}/{}, Guest requires linux/{guest_arch}",
                    config.os,
                    config.architecture
                );
            }

            let release = releases.join(manifest_digest.trim_start_matches("sha256:"));
            if !release.exists() {
                let staged_root = work.join("rootfs");
                fs::create_dir_all(&staged_root)?;
                let mut unpacked_image_bytes = 0u64;
                for (index, layer) in manifest.layers.iter().enumerate() {
                    let blob = work.join(format!("layer-{index}.blob"));
                    registry.blob_file(layer, &blob)?;
                    let unpacked = apply_layer(
                        &staged_root,
                        &blob,
                        &layer.media_type,
                        &work,
                        self.preserve_metadata,
                    )
                    .with_context(|| format!("apply OCI layer {}", layer.digest))?;
                    unpacked_image_bytes = unpacked_image_bytes
                        .checked_add(unpacked)
                        .context("unpacked OCI image size overflow")?;
                    if unpacked_image_bytes > MAX_UNPACKED_IMAGE_BYTES {
                        bail!(
                            "unpacked OCI image exceeds the {MAX_UNPACKED_IMAGE_BYTES}-byte limit"
                        );
                    }
                    fs::remove_file(&blob)?;
                    let tar = work.join("layer.tar");
                    if tar.exists() {
                        fs::remove_file(tar)?;
                    }
                }
                fs::rename(&staged_root, &release).context("publish flattened OCI release")?;
                File::open(&releases)?.sync_all()?;
            }

            let unit_name = format!("cats-oci-{}.service", request.app);
            let current = app_root.join("current");
            // Resolve argv/user/working-directory and finish the unit before
            // changing the active symlink. Invalid image metadata therefore
            // cannot replace a working release.
            //
            // RootDirectory must name the immutable release itself: systemd
            // bind-mounts this path and rejects a final `current` symlink with
            // status=226/NAMESPACE.
            let unit = render_unit(&request.app, &release, &release, &config.config, &request)?;
            let next = app_root.join(format!(".current-{}", Uuid::new_v4().simple()));
            #[cfg(unix)]
            std::os::unix::fs::symlink(
                Path::new("releases").join(manifest_digest.trim_start_matches("sha256:")),
                &next,
            )?;
            fs::rename(&next, &current).context("activate OCI release")?;
            File::open(&app_root)?.sync_all()?;
            write_atomic(&self.unit_dir.join(&unit_name), unit.as_bytes())?;
            if self.systemd {
                systemctl(&["daemon-reload"])?;
                systemctl(&["enable", &unit_name])?;
                systemctl(&["restart", &unit_name])?;
                systemctl(&["is-active", "--quiet", &unit_name])?;
            }
            Ok(OciDeployment {
                app: request.app.clone(),
                image_digest: requested_digest,
                manifest_digest,
                service: unit_name,
                active: self.systemd,
            })
        })();
        let _ = fs::remove_dir_all(&work);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn image_reference_requires_a_canonical_digest() {
        let parsed = ImageReference::parse(
            "ghcr.io/paperboy-ai/server@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        assert_eq!(parsed.registry, "ghcr.io");
        assert_eq!(parsed.repository, "paperboy-ai/server");
        assert_eq!(parsed.scheme, "https");

        assert!(ImageReference::parse("ghcr.io/paperboy-ai/server:latest").is_err());
        assert!(ImageReference::parse(
            "ghcr.io/paperboy-ai/server:latest@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        .is_err());
        assert!(ImageReference::parse(
            "ghcr.io/paperboy-ai/server?redirect=evil@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        .is_err());

        let docker_hub = ImageReference::parse(
            "docker.io/library/busybox@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        assert_eq!(docker_hub.registry, "registry-1.docker.io");
        assert_eq!(
            docker_hub.base(),
            "https://registry-1.docker.io/v2/library/busybox"
        );
    }

    #[test]
    fn systemd_path_values_are_unquoted_and_escape_unit_syntax() {
        assert_eq!(
            unit_path_value("/srv/work dir/100%").unwrap(),
            "/srv/work\\x20dir/100%%"
        );
        assert!(unit_path_value("relative/path").is_err());
        assert!(unit_path_value("/srv/bad\npath").is_err());
    }

    #[test]
    fn layer_whiteouts_remove_lower_content_before_adding_new_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let work = dir.path().join("work");
        fs::create_dir_all(root.join("etc/app")).unwrap();
        fs::create_dir_all(&work).unwrap();
        fs::write(root.join("etc/app/old"), "old").unwrap();

        let blob = work.join("layer.blob");
        {
            let file = File::create(&blob).unwrap();
            let mut builder = tar::Builder::new(file);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append_data(&mut header, ".", &[][..]).unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "etc/app/.wh.old", &[][..])
                .unwrap();
            let bytes = b"new";
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "etc/app/new", &bytes[..])
                .unwrap();
            builder.finish().unwrap();
        }

        apply_layer(
            &root,
            &blob,
            "application/vnd.oci.image.layer.v1.tar",
            &work,
            false,
        )
        .unwrap();
        assert!(!root.join("etc/app/old").exists());
        assert_eq!(fs::read(root.join("etc/app/new")).unwrap(), b"new");
        assert!(!root.join("etc/app/.wh.old").exists());
    }

    #[test]
    fn rendered_unit_uses_chroot_without_an_overlay_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("rootfs");
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::write(root.join("usr/bin/app"), "binary").unwrap();
        let config = ImageConfig {
            env: vec!["PATH=/usr/bin".into(), "MODE=image".into()],
            entrypoint: vec!["./app".into()],
            cmd: vec!["serve".into(), "$MODE".into()],
            working_dir: "/usr/bin".into(),
            user: String::new(),
        };
        let request = DeployOciRequest {
            app: "paperboy-server".into(),
            image: "unused@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            command: Vec::new(),
            env: BTreeMap::from([("MODE".into(), "staging".into())]),
            registry_auth: None,
        };
        let unit = render_unit("paperboy-server", &root, &root, &config, &request).unwrap();
        assert!(unit.contains(&format!("RootDirectory={}", root.display())));
        assert!(unit.contains("WorkingDirectory=/usr/bin"));
        assert!(unit.contains("ExecStart=\"/usr/bin/app\" \"serve\" \"$$MODE\""));
        assert!(unit.contains("Environment=\"MODE=staging\""));
        assert!(!unit.contains("overlay"));
    }

    #[test]
    fn process_paths_cannot_escape_the_flattened_release() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("rootfs");
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::write(root.join("usr/bin/app"), "binary").unwrap();
        let request = DeployOciRequest {
            app: "app".into(),
            image: "unused@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            command: Vec::new(),
            env: BTreeMap::new(),
            registry_auth: None,
        };
        let config = ImageConfig {
            env: vec!["PATH=/usr/bin".into()],
            entrypoint: vec!["/usr/bin/app".into()],
            cmd: Vec::new(),
            working_dir: "/../../tmp/cats-oci-escape".into(),
            user: String::new(),
        };

        assert!(render_unit("app", &root, &root, &config, &request).is_err());
        assert!(!dir.path().join("tmp/cats-oci-escape").exists());
    }

    #[test]
    fn test_deployer_keeps_units_outside_the_host_systemd_directory() {
        let dir = tempfile::tempdir().unwrap();
        let deployer = OciDeployer::for_test(dir.path().join("oci"), dir.path().join("units"));
        assert!(!deployer.systemd);
        assert_eq!(deployer.unit_dir, dir.path().join("units"));
    }

    #[test]
    fn deploy_pulls_and_verifies_a_registry_image_before_writing_the_unit() {
        let mut layer = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut layer);
            let bytes = b"#!/bin/sh\nexit 0\n";
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(bytes.len() as u64);
            header.set_mode(0o755);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            builder
                .append_data(&mut header, "usr/bin/cats-fixture", &bytes[..])
                .unwrap();
            builder.finish().unwrap();
        }
        let layer_digest = digest_bytes(&layer);
        let (architecture, _) = guest_architecture().unwrap();
        let config = serde_json::to_vec(&serde_json::json!({
            "architecture": architecture,
            "os": "linux",
            "config": {
                "Env": ["PATH=/usr/bin"],
                "Entrypoint": ["cats-fixture"],
                "Cmd": null,
                "WorkingDir": "/",
                "User": ""
            }
        }))
        .unwrap();
        let config_digest = digest_bytes(&config);
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": config.len()
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": layer_digest,
                "size": layer.len()
            }]
        }))
        .unwrap();
        let manifest_digest = digest_bytes(&manifest);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let responses = BTreeMap::from([
            (
                format!("/v2/example/app/manifests/{manifest_digest}"),
                (OCI_MANIFEST.to_string(), manifest),
            ),
            (
                format!("/v2/example/app/blobs/{config_digest}"),
                (
                    "application/vnd.oci.image.config.v1+json".to_string(),
                    config,
                ),
            ),
            (
                format!("/v2/example/app/blobs/{layer_digest}"),
                ("application/vnd.oci.image.layer.v1.tar".to_string(), layer),
            ),
        ]);
        let expected_manifest_path = format!("/v2/example/app/manifests/{manifest_digest}");
        let server = thread::spawn(move || {
            for request_index in 0..responses.len() + 2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                let request = String::from_utf8_lossy(&request);
                let first = request.lines().next().unwrap().to_string();
                let path = first.split_whitespace().nth(1).unwrap();
                if request_index == 0 {
                    assert_eq!(path, expected_manifest_path);
                    assert!(request
                        .to_ascii_lowercase()
                        .contains("authorization: basic y2k6c2hvcnqtbgl2zwq="));
                    write!(
                        stream,
                        "HTTP/1.1 401 Unauthorized\r\nwww-authenticate: Bearer realm=\"http://{address}/token\",service=\"fixture\",scope=\"repository:example/app:pull\"\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    )
                    .unwrap();
                    continue;
                }
                if request_index == 1 {
                    assert!(path.starts_with("/token?"));
                    assert!(request
                        .to_ascii_lowercase()
                        .contains("authorization: basic y2k6c2hvcnqtbgl2zwq="));
                    let body = br#"{"token":"fixture-token"}"#;
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    )
                    .unwrap();
                    stream.write_all(body).unwrap();
                    continue;
                }
                assert!(request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer fixture-token"));
                let (media_type, body) = responses.get(path).unwrap();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: {media_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(body).unwrap();
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let mut deployer = OciDeployer::for_test(dir.path().join("oci"), dir.path().join("units"));
        let deployment = deployer
            .deploy(DeployOciRequest {
                app: "fixture".into(),
                image: format!("{address}/example/app@{manifest_digest}"),
                command: Vec::new(),
                env: BTreeMap::new(),
                registry_auth: Some(OciRegistryAuth {
                    username: "ci".into(),
                    password: "short-lived".into(),
                }),
            })
            .unwrap();
        server.join().unwrap();

        assert_eq!(deployment.image_digest, manifest_digest);
        assert_eq!(deployment.manifest_digest, manifest_digest);
        assert!(
            !deployment.active,
            "the test manager must not invoke host systemd"
        );
        assert!(dir
            .path()
            .join("oci/fixture/current/usr/bin/cats-fixture")
            .exists());
        let unit = fs::read_to_string(dir.path().join("units/cats-oci-fixture.service")).unwrap();
        let release_root = dir
            .path()
            .join("oci/fixture/releases")
            .join(manifest_digest.trim_start_matches("sha256:"));
        assert!(unit.contains(&format!(
            "RootDirectory={}",
            unit_path_value(&release_root.display().to_string()).unwrap()
        )));
        assert!(unit.contains("ExecStart=\"/usr/bin/cats-fixture\""));
    }
}
