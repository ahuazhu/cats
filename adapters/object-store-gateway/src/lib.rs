//! ObjectWrite Gateway adapter for the provider-neutral Cats blob-store port.
//!
//! Production bare-metal workers are denied direct ChunkStore mutation by IAM
//! (`DenyDirectChunkStoreMutation`). The ObjectWrite Gateway is the only
//! principal that holds PUT authority, so every immutable publish from blockd
//! has to travel through it. This adapter is that transport: it recovers the
//! closed signed key class from the caller's flat object key, signs one
//! `ObjectWriteIngressDescriptor` with the attachment-scoped Ed25519
//! credential, and POSTs the exact body to
//! [`OBJECT_WRITE_GATEWAY_PATH`].
//!
//! # What this adapter is not
//!
//! **Reads are not proxied.** The worker's IAM role still permits GET and
//! LIST, so `get`, `get_bounded`, `get_bounded_until`, `exists`, `list` and
//! `list_bounded` are delegated unchanged to an injected read store. In
//! production that store is `cats-object-store-aws-s3` opened from exactly the
//! same provider configuration blockd uses today; the gateway sees only
//! writes.
//!
//! **Deletion is not available.** The signed contract has no delete class and
//! the worker role is denied `s3:DeleteObject`, so `delete`, `delete_until`
//! and `list_for_delete_bounded_until` fail closed rather than delegate a call
//! that would be refused, or worse, silently appear to succeed.
//!
//! **Qualification faults are never requested.** `qualification_fault` is
//! always `None` on this path. A receipt that carries qualification evidence
//! back is treated as an authority breach and fails the write.
//!
//! # Ambiguity
//!
//! The gateway keys an attempt by a `request_id` derived from the writer
//! authority, the target, the key class, the content digest and the content
//! length — every one of which is fixed by the signed descriptor. Re-sending
//! the byte-identical request is therefore a lookup of the already-settled
//! attempt, not a second destructive effect: the gateway returns the terminal
//! receipt it recorded the first time. That is the only recovery this adapter
//! performs after a timeout or a lost connection. It never rewrites the
//! descriptor, never invents a new attempt identity, and never reports success
//! for a request whose receipt it has not read.

mod key;

use std::io::Read as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cats_api::agent_registration::Ed25519RequestSigner;
use cats_api::error::ErrorBody;
use cats_api::object_write_gateway::{
    decode_object_write_gateway_receipt, sign_object_write_request,
    ObjectWriteGatewayContractError, ObjectWriteGatewayReceipt, ObjectWriteGatewayTerminalReceipt,
    ObjectWriteIngressDescriptor, ObjectWriteRequestProof, OBJECT_WRITE_BODY_MAX_BYTES,
    OBJECT_WRITE_CREDENTIAL_ID_HEADER, OBJECT_WRITE_DESCRIPTOR_HEADER,
    OBJECT_WRITE_GATEWAY_CONTENT_TYPE, OBJECT_WRITE_GATEWAY_PATH,
    OBJECT_WRITE_GATEWAY_RECEIPT_MAX_BYTES, OBJECT_WRITE_PUBLIC_KEY_SPKI_HEADER,
    OBJECT_WRITE_SIGNATURE_HEADER,
};
use cats_api::runtime_reconciliation::{ContractVersion, Id, Sha256Digest, WireU64};
use cats_storage::blob::{BlobError, BlobListPage, BlobStore, QualifiedDeleteListPage};
use cats_storage::{AdapterConfig, AdapterError, BlobStoreFactory};
use sha2::Digest as _;

pub const ADAPTER_NAME: &str = "object-write-gateway";

/// Total attempts for one object write, including the first. Every attempt
/// carries the identical signed descriptor, so the budget bounds recovery
/// without ever widening the set of effects that can happen.
const WRITE_ATTEMPTS: u32 = 4;
const RETRY_INITIAL_DELAY: Duration = Duration::from_millis(100);
const RETRY_MAX_DELAY: Duration = Duration::from_secs(3);
/// One attempt must outlive the gateway's own 60-second request deadline, so
/// that a gateway-issued terminal receipt is preferred over a local timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(90);
const ERROR_BODY_MAX_BYTES: usize = 8 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ObjectWriteError {
    #[error("object key {key:?} is not writable through the ObjectWrite Gateway: {reason}")]
    UnrepresentableKey { key: String, reason: String },
    #[error("object key {key:?} names volume {found:?}, not the attached volume {expected:?}")]
    VolumeMismatch {
        key: String,
        expected: String,
        found: String,
    },
    #[error("object-write body for {key:?} is {observed} bytes, over the {maximum}-byte bound")]
    BodyTooLarge {
        key: String,
        observed: usize,
        maximum: usize,
    },
    #[error("object-write request for {key:?} could not be signed: {source}")]
    Contract {
        key: String,
        #[source]
        source: ObjectWriteGatewayContractError,
    },
    #[error("the ObjectWrite Gateway rejected the write of {key:?} with HTTP {status}: {message}")]
    Rejected {
        key: String,
        status: u16,
        message: String,
    },
    #[error(
        "the ObjectWrite Gateway did not authenticate the attachment credential for {key:?}: \
         {message}"
    )]
    CredentialRejected { key: String, message: String },
    #[error("the ObjectWrite Gateway permanently failed the write of {key:?}: receipt {receipt}")]
    PermanentlyFailed { key: String, receipt: String },
    #[error(
        "the ObjectWrite Gateway answered the ordinary production write of {key:?} with a \
         qualification receipt"
    )]
    UnexpectedQualificationReceipt { key: String },
    /// The write may or may not have been published. It must never be reported
    /// as success, and the caller must not compensate for it blindly.
    #[error(
        "the outcome of the write of {key:?} is unknown after {attempts} identical attempts: {last}"
    )]
    Ambiguous {
        key: String,
        attempts: u32,
        last: String,
    },
    /// Every attempt failed before the request reached the gateway, so no
    /// effect can have happened.
    #[error(
        "the ObjectWrite Gateway was unreachable for {key:?} after {attempts} attempts: {last}"
    )]
    Unreachable {
        key: String,
        attempts: u32,
        last: String,
    },
    #[error("the ObjectWrite Gateway has no delete authority; refusing to delete {key:?}")]
    DeleteUnavailable { key: String },
    #[error("invalid ObjectWrite Gateway base URL: {message}")]
    InvalidBaseUrl { message: String },
    #[error("the ObjectWrite Gateway HTTP client could not be built: {message}")]
    Client { message: String },
    #[error("the ObjectWrite Gateway server trust anchor is unusable: {message}")]
    InvalidServerTrust { message: String },
}

impl ObjectWriteError {
    fn into_blob_error(self, key: &str) -> BlobError {
        match self {
            Self::BodyTooLarge {
                observed, maximum, ..
            } => BlobError::TooLarge {
                key: key.to_owned(),
                maximum,
                observed_at_least: observed,
            },
            Self::UnrepresentableKey { .. } | Self::VolumeMismatch { .. } => {
                BlobError::InvalidKey {
                    key: key.to_owned(),
                    message: self.to_string(),
                }
            }
            other => BlobError::Backend {
                key: key.to_owned(),
                message: other.to_string(),
            },
        }
    }
}

/// How this adapter authenticates the ObjectWrite Gateway it publishes through.
///
/// The gateway serves a certificate issued by the deployment's own Route v2
/// root, which no public trust store contains, so the caller must hand over
/// that root explicitly. There is deliberately no "use the built-in roots"
/// case: a production write path that silently fell back to the public trust
/// store would accept any publicly issued certificate for the gateway host.
#[derive(Debug, Clone, Copy)]
pub enum ObjectWriteGatewayServerTrust<'a> {
    /// Verify the gateway against exactly these PEM roots and nothing else.
    Roots(&'a [u8]),
    /// The in-process test double and local development, which serve plaintext
    /// on a loopback literal and therefore authenticate nothing.
    PlaintextLoopback,
}

/// A [`BlobStore`] whose writes are published by the ObjectWrite Gateway.
pub struct ObjectWriteGatewayBlobStore {
    endpoint: String,
    volume_id: Id,
    signer: Ed25519RequestSigner,
    reads: Arc<dyn BlobStore>,
    client: reqwest::blocking::Client,
}

impl std::fmt::Debug for ObjectWriteGatewayBlobStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ObjectWriteGatewayBlobStore")
            .field("endpoint", &self.endpoint)
            .field("volume_id", &self.volume_id)
            .field("signer", &self.signer)
            .finish_non_exhaustive()
    }
}

impl ObjectWriteGatewayBlobStore {
    /// Bind one attachment-scoped object-write credential to one gateway and
    /// one volume.
    ///
    /// `gateway_base_url` is an origin such as `https://gateway.internal:8443`;
    /// the contract path is appended by this adapter. The gateway serves TLS
    /// only, so a plaintext origin is accepted for a loopback literal — the
    /// in-process test double and local development — and refused everywhere
    /// else rather than shipping volume bytes in the clear.
    ///
    /// `signer` is the registered attachment key. This adapter neither loads
    /// nor persists key material: the Node registers the credential and hands
    /// over the ready signer.
    ///
    /// `reads` serves every non-mutating method unchanged. In production it is
    /// the same `cats-object-store-aws-s3` store the worker already uses.
    pub fn new(
        gateway_base_url: &str,
        volume_id: Id,
        signer: Ed25519RequestSigner,
        reads: Arc<dyn BlobStore>,
        trust: ObjectWriteGatewayServerTrust<'_>,
    ) -> Result<Self, ObjectWriteError> {
        let origin = validated_origin(gateway_base_url)?;
        let mut client = reqwest::blocking::Client::builder()
            // A signed body must never be replayed to a Location that was not
            // part of the request the attachment key authorized.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT);
        client = install_server_trust(client, &origin, trust)?;
        let client = client.build().map_err(|error| ObjectWriteError::Client {
            message: error.to_string(),
        })?;
        Ok(Self {
            endpoint: format!("{origin}{OBJECT_WRITE_GATEWAY_PATH}"),
            volume_id,
            signer,
            reads,
            client,
        })
    }

    /// Publish `data` at `key`, returning the exact gateway failure rather than
    /// the port's flattened [`BlobError`].
    pub fn publish(&self, key: &str, data: &[u8]) -> Result<(), ObjectWriteError> {
        let too_large = || ObjectWriteError::BodyTooLarge {
            key: key.to_owned(),
            observed: data.len(),
            maximum: OBJECT_WRITE_BODY_MAX_BYTES,
        };
        if data.len() > OBJECT_WRITE_BODY_MAX_BYTES {
            return Err(too_large());
        }
        let content_length = u64::try_from(data.len())
            .ok()
            .and_then(WireU64::new)
            .ok_or_else(too_large)?;
        let content_sha256 = Sha256Digest::from_bytes(sha2::Sha256::digest(data).into());
        let immutable_key = key::immutable_key_for(&self.volume_id, key, &content_sha256)?;
        let descriptor = ObjectWriteIngressDescriptor {
            version: ContractVersion::V1,
            volume_id: self.volume_id.clone(),
            key: immutable_key,
            content_sha256,
            content_length,
            qualification_fault: None,
        };
        let proof = sign_object_write_request(&self.signer, &descriptor).map_err(|source| {
            ObjectWriteError::Contract {
                key: key.to_owned(),
                source,
            }
        })?;
        self.settle(key, &proof, data)
    }

    /// Drive the identical signed request until the gateway settles it or the
    /// attempt budget runs out.
    fn settle(
        &self,
        key: &str,
        proof: &ObjectWriteRequestProof,
        data: &[u8],
    ) -> Result<(), ObjectWriteError> {
        let mut delay = RETRY_INITIAL_DELAY;
        let mut ambiguous = false;
        let mut attempt = 1;
        loop {
            let outcome = self.send_once(proof, data);
            let detail = match outcome {
                Attempt::Settled(receipt) => return interpret(key, &receipt),
                Attempt::Rejected {
                    status,
                    message,
                    authentication,
                } => {
                    return Err(if authentication {
                        ObjectWriteError::CredentialRejected {
                            key: key.to_owned(),
                            message,
                        }
                    } else {
                        ObjectWriteError::Rejected {
                            key: key.to_owned(),
                            status,
                            message,
                        }
                    });
                }
                Attempt::Unresolved { detail, reached } => {
                    ambiguous |= reached;
                    detail
                }
            };
            if attempt >= WRITE_ATTEMPTS {
                tracing::warn!(
                    key,
                    attempts = attempt,
                    ambiguous,
                    detail,
                    "object write did not settle"
                );
                return Err(if ambiguous {
                    ObjectWriteError::Ambiguous {
                        key: key.to_owned(),
                        attempts: attempt,
                        last: detail,
                    }
                } else {
                    ObjectWriteError::Unreachable {
                        key: key.to_owned(),
                        attempts: attempt,
                        last: detail,
                    }
                });
            }
            tracing::warn!(
                key,
                attempt,
                detail,
                "object write unresolved; re-sending the identical signed request"
            );
            std::thread::sleep(delay);
            delay = (delay * 4).min(RETRY_MAX_DELAY);
            attempt += 1;
        }
    }

    fn send_once(&self, proof: &ObjectWriteRequestProof, data: &[u8]) -> Attempt {
        // Each attempt re-sends the identical body; reqwest's blocking client
        // takes ownership of the buffer, so the copy is the price of keeping
        // the request byte-identical across attempts.
        let request = self
            .client
            .post(&self.endpoint)
            .header(
                reqwest::header::CONTENT_TYPE,
                OBJECT_WRITE_GATEWAY_CONTENT_TYPE,
            )
            .header(OBJECT_WRITE_DESCRIPTOR_HEADER, &proof.descriptor)
            .header(
                OBJECT_WRITE_CREDENTIAL_ID_HEADER,
                &proof.credential.credential_id,
            )
            .header(
                OBJECT_WRITE_PUBLIC_KEY_SPKI_HEADER,
                &proof.credential.public_key_spki,
            )
            .header(OBJECT_WRITE_SIGNATURE_HEADER, &proof.credential.signature)
            .body(data.to_vec());
        let response = match request.send() {
            Ok(response) => response,
            Err(error) => {
                // A connection that was never established cannot have produced
                // an effect; anything later leaves the outcome unknown.
                return Attempt::Unresolved {
                    detail: error.to_string(),
                    reached: !error.is_connect(),
                };
            }
        };
        let status = response.status().as_u16();
        let body = match read_bounded(response, status) {
            Ok(body) => body,
            Err(detail) => {
                return Attempt::Unresolved {
                    detail,
                    reached: true,
                }
            }
        };
        match status {
            200..=299 => match decode_object_write_gateway_receipt(&body) {
                Ok(receipt) => Attempt::Settled(receipt),
                Err(error) => Attempt::Unresolved {
                    detail: format!("HTTP {status} carried an undecodable receipt: {error}"),
                    reached: true,
                },
            },
            // The gateway settles every 4xx of its own before it accepts a
            // sequence, so those rejections published nothing and repeating
            // them would only widen the failure window. 429 is not one of its
            // codes — it is an intermediary asking for the same request again.
            429 => Attempt::Unresolved {
                detail: format!("HTTP 429: {}", describe(&body)),
                reached: true,
            },
            400..=499 => Attempt::Rejected {
                status,
                message: describe(&body),
                authentication: status == 401 || status == 403,
            },
            _ => Attempt::Unresolved {
                detail: format!("HTTP {status}: {}", describe(&body)),
                reached: true,
            },
        }
    }
}

enum Attempt {
    Settled(ObjectWriteGatewayReceipt),
    Rejected {
        status: u16,
        message: String,
        authentication: bool,
    },
    Unresolved {
        detail: String,
        /// Whether the request may have reached the gateway.
        reached: bool,
    },
}

fn interpret(key: &str, receipt: &ObjectWriteGatewayReceipt) -> Result<(), ObjectWriteError> {
    match &receipt.terminal {
        ObjectWriteGatewayTerminalReceipt::SucceededVisible {
            qualification_ambiguity: None,
            ..
        } => Ok(()),
        ObjectWriteGatewayTerminalReceipt::SucceededVisible { .. }
        | ObjectWriteGatewayTerminalReceipt::QualificationUnprovenVisible { .. } => {
            Err(ObjectWriteError::UnexpectedQualificationReceipt {
                key: key.to_owned(),
            })
        }
        ObjectWriteGatewayTerminalReceipt::PermanentlyFailed {
            failure_receipt_id, ..
        } => Err(ObjectWriteError::PermanentlyFailed {
            key: key.to_owned(),
            receipt: failure_receipt_id.as_str().to_owned(),
        }),
    }
}

/// Pins the client to the deployment's own gateway roots, or proves that the
/// origin authenticates nothing because it is plaintext loopback.
///
/// `tls_built_in_root_certs(false)` is what makes `Roots` exact: the gateway
/// is a fixed internal origin, so the public roots are not a fallback but an
/// additional way to be impersonated.
fn install_server_trust(
    builder: reqwest::blocking::ClientBuilder,
    origin: &str,
    trust: ObjectWriteGatewayServerTrust<'_>,
) -> Result<reqwest::blocking::ClientBuilder, ObjectWriteError> {
    let invalid = |message: &str| ObjectWriteError::InvalidServerTrust {
        message: message.to_owned(),
    };
    let plaintext = origin.starts_with("http://");
    match trust {
        ObjectWriteGatewayServerTrust::PlaintextLoopback => {
            if plaintext {
                return Ok(builder);
            }
            Err(invalid(
                "an https gateway origin requires explicit server roots",
            ))
        }
        ObjectWriteGatewayServerTrust::Roots(pem) => {
            if plaintext {
                return Err(invalid(
                    "a plaintext loopback origin cannot authenticate server roots",
                ));
            }
            let roots = reqwest::tls::Certificate::from_pem_bundle(pem)
                .map_err(|error| invalid(&format!("unreadable PEM bundle: {error}")))?;
            if roots.is_empty() {
                return Err(invalid("the PEM bundle contains no certificate"));
            }
            let mut builder = builder.https_only(true).tls_built_in_root_certs(false);
            for root in roots {
                builder = builder.add_root_certificate(root);
            }
            Ok(builder)
        }
    }
}

fn validated_origin(base_url: &str) -> Result<String, ObjectWriteError> {
    let url = reqwest::Url::parse(base_url).map_err(|error| ObjectWriteError::InvalidBaseUrl {
        message: error.to_string(),
    })?;
    let invalid = |message: &str| ObjectWriteError::InvalidBaseUrl {
        message: message.to_owned(),
    };
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(invalid(
            "expected a bare origin without a path, query, or fragment",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("an origin must not carry credentials"));
    }
    match url.scheme() {
        "https" => {}
        "http" if is_loopback(&url) => {}
        "http" => {
            return Err(invalid(
                "a plaintext origin is only accepted for a loopback address",
            ));
        }
        _ => return Err(invalid("expected an http or https origin")),
    }
    if !url.has_host() {
        return Err(invalid("an origin must name a host"));
    }
    Ok(url.origin().ascii_serialization())
}

/// Only a loopback IP literal counts. A name such as `localhost` is not
/// accepted: what it resolves to is ambient host configuration, not something
/// this adapter can prove before it sends volume bytes in the clear.
fn is_loopback(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

fn read_bounded(mut response: reqwest::blocking::Response, status: u16) -> Result<Vec<u8>, String> {
    let maximum = if (200..300).contains(&status) {
        OBJECT_WRITE_GATEWAY_RECEIPT_MAX_BYTES
    } else {
        ERROR_BODY_MAX_BYTES
    };
    let mut body = Vec::new();
    (&mut response)
        .take(maximum as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|error| format!("HTTP {status} body could not be read: {error}"))?;
    if body.len() > maximum {
        return Err(format!("HTTP {status} body exceeded {maximum} bytes"));
    }
    Ok(body)
}

fn describe(body: &[u8]) -> String {
    match serde_json::from_slice::<ErrorBody>(body) {
        Ok(error) => format!("{:?} {}", error.code, error.message),
        Err(_) => String::from_utf8_lossy(body).chars().take(256).collect(),
    }
}

impl BlobStore for ObjectWriteGatewayBlobStore {
    fn put_immutable(&self, key: &str, data: &[u8]) -> cats_storage::blob::Result<()> {
        self.publish(key, data)
            .map_err(|error| error.into_blob_error(key))
    }

    fn get(&self, key: &str) -> cats_storage::blob::Result<Vec<u8>> {
        self.reads.get(key)
    }

    fn get_bounded(&self, key: &str, maximum: usize) -> cats_storage::blob::Result<Vec<u8>> {
        self.reads.get_bounded(key, maximum)
    }

    fn get_bounded_until(
        &self,
        key: &str,
        maximum: usize,
        deadline: Instant,
    ) -> cats_storage::blob::Result<Vec<u8>> {
        self.reads.get_bounded_until(key, maximum, deadline)
    }

    fn exists(&self, key: &str) -> cats_storage::blob::Result<bool> {
        self.reads.exists(key)
    }

    fn delete(&self, key: &str) -> cats_storage::blob::Result<()> {
        Err(ObjectWriteError::DeleteUnavailable {
            key: key.to_owned(),
        }
        .into_blob_error(key))
    }

    fn delete_until(&self, key: &str, _deadline: Instant) -> cats_storage::blob::Result<()> {
        self.delete(key)
    }

    fn list(&self, prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
        self.reads.list(prefix)
    }

    fn list_bounded(
        &self,
        prefix: &str,
        maximum: usize,
    ) -> cats_storage::blob::Result<BlobListPage> {
        self.reads.list_bounded(prefix, maximum)
    }

    fn list_for_delete_bounded_until(
        &self,
        prefix: &str,
        _maximum: usize,
        _deadline: Instant,
    ) -> cats_storage::blob::Result<QualifiedDeleteListPage> {
        // A destructive LIST authorizes a deletion receipt. This adapter can
        // never settle one, so it must not qualify the listing either.
        Err(ObjectWriteError::DeleteUnavailable {
            key: prefix.to_owned(),
        }
        .into_blob_error(prefix))
    }
}

/// Opens [`ObjectWriteGatewayBlobStore`] through the adapter port.
///
/// The attachment credential and the read store are held by the factory rather
/// than named in [`AdapterConfig`]: `AdapterConfig` is opaque process
/// configuration and must never carry key material.
pub struct ObjectWriteGatewayBlobStoreFactory {
    signer: Ed25519RequestSigner,
    reads: Arc<dyn BlobStore>,
}

impl ObjectWriteGatewayBlobStoreFactory {
    pub fn new(signer: Ed25519RequestSigner, reads: Arc<dyn BlobStore>) -> Self {
        Self { signer, reads }
    }
}

impl BlobStoreFactory for ObjectWriteGatewayBlobStoreFactory {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn open(&self, config: &AdapterConfig) -> Result<Arc<dyn BlobStore>, AdapterError> {
        config.ensure_only(
            ADAPTER_NAME,
            &["gateway-url", "volume-id", "server-ca-file"],
        )?;
        let gateway_url = config.required(ADAPTER_NAME, "gateway-url")?;
        let volume_id = config.required(ADAPTER_NAME, "volume-id")?;
        let volume_id = Id::new(volume_id).ok_or_else(|| AdapterError::InvalidConfig {
            adapter: ADAPTER_NAME,
            message: "volume-id is not a valid identifier".into(),
        })?;
        // Required, not optional: the gateway is certified by the deployment's
        // own root, so a store opened without it could never publish.
        let server_ca_file = config.required(ADAPTER_NAME, "server-ca-file")?;
        let server_ca_bundle =
            std::fs::read(server_ca_file).map_err(|error| AdapterError::InvalidConfig {
                adapter: ADAPTER_NAME,
                message: format!("server-ca-file is unreadable: {error}"),
            })?;
        ObjectWriteGatewayBlobStore::new(
            gateway_url,
            volume_id,
            self.signer.clone(),
            Arc::clone(&self.reads),
            ObjectWriteGatewayServerTrust::Roots(&server_ca_bundle),
        )
        .map(|store| Arc::new(store) as Arc<dyn BlobStore>)
        .map_err(|error| AdapterError::Open {
            adapter: ADAPTER_NAME,
            message: error.to_string(),
        })
    }
}

#[cfg(test)]
mod tests;
