//! Tests against an in-process double of the ObjectWrite Gateway's HTTP
//! surface.
//!
//! The double is deliberately strict: it re-runs the gateway's own transport
//! and authentication checks with
//! [`verify_object_write_request`], recomputes the body digest, and answers
//! `401`/`400` when the client gets any of it wrong. A passing success test is
//! therefore the positive calibration for every negative test here — if the
//! adapter signed the wrong bytes, named the wrong key class, or sent a
//! forbidden transport header, no test in this file could pass.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use cats_api::error::ErrorCode;
use cats_api::object_write_gateway::{
    encode_object_write_gateway_receipt, object_write_key, verify_object_write_request,
    ObjectWriteGatewayReceipt, ObjectWriteGatewayTerminalReceipt, ObjectWriteImmutableKey,
    ObjectWriteIngressDescriptor, ObjectWriteQualificationAmbiguityReceiptV1, VolumeDataObjectKind,
    OBJECT_WRITE_BODY_MAX_BYTES, OBJECT_WRITE_CREDENTIAL_ID_HEADER, OBJECT_WRITE_DESCRIPTOR_HEADER,
    OBJECT_WRITE_GATEWAY_CONTENT_TYPE, OBJECT_WRITE_GATEWAY_METHOD, OBJECT_WRITE_GATEWAY_PATH,
    OBJECT_WRITE_PUBLIC_KEY_SPKI_HEADER, OBJECT_WRITE_QUALIFICATION_CONTROL_SCHEMA_VERSION,
    OBJECT_WRITE_SIGNATURE_HEADER,
};
use cats_api::runtime_reconciliation::{AsciiText, UnixMillis};
use ring::signature::{Ed25519KeyPair, KeyPair as _};

use super::*;

const VOLUME: &str = "vol-1";
const TRANSACTION: &str = "11111111111111111111111111111111";

// ---------------------------------------------------------------------------
// Test double
// ---------------------------------------------------------------------------

/// One scripted answer to one accepted request. The last entry repeats, so a
/// test never turns an exhausted script into a connection refusal, which would
/// silently change what the adapter observes.
#[derive(Clone, Copy)]
enum Reply {
    /// A valid `SucceededVisible` receipt with no qualification evidence.
    Succeeded,
    /// A valid `PermanentlyFailed` receipt.
    PermanentlyFailed,
    /// Read the whole request, then close without answering: the outcome of a
    /// request the gateway may already have settled is unknown to the client.
    Interrupt,
    /// A status the gateway produces before it accepts a sequence.
    Rejected(u16),
    /// `200` whose body is not a receipt this client can validate.
    UndecodableReceipt,
}

#[derive(Clone)]
struct Recorded {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Recorded {
    fn header(&self, name: &str) -> Option<&str> {
        let mut found = self
            .headers
            .iter()
            .filter(|(header, _)| header == name)
            .map(|(_, value)| value.as_str());
        let value = found.next()?;
        // The gateway accepts exactly one of every header it reads.
        found.next().is_none().then_some(value)
    }

    fn descriptor(&self) -> ObjectWriteIngressDescriptor {
        verify_object_write_request(
            self.header(OBJECT_WRITE_DESCRIPTOR_HEADER).unwrap(),
            self.header(OBJECT_WRITE_CREDENTIAL_ID_HEADER).unwrap(),
            self.header(OBJECT_WRITE_PUBLIC_KEY_SPKI_HEADER).unwrap(),
            self.header(OBJECT_WRITE_SIGNATURE_HEADER).unwrap(),
        )
        .expect("the recorded request carries a verifiable proof")
        .1
    }
}

struct GatewayDouble {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<Recorded>>>,
    stop: Arc<AtomicBool>,
    served: Arc<AtomicUsize>,
    worker: Option<JoinHandle<()>>,
}

impl GatewayDouble {
    fn start(script: Vec<Reply>) -> Self {
        assert!(!script.is_empty(), "a script needs at least one reply");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the gateway double");
        let address = listener.local_addr().expect("the double has an address");
        listener
            .set_nonblocking(true)
            .expect("poll for connections so the double can be shut down");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let served = Arc::new(AtomicUsize::new(0));
        let worker = std::thread::spawn({
            let requests = Arc::clone(&requests);
            let stop = Arc::clone(&stop);
            let served = Arc::clone(&served);
            move || loop {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        let index = served.fetch_add(1, Ordering::SeqCst);
                        let reply = script[index.min(script.len() - 1)];
                        serve(stream, reply, &requests);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("the gateway double could not accept: {error}"),
                }
            }
        });
        Self {
            address,
            requests,
            stop,
            served,
            worker: Some(worker),
        }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().expect("recorded requests").clone()
    }

    fn served(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }
}

impl Drop for GatewayDouble {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn serve(mut stream: TcpStream, reply: Reply, requests: &Mutex<Vec<Recorded>>) {
    stream
        .set_nonblocking(false)
        .expect("serve one request synchronously");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("a stalled client must not park the double forever");
    let recorded = read_request(&mut stream);
    requests
        .lock()
        .expect("recorded requests")
        .push(recorded.clone());
    match check_transport(&recorded) {
        Err((status, message)) => respond_json(&mut stream, status, message),
        Ok(()) => match reply {
            Reply::Interrupt => drop(stream),
            Reply::Rejected(status) => {
                respond_json(&mut stream, status, "scripted gateway rejection");
            }
            Reply::UndecodableReceipt => respond(
                &mut stream,
                200,
                br#"{"version":1,"terminal":{"kind":"succeeded_visible"}}"#,
            ),
            Reply::Succeeded => respond(&mut stream, 200, &encoded_receipt(succeeded())),
            Reply::PermanentlyFailed => {
                respond(&mut stream, 200, &encoded_receipt(permanently_failed()));
            }
        },
    }
}

fn read_request(stream: &mut TcpStream) -> Recorded {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("read a request head");
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).expect("the request head is ASCII");
    let mut lines = head.split("\r\n");
    let request_line = lines.next().expect("a request line").to_owned();
    let mut fields = request_line.split(' ');
    let method = fields.next().unwrap_or_default().to_owned();
    let target = fields.next().unwrap_or_default().to_owned();
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect::<Vec<_>>();
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .expect("the gateway requires one Content-Length");
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body).expect("read the request body");
    Recorded {
        method,
        target,
        headers,
        body,
    }
}

/// The gateway's own transport gate, reproduced so that a client mistake shows
/// up as a rejection here instead of as a silent pass.
fn check_transport(recorded: &Recorded) -> Result<(), (u16, &'static str)> {
    if recorded.method != OBJECT_WRITE_GATEWAY_METHOD
        || recorded.target != OBJECT_WRITE_GATEWAY_PATH
    {
        return Err((404, "unknown object-write route"));
    }
    for forbidden in ["content-encoding", "transfer-encoding", "authorization"] {
        if recorded.headers.iter().any(|(name, _)| name == forbidden) {
            return Err((400, "invalid object-write transport"));
        }
    }
    if recorded.header("content-type") != Some(OBJECT_WRITE_GATEWAY_CONTENT_TYPE) {
        return Err((400, "invalid object-write content type"));
    }
    if recorded
        .header("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        != Some(recorded.body.len())
    {
        return Err((400, "Content-Length mismatch"));
    }
    let proof = (
        recorded.header(OBJECT_WRITE_DESCRIPTOR_HEADER),
        recorded.header(OBJECT_WRITE_CREDENTIAL_ID_HEADER),
        recorded.header(OBJECT_WRITE_PUBLIC_KEY_SPKI_HEADER),
        recorded.header(OBJECT_WRITE_SIGNATURE_HEADER),
    );
    let (Some(descriptor), Some(credential), Some(public_key), Some(signature)) = proof else {
        return Err((401, "object-write attachment authentication failed"));
    };
    let Ok((_, descriptor)) =
        verify_object_write_request(descriptor, credential, public_key, signature)
    else {
        return Err((401, "object-write attachment authentication failed"));
    };
    if descriptor.content_length.get() != recorded.body.len() as u64 {
        return Err((400, "Content-Length mismatch"));
    }
    let digest = Sha256Digest::from_bytes(sha2::Sha256::digest(&recorded.body).into());
    if descriptor.content_sha256 != digest {
        return Err((400, "object-write body mismatch"));
    }
    if object_write_key(
        &descriptor.volume_id,
        &descriptor.key,
        &descriptor.content_sha256,
    )
    .is_err()
    {
        return Err((400, "object-write key is not renderable"));
    }
    Ok(())
}

fn respond_json(stream: &mut TcpStream, status: u16, message: &str) {
    let code = match status {
        401 => ErrorCode::Unauthenticated,
        403 => ErrorCode::PermissionDenied,
        404 => ErrorCode::NotFound,
        503 => ErrorCode::Unavailable,
        _ => ErrorCode::InvalidArgument,
    };
    let body = serde_json::to_vec(&ErrorBody::new(code, message)).expect("encode an error body");
    respond(stream, status, &body);
}

fn respond(stream: &mut TcpStream, status: u16, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).expect("write a head");
    stream.write_all(body).expect("write a body");
    stream.flush().expect("flush the response");
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

fn encoded_receipt(receipt: ObjectWriteGatewayReceipt) -> Vec<u8> {
    encode_object_write_gateway_receipt(&receipt).expect("the double emits valid receipts")
}

fn receipt(terminal: ObjectWriteGatewayTerminalReceipt) -> ObjectWriteGatewayReceipt {
    ObjectWriteGatewayReceipt {
        version: ContractVersion::V1,
        writer_authority_id: Id::new("writer-1").expect("a valid writer id"),
        request_id: Sha256Digest::from_bytes([7_u8; 32]),
        accepted_sequence: WireU64::new(1).expect("a valid sequence"),
        terminal,
    }
}

fn succeeded() -> ObjectWriteGatewayReceipt {
    receipt(ObjectWriteGatewayTerminalReceipt::SucceededVisible {
        put_receipt_id: ascii("put-1"),
        put_completed_at_unix_ms: millis(1_000),
        visibility_receipt_id: ascii("visible-1"),
        visible_at_unix_ms: millis(1_001),
        qualification_ambiguity: None,
    })
}

fn permanently_failed() -> ObjectWriteGatewayReceipt {
    receipt(ObjectWriteGatewayTerminalReceipt::PermanentlyFailed {
        failure_receipt_id: ascii("failed-1"),
        failed_at_unix_ms: millis(1_000),
    })
}

fn ascii(value: &str) -> AsciiText {
    AsciiText::new(value).expect("valid printable ASCII")
}

fn millis(value: u64) -> UnixMillis {
    UnixMillis::new(value).expect("a valid wire timestamp")
}

/// One constructible qualification-ambiguity bundle.
///
/// It is written as the wire form so this fixture stays honest about the shape
/// the contract defines instead of drifting into a hand-built Rust value; only
/// the shape matters, because the rule under test refuses every qualification
/// bundle regardless of what its evidence claims.
fn qualification_ambiguity() -> ObjectWriteQualificationAmbiguityReceiptV1 {
    let digest = |fill: char| {
        format!(
            "sha256:{}",
            std::iter::repeat_n(fill, 64).collect::<String>()
        )
    };
    let observation = serde_json::json!({
        "request_id": "provider-request-1",
        "content_sha256": digest('9'),
        "content_length": 5,
    });
    let value = serde_json::json!({
        "version": 1,
        "response_loss": {
            "version": 1,
            "authorization": {
                "version": 1,
                "mutation_class": "object_write_ambiguity",
                "qualification_id": "qualification-1",
                "workspace_id": "workspace-1",
                "deployment_id": "deployment-1",
                "release_id": "release-1",
                "source_commit_sha": "0".repeat(40),
                "control_schema_version": OBJECT_WRITE_QUALIFICATION_CONTROL_SCHEMA_VERSION,
                "qualification_catalog_sha256": digest('4'),
                "admission_binding_sha256": digest('5'),
                "admission_revision": 1,
                "request": {
                    "version": 1,
                    "mutation_class": "object_write_ambiguity",
                    "request_id": digest('7'),
                    "writer_authority_id": "writer-1",
                    "credential": {
                        "credential_id": "credential-1",
                        "public_key_spki_sha256": digest('3'),
                    },
                    "provider_attempt_id": "attempt-1",
                    "fault": {
                        "kind": "successful_put_response_loss",
                        "qualification_id": "qualification-1",
                        "fault_id": TRANSACTION,
                        "qualification_catalog_sha256": digest('4'),
                    },
                    "object_provider_scope": {
                        "provider": "object-provider",
                        "partition": "partition-a",
                        "account_id": "account-a",
                        "region": "region-a",
                    },
                    "object_store_scope_id": "object-store-scope-1",
                    "canonical_logical_key": data_key(1),
                    "content_sha256": digest('9'),
                    "content_length": 5,
                },
                "authorized_at_unix_ms": 900,
                "qualification_expires_at_unix_ms": 2_000,
            },
            "successful_put": {
                "provider_attempt_id": "attempt-1",
                "put_receipt_id": "put-1",
                "provider_request": observation,
                "completed_at_unix_ms": 1_000,
            },
            "injection_receipt_id": "injection-1",
            "injected_at_unix_ms": 1_000,
        },
        "head": {
            "provider_attempt_id": "attempt-1",
            "visibility_receipt_id": "visible-1",
            "provider_request": {
                "request_id": "provider-request-2",
                "content_sha256": digest('9'),
                "content_length": 5,
            },
            "observed_at_unix_ms": 1_001,
        },
    });
    serde_json::from_value(value).expect("the fixture matches the contract shape")
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A read store that records what it was asked for, so a delegated read cannot
/// be confused with a proxied one.
#[derive(Default)]
struct RecordingReads {
    reads: Mutex<Vec<String>>,
}

impl RecordingReads {
    fn calls(&self) -> Vec<String> {
        self.reads.lock().expect("recorded reads").clone()
    }

    fn record(&self, call: String) {
        self.reads.lock().expect("recorded reads").push(call);
    }
}

impl BlobStore for RecordingReads {
    fn put_immutable(&self, key: &str, _data: &[u8]) -> cats_storage::blob::Result<()> {
        panic!("the read store must never be asked to write {key}");
    }

    fn get(&self, key: &str) -> cats_storage::blob::Result<Vec<u8>> {
        self.record(format!("get {key}"));
        Ok(b"read-through".to_vec())
    }

    fn exists(&self, key: &str) -> cats_storage::blob::Result<bool> {
        self.record(format!("exists {key}"));
        Ok(true)
    }

    fn delete(&self, key: &str) -> cats_storage::blob::Result<()> {
        panic!("the read store must never be asked to delete {key}");
    }

    fn list(&self, prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
        self.record(format!("list {prefix}"));
        Ok(Vec::new())
    }
}

fn signer(credential: &str) -> Ed25519RequestSigner {
    let document = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .expect("generate an Ed25519 key");
    let signer = Ed25519RequestSigner::from_pkcs8_der(
        Id::new(credential).expect("a valid credential id"),
        document.as_ref(),
    )
    .expect("parse the generated key");
    assert_eq!(
        signer.public_key_spki_der().len(),
        Ed25519KeyPair::from_pkcs8(document.as_ref())
            .expect("re-parse")
            .public_key()
            .as_ref()
            .len()
            + 12,
        "the signer publishes a 12-byte SPKI prefix plus the raw public key"
    );
    signer
}

struct Fixture {
    double: GatewayDouble,
    store: ObjectWriteGatewayBlobStore,
    reads: Arc<RecordingReads>,
}

fn fixture(script: Vec<Reply>) -> Fixture {
    let double = GatewayDouble::start(script);
    let reads = Arc::new(RecordingReads::default());
    let store = ObjectWriteGatewayBlobStore::new(
        &double.base_url(),
        Id::new(VOLUME).expect("a valid volume id"),
        signer("credential-1"),
        Arc::clone(&reads) as Arc<dyn BlobStore>,
        ObjectWriteGatewayServerTrust::PlaintextLoopback,
    )
    .expect("open the gateway store");
    Fixture {
        double,
        store,
        reads,
    }
}

fn data_key(chunk_index: u64) -> String {
    format!("volumes/{VOLUME}/data/{TRANSACTION}-c{chunk_index}")
}

fn map_key(body: &[u8]) -> String {
    let digest = Sha256Digest::from_bytes(sha2::Sha256::digest(body).into());
    let hex = digest
        .as_str()
        .strip_prefix("sha256:")
        .expect("the frozen digest prefix");
    format!("volumes/{VOLUME}/maps/{hex}.node")
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

/// Proves the whole signed write: the contract route and transport, the four
/// proof headers, a descriptor whose key class, digest and length match the
/// body, an explicitly absent qualification fault, and a `SucceededVisible`
/// receipt read as success.
#[test]
fn a_data_object_is_published_through_one_signed_gateway_request() {
    let fixture = fixture(vec![Reply::Succeeded]);
    let body = b"chunk-bytes".to_vec();

    fixture
        .store
        .put_immutable(&data_key(7), &body)
        .expect("the gateway publishes the object");

    let requests = fixture.double.requests();
    assert_eq!(requests.len(), 1, "one write is one request");
    let recorded = &requests[0];
    assert_eq!(recorded.method, OBJECT_WRITE_GATEWAY_METHOD);
    assert_eq!(recorded.target, OBJECT_WRITE_GATEWAY_PATH);
    assert_eq!(recorded.body, body);
    assert_eq!(
        recorded.header("content-type"),
        Some(OBJECT_WRITE_GATEWAY_CONTENT_TYPE)
    );
    let descriptor = recorded.descriptor();
    assert_eq!(descriptor.version, ContractVersion::V1);
    assert_eq!(descriptor.volume_id.as_str(), VOLUME);
    assert_eq!(descriptor.content_length.get(), body.len() as u64);
    assert_eq!(
        descriptor.content_sha256,
        Sha256Digest::from_bytes(sha2::Sha256::digest(&body).into())
    );
    assert!(
        descriptor.qualification_fault.is_none(),
        "the ordinary production path never requests a qualification fault"
    );
    match descriptor.key {
        ObjectWriteImmutableKey::VolumeData {
            transaction_id,
            chunk_index,
            object_kind,
        } => {
            assert_eq!(transaction_id.as_str(), TRANSACTION);
            assert_eq!(chunk_index.get(), 7);
            assert_eq!(object_kind, VolumeDataObjectKind::Base);
        }
        other => panic!("expected a volume-data key class, got {other:?}"),
    }
}

/// A delta object and a commit record share the transport but not the key
/// class; a map object's key is its own content digest.
#[test]
fn every_writable_key_class_recovers_its_signed_form() {
    let fixture = fixture(vec![Reply::Succeeded]);
    let body = b"map-node-bytes".to_vec();

    let keys = [
        format!("volumes/{VOLUME}/data/{TRANSACTION}-c3-d"),
        format!("volumes/{VOLUME}/commits/9-{TRANSACTION}.json"),
        map_key(&body),
    ];
    for key in &keys {
        fixture
            .store
            .put_immutable(key, &body)
            .unwrap_or_else(|error| panic!("publishing {key} failed: {error}"));
    }

    let classes = fixture
        .double
        .requests()
        .iter()
        .map(|recorded| recorded.descriptor().key)
        .collect::<Vec<_>>();
    assert!(matches!(
        classes[0],
        ObjectWriteImmutableKey::VolumeData {
            object_kind: VolumeDataObjectKind::Delta,
            ..
        }
    ));
    assert!(matches!(
        &classes[1],
        ObjectWriteImmutableKey::VolumeCommit { generation, transaction_id }
            if generation.get() == 9 && transaction_id.as_str() == TRANSACTION
    ));
    assert_eq!(classes[2], ObjectWriteImmutableKey::VolumeMap);
}

/// The signed contract cannot express image objects, another volume's objects,
/// or a map key that is not the body's digest. Each has to fail locally: a
/// request the gateway would refuse must never be signed and sent.
#[test]
fn a_key_outside_the_signed_contract_is_refused_before_any_request() {
    let fixture = fixture(vec![Reply::Succeeded]);
    let body = b"payload".to_vec();

    let unrepresentable = [
        "images/img-1/data/object-1",
        "images/img-1/manifest.json",
        &format!("volumes/{VOLUME}/heads/current.json"),
        &format!("volumes/{VOLUME}/data/not-a-transaction-c1"),
        &format!("volumes/{VOLUME}/commits/0-{TRANSACTION}.json"),
        // A map key is the digest of its own bytes; this one is not.
        &map_key(b"different-bytes"),
    ];
    for key in unrepresentable {
        let error = fixture
            .store
            .publish(key, &body)
            .expect_err("an unrepresentable key must fail");
        assert!(
            matches!(error, ObjectWriteError::UnrepresentableKey { .. }),
            "expected {key} to be unrepresentable, got {error}"
        );
    }

    let other_volume = format!("volumes/vol-2/data/{TRANSACTION}-c1");
    let error = fixture
        .store
        .publish(&other_volume, &body)
        .expect_err("another volume's key must fail");
    assert!(
        matches!(&error, ObjectWriteError::VolumeMismatch { found, .. } if found == "vol-2"),
        "expected a volume mismatch, got {error}"
    );

    assert_eq!(
        fixture.double.served(),
        0,
        "no unrepresentable key may reach the gateway"
    );
}

/// The body bound is the gateway's, so a body over it is refused locally with
/// the exact numbers rather than truncated into a request that would look
/// valid.
#[test]
fn a_body_over_the_gateway_bound_is_refused_without_truncation() {
    let fixture = fixture(vec![Reply::Succeeded]);
    let body = vec![0_u8; OBJECT_WRITE_BODY_MAX_BYTES + 1];

    let error = fixture
        .store
        .publish(&data_key(1), &body)
        .expect_err("an oversize body must fail");
    assert!(
        matches!(
            error,
            ObjectWriteError::BodyTooLarge {
                observed,
                maximum,
                ..
            } if observed == body.len() && maximum == OBJECT_WRITE_BODY_MAX_BYTES
        ),
        "expected a typed body bound error, got {error}"
    );

    let port_error = fixture
        .store
        .put_immutable(&data_key(1), &body)
        .expect_err("the port surface must fail too");
    assert!(
        matches!(
            port_error,
            BlobError::TooLarge { maximum, observed_at_least, .. }
                if maximum == OBJECT_WRITE_BODY_MAX_BYTES && observed_at_least == body.len()
        ),
        "expected a bounded-size port error, got {port_error}"
    );
    assert_eq!(
        fixture.double.served(),
        0,
        "an oversize body must not be sent at all"
    );
}

/// A credential the gateway will not authenticate is settled, not ambiguous:
/// the rejection happens before any sequence is accepted, so retrying it would
/// only widen the failure window.
#[test]
fn a_rejected_credential_fails_closed_without_retrying() {
    let fixture = fixture(vec![Reply::Rejected(401)]);

    let error = fixture
        .store
        .publish(&data_key(1), b"chunk")
        .expect_err("an unauthenticated write must fail");
    assert!(
        matches!(error, ObjectWriteError::CredentialRejected { .. }),
        "expected a credential rejection, got {error}"
    );
    assert_eq!(
        fixture.double.served(),
        1,
        "a settled rejection must not be retried"
    );
}

/// `400` is likewise produced before the gateway accepts a sequence.
#[test]
fn an_invalid_request_rejection_fails_closed_without_retrying() {
    let fixture = fixture(vec![Reply::Rejected(400)]);

    let error = fixture
        .store
        .publish(&data_key(1), b"chunk")
        .expect_err("a rejected write must fail");
    assert!(
        matches!(error, ObjectWriteError::Rejected { status: 400, .. }),
        "expected a settled rejection, got {error}"
    );
    assert_eq!(fixture.double.served(), 1);
}

/// An interrupted response leaves the outcome unknown. The recovery is to
/// re-send the byte-identical signed request, which the gateway resolves
/// against the `request_id` it already recorded — not to publish a second,
/// differently identified object.
#[test]
fn an_interrupted_response_is_resolved_by_re_sending_the_identical_request() {
    let fixture = fixture(vec![Reply::Interrupt, Reply::Succeeded]);

    fixture
        .store
        .publish(&data_key(4), b"chunk")
        .expect("the re-sent request settles the interrupted attempt");

    let requests = fixture.double.requests();
    assert_eq!(requests.len(), 2, "one interruption, one discovery");
    assert_eq!(
        requests[0].header(OBJECT_WRITE_DESCRIPTOR_HEADER),
        requests[1].header(OBJECT_WRITE_DESCRIPTOR_HEADER),
        "the descriptor decides the request identity and must not change"
    );
    assert_eq!(
        requests[0].header(OBJECT_WRITE_SIGNATURE_HEADER),
        requests[1].header(OBJECT_WRITE_SIGNATURE_HEADER),
    );
    assert_eq!(requests[0].body, requests[1].body);
}

/// When every attempt is interrupted the write is neither successful nor
/// provably absent. The adapter must say so, and must not have varied the
/// request while trying.
#[test]
fn a_permanently_unresolved_response_is_never_reported_as_success() {
    let fixture = fixture(vec![Reply::Interrupt]);

    let error = fixture
        .store
        .publish(&data_key(5), b"chunk")
        .expect_err("an unresolved write must not report success");
    assert!(
        matches!(
            error,
            ObjectWriteError::Ambiguous { attempts, .. } if attempts == WRITE_ATTEMPTS
        ),
        "expected a bounded ambiguous outcome, got {error}"
    );

    let requests = fixture.double.requests();
    assert_eq!(requests.len(), WRITE_ATTEMPTS as usize);
    assert!(
        requests.len() > 1,
        "an unknown outcome must be re-driven at least once before it is given up on"
    );
    let descriptors = requests
        .iter()
        .map(|recorded| recorded.header(OBJECT_WRITE_DESCRIPTOR_HEADER).unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        descriptors.len(),
        1,
        "every attempt must reuse the one request identity"
    );
}

/// A `200` whose receipt this client cannot validate proves nothing. It must
/// leave the write ambiguous rather than be read as success.
#[test]
fn an_undecodable_receipt_is_not_success() {
    let fixture = fixture(vec![Reply::UndecodableReceipt]);

    let error = fixture
        .store
        .publish(&data_key(6), b"chunk")
        .expect_err("an undecodable receipt must not report success");
    assert!(
        matches!(error, ObjectWriteError::Ambiguous { .. }),
        "expected an ambiguous outcome, got {error}"
    );
}

/// A gateway that permanently failed the write says so in a valid receipt.
/// That is settled, and it is not success.
#[test]
fn a_permanently_failed_receipt_is_reported_as_failure() {
    let fixture = fixture(vec![Reply::PermanentlyFailed]);

    let error = fixture
        .store
        .publish(&data_key(2), b"chunk")
        .expect_err("a permanent failure must fail");
    assert!(
        matches!(&error, ObjectWriteError::PermanentlyFailed { receipt, .. } if receipt == "failed-1"),
        "expected the failure receipt, got {error}"
    );
    assert_eq!(
        fixture.double.served(),
        1,
        "a settled failure must not be retried"
    );
}

/// `qualification_fault` is always absent on this path, so qualification
/// evidence coming back means the gateway settled something this client never
/// authorized. Reporting that as an ordinary success would hide it.
///
/// The valid qualification receipts are E13 evidence bundles that only the
/// qualification authority can mint, so this exercises the interpretation
/// directly; `an_undecodable_receipt_is_not_success` covers the wire path for
/// a receipt this client cannot validate.
#[test]
fn a_qualification_receipt_on_the_ordinary_path_fails_closed() {
    let ambiguous = receipt(ObjectWriteGatewayTerminalReceipt::SucceededVisible {
        put_receipt_id: ascii("put-1"),
        put_completed_at_unix_ms: millis(1_000),
        visibility_receipt_id: ascii("visible-1"),
        visible_at_unix_ms: millis(1_001),
        qualification_ambiguity: Some(Box::new(qualification_ambiguity())),
    });

    let error = interpret("volumes/vol-1/data/x", &ambiguous)
        .expect_err("qualification evidence must not be read as an ordinary success");
    assert!(
        matches!(
            error,
            ObjectWriteError::UnexpectedQualificationReceipt { .. }
        ),
        "expected a qualification breach, got {error}"
    );
    assert!(
        interpret("volumes/vol-1/data/x", &succeeded()).is_ok(),
        "the same shape without qualification evidence is the success case"
    );
}

// ---------------------------------------------------------------------------
// Reads and deletes
// ---------------------------------------------------------------------------

/// Reads are not proxied: the worker's IAM role still permits them, so they go
/// straight to the injected object-store adapter and never reach the gateway.
#[test]
fn reads_are_delegated_to_the_object_store_and_never_to_the_gateway() {
    let fixture = fixture(vec![Reply::Succeeded]);

    assert_eq!(
        fixture.store.get(&data_key(1)).expect("a delegated read"),
        b"read-through".to_vec()
    );
    assert!(fixture
        .store
        .exists(&data_key(1))
        .expect("a delegated head"));
    assert!(fixture
        .store
        .list(&format!("volumes/{VOLUME}/data/"))
        .expect("a delegated list")
        .is_empty());

    assert_eq!(
        fixture.reads.calls(),
        vec![
            format!("get {}", data_key(1)),
            format!("exists {}", data_key(1)),
            format!("list volumes/{VOLUME}/data/"),
        ]
    );
    assert_eq!(
        fixture.double.served(),
        0,
        "no read may reach the ObjectWrite Gateway"
    );
}

/// Neither this adapter nor the gateway holds delete authority, and the worker
/// role is denied `s3:DeleteObject`. Every destructive method therefore fails
/// closed instead of delegating a call that would be refused, and a listing
/// that cannot settle a deletion is never qualified for one.
#[test]
fn deletion_and_destructive_listing_fail_closed() {
    let fixture = fixture(vec![Reply::Succeeded]);
    let deadline = Instant::now() + Duration::from_secs(30);

    for outcome in [
        fixture.store.delete(&data_key(1)),
        fixture.store.delete_until(&data_key(1), deadline),
    ] {
        let error = outcome.expect_err("delete must fail closed");
        assert!(
            matches!(&error, BlobError::Backend { message, .. } if message.contains("delete authority")),
            "expected a refused delete, got {error}"
        );
    }
    let error = fixture
        .store
        .list_for_delete_bounded_until(&format!("volumes/{VOLUME}/"), 10, deadline)
        .expect_err("a destructive listing must fail closed");
    assert!(
        matches!(&error, BlobError::Backend { message, .. } if message.contains("delete authority")),
        "expected a refused destructive listing, got {error}"
    );
    assert_eq!(fixture.double.served(), 0);
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

/// A fixed self-signed root, standing in for the deployment's Route v2 root.
/// Its only job is to be a parseable trust anchor, so it is a literal rather
/// than something generated per run.
const SELF_SIGNED_ROOT_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIBYzCCARWgAwIBAgIULICwc/RLnF4bSmGzzr94Ux2eOTIwBQYDK2VwMCYxJDAi\n\
BgNVBAMMG0NhdHMgb2JqZWN0LXdyaXRlIHRlc3Qgcm9vdDAgFw0yNjA4MTgxMTAx\n\
NTZaGA8yMTI2MDcyNTExMDE1NlowJjEkMCIGA1UEAwwbQ2F0cyBvYmplY3Qtd3Jp\n\
dGUgdGVzdCByb290MCowBQYDK2VwAyEA1NilIB8rScb67W7/kKsQ7WB/zvZaT1BG\n\
f2zFVOq+kZOjUzBRMB0GA1UdDgQWBBQkQswCbzxcDl5pz/rGPiUdFSpISDAfBgNV\n\
HSMEGDAWgBQkQswCbzxcDl5pz/rGPiUdFSpISDAPBgNVHRMBAf8EBTADAQH/MAUG\n\
AytlcANBAD1/4EhOQ+aymAJVDBlUSZR9rfAwzGDkp3HohSGR+goWZV++BRdaMN/a\n\
AOyU0kuaUva+bGyoQ8A95rEzSQMTmw4=\n\
-----END CERTIFICATE-----\n";

/// The gateway serves TLS only. A plaintext origin is accepted for a loopback
/// literal — the test double and local development — and refused everywhere
/// else, so volume bytes are never shipped in the clear to a routable host.
#[test]
fn a_plaintext_origin_is_accepted_only_for_a_loopback_literal() {
    let reads = Arc::new(RecordingReads::default()) as Arc<dyn BlobStore>;
    let open = |base: &str| {
        let trust = if base.starts_with("https://") {
            ObjectWriteGatewayServerTrust::Roots(SELF_SIGNED_ROOT_PEM.as_bytes())
        } else {
            ObjectWriteGatewayServerTrust::PlaintextLoopback
        };
        ObjectWriteGatewayBlobStore::new(
            base,
            Id::new(VOLUME).expect("a valid volume id"),
            signer("credential-1"),
            Arc::clone(&reads),
            trust,
        )
    };

    assert!(open("http://127.0.0.1:8443").is_ok());
    assert!(open("http://[::1]:8443").is_ok());
    assert!(open("https://gateway.internal:8443").is_ok());

    for rejected in [
        "http://gateway.internal:8443",
        "http://localhost:8443",
        "http://10.0.0.1:8443",
        "ftp://127.0.0.1",
        "https://user:secret@gateway.internal",
        "https://gateway.internal/v1/internal/runtime/object-writes",
        "https://gateway.internal?probe=1",
        "not-a-url",
    ] {
        let error = open(rejected).expect_err("an unusable origin must fail");
        assert!(
            matches!(error, ObjectWriteError::InvalidBaseUrl { .. }),
            "expected {rejected} to be refused, got {error}"
        );
    }
}

/// The adapter port carries the gateway origin and volume, never key material.
#[test]
fn the_factory_opens_from_configuration_without_credentials() {
    let reads = Arc::new(RecordingReads::default()) as Arc<dyn BlobStore>;
    let factory = ObjectWriteGatewayBlobStoreFactory::new(signer("credential-1"), reads);
    assert_eq!(factory.name(), ADAPTER_NAME);

    let bundle = std::env::temp_dir().join("cats-object-write-test-root.pem");
    std::fs::write(&bundle, SELF_SIGNED_ROOT_PEM).expect("write the test trust anchor");
    let bundle = bundle.to_str().expect("a UTF-8 temporary path");

    let config = AdapterConfig::from_pairs([
        ("gateway-url", "https://gateway.internal:8443"),
        ("volume-id", VOLUME),
        ("server-ca-file", bundle),
    ])
    .expect("valid options");
    assert!(factory.open(&config).is_ok());

    let missing = AdapterConfig::from_pairs([("gateway-url", "https://gateway.internal:8443")])
        .expect("valid options");
    assert!(matches!(
        factory.open(&missing),
        Err(AdapterError::MissingOption { .. })
    ));

    // The trust anchor is as mandatory as the volume: a store opened without it
    // could never publish through the gateway it was pointed at.
    let no_trust = AdapterConfig::from_pairs([
        ("gateway-url", "https://gateway.internal:8443"),
        ("volume-id", VOLUME),
    ])
    .expect("valid options");
    assert!(matches!(
        factory.open(&no_trust),
        Err(AdapterError::MissingOption { .. })
    ));

    let unsupported = AdapterConfig::from_pairs([
        ("gateway-url", "https://gateway.internal:8443"),
        ("volume-id", VOLUME),
        ("server-ca-file", bundle),
        ("secret-key", "leaked"),
    ])
    .expect("valid options");
    assert!(matches!(
        factory.open(&unsupported),
        Err(AdapterError::UnsupportedOptions { .. })
    ));
}

/// The gateway's certificate comes from the deployment's own root, so the
/// production store cannot be built without it. These are the two ways a caller
/// could otherwise end up with a client that authenticates nothing: an https
/// origin declared as loopback plaintext, and roots declared for an origin that
/// carries no TLS at all.
#[test]
fn an_https_origin_cannot_be_opened_without_server_roots() {
    let reads = Arc::new(RecordingReads::default()) as Arc<dyn BlobStore>;
    let open = |base: &str, trust| {
        ObjectWriteGatewayBlobStore::new(
            base,
            Id::new(VOLUME).expect("a valid volume id"),
            signer("credential-1"),
            Arc::clone(&reads),
            trust,
        )
    };

    let error = open(
        "https://gateway.internal:8443",
        ObjectWriteGatewayServerTrust::PlaintextLoopback,
    )
    .expect_err("an https origin must not authenticate nothing");
    assert!(
        matches!(error, ObjectWriteError::InvalidServerTrust { .. }),
        "got {error}"
    );

    let error = open(
        "http://127.0.0.1:8443",
        ObjectWriteGatewayServerTrust::Roots(SELF_SIGNED_ROOT_PEM.as_bytes()),
    )
    .expect_err("a plaintext origin must not claim to authenticate roots");
    assert!(
        matches!(error, ObjectWriteError::InvalidServerTrust { .. }),
        "got {error}"
    );

    for unusable in [
        "",
        "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n",
    ] {
        let error = open(
            "https://gateway.internal:8443",
            ObjectWriteGatewayServerTrust::Roots(unusable.as_bytes()),
        )
        .expect_err("an unusable PEM bundle must fail closed");
        assert!(
            matches!(error, ObjectWriteError::InvalidServerTrust { .. }),
            "got {error}"
        );
    }

    open(
        "https://gateway.internal:8443",
        ObjectWriteGatewayServerTrust::Roots(SELF_SIGNED_ROOT_PEM.as_bytes()),
    )
    .expect("the deployment's own root is the usable case");
}
