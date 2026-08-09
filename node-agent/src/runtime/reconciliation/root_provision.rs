//! Narrow Node-side port for the A14 root-image provision control effect.
//!
//! A control response is only a hint. Every returned value deliberately wraps
//! the hint in [`AuthorityRereadRequired`]; callers cannot turn OK into success
//! or ERR into a terminal runtime state without rereading the volume authority.

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cats_api::runtime_reconciliation::{
    decode_provision_root_image_error, decode_provision_root_image_result,
    encode_provision_root_image_request, ProvisionRootImageError, ProvisionRootImageRequest,
    ProvisionRootImageResult, ProvisionRootImageWireDecodeError,
    PROVISION_ROOT_IMAGE_ERROR_MAX_WIRE_BYTES, PROVISION_ROOT_IMAGE_RESULT_MAX_WIRE_BYTES,
};

const COMMAND_PREFIX: &[u8] = b"provision_root_image ";
const OK_PREFIX: &[u8] = b"OK ";
const ERR_PREFIX: &[u8] = b"ERR ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootProvisionResponseHint {
    Ok(ProvisionRootImageResult),
    Closed(ProvisionRootImageError),
    Unknown(RootProvisionUnknownReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootProvisionUnknownReason {
    Connect,
    Write,
    Timeout,
    Eof,
    MalformedFrame,
    MismatchedIdentity,
}

/// The only successful client return. Its name makes the required next read
/// explicit even when the transport carried a syntactically valid OK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityRereadRequired {
    hint: RootProvisionResponseHint,
}

impl AuthorityRereadRequired {
    pub fn hint(&self) -> &RootProvisionResponseHint {
        &self.hint
    }

    fn new(hint: RootProvisionResponseHint) -> Self {
        Self { hint }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RootProvisionClientError {
    #[error("root provision request is not a valid A14 payload: {0}")]
    InvalidRequest(#[from] ProvisionRootImageWireDecodeError),
}

pub trait RootProvisionControlPort: Send + Sync {
    fn execute(
        &self,
        request: &ProvisionRootImageRequest,
    ) -> Result<AuthorityRereadRequired, RootProvisionClientError>;
}

#[derive(Debug, Clone)]
pub struct UnixRootProvisionClient {
    socket_path: PathBuf,
    read_timeout: Duration,
    write_timeout: Duration,
}

impl UnixRootProvisionClient {
    pub fn new(
        socket_path: impl Into<PathBuf>,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            read_timeout,
            write_timeout,
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl RootProvisionControlPort for UnixRootProvisionClient {
    fn execute(
        &self,
        request: &ProvisionRootImageRequest,
    ) -> Result<AuthorityRereadRequired, RootProvisionClientError> {
        let payload = encode_provision_root_image_request(request)?;
        let mut stream = match UnixStream::connect(&self.socket_path) {
            Ok(stream) => stream,
            Err(_) => return Ok(unknown(RootProvisionUnknownReason::Connect)),
        };
        if stream.set_nonblocking(true).is_err() {
            return Ok(unknown(RootProvisionUnknownReason::Connect));
        }
        let mut frame = Vec::with_capacity(COMMAND_PREFIX.len() + payload.len() + 1);
        frame.extend_from_slice(COMMAND_PREFIX);
        frame.extend_from_slice(&payload);
        frame.push(b'\n');
        if !write_all_before(&mut stream, &frame, self.write_timeout) {
            return Ok(unknown(RootProvisionUnknownReason::Write));
        }

        let frame = match read_response_frame(&mut stream, self.read_timeout) {
            Ok(frame) => frame,
            Err(reason) => return Ok(unknown(reason)),
        };
        let hint = match frame {
            ResponseFrame::Ok(payload) => match decode_provision_root_image_result(&payload) {
                Ok(result) if result_matches_request(&result, request) => {
                    RootProvisionResponseHint::Ok(result)
                }
                Ok(_) => RootProvisionResponseHint::Unknown(
                    RootProvisionUnknownReason::MismatchedIdentity,
                ),
                Err(_) => {
                    RootProvisionResponseHint::Unknown(RootProvisionUnknownReason::MalformedFrame)
                }
            },
            ResponseFrame::Error(payload) => match decode_provision_root_image_error(&payload) {
                Ok(error) if error_matches_request(&error, request) => {
                    RootProvisionResponseHint::Closed(error)
                }
                Ok(_) => RootProvisionResponseHint::Unknown(
                    RootProvisionUnknownReason::MismatchedIdentity,
                ),
                Err(_) => {
                    RootProvisionResponseHint::Unknown(RootProvisionUnknownReason::MalformedFrame)
                }
            },
        };
        Ok(AuthorityRereadRequired::new(hint))
    }
}

enum ResponseFrame {
    Ok(Vec<u8>),
    Error(Vec<u8>),
}

fn read_response_frame(
    stream: &mut UnixStream,
    timeout: Duration,
) -> Result<ResponseFrame, RootProvisionUnknownReason> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(RootProvisionUnknownReason::Timeout)?;
    let mut prefix = [0_u8; 4];
    read_exact_before(stream, &mut prefix, deadline)?;
    let (kind, maximum) = if prefix.starts_with(OK_PREFIX) {
        // `OK ` is three bytes; the fourth byte is the first payload byte.
        (true, PROVISION_ROOT_IMAGE_RESULT_MAX_WIRE_BYTES)
    } else if prefix == ERR_PREFIX {
        (false, PROVISION_ROOT_IMAGE_ERROR_MAX_WIRE_BYTES)
    } else {
        return Err(RootProvisionUnknownReason::MalformedFrame);
    };

    let first_payload = if kind { Some(prefix[3]) } else { None };
    let mut payload = Vec::with_capacity(maximum.min(4096));
    if let Some(byte) = first_payload {
        if byte == b'\n' || byte == b'\r' {
            return Err(RootProvisionUnknownReason::MalformedFrame);
        }
        payload.push(byte);
    }
    let mut buffer = [0_u8; 512];
    loop {
        let read = read_before(stream, &mut buffer, deadline)?;
        if read == 0 {
            return Err(RootProvisionUnknownReason::Eof);
        }
        for &byte in &buffer[..read] {
            if byte == b'\n' {
                if payload.last() == Some(&b'\r') {
                    return Err(RootProvisionUnknownReason::MalformedFrame);
                }
                return if kind {
                    Ok(ResponseFrame::Ok(payload))
                } else {
                    Ok(ResponseFrame::Error(payload))
                };
            }
            if payload.len() == maximum {
                return Err(RootProvisionUnknownReason::MalformedFrame);
            }
            payload.push(byte);
        }
    }
}

fn read_exact_before(
    stream: &mut UnixStream,
    bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), RootProvisionUnknownReason> {
    let mut filled = 0;
    while filled < bytes.len() {
        let read = read_before(stream, &mut bytes[filled..], deadline)?;
        if read == 0 {
            return Err(RootProvisionUnknownReason::Eof);
        }
        filled += read;
    }
    Ok(())
}

fn read_before(
    stream: &mut UnixStream,
    bytes: &mut [u8],
    deadline: Instant,
) -> Result<usize, RootProvisionUnknownReason> {
    loop {
        ensure_before(deadline)?;
        match stream.read(bytes) {
            Ok(read) => return Ok(read),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => wait_for_io(deadline)?,
            Err(error) => return Err(classify_read_error(error)),
        }
    }
}

fn write_all_before(stream: &mut UnixStream, mut bytes: &[u8], timeout: Duration) -> bool {
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return false;
    };
    while !bytes.is_empty() {
        if ensure_before(deadline).is_err() {
            return false;
        }
        match stream.write(bytes) {
            Ok(0) => return false,
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if wait_for_io(deadline).is_err() {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    true
}

fn ensure_before(deadline: Instant) -> Result<(), RootProvisionUnknownReason> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|_| ())
        .ok_or(RootProvisionUnknownReason::Timeout)
}

fn wait_for_io(deadline: Instant) -> Result<(), RootProvisionUnknownReason> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(RootProvisionUnknownReason::Timeout)?;
    std::thread::sleep(remaining.min(Duration::from_millis(1)));
    Ok(())
}

fn classify_read_error(error: std::io::Error) -> RootProvisionUnknownReason {
    if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) {
        RootProvisionUnknownReason::Timeout
    } else {
        RootProvisionUnknownReason::MalformedFrame
    }
}

fn result_matches_request(
    result: &ProvisionRootImageResult,
    request: &ProvisionRootImageRequest,
) -> bool {
    result.provision_transition_id == request.provision_transition_id
        && result.volume_id == request.volume_id
        && result.attachment_id == request.attachment_id
        && result.attachment_epoch == request.attachment_epoch
        && result.resulting_head == request.expected_provisioned_head
}

fn error_matches_request(
    error: &ProvisionRootImageError,
    request: &ProvisionRootImageRequest,
) -> bool {
    let (transition, volume, attachment, epoch) = match error {
        ProvisionRootImageError::Retryable {
            provision_transition_id,
            volume_id,
            attachment_id,
            attachment_epoch,
            ..
        }
        | ProvisionRootImageError::DefiniteConflict {
            provision_transition_id,
            volume_id,
            attachment_id,
            attachment_epoch,
            ..
        } => (
            provision_transition_id,
            volume_id,
            attachment_id,
            attachment_epoch,
        ),
    };
    transition == &request.provision_transition_id
        && volume == &request.volume_id
        && attachment == &request.attachment_id
        && epoch == &request.attachment_epoch
}

fn unknown(reason: RootProvisionUnknownReason) -> AuthorityRereadRequired {
    AuthorityRereadRequired::new(RootProvisionResponseHint::Unknown(reason))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;

    use cats_api::runtime_reconciliation::{
        encode_provision_root_image_error, encode_provision_root_image_result, AsciiText,
        FenceEpoch, Generation, Id, ProvisionRootImageRetryableProblem, RandomId128, RemoteHead,
        Sha256Digest,
    };

    fn request() -> ProvisionRootImageRequest {
        ProvisionRootImageRequest {
            provision_transition_id: RandomId128::new("13579bdf2468ace013579bdf2468ace0").unwrap(),
            volume_id: Id::new("vol_root").unwrap(),
            attachment_id: Id::new("att_root").unwrap(),
            attachment_epoch: FenceEpoch::new(7).unwrap(),
            size_bytes: cats_api::chunk::CHUNK_SIZE as u64,
            boot_image_digest: Sha256Digest::from_bytes([1; 32]),
            expected_blank_head: RemoteHead {
                generation: Generation::new(0).unwrap(),
                root_hash: None,
                root_object_id: None,
            },
            expected_provisioned_head: RemoteHead {
                generation: Generation::new(1).unwrap(),
                root_hash: Some(Sha256Digest::from_bytes([2; 32])),
                root_object_id: Some(AsciiText::new(format!("{}.node", "02".repeat(32))).unwrap()),
            },
        }
    }

    fn result(request: &ProvisionRootImageRequest) -> ProvisionRootImageResult {
        ProvisionRootImageResult {
            provision_transition_id: request.provision_transition_id.clone(),
            volume_id: request.volume_id.clone(),
            attachment_id: request.attachment_id.clone(),
            attachment_epoch: request.attachment_epoch,
            resulting_head: request.expected_provisioned_head.clone(),
        }
    }

    struct TestServer {
        _dir: tempfile::TempDir,
        path: PathBuf,
        done: mpsc::Receiver<()>,
    }

    impl TestServer {
        fn one(response: Vec<u8>, delay: Duration) -> Self {
            Self::responding(move |stream| {
                if !delay.is_zero() {
                    std::thread::sleep(delay);
                }
                let _ = stream.write_all(&response);
            })
        }

        fn trickle(response: Vec<u8>, bytes: usize, interval: Duration) -> Self {
            Self::responding(move |stream| {
                for byte in response.into_iter().take(bytes) {
                    if stream.write_all(std::slice::from_ref(&byte)).is_err() {
                        break;
                    }
                    std::thread::sleep(interval);
                }
            })
        }

        fn responding(write_response: impl FnOnce(&mut UnixStream) + Send + 'static) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("control.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let (sent, done) = mpsc::channel();
            std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut byte = [0_u8; 1];
                while stream.read_exact(&mut byte).is_ok() {
                    request.push(byte[0]);
                    if byte[0] == b'\n' {
                        break;
                    }
                }
                assert!(request.starts_with(COMMAND_PREFIX));
                write_response(&mut stream);
                let _ = sent.send(());
            });
            Self {
                _dir: dir,
                path,
                done,
            }
        }

        fn client(&self, timeout: Duration) -> UnixRootProvisionClient {
            UnixRootProvisionClient::new(&self.path, timeout, Duration::from_secs(1))
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            let _ = self.done.recv_timeout(Duration::from_secs(2));
        }
    }

    fn ok_wire(result: &ProvisionRootImageResult) -> Vec<u8> {
        let mut wire = b"OK ".to_vec();
        wire.extend(encode_provision_root_image_result(result).unwrap());
        wire.push(b'\n');
        wire
    }

    #[test]
    fn ok_and_closed_error_are_only_hints_and_both_require_authority_reread() {
        let request = request();
        let server = TestServer::one(ok_wire(&result(&request)), Duration::ZERO);
        let observed = server
            .client(Duration::from_secs(1))
            .execute(&request)
            .unwrap();
        assert!(matches!(
            observed.hint(),
            RootProvisionResponseHint::Ok(value) if value == &result(&request)
        ));

        let error = ProvisionRootImageError::Retryable {
            provision_transition_id: request.provision_transition_id.clone(),
            volume_id: request.volume_id.clone(),
            attachment_id: request.attachment_id.clone(),
            attachment_epoch: request.attachment_epoch,
            problem: ProvisionRootImageRetryableProblem::ImageUnavailable,
        };
        let mut wire = b"ERR ".to_vec();
        wire.extend(encode_provision_root_image_error(&error).unwrap());
        wire.push(b'\n');
        let server = TestServer::one(wire, Duration::ZERO);
        let observed = server
            .client(Duration::from_secs(1))
            .execute(&request)
            .unwrap();
        assert!(matches!(
            observed.hint(),
            RootProvisionResponseHint::Closed(value) if value == &error
        ));
    }

    #[test]
    fn malformed_oversized_and_timed_out_responses_are_unknown_not_success() {
        let request = request();
        let cases = [
            (
                b"WHAT {}\n".to_vec(),
                RootProvisionUnknownReason::MalformedFrame,
            ),
            (
                b"OK {}\r\n".to_vec(),
                RootProvisionUnknownReason::MalformedFrame,
            ),
            (
                b"OK {\n".to_vec(),
                RootProvisionUnknownReason::MalformedFrame,
            ),
            (
                {
                    let mut wire = b"OK ".to_vec();
                    wire.extend(vec![b' '; PROVISION_ROOT_IMAGE_RESULT_MAX_WIRE_BYTES + 1]);
                    wire.push(b'\n');
                    wire
                },
                RootProvisionUnknownReason::MalformedFrame,
            ),
        ];
        for (wire, expected) in cases {
            let server = TestServer::one(wire, Duration::ZERO);
            let observed = server
                .client(Duration::from_secs(1))
                .execute(&request)
                .unwrap();
            assert_eq!(
                observed.hint(),
                &RootProvisionResponseHint::Unknown(expected)
            );
        }

        let server = TestServer::one(ok_wire(&result(&request)), Duration::from_millis(100));
        let observed = server
            .client(Duration::from_millis(10))
            .execute(&request)
            .unwrap();
        assert_eq!(
            observed.hint(),
            &RootProvisionResponseHint::Unknown(RootProvisionUnknownReason::Timeout)
        );

        let server = TestServer::trickle(ok_wire(&result(&request)), 10, Duration::from_millis(30));
        let started = Instant::now();
        let observed = server
            .client(Duration::from_millis(80))
            .execute(&request)
            .unwrap();
        assert_eq!(
            observed.hint(),
            &RootProvisionResponseHint::Unknown(RootProvisionUnknownReason::Timeout)
        );
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "response bytes reset the total read deadline"
        );
    }

    #[test]
    fn every_response_identity_mismatch_is_unknown_and_exact_limit_is_accepted() {
        let request = request();
        let mut mismatches = Vec::new();
        let mut value = result(&request);
        value.provision_transition_id =
            RandomId128::new("2468ace013579bdf2468ace013579bdf").unwrap();
        mismatches.push(value);
        let mut value = result(&request);
        value.volume_id = Id::new("other-volume").unwrap();
        mismatches.push(value);
        let mut value = result(&request);
        value.attachment_id = Id::new("other-owner").unwrap();
        mismatches.push(value);
        let mut value = result(&request);
        value.attachment_epoch = FenceEpoch::new(8).unwrap();
        mismatches.push(value);
        let mut value = result(&request);
        value.resulting_head.root_hash = Some(Sha256Digest::from_bytes([3; 32]));
        mismatches.push(value);

        for mismatch in mismatches {
            let server = TestServer::one(ok_wire(&mismatch), Duration::ZERO);
            let observed = server
                .client(Duration::from_secs(1))
                .execute(&request)
                .unwrap();
            assert_eq!(
                observed.hint(),
                &RootProvisionResponseHint::Unknown(RootProvisionUnknownReason::MismatchedIdentity)
            );
        }

        let mut exact = b"OK ".to_vec();
        let payload = encode_provision_root_image_result(&result(&request)).unwrap();
        exact.extend(&payload);
        exact.extend(vec![
            b' ';
            PROVISION_ROOT_IMAGE_RESULT_MAX_WIRE_BYTES
                - payload.len()
        ]);
        exact.push(b'\n');
        // A second frame is tail, not another response.
        exact.extend(b"ERR {}\n");
        let server = TestServer::one(exact, Duration::ZERO);
        let observed = server
            .client(Duration::from_secs(1))
            .execute(&request)
            .unwrap();
        assert!(matches!(observed.hint(), RootProvisionResponseHint::Ok(_)));
    }

    #[test]
    fn intrinsically_invalid_typed_request_never_reaches_the_socket() {
        let mut request = request();
        request.expected_blank_head.root_hash = Some(Sha256Digest::from_bytes([9; 32]));
        let client = UnixRootProvisionClient::new(
            "/definitely/not/a/socket",
            Duration::from_millis(1),
            Duration::from_millis(1),
        );
        assert!(matches!(
            client.execute(&request),
            Err(RootProvisionClientError::InvalidRequest(_))
        ));
    }
}
