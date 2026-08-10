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

use crate::proc::ProcIdentity;
use crate::runtime_spine::RuntimePhysicalReadContext;

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
    Cancelled,
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

/// Read-only process identity probe used while the connected provision
/// stream pins its Unix peer. Implementations must not open the blockd control
/// socket: that listener handles one connection at a time, so a nested status
/// request would deadlock behind the retained provision stream.
pub(crate) trait RootProvisionProcessIdentityPort: Send + Sync {
    fn sample(&self, process_id: u32) -> ProcIdentity;
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PlatformRootProvisionProcessIdentityPort;

impl RootProvisionProcessIdentityPort for PlatformRootProvisionProcessIdentityPort {
    fn sample(&self, process_id: u32) -> ProcIdentity {
        ProcIdentity::sample(process_id)
    }
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

    /// Execute only when the connected Unix peer is the process which the
    /// caller fully revalidated before opening this transport. The retained
    /// connection binds the peer PID, then a socket-free identity sample binds
    /// the same start time and executable before the first request byte.
    pub(crate) fn execute_with_context_for_peer(
        &self,
        request: &ProvisionRootImageRequest,
        expected_peer_process: &ProcIdentity,
        process_identity: &dyn RootProvisionProcessIdentityPort,
        context: &dyn RuntimePhysicalReadContext,
    ) -> Result<AuthorityRereadRequired, RootProvisionClientError> {
        self.execute_bounded(
            request,
            Some(context),
            Some(expected_peer_process),
            Some(process_identity),
        )
    }

    fn execute_bounded(
        &self,
        request: &ProvisionRootImageRequest,
        context: Option<&dyn RuntimePhysicalReadContext>,
        expected_peer_process: Option<&ProcIdentity>,
        process_identity: Option<&dyn RootProvisionProcessIdentityPort>,
    ) -> Result<AuthorityRereadRequired, RootProvisionClientError> {
        let payload = encode_provision_root_image_request(request)?;
        let write_deadline = phase_deadline(self.write_timeout, context);
        let mut stream = match connect_before(&self.socket_path, write_deadline, context) {
            Ok(stream) => stream,
            Err(reason) => return Ok(unknown(reason)),
        };
        if let Some(expected) = expected_peer_process {
            let Some(actual_process_id) = connected_peer_process_id(&stream) else {
                return Ok(unknown(RootProvisionUnknownReason::MismatchedIdentity));
            };
            if actual_process_id != expected.pid
                || process_identity
                    .map(|identity| identity.sample(actual_process_id))
                    .as_ref()
                    != Some(expected)
            {
                return Ok(unknown(RootProvisionUnknownReason::MismatchedIdentity));
            }
        }
        let mut frame = Vec::with_capacity(COMMAND_PREFIX.len() + payload.len() + 1);
        frame.extend_from_slice(COMMAND_PREFIX);
        frame.extend_from_slice(&payload);
        frame.push(b'\n');
        if let Err(reason) = write_all_before(&mut stream, &frame, write_deadline, context) {
            return Ok(unknown(reason));
        }

        let read_deadline = phase_deadline(self.read_timeout, context);
        let frame = match read_response_frame(&mut stream, read_deadline, context) {
            Ok(frame) => frame,
            Err(reason) => return Ok(unknown(reason)),
        };
        Ok(AuthorityRereadRequired::new(classify_frame(frame, request)))
    }
}

impl RootProvisionControlPort for UnixRootProvisionClient {
    fn execute(
        &self,
        request: &ProvisionRootImageRequest,
    ) -> Result<AuthorityRereadRequired, RootProvisionClientError> {
        self.execute_bounded(request, None, None, None)
    }
}

fn classify_frame(
    frame: ResponseFrame,
    request: &ProvisionRootImageRequest,
) -> RootProvisionResponseHint {
    match frame {
        ResponseFrame::Ok(payload) => match decode_provision_root_image_result(&payload) {
            Ok(result) if result_matches_request(&result, request) => {
                RootProvisionResponseHint::Ok(result)
            }
            Ok(_) => {
                RootProvisionResponseHint::Unknown(RootProvisionUnknownReason::MismatchedIdentity)
            }
            Err(_) => {
                RootProvisionResponseHint::Unknown(RootProvisionUnknownReason::MalformedFrame)
            }
        },
        ResponseFrame::Error(payload) => match decode_provision_root_image_error(&payload) {
            Ok(error) if error_matches_request(&error, request) => {
                RootProvisionResponseHint::Closed(error)
            }
            Ok(_) => {
                RootProvisionResponseHint::Unknown(RootProvisionUnknownReason::MismatchedIdentity)
            }
            Err(_) => {
                RootProvisionResponseHint::Unknown(RootProvisionUnknownReason::MalformedFrame)
            }
        },
    }
}

enum ResponseFrame {
    Ok(Vec<u8>),
    Error(Vec<u8>),
}

fn read_response_frame(
    stream: &mut UnixStream,
    deadline: Instant,
    context: Option<&dyn RuntimePhysicalReadContext>,
) -> Result<ResponseFrame, RootProvisionUnknownReason> {
    let mut prefix = [0_u8; 4];
    read_exact_before(stream, &mut prefix, deadline, context)?;
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
        let read = read_before(stream, &mut buffer, deadline, context)?;
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
    context: Option<&dyn RuntimePhysicalReadContext>,
) -> Result<(), RootProvisionUnknownReason> {
    let mut filled = 0;
    while filled < bytes.len() {
        let read = read_before(stream, &mut bytes[filled..], deadline, context)?;
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
    context: Option<&dyn RuntimePhysicalReadContext>,
) -> Result<usize, RootProvisionUnknownReason> {
    loop {
        ensure_before(deadline, context)?;
        match stream.read(bytes) {
            Ok(read) => return Ok(read),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                wait_for_io(stream, libc::POLLIN, deadline, context)?
            }
            Err(error) => return Err(classify_read_error(error)),
        }
    }
}

fn write_all_before(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
    context: Option<&dyn RuntimePhysicalReadContext>,
) -> Result<(), RootProvisionUnknownReason> {
    while !bytes.is_empty() {
        ensure_before(deadline, context)?;
        match stream.write(bytes) {
            Ok(0) => return Err(RootProvisionUnknownReason::Write),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                wait_for_io(stream, libc::POLLOUT, deadline, context)?;
            }
            Err(_) => return Err(RootProvisionUnknownReason::Write),
        }
    }
    Ok(())
}

fn ensure_before(
    deadline: Instant,
    context: Option<&dyn RuntimePhysicalReadContext>,
) -> Result<(), RootProvisionUnknownReason> {
    if context.is_some_and(|context| context.check_active().is_err()) {
        return Err(RootProvisionUnknownReason::Cancelled);
    }
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|_| ())
        .ok_or(RootProvisionUnknownReason::Timeout)
}

fn phase_deadline(timeout: Duration, context: Option<&dyn RuntimePhysicalReadContext>) -> Instant {
    let local = Instant::now()
        .checked_add(timeout)
        .unwrap_or(Instant::now());
    context.map_or(local, |context| local.min(context.deadline()))
}

fn wait_for_io(
    stream: &UnixStream,
    events: i16,
    deadline: Instant,
    context: Option<&dyn RuntimePhysicalReadContext>,
) -> Result<(), RootProvisionUnknownReason> {
    use std::os::fd::AsRawFd as _;
    loop {
        ensure_before(deadline, context)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = i32::try_from(remaining.min(Duration::from_millis(5)).as_millis())
            .unwrap_or(1)
            .max(1);
        let mut poll = libc::pollfd {
            fd: stream.as_raw_fd(),
            events,
            revents: 0,
        };
        // SAFETY: poll points to one initialized pollfd for this call only.
        let result = unsafe { libc::poll(&raw mut poll, 1, timeout) };
        if result > 0 {
            return Ok(());
        }
        if result < 0 && std::io::Error::last_os_error().kind() != ErrorKind::Interrupted {
            return Err(RootProvisionUnknownReason::Connect);
        }
    }
}

fn connect_before(
    path: &Path,
    deadline: Instant,
    context: Option<&dyn RuntimePhysicalReadContext>,
) -> Result<UnixStream, RootProvisionUnknownReason> {
    use std::mem::{offset_of, size_of};
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;

    ensure_before(deadline, context)?;
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: zero is a valid initial representation for sockaddr_un; the
    // family, optional BSD length, and used path bytes are initialized below.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(RootProvisionUnknownReason::Connect);
    }
    let address_length = offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    let socket_type = libc::SOCK_STREAM;
    #[cfg(target_os = "linux")]
    let socket_type = socket_type | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    // SAFETY: socket returns a fresh descriptor and retains no Rust memory.
    let descriptor = unsafe { libc::socket(libc::AF_UNIX, socket_type, 0) };
    if descriptor < 0 {
        return Err(RootProvisionUnknownReason::Connect);
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Darwin/BSD do not expose Linux's atomic socket type flags. Set both
        // descriptor flags before the fd enters any blocking operation.
        // SAFETY: descriptor is live and each fcntl reads or updates only its
        // integer flags.
        let status = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        // SAFETY: descriptor is live and F_SETFL consumes only the integer
        // status flags obtained immediately above.
        let set_nonblocking =
            unsafe { libc::fcntl(descriptor, libc::F_SETFL, status | libc::O_NONBLOCK) };
        // SAFETY: descriptor is live and F_SETFD consumes only FD_CLOEXEC.
        let set_close_on_exec = unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) };
        let nonblocking = status >= 0 && set_nonblocking == 0 && set_close_on_exec == 0;
        if !nonblocking {
            // SAFETY: descriptor remains owned here.
            unsafe { libc::close(descriptor) };
            return Err(RootProvisionUnknownReason::Connect);
        }
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    {
        address.sun_len =
            u8::try_from(address_length).map_err(|_| RootProvisionUnknownReason::Connect)?;
    }
    for (target, source) in address.sun_path.iter_mut().zip(bytes.iter().copied()) {
        *target = source as libc::c_char;
    }
    let address_length = address_length as libc::socklen_t;
    // SAFETY: descriptor/address are initialized and connect retains neither.
    let connected = unsafe {
        libc::connect(
            descriptor,
            (&raw const address).cast::<libc::sockaddr>(),
            address_length,
        )
    };
    if connected != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            // SAFETY: descriptor remains owned here.
            unsafe { libc::close(descriptor) };
            return Err(RootProvisionUnknownReason::Connect);
        }
    }
    // SAFETY: ownership of the descriptor moves into UnixStream.
    let stream = unsafe { UnixStream::from_raw_fd(descriptor) };
    if connected != 0 {
        wait_for_io(&stream, libc::POLLOUT, deadline, context)?;
        let mut socket_error = 0_i32;
        let mut length = size_of::<i32>() as libc::socklen_t;
        // SAFETY: both pointers reference valid writable scalars for this call.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&raw mut socket_error).cast(),
                &raw mut length,
            )
        };
        if result != 0 || socket_error != 0 {
            return Err(RootProvisionUnknownReason::Connect);
        }
    }
    Ok(stream)
}

#[cfg(target_os = "linux")]
fn connected_peer_process_id(stream: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd as _;

    // SAFETY: all-zero is a valid initial value for ucred before getsockopt
    // writes the complete structure below.
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: credentials and length are valid writable storage for this
    // getsockopt call, and stream retains ownership of its live descriptor.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &raw mut length,
        )
    };
    (result == 0 && length as usize == std::mem::size_of::<libc::ucred>() && credentials.pid > 0)
        .then(|| u32::try_from(credentials.pid).ok())
        .flatten()
}

#[cfg(target_os = "macos")]
fn connected_peer_process_id(stream: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd as _;

    let mut process_id: libc::pid_t = 0;
    let mut length = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: process_id and length are valid writable storage for this
    // getsockopt call, and stream retains ownership of its live descriptor.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut process_id).cast(),
            &raw mut length,
        )
    };
    (result == 0 && length as usize == std::mem::size_of::<libc::pid_t>() && process_id > 0)
        .then(|| u32::try_from(process_id).ok())
        .flatten()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn connected_peer_process_id(_stream: &UnixStream) -> Option<u32> {
    None
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
    use std::sync::{mpsc, Arc};

    use crate::runtime_spine::RuntimeDesiredEffectContext;
    use cats_api::runtime_reconciliation::{
        encode_provision_root_image_error, encode_provision_root_image_result, AsciiText,
        FenceEpoch, Generation, Id, ProvisionRootImageRetryableProblem, RandomId128, RemoteHead,
        Sha256Digest,
    };

    #[derive(Clone)]
    struct FixedProcessIdentity(ProcIdentity);

    impl RootProvisionProcessIdentityPort for FixedProcessIdentity {
        fn sample(&self, process_id: u32) -> ProcIdentity {
            assert_eq!(process_id, self.0.pid);
            self.0.clone()
        }
    }

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
        request_received: mpsc::Receiver<()>,
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
            let (request_sent, request_received) = mpsc::channel();
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
                let _ = request_sent.send(());
                write_response(&mut stream);
                let _ = sent.send(());
            });
            Self {
                _dir: dir,
                path,
                request_received,
                done,
            }
        }

        fn client(&self, timeout: Duration) -> UnixRootProvisionClient {
            UnixRootProvisionClient::new(&self.path, timeout, Duration::from_secs(1))
        }

        fn wait_for_request(&self) {
            self.request_received
                .recv_timeout(Duration::from_secs(2))
                .expect("server did not receive the exact request");
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

    #[test]
    fn runner_cancellation_bounds_an_inflight_response_wait() {
        let request = request();
        let server = TestServer::one(ok_wire(&result(&request)), Duration::from_millis(250));
        let state = tempfile::tempdir().unwrap();
        let context = Arc::new(RuntimeDesiredEffectContext::for_test(
            crate::state_directory::StateDirectory::unanchored(state.path().to_path_buf()),
            Instant::now() + Duration::from_secs(2),
        ));
        let client = server.client(Duration::from_secs(1));
        let worker_context = Arc::clone(&context);
        let worker = std::thread::spawn(move || {
            let expected = ProcIdentity::sample(std::process::id());
            client
                .execute_with_context_for_peer(
                    &request,
                    &expected,
                    &PlatformRootProvisionProcessIdentityPort,
                    worker_context.as_ref(),
                )
                .unwrap()
        });
        server.wait_for_request();
        let cancelled_at = Instant::now();
        context.cancel_for_test();
        let observed = worker.join().unwrap();
        assert_eq!(
            observed.hint(),
            &RootProvisionResponseHint::Unknown(RootProvisionUnknownReason::Cancelled)
        );
        assert!(cancelled_at.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn wrong_connected_peer_pid_receives_zero_request_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("peer.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (sent, received) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).unwrap();
            sent.send(bytes).unwrap();
        });
        let state = tempfile::tempdir().unwrap();
        let context = RuntimeDesiredEffectContext::for_test(
            crate::state_directory::StateDirectory::unanchored(state.path().to_path_buf()),
            Instant::now() + Duration::from_secs(2),
        );
        let wrong_pid = std::process::id().checked_add(1).unwrap();
        let mut expected = ProcIdentity::sample(std::process::id());
        expected.pid = wrong_pid;
        let observed =
            UnixRootProvisionClient::new(&path, Duration::from_secs(1), Duration::from_secs(1))
                .execute_with_context_for_peer(
                    &request(),
                    &expected,
                    &PlatformRootProvisionProcessIdentityPort,
                    &context,
                )
                .unwrap();
        assert_eq!(
            observed.hint(),
            &RootProvisionResponseHint::Unknown(RootProvisionUnknownReason::MismatchedIdentity)
        );
        assert_eq!(
            received.recv_timeout(Duration::from_secs(2)).unwrap(),
            Vec::<u8>::new()
        );
        server.join().unwrap();
    }

    #[test]
    fn exact_connected_peer_pid_sends_the_bounded_request() {
        let request = request();
        let server = TestServer::one(ok_wire(&result(&request)), Duration::ZERO);
        let state = tempfile::tempdir().unwrap();
        let context = RuntimeDesiredEffectContext::for_test(
            crate::state_directory::StateDirectory::unanchored(state.path().to_path_buf()),
            Instant::now() + Duration::from_secs(2),
        );
        let expected = ProcIdentity::sample(std::process::id());
        let observed = server
            .client(Duration::from_secs(1))
            .execute_with_context_for_peer(
                &request,
                &expected,
                &PlatformRootProvisionProcessIdentityPort,
                &context,
            )
            .unwrap();
        server.wait_for_request();
        assert_eq!(
            observed.hint(),
            &RootProvisionResponseHint::Ok(result(&request))
        );
    }

    #[test]
    fn connected_peer_start_or_executable_drift_receives_zero_request_bytes() {
        let expected = ProcIdentity {
            pid: std::process::id(),
            start_ticks: Some(42),
            exe: Some(PathBuf::from("/usr/bin/cats-blockd")),
        };
        let drifted = [
            ProcIdentity {
                start_ticks: Some(43),
                ..expected.clone()
            },
            ProcIdentity {
                exe: Some(PathBuf::from("/usr/bin/not-cats-blockd")),
                ..expected.clone()
            },
        ];

        for actual in drifted {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("identity-drift.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let (sent, received) = mpsc::channel();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut bytes = Vec::new();
                stream.read_to_end(&mut bytes).unwrap();
                sent.send(bytes).unwrap();
            });
            let state = tempfile::tempdir().unwrap();
            let context = RuntimeDesiredEffectContext::for_test(
                crate::state_directory::StateDirectory::unanchored(state.path().to_path_buf()),
                Instant::now() + Duration::from_secs(2),
            );
            let observed =
                UnixRootProvisionClient::new(&path, Duration::from_secs(1), Duration::from_secs(1))
                    .execute_with_context_for_peer(
                        &request(),
                        &expected,
                        &FixedProcessIdentity(actual),
                        &context,
                    )
                    .unwrap();
            assert_eq!(
                observed.hint(),
                &RootProvisionResponseHint::Unknown(RootProvisionUnknownReason::MismatchedIdentity)
            );
            assert_eq!(
                received.recv_timeout(Duration::from_secs(2)).unwrap(),
                Vec::<u8>::new()
            );
            server.join().unwrap();
        }
    }
}
