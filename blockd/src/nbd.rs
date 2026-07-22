//! NBD frontend (spec §7): newstyle-fixed handshake with `NBD_OPT_GO`,
//! transmission commands READ / WRITE / FLUSH / TRIM / WRITE_ZEROES / DISC.
//!
//! The server is the dev/test/recovery frontend for `ChunkEngine`; the
//! userspace client is shared by tests and by the fake guest, and speaks the
//! exact same protocol a Linux `nbd-client` would.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;

use crate::engine::{ChunkEngine, EngineError};

pub const NBD_MAGIC: u64 = 0x4e42_444d_4147_4943; // "NBDMAGIC"
pub const IHAVEOPT: u64 = 0x4948_4156_454f_5054; // "IHAVEOPT"
pub const REPLY_MAGIC: u64 = 0x0003_e889_0455_65a9;
pub const REQUEST_MAGIC: u32 = 0x2560_9513;
pub const SIMPLE_REPLY_MAGIC: u32 = 0x6744_6698;

pub const FLAG_FIXED_NEWSTYLE: u16 = 1 << 0;
pub const FLAG_NO_ZEROES: u16 = 1 << 1;
pub const CFLAG_FIXED_NEWSTYLE: u32 = 1 << 0;
pub const CFLAG_NO_ZEROES: u32 = 1 << 1;

pub const OPT_EXPORT_NAME: u32 = 1;
pub const OPT_ABORT: u32 = 2;
pub const OPT_LIST: u32 = 3;
pub const OPT_INFO: u32 = 6;
pub const OPT_GO: u32 = 7;

pub const REP_ACK: u32 = 1;
pub const REP_SERVER: u32 = 2;
pub const REP_INFO: u32 = 3;
pub const REP_ERR_UNSUP: u32 = 0x8000_0001;

pub const INFO_EXPORT: u16 = 0;

pub const CMD_READ: u16 = 0;
pub const CMD_WRITE: u16 = 1;
pub const CMD_DISC: u16 = 2;
pub const CMD_FLUSH: u16 = 3;
pub const CMD_TRIM: u16 = 4;
pub const CMD_WRITE_ZEROES: u16 = 6;

pub const CMD_FLAG_FUA: u16 = 1 << 0;

/// Transmission flags: HAS_FLAGS | SEND_FLUSH | SEND_FUA | SEND_TRIM | SEND_WRITE_ZEROES
pub const TRANSMISSION_FLAGS: u16 = 1 | 4 | 8 | 32 | 64;

pub const EPERM: u32 = 1;
pub const EIO: u32 = 5;
pub const EINVAL: u32 = 22;

/// Maximum payload we accept per request.
pub const MAX_PAYLOAD: u32 = 32 * 1024 * 1024;

fn io_err(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::other(msg.into())
}

trait Wire: Read + Write {
    fn get_u16(&mut self) -> std::io::Result<u16> {
        let mut b = [0u8; 2];
        self.read_exact(&mut b)?;
        Ok(u16::from_be_bytes(b))
    }
    fn get_u32(&mut self) -> std::io::Result<u32> {
        let mut b = [0u8; 4];
        self.read_exact(&mut b)?;
        Ok(u32::from_be_bytes(b))
    }
    fn get_u64(&mut self) -> std::io::Result<u64> {
        let mut b = [0u8; 8];
        self.read_exact(&mut b)?;
        Ok(u64::from_be_bytes(b))
    }
    fn put_u16(&mut self, v: u16) -> std::io::Result<()> {
        self.write_all(&v.to_be_bytes())
    }
    fn put_u32(&mut self, v: u32) -> std::io::Result<()> {
        self.write_all(&v.to_be_bytes())
    }
    fn put_u64(&mut self, v: u64) -> std::io::Result<()> {
        self.write_all(&v.to_be_bytes())
    }
}
impl<T: Read + Write + ?Sized> Wire for T {}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Serve NBD connections on a unix listener until the process exits.
pub fn serve_unix(listener: UnixListener, engine: Arc<ChunkEngine>) {
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let engine = engine.clone();
                std::thread::spawn(move || {
                    if let Err(e) = handle_connection(stream, engine) {
                        tracing::debug!("nbd connection ended: {e}");
                    }
                });
            }
            Err(e) => {
                tracing::warn!("nbd accept failed: {e}");
                return;
            }
        }
    }
}

/// Handle one NBD connection (handshake + transmission) to completion.
pub fn handle_connection<S: Read + Write>(
    mut stream: S,
    engine: Arc<ChunkEngine>,
) -> std::io::Result<()> {
    // Handshake.
    stream.put_u64(NBD_MAGIC)?;
    stream.put_u64(IHAVEOPT)?;
    stream.put_u16(FLAG_FIXED_NEWSTYLE | FLAG_NO_ZEROES)?;
    stream.flush()?;
    let client_flags = stream.get_u32()?;
    let client_no_zeroes = client_flags & CFLAG_NO_ZEROES != 0;

    // Option haggling.
    loop {
        let magic = stream.get_u64()?;
        if magic != IHAVEOPT {
            return Err(io_err("bad option magic"));
        }
        let option = stream.get_u32()?;
        let len = stream.get_u32()?;
        if len > 4096 {
            return Err(io_err("oversized option"));
        }
        let mut data = vec![0u8; len as usize];
        stream.read_exact(&mut data)?;

        match option {
            OPT_GO | OPT_INFO => {
                // data: u32 name_len + name + u16 n_info_requests (+ u16 each)
                if data.len() < 6 {
                    reply_opt(&mut stream, option, REP_ERR_UNSUP, &[])?;
                    continue;
                }
                // REP_INFO / NBD_INFO_EXPORT.
                let mut info = Vec::with_capacity(12);
                info.extend_from_slice(&INFO_EXPORT.to_be_bytes());
                info.extend_from_slice(&engine.size().to_be_bytes());
                info.extend_from_slice(&TRANSMISSION_FLAGS.to_be_bytes());
                reply_opt(&mut stream, option, REP_INFO, &info)?;
                reply_opt(&mut stream, option, REP_ACK, &[])?;
                if option == OPT_GO {
                    break;
                }
            }
            OPT_EXPORT_NAME => {
                stream.put_u64(engine.size())?;
                stream.put_u16(TRANSMISSION_FLAGS)?;
                if !client_no_zeroes {
                    stream.write_all(&[0u8; 124])?;
                }
                stream.flush()?;
                break;
            }
            OPT_ABORT => {
                reply_opt(&mut stream, option, REP_ACK, &[])?;
                return Ok(());
            }
            OPT_LIST => {
                // One nameless export.
                reply_opt(&mut stream, option, REP_SERVER, &0u32.to_be_bytes())?;
                reply_opt(&mut stream, option, REP_ACK, &[])?;
            }
            _ => reply_opt(&mut stream, option, REP_ERR_UNSUP, &[])?,
        }
    }

    // Transmission.
    loop {
        let magic = stream.get_u32()?;
        if magic != REQUEST_MAGIC {
            return Err(io_err("bad request magic"));
        }
        let flags = stream.get_u16()?;
        let cmd = stream.get_u16()?;
        let handle = stream.get_u64()?;
        let offset = stream.get_u64()?;
        let length = stream.get_u32()?;

        match cmd {
            CMD_READ => {
                if length > MAX_PAYLOAD {
                    simple_reply(&mut stream, EINVAL, handle, &[])?;
                    continue;
                }
                let mut buf = vec![0u8; length as usize];
                match engine.read(offset, &mut buf) {
                    Ok(()) => simple_reply(&mut stream, 0, handle, &buf)?,
                    Err(e) => simple_reply(&mut stream, errno_for(&e), handle, &[])?,
                }
            }
            CMD_WRITE => {
                if length > MAX_PAYLOAD {
                    // Consume the payload to keep the stream in sync.
                    drain(&mut stream, length as u64)?;
                    simple_reply(&mut stream, EINVAL, handle, &[])?;
                    continue;
                }
                let mut buf = vec![0u8; length as usize];
                stream.read_exact(&mut buf)?;
                let mut result = engine.write(offset, &buf);
                if result.is_ok() && flags & CMD_FLAG_FUA != 0 {
                    result = engine.flush().map(|_| ());
                }
                match result {
                    Ok(()) => simple_reply(&mut stream, 0, handle, &[])?,
                    Err(e) => simple_reply(&mut stream, errno_for(&e), handle, &[])?,
                }
            }
            CMD_FLUSH => match engine.flush() {
                Ok(_) => simple_reply(&mut stream, 0, handle, &[])?,
                Err(e) => simple_reply(&mut stream, errno_for(&e), handle, &[])?,
            },
            CMD_TRIM | CMD_WRITE_ZEROES => {
                let mut result = engine.write_zeroes(offset, length as u64);
                if result.is_ok() && flags & CMD_FLAG_FUA != 0 {
                    result = engine.flush().map(|_| ());
                }
                match result {
                    Ok(()) => simple_reply(&mut stream, 0, handle, &[])?,
                    Err(e) => simple_reply(&mut stream, errno_for(&e), handle, &[])?,
                }
            }
            CMD_DISC => return Ok(()),
            _ => simple_reply(&mut stream, EINVAL, handle, &[])?,
        }
    }
}

fn drain<S: Read>(stream: &mut S, mut n: u64) -> std::io::Result<()> {
    let mut buf = [0u8; 8192];
    while n > 0 {
        let step = buf.len().min(n as usize);
        stream.read_exact(&mut buf[..step])?;
        n -= step as u64;
    }
    Ok(())
}

fn errno_for(e: &EngineError) -> u32 {
    match e {
        EngineError::Fenced => EPERM,
        EngineError::OutOfBounds { .. } => EINVAL,
        _ => EIO,
    }
}

fn reply_opt<S: Read + Write>(
    stream: &mut S,
    option: u32,
    reply_type: u32,
    data: &[u8],
) -> std::io::Result<()> {
    stream.put_u64(REPLY_MAGIC)?;
    stream.put_u32(option)?;
    stream.put_u32(reply_type)?;
    stream.put_u32(data.len() as u32)?;
    stream.write_all(data)?;
    stream.flush()
}

fn simple_reply<S: Read + Write>(
    stream: &mut S,
    error: u32,
    handle: u64,
    data: &[u8],
) -> std::io::Result<()> {
    stream.put_u32(SIMPLE_REPLY_MAGIC)?;
    stream.put_u32(error)?;
    stream.put_u64(handle)?;
    stream.write_all(data)?;
    stream.flush()
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum NbdError {
    #[error("nbd i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("nbd protocol error: {0}")]
    Protocol(String),
    #[error("nbd server returned errno {0}")]
    Server(u32),
}

pub type NbdResult<T> = std::result::Result<T, NbdError>;

pub trait ReadWriteSend: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWriteSend for T {}

/// Synchronous userspace NBD client.
pub struct NbdClient {
    stream: Box<dyn ReadWriteSend>,
    size: u64,
    next_handle: u64,
}

impl NbdClient {
    pub fn connect_unix(path: &Path) -> NbdResult<Self> {
        let stream = UnixStream::connect(path)?;
        Self::handshake(Box::new(stream))
    }

    pub fn connect_tcp(addr: &str) -> NbdResult<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true).ok();
        Self::handshake(Box::new(stream))
    }

    /// Handshake over an arbitrary stream (tests use `UnixStream::pair`).
    pub fn handshake(mut stream: Box<dyn ReadWriteSend>) -> NbdResult<Self> {
        let magic = stream.get_u64()?;
        if magic != NBD_MAGIC {
            return Err(NbdError::Protocol("bad server magic".into()));
        }
        let opt_magic = stream.get_u64()?;
        if opt_magic != IHAVEOPT {
            return Err(NbdError::Protocol("server is not newstyle".into()));
        }
        let _server_flags = stream.get_u16()?;
        stream.put_u32(CFLAG_FIXED_NEWSTYLE | CFLAG_NO_ZEROES)?;

        // NBD_OPT_GO with the default (empty) export name, no info requests.
        stream.put_u64(IHAVEOPT)?;
        stream.put_u32(OPT_GO)?;
        stream.put_u32(6)?; // u32 name_len(0) + u16 n_infos(0)
        stream.put_u32(0)?;
        stream.put_u16(0)?;
        stream.flush()?;

        let mut size: Option<u64> = None;
        loop {
            let magic = stream.get_u64()?;
            if magic != REPLY_MAGIC {
                return Err(NbdError::Protocol("bad option reply magic".into()));
            }
            let _option = stream.get_u32()?;
            let reply_type = stream.get_u32()?;
            let len = stream.get_u32()?;
            let mut data = vec![0u8; len as usize];
            stream.read_exact(&mut data)?;
            match reply_type {
                REP_INFO => {
                    if data.len() >= 12 {
                        let info_type = u16::from_be_bytes([data[0], data[1]]);
                        if info_type == INFO_EXPORT {
                            size = Some(u64::from_be_bytes(data[2..10].try_into().unwrap()));
                        }
                    }
                }
                REP_ACK => break,
                t if t >= 0x8000_0000 => {
                    return Err(NbdError::Protocol(format!("GO rejected: {t:#x}")));
                }
                _ => {}
            }
        }
        let size = size.ok_or_else(|| NbdError::Protocol("no export info".into()))?;
        Ok(Self {
            stream,
            size,
            next_handle: 1,
        })
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    fn roundtrip(
        &mut self,
        cmd: u16,
        flags: u16,
        offset: u64,
        length: u32,
        payload: Option<&[u8]>,
        read_back: bool,
    ) -> NbdResult<Vec<u8>> {
        let handle = self.next_handle;
        self.next_handle += 1;
        self.stream.put_u32(REQUEST_MAGIC)?;
        self.stream.put_u16(flags)?;
        self.stream.put_u16(cmd)?;
        self.stream.put_u64(handle)?;
        self.stream.put_u64(offset)?;
        self.stream.put_u32(length)?;
        if let Some(p) = payload {
            self.stream.write_all(p)?;
        }
        self.stream.flush()?;

        let magic = self.stream.get_u32()?;
        if magic != SIMPLE_REPLY_MAGIC {
            return Err(NbdError::Protocol("bad reply magic".into()));
        }
        let error = self.stream.get_u32()?;
        let reply_handle = self.stream.get_u64()?;
        if reply_handle != handle {
            return Err(NbdError::Protocol("reply handle mismatch".into()));
        }
        if error != 0 {
            return Err(NbdError::Server(error));
        }
        if read_back {
            let mut data = vec![0u8; length as usize];
            self.stream.read_exact(&mut data)?;
            Ok(data)
        } else {
            Ok(Vec::new())
        }
    }

    pub fn read(&mut self, offset: u64, length: u32) -> NbdResult<Vec<u8>> {
        self.roundtrip(CMD_READ, 0, offset, length, None, true)
    }

    pub fn write(&mut self, offset: u64, data: &[u8]) -> NbdResult<()> {
        self.roundtrip(CMD_WRITE, 0, offset, data.len() as u32, Some(data), false)?;
        Ok(())
    }

    pub fn write_fua(&mut self, offset: u64, data: &[u8]) -> NbdResult<()> {
        self.roundtrip(
            CMD_WRITE,
            CMD_FLAG_FUA,
            offset,
            data.len() as u32,
            Some(data),
            false,
        )?;
        Ok(())
    }

    pub fn flush(&mut self) -> NbdResult<()> {
        self.roundtrip(CMD_FLUSH, 0, 0, 0, None, false)?;
        Ok(())
    }

    pub fn trim(&mut self, offset: u64, length: u32) -> NbdResult<()> {
        self.roundtrip(CMD_TRIM, 0, offset, length, None, false)?;
        Ok(())
    }

    pub fn disconnect(mut self) -> NbdResult<()> {
        let handle = self.next_handle;
        self.stream.put_u32(REQUEST_MAGIC)?;
        self.stream.put_u16(0)?;
        self.stream.put_u16(CMD_DISC)?;
        self.stream.put_u64(handle)?;
        self.stream.put_u64(0)?;
        self.stream.put_u32(0)?;
        self.stream.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EngineConfig;
    use cats_metadata_store_sqlite::SqliteMetadataStore;
    use cats_object_store_file::FileBlobStore;
    use cats_storage::MetadataStore;

    fn engine(dir: &Path) -> Arc<ChunkEngine> {
        let blob = Arc::new(FileBlobStore::open(dir.join("blob")).unwrap());
        let meta = Arc::new(SqliteMetadataStore::open(&dir.join("meta.db")).unwrap());
        meta.create_volume("vol_nbd", 4 * cats_api::chunk::CHUNK_SIZE as u64)
            .unwrap();
        ChunkEngine::attach(
            EngineConfig::new("vol_nbd", dir.join("data"), "att1"),
            blob,
            meta,
        )
        .unwrap()
    }

    #[test]
    fn client_server_loopback_over_unix_pair() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine(dir.path());
        let (a, b) = UnixStream::pair().unwrap();
        let server_engine = engine.clone();
        let server = std::thread::spawn(move || handle_connection(a, server_engine));

        let mut client = NbdClient::handshake(Box::new(b)).unwrap();
        assert_eq!(client.size(), 4 * cats_api::chunk::CHUNK_SIZE as u64);

        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        client.write(4096, &data).unwrap();
        assert_eq!(client.read(4096, 10_000).unwrap(), data);
        client.flush().unwrap();
        // Zero a hole region and read it back.
        client.trim(4096, 512).unwrap();
        assert!(client.read(4096, 512).unwrap().iter().all(|&b| b == 0));
        // FUA write commits durably.
        client.write_fua(0, b"fua!").unwrap();
        assert!(engine.generation() >= 2);
        // Out-of-bounds surfaces as EINVAL.
        let err = client.write(client.size(), b"x").unwrap_err();
        assert!(matches!(err, NbdError::Server(e) if e == EINVAL));

        client.disconnect().unwrap();
        server.join().unwrap().unwrap();
        engine.detach();
    }
}
