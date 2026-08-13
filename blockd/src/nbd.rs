//! NBD frontend (spec §7): newstyle-fixed handshake with `NBD_OPT_GO`,
//! transmission commands READ / WRITE / FLUSH / TRIM / WRITE_ZEROES / DISC.
//!
//! The server is the dev/test/recovery frontend for `ChunkEngine`; the
//! lightweight userspace client lives in `cats-block-client` and speaks the
//! same protocol a Linux `nbd-client` would.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::sync::Arc;

#[cfg(test)]
use std::os::unix::net::UnixStream;

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
                    Err(e) => simple_reply(
                        &mut stream,
                        errno_for("read", offset, length, &e),
                        handle,
                        &[],
                    )?,
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
                    Err(e) => simple_reply(
                        &mut stream,
                        errno_for("write", offset, length, &e),
                        handle,
                        &[],
                    )?,
                }
            }
            CMD_FLUSH => match engine.flush() {
                Ok(_) => simple_reply(&mut stream, 0, handle, &[])?,
                Err(e) => simple_reply(
                    &mut stream,
                    errno_for("flush", offset, length, &e),
                    handle,
                    &[],
                )?,
            },
            CMD_TRIM | CMD_WRITE_ZEROES => {
                let mut result = engine.write_zeroes(offset, length as u64);
                if result.is_ok() && flags & CMD_FLAG_FUA != 0 {
                    result = engine.flush().map(|_| ());
                }
                match result {
                    Ok(()) => simple_reply(&mut stream, 0, handle, &[])?,
                    Err(e) => simple_reply(
                        &mut stream,
                        errno_for("write_zeroes", offset, length, &e),
                        handle,
                        &[],
                    )?,
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

/// Map an engine failure to an NBD errno, and say what it was.
///
/// The Guest only ever learns the errno, and an errno is not a diagnosis: an
/// EIO returned for a FLUSH makes ext4 abort its journal and remount the root
/// read-only, which surfaces to the operator as a broken Cat with nothing in
/// any log explaining why. Log the underlying error where it is still known.
/// `Fenced` is an expected outcome of losing an attachment race, so it stays at
/// warn; everything else is a real I/O failure.
fn errno_for(cmd: &str, offset: u64, length: u32, e: &EngineError) -> u32 {
    match e {
        EngineError::Fenced => {
            tracing::warn!(
                cmd,
                offset,
                length,
                "nbd request rejected: attachment fenced"
            );
            EPERM
        }
        EngineError::OutOfBounds { .. } => {
            tracing::warn!(cmd, offset, length, error = %e, "nbd request out of bounds");
            EINVAL
        }
        _ => {
            tracing::error!(cmd, offset, length, error = %e, "nbd request failed");
            EIO
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EngineConfig;
    use cats_block_client::{NbdClient, NbdError};
    use cats_metadata_store_sqlite::SqliteMetadataStore;
    use cats_object_store_file::FileBlobStore;
    use cats_storage::MetadataStore;
    use std::path::Path;

    fn engine(dir: &Path) -> Arc<ChunkEngine> {
        let blob = Arc::new(FileBlobStore::open(dir.join("blob")).unwrap());
        let meta = Arc::new(SqliteMetadataStore::open(&dir.join("meta.db")).unwrap());
        meta.create_volume("vol_nbd", 4 * cats_api::chunk::CHUNK_SIZE as u64)
            .unwrap();
        let epoch = 1;
        meta.install_grant_for_tests("vol_nbd", "att1", epoch)
            .unwrap();
        ChunkEngine::attach_granted_epoch(
            EngineConfig::new("vol_nbd", dir.join("data"), "att1"),
            epoch,
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
        engine.detach().unwrap();
    }
}
