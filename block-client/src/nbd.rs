//! Synchronous userspace client for the portable Cats NBD frontend.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

const NBD_MAGIC: u64 = 0x4e42_444d_4147_4943;
const IHAVEOPT: u64 = 0x4948_4156_454f_5054;
const REPLY_MAGIC: u64 = 0x0003_e889_0455_65a9;
const REQUEST_MAGIC: u32 = 0x2560_9513;
const SIMPLE_REPLY_MAGIC: u32 = 0x6744_6698;

const CFLAG_FIXED_NEWSTYLE: u32 = 1 << 0;
const CFLAG_NO_ZEROES: u32 = 1 << 1;

const OPT_GO: u32 = 7;
const REP_ACK: u32 = 1;
const REP_INFO: u32 = 3;
const INFO_EXPORT: u16 = 0;

const CMD_READ: u16 = 0;
const CMD_WRITE: u16 = 1;
const CMD_DISC: u16 = 2;
const CMD_FLUSH: u16 = 3;
const CMD_TRIM: u16 = 4;
const CMD_FLAG_FUA: u16 = 1 << 0;

pub const EPERM: u32 = 1;
pub const EIO: u32 = 5;
pub const EINVAL: u32 = 22;

trait Wire: Read + Write {
    fn get_u16(&mut self) -> std::io::Result<u16> {
        let mut bytes = [0u8; 2];
        self.read_exact(&mut bytes)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn get_u32(&mut self) -> std::io::Result<u32> {
        let mut bytes = [0u8; 4];
        self.read_exact(&mut bytes)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn get_u64(&mut self) -> std::io::Result<u64> {
        let mut bytes = [0u8; 8];
        self.read_exact(&mut bytes)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn put_u16(&mut self, value: u16) -> std::io::Result<()> {
        self.write_all(&value.to_be_bytes())
    }

    fn put_u32(&mut self, value: u32) -> std::io::Result<()> {
        self.write_all(&value.to_be_bytes())
    }

    fn put_u64(&mut self, value: u64) -> std::io::Result<()> {
        self.write_all(&value.to_be_bytes())
    }
}

impl<T: Read + Write + ?Sized> Wire for T {}

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
                reply if reply >= 0x8000_0000 => {
                    return Err(NbdError::Protocol(format!("GO rejected: {reply:#x}")));
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
        command: u16,
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
        self.stream.put_u16(command)?;
        self.stream.put_u64(handle)?;
        self.stream.put_u64(offset)?;
        self.stream.put_u32(length)?;
        if let Some(payload) = payload {
            self.stream.write_all(payload)?;
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

    #[test]
    fn malformed_handshake_magic_is_rejected() {
        let (mut server, client) = UnixStream::pair().unwrap();
        let peer = std::thread::spawn(move || {
            server.put_u64(0).unwrap();
            server.flush().unwrap();
        });
        let error = match NbdClient::handshake(Box::new(client)) {
            Ok(_) => panic!("malformed handshake unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            NbdError::Protocol(message) if message == "bad server magic"
        ));
        peer.join().unwrap();
    }
}
