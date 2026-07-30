//! Filesystem adapter for the immutable blob-store port.
//!
//! This is a development, test, and fault-injection adapter. Local files are
//! not a production durability substitute for a remote object store.

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use cats_storage::blob::{validate_key, BlobError, BlobStore, Result};
use cats_storage::{AdapterConfig, AdapterError, BlobStoreFactory};

pub const ADAPTER_NAME: &str = "file";

/// Filesystem-backed blob store rooted below one private directory.
pub struct FileBlobStore {
    root: PathBuf,
    tmp_seq: AtomicU64,
}

impl FileBlobStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|source| BlobError::Io {
            key: root.display().to_string(),
            source,
        })?;
        Ok(Self {
            root,
            tmp_seq: AtomicU64::new(0),
        })
    }

    fn path_for(&self, key: &str) -> Result<PathBuf> {
        validate_key(key)?;
        Ok(self.root.join(key))
    }

    fn io_err(key: &str, source: std::io::Error) -> BlobError {
        BlobError::Io {
            key: key.to_string(),
            source,
        }
    }

    fn compare_existing(path: &Path, key: &str, data: &[u8]) -> Result<()> {
        let existing = fs::read(path).map_err(|source| Self::io_err(key, source))?;
        if existing == data {
            Ok(())
        } else {
            Err(BlobError::Backend {
                key: key.to_string(),
                message: "immutable object overwrite with different content".into(),
            })
        }
    }

    fn create_temp(&self, parent: &Path, key: &str) -> Result<(PathBuf, fs::File)> {
        loop {
            let path = parent.join(format!(
                ".tmp-{}-{}",
                std::process::id(),
                self.tmp_seq.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(source) => return Err(Self::io_err(key, source)),
            }
        }
    }
}

impl BlobStore for FileBlobStore {
    fn put_immutable(&self, key: &str, data: &[u8]) -> Result<()> {
        let path = self.path_for(key)?;
        if path.exists() {
            return Self::compare_existing(&path, key, data);
        }

        let parent = path.parent().ok_or_else(|| BlobError::InvalidKey {
            key: key.to_string(),
            message: "object key has no parent".into(),
        })?;
        fs::create_dir_all(parent).map_err(|source| Self::io_err(key, source))?;
        let (tmp, mut file) = self.create_temp(parent, key)?;
        let write_result = (|| {
            file.write_all(data)
                .map_err(|source| Self::io_err(key, source))?;
            file.sync_data()
                .map_err(|source| Self::io_err(key, source))?;
            drop(file);

            match fs::hard_link(&tmp, &path) {
                Ok(()) => {
                    fs::File::open(parent)
                        .and_then(|directory| directory.sync_all())
                        .map_err(|source| Self::io_err(key, source))?;
                    Ok(())
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    Self::compare_existing(&path, key, data)
                }
                Err(source) => Err(Self::io_err(key, source)),
            }
        })();
        let _ = fs::remove_file(tmp);
        write_result
    }

    fn get(&self, key: &str) -> Result<Vec<u8>> {
        match fs::read(self.path_for(key)?) {
            Ok(data) => Ok(data),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                Err(BlobError::NotFound(key.to_string()))
            }
            Err(source) => Err(Self::io_err(key, source)),
        }
    }

    fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.path_for(key)?.exists())
    }

    fn delete(&self, key: &str) -> Result<()> {
        match fs::remove_file(self.path_for(key)?) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(source) => Err(Self::io_err(key, source)),
        }
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let mut output = Vec::new();
        let mut stack = vec![self.root.clone()];
        while let Some(directory) = stack.pop() {
            let entries = match fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(error) if error.kind() == ErrorKind::NotFound => continue,
                Err(source) => return Err(Self::io_err(prefix, source)),
            };
            for entry in entries {
                let entry = entry.map_err(|source| Self::io_err(prefix, source))?;
                let file_type = entry
                    .file_type()
                    .map_err(|source| Self::io_err(prefix, source))?;
                let path = entry.path();
                if file_type.is_dir() {
                    stack.push(path);
                } else if file_type.is_file() {
                    let relative =
                        path.strip_prefix(&self.root)
                            .map_err(|error| BlobError::Backend {
                                key: prefix.to_string(),
                                message: error.to_string(),
                            })?;
                    let key = relative
                        .components()
                        .map(|component| component.as_os_str().to_string_lossy())
                        .collect::<Vec<_>>()
                        .join("/");
                    if key.starts_with(prefix)
                        && !relative
                            .file_name()
                            .is_some_and(|name| name.to_string_lossy().starts_with(".tmp-"))
                    {
                        output.push(key);
                    }
                }
            }
        }
        output.sort();
        Ok(output)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FileBlobStoreFactory;

impl BlobStoreFactory for FileBlobStoreFactory {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn open(
        &self,
        config: &AdapterConfig,
    ) -> std::result::Result<Arc<dyn BlobStore>, AdapterError> {
        config.ensure_only(ADAPTER_NAME, &["root"])?;
        let root = config.required(ADAPTER_NAME, "root")?;
        FileBlobStore::open(root)
            .map(|store| Arc::new(store) as Arc<dyn BlobStore>)
            .map_err(|error| AdapterError::Open {
                adapter: ADAPTER_NAME,
                message: error.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_blob_store_contract() {
        let directory = tempfile::tempdir().unwrap();
        cats_test_support::blob_store_contract(|| {
            Arc::new(FileBlobStore::open(directory.path()).unwrap())
        });
    }

    #[test]
    fn concurrent_writers_cannot_replace_an_immutable_object() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(FileBlobStore::open(directory.path()).unwrap());
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let writers = [b"first".as_slice(), b"second".as_slice()].map(|value| {
            let store = store.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.put_immutable("volumes/v1/data/race", value)
            })
        });
        barrier.wait();
        let results = writers.map(|writer| writer.join().unwrap());
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let stored = store.get("volumes/v1/data/race").unwrap();
        assert!(stored == b"first" || stored == b"second");
    }
}
