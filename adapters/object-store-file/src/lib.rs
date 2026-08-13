//! Filesystem adapter for the immutable blob-store port.
//!
//! This is a development, test, and fault-injection adapter. Local files are
//! not a production durability substitute for a remote object store.

use std::collections::BinaryHeap;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use cats_storage::blob::{
    validate_key, validate_list_maximum, validate_list_result, BlobError, BlobListPage, BlobStore,
    QualifiedDeleteListPage, Result,
};
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

    fn list_page(&self, prefix: &str, maximum: usize) -> Result<BlobListPage> {
        validate_list_maximum(prefix, maximum)?;
        let directory_prefix = prefix.strip_suffix('/').unwrap_or(prefix);
        if directory_prefix
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
        {
            return Err(BlobError::InvalidKey {
                key: prefix.to_string(),
                message: "expected a non-empty relative slash-separated prefix".into(),
            });
        }
        let anchor = if prefix.ends_with('/') {
            self.root.join(directory_prefix)
        } else {
            let parent = directory_prefix
                .rsplit_once('/')
                .map_or("", |(parent, _)| parent);
            self.root.join(parent)
        };
        // Walk the exact prefix subtree while retaining only the lexically
        // smallest requested page. Traversal may inspect every directory
        // entry, but memory remains O(maximum + directory depth), never O(all
        // objects).
        let mut output = BinaryHeap::with_capacity(maximum);
        let mut is_truncated = false;
        self.collect_page_entries(&anchor, prefix, maximum, &mut output, &mut is_truncated)?;
        let output = output.into_sorted_vec();
        validate_list_result(prefix, &output)?;
        Ok(BlobListPage {
            keys: output,
            is_truncated,
        })
    }

    fn collect_page_entries(
        &self,
        path: &Path,
        prefix: &str,
        maximum: usize,
        output: &mut BinaryHeap<String>,
        is_truncated: &mut bool,
    ) -> Result<()> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(source) => return Err(Self::io_err(prefix, source)),
        };
        if metadata.is_dir() {
            let entries = match fs::read_dir(path) {
                Ok(entries) => entries,
                Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
                Err(source) => return Err(Self::io_err(prefix, source)),
            };
            for entry in entries {
                let entry = entry.map_err(|source| Self::io_err(prefix, source))?;
                self.collect_page_entries(&entry.path(), prefix, maximum, output, is_truncated)?;
            }
            return Ok(());
        }
        if !metadata.is_file()
            || path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".tmp-"))
        {
            return Ok(());
        }
        let relative = path
            .strip_prefix(&self.root)
            .map_err(|error| BlobError::Backend {
                key: prefix.to_string(),
                message: error.to_string(),
            })?;
        let key = relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        if key.starts_with(prefix) {
            if output.len() < maximum {
                output.push(key);
            } else {
                *is_truncated = true;
                if output.peek().is_some_and(|largest| &key < largest) {
                    output.pop();
                    output.push(key);
                }
            }
        }
        Ok(())
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

    fn get_bounded(&self, key: &str, maximum: usize) -> Result<Vec<u8>> {
        let path = self.path_for(key)?;
        let mut file = match fs::File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(BlobError::NotFound(key.to_string()));
            }
            Err(source) => return Err(Self::io_err(key, source)),
        };
        let maximum_u64 = u64::try_from(maximum).unwrap_or(u64::MAX);
        let metadata_len = file
            .metadata()
            .map_err(|source| Self::io_err(key, source))?
            .len();
        if metadata_len > maximum_u64 {
            return Err(BlobError::TooLarge {
                key: key.to_string(),
                maximum,
                observed_at_least: maximum.saturating_add(1),
            });
        }

        // Metadata is only an early reject: the file can grow between stat and
        // read, so the actual stream remains capped at maximum + 1 bytes.
        let read_limit = maximum.saturating_add(1);
        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata_len)
                .unwrap_or(maximum)
                .min(maximum),
        );
        Read::by_ref(&mut file)
            .take(u64::try_from(read_limit).unwrap_or(u64::MAX))
            .read_to_end(&mut bytes)
            .map_err(|source| Self::io_err(key, source))?;
        if bytes.len() > maximum {
            return Err(BlobError::TooLarge {
                key: key.to_string(),
                maximum,
                observed_at_least: bytes.len(),
            });
        }
        Ok(bytes)
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

    fn list_bounded(&self, prefix: &str, maximum: usize) -> Result<BlobListPage> {
        self.list_page(prefix, maximum)
    }

    fn list_for_delete_bounded_until(
        &self,
        prefix: &str,
        maximum: usize,
        deadline: Instant,
    ) -> Result<QualifiedDeleteListPage> {
        if Instant::now() >= deadline {
            return Err(BlobError::Backend {
                key: prefix.to_string(),
                message: "destructive LIST deadline elapsed".into(),
            });
        }
        let page = self.list_page(prefix, maximum)?;
        if Instant::now() > deadline {
            return Err(BlobError::Backend {
                key: prefix.to_string(),
                message: "destructive LIST deadline elapsed".into(),
            });
        }
        Ok(QualifiedDeleteListPage::from_strongly_consistent_adapter(
            page,
        ))
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

    #[test]
    fn bounded_list_stops_at_one_page_and_preserves_lexical_order() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileBlobStore::open(directory.path()).unwrap();
        for key in [
            "volumes/v1/maps/c",
            "volumes/v1/data/b",
            "volumes/v1/data/a",
            "volumes/v2/data/keep",
        ] {
            store.put_immutable(key, b"x").unwrap();
        }
        assert_eq!(
            store.list_bounded("volumes/v1/", 2).unwrap(),
            BlobListPage {
                keys: vec!["volumes/v1/data/a".into(), "volumes/v1/data/b".into()],
                is_truncated: true,
            }
        );
    }

    #[test]
    fn bounded_get_rejects_before_returning_an_oversized_body() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileBlobStore::open(directory.path()).unwrap();
        store
            .put_immutable("images/test/manifest.json", b"12345")
            .unwrap();

        assert_eq!(
            store.get_bounded("images/test/manifest.json", 5).unwrap(),
            b"12345"
        );
        assert!(matches!(
            store.get_bounded("images/test/manifest.json", 4),
            Err(BlobError::TooLarge {
                maximum: 4,
                observed_at_least: 5,
                ..
            })
        ));
    }

    #[test]
    fn immutable_key_cannot_be_replaced_after_adapter_restart() {
        let directory = tempfile::tempdir().unwrap();
        let key = "images/test/manifest.json";
        FileBlobStore::open(directory.path())
            .unwrap()
            .put_immutable(key, b"first")
            .unwrap();

        let reopened = FileBlobStore::open(directory.path()).unwrap();
        reopened.put_immutable(key, b"first").unwrap();
        assert!(matches!(
            reopened.put_immutable(key, b"different"),
            Err(BlobError::Backend { .. })
        ));
        assert_eq!(reopened.get(key).unwrap(), b"first");
    }
}
