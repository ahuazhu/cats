//! Provider-neutral, level-triggered volume object deletion.
//!
//! PostgreSQL `Deleting` rows remain the work authority.  This module owns no
//! job, cursor, claim, or completion flag: every bounded pass starts at the
//! exact volume prefix and authoritative completion is an empty re-list.

use cats_protocol::runtime_reconciliation::Id;
use std::time::Instant;

use crate::blob::{validate_list_result, BlobError, BlobStore, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletePrefixPage {
    Empty,
    Progress { deleted: usize, now_empty: bool },
}

pub fn volume_object_prefix(volume_id: &Id) -> String {
    // `Id` excludes slash, so this cannot escape into `images/` or another
    // volume.  The trailing slash is intentional and excludes prefix peers.
    format!("volumes/{volume_id}/")
}

/// Delete one bounded page and re-list from the beginning.
///
/// A failed DELETE is ambiguous: discovery decides it succeeded only when a
/// subsequent linearizable LIST no longer contains the exact key.  A caller
/// crash can abandon this function at any point; the next level-triggered pass
/// starts from the same prefix and safely repeats the idempotent effect.
pub fn delete_volume_objects_page(
    blob: &dyn BlobStore,
    volume_id: &Id,
    maximum: usize,
    deadline: Instant,
) -> Result<DeletePrefixPage> {
    let prefix = volume_object_prefix(volume_id);
    let page = checked_page(blob, &prefix, maximum, deadline)?;
    if page.keys.is_empty() && !page.is_truncated {
        return Ok(DeletePrefixPage::Empty);
    }

    let mut deleted = 0;
    for key in page.keys {
        match blob.delete_until(&key, deadline) {
            Ok(()) => deleted += 1,
            Err(delete_error) => {
                let discovery = checked_page(blob, &prefix, maximum, deadline)?;
                if discovery.keys.iter().any(|candidate| candidate == &key) {
                    return Err(delete_error);
                }
                deleted += 1;
            }
        }
    }

    let discovery = checked_page(blob, &prefix, maximum, deadline)?;
    Ok(DeletePrefixPage::Progress {
        deleted,
        now_empty: discovery.keys.is_empty() && !discovery.is_truncated,
    })
}

fn checked_page(
    blob: &dyn BlobStore,
    prefix: &str,
    maximum: usize,
    deadline: Instant,
) -> Result<crate::blob::BlobListPage> {
    let page = blob
        .list_for_delete_bounded_until(prefix, maximum, deadline)?
        .into_page();
    if page.keys.len() > maximum {
        return Err(BlobError::Backend {
            key: prefix.to_string(),
            message: "bounded LIST exceeded its requested key count".into(),
        });
    }
    if page.keys.is_empty() && page.is_truncated {
        return Err(BlobError::Backend {
            key: prefix.to_string(),
            message: "bounded LIST claimed an empty truncated page".into(),
        });
    }
    validate_list_result(prefix, &page.keys)?;
    Ok(page)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    use crate::{BlobListPage, BlobStore, QualifiedDeleteListPage};

    use super::*;

    struct LostDeleteResponseBlob {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
        lose_once: AtomicBool,
    }

    struct StaleEmptyBlob {
        object: Mutex<Option<String>>,
    }

    struct EmptyTruncatedBlob;

    impl BlobStore for StaleEmptyBlob {
        fn put_immutable(&self, _key: &str, _data: &[u8]) -> Result<()> {
            unreachable!()
        }
        fn get(&self, _key: &str) -> Result<Vec<u8>> {
            unreachable!()
        }
        fn exists(&self, _key: &str) -> Result<bool> {
            unreachable!()
        }
        fn delete(&self, _key: &str) -> Result<()> {
            unreachable!()
        }
        fn list(&self, _prefix: &str) -> Result<Vec<String>> {
            Ok(Vec::new())
        }
        fn list_bounded(&self, _prefix: &str, _maximum: usize) -> Result<BlobListPage> {
            Ok(BlobListPage {
                keys: Vec::new(),
                is_truncated: false,
            })
        }
    }

    impl BlobStore for EmptyTruncatedBlob {
        fn put_immutable(&self, _key: &str, _data: &[u8]) -> Result<()> {
            unreachable!()
        }
        fn get(&self, _key: &str) -> Result<Vec<u8>> {
            unreachable!()
        }
        fn exists(&self, _key: &str) -> Result<bool> {
            unreachable!()
        }
        fn delete(&self, _key: &str) -> Result<()> {
            unreachable!()
        }
        fn list(&self, _prefix: &str) -> Result<Vec<String>> {
            unreachable!()
        }
        fn list_for_delete_bounded_until(
            &self,
            _prefix: &str,
            _maximum: usize,
            _deadline: Instant,
        ) -> Result<QualifiedDeleteListPage> {
            Ok(QualifiedDeleteListPage::from_strongly_consistent_adapter(
                BlobListPage {
                    keys: Vec::new(),
                    is_truncated: true,
                },
            ))
        }
    }

    impl LostDeleteResponseBlob {
        fn with_objects(keys: &[&str]) -> Self {
            Self {
                objects: Mutex::new(
                    keys.iter()
                        .map(|key| ((*key).to_string(), Vec::new()))
                        .collect(),
                ),
                lose_once: AtomicBool::new(true),
            }
        }
    }

    impl BlobStore for LostDeleteResponseBlob {
        fn put_immutable(&self, key: &str, data: &[u8]) -> Result<()> {
            self.objects
                .lock()
                .unwrap()
                .insert(key.to_string(), data.to_vec());
            Ok(())
        }

        fn get(&self, key: &str) -> Result<Vec<u8>> {
            self.objects
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| BlobError::NotFound(key.to_string()))
        }

        fn exists(&self, key: &str) -> Result<bool> {
            Ok(self.objects.lock().unwrap().contains_key(key))
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.objects.lock().unwrap().remove(key);
            if self.lose_once.swap(false, Ordering::SeqCst) {
                return Err(BlobError::Backend {
                    key: key.to_string(),
                    message: "injected response loss".into(),
                });
            }
            Ok(())
        }

        fn delete_until(&self, key: &str, deadline: Instant) -> Result<()> {
            if Instant::now() >= deadline {
                return Err(BlobError::Backend {
                    key: key.to_string(),
                    message: "test delete deadline elapsed".into(),
                });
            }
            self.delete(key)
        }

        fn list(&self, prefix: &str) -> Result<Vec<String>> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .keys()
                .filter(|key| key.starts_with(prefix))
                .cloned()
                .collect())
        }

        fn list_bounded(&self, prefix: &str, maximum: usize) -> Result<BlobListPage> {
            let mut keys = self.list(prefix)?;
            let is_truncated = keys.len() > maximum;
            keys.truncate(maximum);
            Ok(BlobListPage { keys, is_truncated })
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
                    message: "test LIST deadline elapsed".into(),
                });
            }
            self.list_bounded(prefix, maximum)
                .map(QualifiedDeleteListPage::from_strongly_consistent_adapter)
        }
    }

    #[test]
    fn ambiguous_delete_is_settled_by_relist_and_never_crosses_prefix() {
        let blob = LostDeleteResponseBlob::with_objects(&[
            "volumes/vol_a/data/a",
            "volumes/vol_a/maps/b",
            "volumes/vol_ab/data/keep",
            "images/shared/data/keep",
        ]);
        let volume = Id::new("vol_a").unwrap();

        assert_eq!(
            delete_volume_objects_page(
                &blob,
                &volume,
                2,
                Instant::now() + std::time::Duration::from_secs(1),
            )
            .unwrap(),
            DeletePrefixPage::Progress {
                deleted: 2,
                now_empty: true,
            }
        );
        assert_eq!(
            delete_volume_objects_page(
                &blob,
                &volume,
                2,
                Instant::now() + std::time::Duration::from_secs(1),
            )
            .unwrap(),
            DeletePrefixPage::Empty
        );
        assert!(blob.exists("volumes/vol_ab/data/keep").unwrap());
        assert!(blob.exists("images/shared/data/keep").unwrap());
    }

    #[test]
    fn page_limit_makes_restart_progress_level_triggered() {
        let blob = LostDeleteResponseBlob {
            objects: Mutex::new(
                [
                    "volumes/vol_a/data/a",
                    "volumes/vol_a/data/b",
                    "volumes/vol_a/data/c",
                ]
                .into_iter()
                .map(|key| (key.to_string(), Vec::new()))
                .collect(),
            ),
            lose_once: AtomicBool::new(false),
        };
        let volume = Id::new("vol_a").unwrap();

        assert_eq!(
            delete_volume_objects_page(
                &blob,
                &volume,
                2,
                Instant::now() + std::time::Duration::from_secs(1),
            )
            .unwrap(),
            DeletePrefixPage::Progress {
                deleted: 2,
                now_empty: false,
            }
        );
        assert_eq!(
            delete_volume_objects_page(
                &blob,
                &volume,
                2,
                Instant::now() + std::time::Duration::from_secs(1),
            )
            .unwrap(),
            DeletePrefixPage::Progress {
                deleted: 1,
                now_empty: true,
            }
        );
    }

    #[test]
    fn unqualified_stale_empty_list_cannot_stamp_delete_completion() {
        let blob = StaleEmptyBlob {
            object: Mutex::new(Some("volumes/vol_a/data/late".into())),
        };
        let error = delete_volume_objects_page(
            &blob,
            &Id::new("vol_a").unwrap(),
            2,
            Instant::now() + std::time::Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(matches!(error, BlobError::Backend { .. }));
        assert!(blob.object.lock().unwrap().is_some());
    }

    #[test]
    fn empty_truncated_page_is_never_delete_completion() {
        assert!(delete_volume_objects_page(
            &EmptyTruncatedBlob,
            &Id::new("vol_a").unwrap(),
            2,
            Instant::now() + std::time::Duration::from_secs(1),
        )
        .is_err());
    }
}
