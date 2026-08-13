//! Provider-neutral, level-triggered volume object deletion.
//!
//! PostgreSQL `Deleting` rows remain the work authority.  This module owns no
//! job, cursor, claim, or completion flag: every bounded pass starts at the
//! exact volume prefix and authoritative completion is an empty re-list.

use cats_api::runtime_reconciliation::Id;

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
) -> Result<DeletePrefixPage> {
    let prefix = volume_object_prefix(volume_id);
    let page = checked_page(blob, &prefix, maximum)?;
    if page.keys.is_empty() {
        return Ok(DeletePrefixPage::Empty);
    }

    let mut deleted = 0;
    for key in page.keys {
        match blob.delete(&key) {
            Ok(()) => deleted += 1,
            Err(delete_error) => {
                let discovery = checked_page(blob, &prefix, maximum)?;
                if discovery.keys.iter().any(|candidate| candidate == &key) {
                    return Err(delete_error);
                }
                deleted += 1;
            }
        }
    }

    let discovery = checked_page(blob, &prefix, maximum)?;
    Ok(DeletePrefixPage::Progress {
        deleted,
        now_empty: discovery.keys.is_empty(),
    })
}

fn checked_page(
    blob: &dyn BlobStore,
    prefix: &str,
    maximum: usize,
) -> Result<crate::blob::BlobListPage> {
    let page = blob.list_bounded(prefix, maximum)?;
    if page.keys.len() > maximum {
        return Err(BlobError::Backend {
            key: prefix.to_string(),
            message: "bounded LIST exceeded its requested key count".into(),
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

    use crate::{BlobListPage, BlobStore};

    use super::*;

    struct LostDeleteResponseBlob {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
        lose_once: AtomicBool,
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
            delete_volume_objects_page(&blob, &volume, 2).unwrap(),
            DeletePrefixPage::Progress {
                deleted: 2,
                now_empty: true,
            }
        );
        assert_eq!(
            delete_volume_objects_page(&blob, &volume, 2).unwrap(),
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
            delete_volume_objects_page(&blob, &volume, 2).unwrap(),
            DeletePrefixPage::Progress {
                deleted: 2,
                now_empty: false,
            }
        );
        assert_eq!(
            delete_volume_objects_page(&blob, &volume, 2).unwrap(),
            DeletePrefixPage::Progress {
                deleted: 1,
                now_empty: true,
            }
        );
    }
}
