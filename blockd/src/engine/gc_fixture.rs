//! Legacy engine-test convenience only.
//!
//! Production composition has no attached/no-root GC entry point. These tests
//! continue to exercise current-root object shapes through the claim-gated
//! provider-neutral collector while the product snapshot regressions live in
//! `crate::gc::tests`.

use std::time::{Duration, Instant};

use super::*;
use crate::gc::{
    collect_garbage, GarbageCollectionClaim, GcStats, RetainedRoot, RetainedRootSource,
};

impl ChunkEngine {
    pub(super) fn collect_garbage(&self) -> Result<GcStats> {
        let _flush = self.flush_lock.lock().unwrap();
        let _publish = self.publish_lock.lock().unwrap();
        let head = self.authority.load_head(&self.cfg.volume_id)?;
        let current = remote_head_from_fixture_projection(&head)?;
        if current != self.state.lock().unwrap().remote_head {
            return Err(EngineError::Corrupt(
                "fixture GC head differs from engine state".into(),
            ));
        }
        let claim = GarbageCollectionClaim::new(
            Id::new("11111111111111111111111111111111".to_string())
                .expect("fixed fixture claim ID"),
            Id::new(self.cfg.volume_id.clone()).expect("fixture volume ID"),
            self.size,
            vec![RetainedRoot {
                source: RetainedRootSource::Current,
                head: current,
            }],
        )
        .map_err(|error| EngineError::Corrupt(error.to_string()))?;
        collect_garbage(
            self.blob.as_ref(),
            &claim,
            cats_storage::BLOB_LIST_PAGE_MAX_KEYS,
            Instant::now() + Duration::from_secs(30),
        )
        .map_err(|error| EngineError::Corrupt(error.to_string()))
    }
}
