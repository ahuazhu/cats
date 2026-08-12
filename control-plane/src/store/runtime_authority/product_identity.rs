//! Server-owned identities for covered Workspace product candidates.

use cats_api::error::ApiError;
use cats_api::runtime_reconciliation::RandomId128;

use crate::store::Result;

pub(crate) trait ProductIdentitySource: Send + Sync {
    fn random_id(&self) -> Result<RandomId128>;
}

#[derive(Debug, Default)]
pub(crate) struct UuidProductIdentitySource;

impl ProductIdentitySource for UuidProductIdentitySource {
    fn random_id(&self) -> Result<RandomId128> {
        // UUID v4 fixes non-zero version and variant bits, so the canonical
        // 128-bit random identity cannot be the forbidden all-zero value.
        RandomId128::new(uuid::Uuid::new_v4().simple().to_string())
            .ok_or_else(|| ApiError::internal("UUID v4 did not form a RandomId128"))
    }
}
