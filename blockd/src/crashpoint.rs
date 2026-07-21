//! Deterministic crash injection for durability tests (spec §8.1).
//!
//! When the environment variable `CATS_CRASH_POINT` equals one of the
//! well-known point names, the process aborts (as close to `kill -9` as an
//! in-process hook can get) the first time execution reaches that point.
//! The integration tests spawn the real `cats-blockd` binary with this set
//! and then verify recovery.

pub const AFTER_PACK: &str = "after_pack";
pub const AFTER_DATA_UPLOAD: &str = "after_data_upload";
pub const BEFORE_CAS: &str = "before_cas";
pub const AFTER_CAS: &str = "after_cas";

pub fn maybe_crash(point: &str) {
    if let Ok(v) = std::env::var("CATS_CRASH_POINT") {
        if v == point {
            // Flush nothing, run no destructors: simulate power loss for this
            // process. eprintln is best-effort diagnostics for the harness.
            eprintln!("cats-blockd: hitting crash point {point}; aborting");
            std::process::abort();
        }
    }
}
