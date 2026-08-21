//! Canonical Host-global execution boundary for one Cat.
//!
//! Every long-lived process which can execute Guest work or publish a
//! Guest-facing block frontend belongs to one deterministic systemd slice.
//! The lifecycle command lane kills that exact parent slice after the grace
//! deadline; individual transient service names remain process identities,
//! never the complete Stop boundary.

use std::path::Path;

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{HostPath, Id, Sha256Digest};
use sha2::{Digest as _, Sha256};

const CAT_EXECUTION_SLICE_DOMAIN: &[u8] = b"cats.atomic-lifecycle.cat-execution-slice.v1";
const CAT_EXECUTION_SLICE_PREFIX: &str = "cats-cat-";
const CAT_EXECUTION_SLICE_SUFFIX: &str = ".slice";

/// Whether a Host cgroup entry is in the reserved deterministic Cat-slice
/// namespace. This does not attribute the digest back to a Cat; inventory may
/// only do that by comparing it with a manifest-derived exact slice name.
pub(crate) fn is_cat_execution_slice_name(name: &str) -> bool {
    name.len() == CAT_EXECUTION_SLICE_PREFIX.len() + 64 + CAT_EXECUTION_SLICE_SUFFIX.len()
        && name.starts_with(CAT_EXECUTION_SLICE_PREFIX)
        && name.ends_with(CAT_EXECUTION_SLICE_SUFFIX)
        && name[CAT_EXECUTION_SLICE_PREFIX.len()..name.len() - CAT_EXECUTION_SLICE_SUFFIX.len()]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Derive the one systemd slice which contains every long-lived process for
/// `cat_id`. The full digest keeps the unit below systemd's name bound even
/// when the protocol Cat ID is at its own 128-byte maximum.
pub(crate) fn cat_execution_slice_id(cat_id: &Id) -> Id {
    let mut digest = Sha256::new();
    digest.update(CAT_EXECUTION_SLICE_DOMAIN);
    digest.update([0]);
    digest.update(cat_id.as_str().as_bytes());
    let digest = Sha256Digest::from_bytes(digest.finalize().into());
    let unit = format!(
        "{CAT_EXECUTION_SLICE_PREFIX}{}{CAT_EXECUTION_SLICE_SUFFIX}",
        digest
            .as_str()
            .strip_prefix("sha256:")
            .expect("Sha256Digest always carries its canonical prefix")
    );
    Id::new(unit).expect("full SHA-256 Cat slice name is a bounded canonical Id")
}

/// systemd's canonical ControlGroup value for the Cat parent slice.
pub(crate) fn cat_execution_slice_control_group(cat_id: &Id) -> String {
    format!("/{}", cat_execution_slice_id(cat_id))
}

/// systemd's canonical ControlGroup value for one transient service inside
/// the Cat parent slice.
pub(crate) fn cat_service_control_group(cat_id: &Id, service_id: &Id) -> String {
    format!(
        "/{}/{}",
        cat_execution_slice_id(cat_id),
        service_id.as_str()
    )
}

/// Physical cgroup-v2 path for one transient service inside the Cat slice.
pub(crate) fn cat_service_cgroup_path(
    cgroup_root: &Path,
    cat_id: &Id,
    service_id: &Id,
) -> anyhow::Result<HostPath> {
    let path = cgroup_root
        .join(cat_execution_slice_id(cat_id).as_str())
        .join(service_id.as_str());
    HostPath::new(path.to_string_lossy().into_owned())
        .context("Cat execution service cgroup path is not a canonical HostPath")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).expect("valid test ID")
    }

    #[test]
    fn slice_identity_is_stable_bounded_and_cat_specific() {
        let first = cat_execution_slice_id(&id("cat_a"));
        assert_eq!(first, cat_execution_slice_id(&id("cat_a")));
        assert_ne!(first, cat_execution_slice_id(&id("cat_b")));
        assert!(first.as_str().starts_with(CAT_EXECUTION_SLICE_PREFIX));
        assert!(first.as_str().ends_with(CAT_EXECUTION_SLICE_SUFFIX));
        assert!(first.as_str().len() <= 128);
    }

    #[test]
    fn child_service_is_nested_under_exact_parent_slice() {
        let cat_id = id("cat_a");
        let service = id("cats-vmm-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.service");
        let slice = cat_execution_slice_id(&cat_id);
        assert_eq!(
            cat_service_control_group(&cat_id, &service),
            format!("/{slice}/{service}")
        );
        assert_eq!(
            cat_service_cgroup_path(Path::new("/sys/fs/cgroup"), &cat_id, &service)
                .expect("canonical path")
                .as_str(),
            format!("/sys/fs/cgroup/{slice}/{service}")
        );
    }

    #[test]
    fn reserved_slice_namespace_requires_one_canonical_sha256_name() {
        let canonical = cat_execution_slice_id(&id("cat_a"));
        assert!(is_cat_execution_slice_name(canonical.as_str()));
        assert!(!is_cat_execution_slice_name("cats-cat-deadbeef.slice"));
        assert!(!is_cat_execution_slice_name(
            "cats-cat-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.slice"
        ));
        assert!(!is_cat_execution_slice_name(
            "other-cat-0000000000000000000000000000000000000000000000000000000000000000.slice"
        ));
    }
}
