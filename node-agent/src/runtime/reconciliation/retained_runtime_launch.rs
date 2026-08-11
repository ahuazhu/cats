//! Narrow access to the checkpoint-level VMM launch authority.
//!
//! `StartRuntime` duplicates this identity only at the one launch boundary.
//! Every inventory, adoption and recovery path must instead read the retained
//! top-level value so replacing the current step cannot erase the live VMM's
//! identity.

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    encode_runtime_checkpoint, RuntimeCheckpoint, RuntimeLaunch, RuntimeLaunchIdentity,
    Sha256Digest,
};
use sha2::{Digest as _, Sha256};

#[derive(Debug, Clone, Copy)]
pub(crate) struct RetainedRuntimeLaunchAuthority<'a> {
    #[cfg(target_os = "linux")]
    checkpoint: &'a RuntimeCheckpoint,
    identity: &'a RuntimeLaunchIdentity,
}

impl<'a> RetainedRuntimeLaunchAuthority<'a> {
    pub(crate) fn from_checkpoint(checkpoint: &'a RuntimeCheckpoint) -> anyhow::Result<Self> {
        // Direct Rust construction crosses the same F0/cross validator as a
        // persisted checkpoint before any provider-private path is derived.
        if let Err(error) = encode_runtime_checkpoint(checkpoint) {
            anyhow::bail!(
                "validate retained Runtime launch checkpoint: {:?}",
                error.error
            )
        }
        let RuntimeLaunch::Present(identity) = &checkpoint.runtime_launch else {
            anyhow::bail!("Runtime checkpoint has no retained VMM launch authority")
        };
        anyhow::ensure!(
            checkpoint.runtime_incarnation.as_ref() == Some(&identity.runtime_incarnation),
            "retained VMM launch incarnation is not top-level exact"
        );
        Ok(Self {
            #[cfg(target_os = "linux")]
            checkpoint,
            identity,
        })
    }

    /// The initial physical launch is narrower than later adoption: both
    /// durable copies must still be byte-for-byte the same StartRuntime
    /// identity at this boundary.
    pub(crate) fn from_start_runtime_checkpoint(
        checkpoint: &'a RuntimeCheckpoint,
    ) -> anyhow::Result<Self> {
        let authority = Self::from_checkpoint(checkpoint)?;
        anyhow::ensure!(
            checkpoint.step.start_runtime_launch_identity().as_ref() == Some(authority.identity),
            "physical VMM launch checkpoint is not exact StartRuntime authority"
        );
        Ok(authority)
    }

    pub(crate) fn identity(&self) -> &'a RuntimeLaunchIdentity {
        self.identity
    }

    /// Provider-private digest used by the durable receipt. The enclosing
    /// checkpoint was already validated, and `RuntimeLaunchIdentity` contains
    /// no map or floating-point member, so serde's struct order is stable.
    pub(crate) fn identity_content_digest(&self) -> anyhow::Result<Sha256Digest> {
        let bytes =
            serde_json::to_vec(self.identity).context("encode retained Runtime launch identity")?;
        Ok(Sha256Digest::from_bytes(Sha256::digest(bytes).into()))
    }

    /// Validate the immutable checkpoint bytes inherited by the VMM at fd64.
    /// The current checkpoint pathname may legitimately have advanced to a
    /// Running-tail inode; the inherited descriptor must remain the canonical
    /// StartRuntime checkpoint for this exact retained identity and Cat/Node.
    #[cfg(target_os = "linux")]
    pub(crate) fn matches_launch_checkpoint(
        &self,
        launch_checkpoint: &RuntimeCheckpoint,
    ) -> anyhow::Result<bool> {
        encode_runtime_checkpoint(launch_checkpoint)
            .context("validate inherited StartRuntime checkpoint")?;
        let RuntimeLaunch::Present(launch_identity) = &launch_checkpoint.runtime_launch else {
            return Ok(false);
        };
        if launch_checkpoint
            .step
            .start_runtime_launch_identity()
            .as_ref()
            != Some(launch_identity.as_ref())
        {
            return Ok(false);
        }
        Ok(launch_checkpoint.cat_id == self.checkpoint.cat_id
            && launch_checkpoint.node_id == self.checkpoint.node_id
            && launch_identity.as_ref() == self.identity)
    }
}
