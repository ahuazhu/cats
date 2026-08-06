mod git;
mod model;

use std::{io, path::Path, string::FromUtf8Error};

use git::GitRepository;
pub use model::{
    ApprovalEvidence, CheckEvidence, IntegrationEvidence, IntegrationKind, PushEvidence,
    SourceChainRecord, SourceChainVerdict,
};
use thiserror::Error;

pub type GuardResult<T> = Result<T, GuardError>;

#[derive(Debug, Error)]
pub enum GuardError {
    #[error("invalid source-chain record: {0}")]
    InvalidRecord(String),
    #[error("could not run git: {0}")]
    GitSpawn(#[source] io::Error),
    #[error("{command} failed: {stderr}")]
    GitCommand { command: String, stderr: String },
    #[error("git returned non-UTF-8 output: {0}")]
    GitOutput(#[source] FromUtf8Error),
}

#[derive(Debug)]
pub struct VerificationContext<'a> {
    pub repository_root: &'a Path,
    pub expected_repository: &'a str,
    pub expected_rc_ref: &'a str,
    pub expected_rc_branch: &'a str,
    pub expected_controller_sha: &'a str,
    pub expected_before_sha: &'a str,
    pub expected_after_sha: &'a str,
    pub trusted_main_head_sha: &'a str,
    pub expected_required_checks: &'a [&'a str],
}

pub fn verify_source_chain(
    record: &SourceChainRecord,
    context: &VerificationContext<'_>,
) -> GuardResult<SourceChainVerdict> {
    record.validate_common(
        context.expected_repository,
        context.expected_rc_ref,
        context.expected_controller_sha,
    )?;
    let integration_kind = record
        .validate_integration_shape(context.expected_rc_branch, context.expected_required_checks)?;
    let repository = GitRepository::new(context.repository_root);

    if record.push.before_sha != context.expected_before_sha {
        return invalid(format!(
            "push.before_sha {} does not match trusted push evidence {}",
            record.push.before_sha, context.expected_before_sha
        ));
    }
    if record.push.after_sha != context.expected_after_sha {
        return invalid(format!(
            "push.after_sha {} does not match trusted push evidence {}",
            record.push.after_sha, context.expected_after_sha
        ));
    }

    let previous = repository.resolve_commit(context.expected_before_sha)?;
    let candidate = repository.resolve_commit(context.expected_after_sha)?;
    if previous != context.expected_before_sha || candidate != context.expected_after_sha {
        return invalid("trusted RC endpoints do not resolve to their exact commits");
    }
    if !repository.is_ancestor(&previous, &candidate)? {
        return invalid(format!(
            "RC movement is not a fast-forward: {previous} is not an ancestor of {candidate}"
        ));
    }

    let controller = repository.resolve_commit(context.expected_controller_sha)?;
    let trusted_main_head = repository.resolve_commit(context.trusted_main_head_sha)?;
    if trusted_main_head != context.trusted_main_head_sha {
        return invalid("trusted main head does not resolve to its exact commit");
    }
    if !repository.is_ancestor(&controller, &trusted_main_head)? {
        return invalid(format!(
            "controller {controller} is not contained in trusted main history {trusted_main_head}"
        ));
    }

    match &record.integration {
        IntegrationEvidence::ReviewedPullRequest {
            reviewed_head_sha, ..
        } => {
            let reviewed_head = repository.resolve_commit(reviewed_head_sha)?;
            if repository.tree(&reviewed_head)? != repository.tree(&candidate)? {
                return invalid(
                    "integrated candidate tree differs from the exact reviewed PR head tree",
                );
            }
        }
        IntegrationEvidence::EmergencyMainSync { main_sha, .. } => {
            if main_sha != &trusted_main_head {
                return invalid(format!(
                    "emergency sync candidate {main_sha} is not exact trusted main head {trusted_main_head}"
                ));
            }
        }
    }

    let mut required_checks = context
        .expected_required_checks
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    required_checks.sort();

    Ok(SourceChainVerdict {
        schema: model::VERDICT_SCHEMA,
        valid: true,
        repository: record.repository.clone(),
        rc_ref: record.push.git_ref.clone(),
        previous_rc_sha: previous,
        candidate_sha: candidate,
        controller_sha: controller,
        trusted_main_head_sha: trusted_main_head,
        required_checks,
        integration_kind,
    })
}

fn invalid<T>(message: impl Into<String>) -> GuardResult<T> {
    Err(GuardError::InvalidRecord(message.into()))
}
