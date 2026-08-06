use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{GuardError, GuardResult};

pub(crate) const RECORD_SCHEMA: &str = "cats.rc-source-chain.v1";
pub(crate) const VERDICT_SCHEMA: &str = "cats.rc-source-chain-verdict.v1";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceChainRecord {
    pub schema: String,
    pub repository: String,
    pub controller_sha: String,
    pub push: PushEvidence,
    pub integration: IntegrationEvidence,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushEvidence {
    pub event_name: String,
    pub git_ref: String,
    pub before_sha: String,
    pub after_sha: String,
    pub forced: bool,
    pub workflow_run_id: u64,
    pub workflow_run_attempt: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IntegrationEvidence {
    ReviewedPullRequest {
        pull_request_number: u64,
        base_ref: String,
        author_login: String,
        reviewed_head_sha: String,
        integrated_sha: String,
        approvals: Vec<ApprovalEvidence>,
        required_checks: Vec<CheckEvidence>,
    },
    EmergencyMainSync {
        issue_number: u64,
        reason: String,
        initiated_by: String,
        main_sha: String,
        approved_by: Vec<String>,
        required_checks: Vec<CheckEvidence>,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalEvidence {
    pub reviewer_login: String,
    pub reviewed_head_sha: String,
    pub state: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckEvidence {
    pub name: String,
    pub head_sha: String,
    pub conclusion: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationKind {
    ReviewedPullRequest,
    EmergencyMainSync,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceChainVerdict {
    pub schema: &'static str,
    pub valid: bool,
    pub repository: String,
    pub rc_ref: String,
    pub previous_rc_sha: String,
    pub candidate_sha: String,
    pub controller_sha: String,
    pub trusted_main_head_sha: String,
    pub required_checks: Vec<String>,
    pub integration_kind: IntegrationKind,
}

impl SourceChainRecord {
    pub(crate) fn validate_common(
        &self,
        expected_repository: &str,
        expected_rc_ref: &str,
        expected_controller_sha: &str,
    ) -> GuardResult<()> {
        require_equal("schema", &self.schema, RECORD_SCHEMA)?;
        require_equal("repository", &self.repository, expected_repository)?;
        validate_sha("controller_sha", &self.controller_sha)?;
        validate_sha("expected_controller_sha", expected_controller_sha)?;
        require_equal(
            "controller_sha",
            &self.controller_sha,
            expected_controller_sha,
        )?;

        require_equal("push.event_name", &self.push.event_name, "push")?;
        require_equal("push.git_ref", &self.push.git_ref, expected_rc_ref)?;
        validate_sha("push.before_sha", &self.push.before_sha)?;
        validate_sha("push.after_sha", &self.push.after_sha)?;
        if self.push.before_sha == self.push.after_sha {
            return invalid("push.before_sha and push.after_sha must describe a movement");
        }
        if self.push.forced {
            return invalid("forced RC movement is forbidden");
        }
        if self.push.workflow_run_id == 0 || self.push.workflow_run_attempt == 0 {
            return invalid("push workflow identity must use positive run id and attempt");
        }
        Ok(())
    }

    pub(crate) fn validate_integration_shape(
        &self,
        expected_rc_branch: &str,
        expected_required_checks: &[&str],
    ) -> GuardResult<IntegrationKind> {
        match &self.integration {
            IntegrationEvidence::ReviewedPullRequest {
                pull_request_number,
                base_ref,
                author_login,
                reviewed_head_sha,
                integrated_sha,
                approvals,
                required_checks,
            } => {
                if *pull_request_number == 0 {
                    return invalid("pull_request_number must be positive");
                }
                require_equal("integration.base_ref", base_ref, expected_rc_branch)?;
                validate_login("integration.author_login", author_login)?;
                validate_sha("integration.reviewed_head_sha", reviewed_head_sha)?;
                validate_sha("integration.integrated_sha", integrated_sha)?;
                require_equal(
                    "integration.integrated_sha",
                    integrated_sha,
                    &self.push.after_sha,
                )?;
                validate_approvals(author_login, reviewed_head_sha, approvals)?;
                validate_checks(reviewed_head_sha, required_checks, expected_required_checks)?;
                Ok(IntegrationKind::ReviewedPullRequest)
            }
            IntegrationEvidence::EmergencyMainSync {
                issue_number,
                reason,
                initiated_by,
                main_sha,
                approved_by,
                required_checks,
            } => {
                if *issue_number == 0 {
                    return invalid("emergency issue_number must be positive");
                }
                require_non_empty("integration.reason", reason)?;
                validate_login("integration.initiated_by", initiated_by)?;
                validate_sha("integration.main_sha", main_sha)?;
                require_equal("integration.main_sha", main_sha, &self.push.after_sha)?;
                validate_emergency_approvers(initiated_by, approved_by)?;
                validate_checks(main_sha, required_checks, expected_required_checks)?;
                Ok(IntegrationKind::EmergencyMainSync)
            }
        }
    }
}

fn validate_approvals(
    author_login: &str,
    reviewed_head_sha: &str,
    approvals: &[ApprovalEvidence],
) -> GuardResult<()> {
    if approvals.is_empty() {
        return invalid("reviewed PR integration needs at least one approval");
    }
    let mut reviewers = BTreeSet::new();
    for approval in approvals {
        validate_login("approval.reviewer_login", &approval.reviewer_login)?;
        if approval.reviewer_login.eq_ignore_ascii_case(author_login) {
            return invalid("the PR author cannot supply the required approval");
        }
        require_equal("approval.state", &approval.state, "approved")?;
        validate_sha("approval.reviewed_head_sha", &approval.reviewed_head_sha)?;
        require_equal(
            "approval.reviewed_head_sha",
            &approval.reviewed_head_sha,
            reviewed_head_sha,
        )?;
        if !reviewers.insert(approval.reviewer_login.to_ascii_lowercase()) {
            return invalid("duplicate PR reviewer evidence");
        }
    }
    Ok(())
}

fn validate_emergency_approvers(initiated_by: &str, approved_by: &[String]) -> GuardResult<()> {
    if approved_by.is_empty() {
        return invalid("emergency main sync needs an independent approver");
    }
    let mut reviewers = BTreeSet::new();
    for reviewer in approved_by {
        validate_login("integration.approved_by", reviewer)?;
        if reviewer.eq_ignore_ascii_case(initiated_by) {
            return invalid("the emergency initiator cannot self-approve");
        }
        if !reviewers.insert(reviewer.to_ascii_lowercase()) {
            return invalid("duplicate emergency approver evidence");
        }
    }
    Ok(())
}

fn validate_checks(
    expected_head_sha: &str,
    checks: &[CheckEvidence],
    expected_required_checks: &[&str],
) -> GuardResult<()> {
    if expected_required_checks.is_empty() {
        return invalid("trusted required-check policy must not be empty");
    }
    let mut expected_names = BTreeSet::new();
    for name in expected_required_checks {
        require_non_empty("trusted required-check name", name)?;
        if !expected_names.insert((*name).to_owned()) {
            return invalid("trusted required-check policy contains a duplicate name");
        }
    }

    let mut names = BTreeSet::new();
    for check in checks {
        require_non_empty("check.name", &check.name)?;
        validate_sha("check.head_sha", &check.head_sha)?;
        require_equal("check.head_sha", &check.head_sha, expected_head_sha)?;
        require_equal("check.conclusion", &check.conclusion, "success")?;
        if !names.insert(check.name.clone()) {
            return invalid("duplicate required check evidence");
        }
    }

    if names != expected_names {
        let missing = expected_names
            .difference(&names)
            .cloned()
            .collect::<Vec<_>>();
        let unexpected = names
            .difference(&expected_names)
            .cloned()
            .collect::<Vec<_>>();
        return invalid(format!(
            "required check evidence does not match trusted policy; missing={missing:?}, unexpected={unexpected:?}"
        ));
    }
    Ok(())
}

pub(crate) fn validate_sha(field: &str, value: &str) -> GuardResult<()> {
    if value.len() != 40
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
        || value.bytes().all(|byte| byte == b'0')
    {
        return invalid(format!(
            "{field} must be a non-zero lowercase 40-character Git SHA-1"
        ));
    }
    Ok(())
}

fn validate_login(field: &str, value: &str) -> GuardResult<()> {
    require_non_empty(field, value)?;
    if value.len() > 100
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return invalid(format!("{field} is not a valid normalized GitHub login"));
    }
    Ok(())
}

fn require_non_empty(field: &str, value: &str) -> GuardResult<()> {
    if value.trim().is_empty() || value.len() > 1024 {
        return invalid(format!("{field} must be non-empty and at most 1024 bytes"));
    }
    Ok(())
}

fn require_equal(field: &str, actual: &str, expected: &str) -> GuardResult<()> {
    if actual != expected {
        return invalid(format!("{field} must be {expected:?}, found {actual:?}"));
    }
    Ok(())
}

fn invalid<T>(message: impl Into<String>) -> GuardResult<T> {
    Err(GuardError::InvalidRecord(message.into()))
}
