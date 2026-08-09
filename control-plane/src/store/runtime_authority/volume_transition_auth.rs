//! Same-transaction authentication prefix for A22 volume authority access.
//!
//! A proof verifier can only construct [`AuthenticatedNodeCredential`].  It
//! cannot choose a Node id or manufacture one of the private transaction
//! contexts below.  Evidence and mutation entrypoints therefore have to take
//! the exact NodeIdentity, active credential lineage and current AgentSession
//! locks before they can reach an authorization or Volume row.

use cats_api::runtime_reconciliation::{
    encode_runtime_volume_transition_evidence_request, AgentSession, ContractError,
    ContractErrorDetail, ContractVersion, CredentialBinding, Id, NodeIdentity, NodeIdentityState,
    RuntimeVolumeTransitionEvidenceRequest, SessionBinding, Sha256Digest, UnixMillis,
};
use cats_storage::authority::TakeoverResult;
use postgres::Transaction;

use super::events::consume_volume_takeover_in;
use super::rows::database_now;
use super::volume_transition_evidence::{
    load_volume_transition_evidence_in, VolumeTransitionEvidenceLoad,
};
use crate::store::agent_sessions::{
    load_current_session_for_share, load_current_session_for_update,
    load_identity_by_credential_for_share, load_identity_by_credential_for_update,
    lock_exact_credential_lineage, AuthenticatedNodeCredential, CredentialLineageState,
};
use crate::store::transaction::AuthorityTxResult;
use crate::store::{Result, Store};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VolumeTransitionStoreOutcome<T> {
    Accepted(T),
    Rejected(VolumeTransitionStoreRejection),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VolumeTransitionStoreRejection {
    IdentityNotEligible,
    Contract(ContractError),
}

/// Capability for the A22 logical read path. Its fields and constructors are
/// private, and it owns the current transaction's mutable borrow, so a sibling
/// authority module can neither forge it from body data nor pair it with a
/// different transaction.
pub(super) struct EvidenceTransactionContext<'transaction, 'connection> {
    transaction: &'transaction mut Transaction<'connection>,
    authenticated: AuthenticatedNodeTransaction,
}

/// Capability for the A22 mutation path. It is distinct from the evidence
/// context at the type level so a share-locked read prefix cannot be passed to
/// a writer accidentally.
pub(super) struct MutationTransactionContext<'transaction, 'connection> {
    transaction: &'transaction mut Transaction<'connection>,
    authenticated: AuthenticatedNodeTransaction,
}

struct AuthenticatedNodeTransaction {
    node_id: Id,
    db_now: UnixMillis,
}

impl<'transaction, 'connection> EvidenceTransactionContext<'transaction, 'connection> {
    pub(super) fn into_parts(self) -> (&'transaction mut Transaction<'connection>, Id, UnixMillis) {
        (
            self.transaction,
            self.authenticated.node_id,
            self.authenticated.db_now,
        )
    }
}

impl<'transaction, 'connection> MutationTransactionContext<'transaction, 'connection> {
    pub(super) fn into_parts(self) -> (&'transaction mut Transaction<'connection>, Id, UnixMillis) {
        (
            self.transaction,
            self.authenticated.node_id,
            self.authenticated.db_now,
        )
    }
}

impl Store {
    /// Loads one exact authorization evidence bundle under the credential and
    /// current AgentSession selected by the proof adapter.
    pub(crate) fn runtime_volume_transition_evidence(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        request: &RuntimeVolumeTransitionEvidenceRequest,
        active_guest_config_digest: &Sha256Digest,
    ) -> Result<VolumeTransitionStoreOutcome<VolumeTransitionEvidenceLoad>> {
        if let Err(error) = encode_runtime_volume_transition_evidence_request(request) {
            return Ok(VolumeTransitionStoreOutcome::Rejected(
                VolumeTransitionStoreRejection::Contract(error),
            ));
        }
        self.authority_locking_read_snapshot(|transaction| {
            let context = match authenticate_evidence_context_in(
                transaction,
                authenticated,
                &request.session,
                active_guest_config_digest,
            )? {
                VolumeTransitionStoreOutcome::Accepted(context) => context,
                VolumeTransitionStoreOutcome::Rejected(rejection) => {
                    return Ok(VolumeTransitionStoreOutcome::Rejected(rejection));
                }
            };
            load_volume_transition_evidence_in(context, request)
                .map(VolumeTransitionStoreOutcome::Accepted)
        })
    }

    /// Consumes one takeover authorization only after the mutation-strength
    /// identity/session prefix has been locked in this same transaction.
    pub(crate) fn runtime_consume_volume_takeover(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        session: &SessionBinding,
        authorization_id: &Id,
        active_guest_config_digest: &Sha256Digest,
    ) -> Result<VolumeTransitionStoreOutcome<TakeoverResult>> {
        self.authority_transaction(|transaction| {
            let context = match authenticate_mutation_context_in(
                transaction,
                authenticated,
                session,
                active_guest_config_digest,
            )? {
                VolumeTransitionStoreOutcome::Accepted(context) => context,
                VolumeTransitionStoreOutcome::Rejected(rejection) => {
                    return Ok(VolumeTransitionStoreOutcome::Rejected(rejection));
                }
            };
            consume_volume_takeover_in(context, authorization_id)
                .map(VolumeTransitionStoreOutcome::Accepted)
        })
    }
}

pub(super) fn authenticate_evidence_context_in<'transaction, 'connection>(
    transaction: &'transaction mut Transaction<'connection>,
    authenticated: &AuthenticatedNodeCredential,
    presented_session: &SessionBinding,
    active_guest_config_digest: &Sha256Digest,
) -> AuthorityTxResult<
    VolumeTransitionStoreOutcome<EvidenceTransactionContext<'transaction, 'connection>>,
> {
    let Some(identity) =
        load_identity_by_credential_for_share(transaction, authenticated.credential_id())?
    else {
        return Ok(identity_rejected());
    };
    let authenticated = match authenticate_locked_identity(
        transaction,
        authenticated,
        identity,
        presented_session,
        active_guest_config_digest,
        load_current_session_for_share,
    )? {
        VolumeTransitionStoreOutcome::Accepted(authenticated) => authenticated,
        VolumeTransitionStoreOutcome::Rejected(rejection) => {
            return Ok(VolumeTransitionStoreOutcome::Rejected(rejection));
        }
    };
    Ok(VolumeTransitionStoreOutcome::Accepted(
        EvidenceTransactionContext {
            transaction,
            authenticated,
        },
    ))
}

fn authenticate_mutation_context_in<'transaction, 'connection>(
    transaction: &'transaction mut Transaction<'connection>,
    authenticated: &AuthenticatedNodeCredential,
    presented_session: &SessionBinding,
    active_guest_config_digest: &Sha256Digest,
) -> AuthorityTxResult<
    VolumeTransitionStoreOutcome<MutationTransactionContext<'transaction, 'connection>>,
> {
    let Some(identity) =
        load_identity_by_credential_for_update(transaction, authenticated.credential_id())?
    else {
        return Ok(identity_rejected());
    };
    let authenticated = match authenticate_locked_identity(
        transaction,
        authenticated,
        identity,
        presented_session,
        active_guest_config_digest,
        load_current_session_for_update,
    )? {
        VolumeTransitionStoreOutcome::Accepted(authenticated) => authenticated,
        VolumeTransitionStoreOutcome::Rejected(rejection) => {
            return Ok(VolumeTransitionStoreOutcome::Rejected(rejection));
        }
    };
    Ok(VolumeTransitionStoreOutcome::Accepted(
        MutationTransactionContext {
            transaction,
            authenticated,
        },
    ))
}

fn authenticate_locked_identity(
    transaction: &mut Transaction<'_>,
    authenticated: &AuthenticatedNodeCredential,
    identity: NodeIdentity,
    presented_session: &SessionBinding,
    active_guest_config_digest: &Sha256Digest,
    load_session: fn(&mut Transaction<'_>, &Id) -> AuthorityTxResult<Option<AgentSession>>,
) -> AuthorityTxResult<VolumeTransitionStoreOutcome<AuthenticatedNodeTransaction>> {
    if identity.state != NodeIdentityState::Provisioned
        || identity.credential_id != *authenticated.credential_id()
        || identity.credential_binding != *authenticated.binding()
        || !matches!(
            identity.credential_binding,
            CredentialBinding::PublicKey { .. }
        )
    {
        return Ok(identity_rejected());
    }
    if lock_exact_credential_lineage(transaction, &identity)?
        != Some(CredentialLineageState::Active)
    {
        return Ok(identity_rejected());
    }

    let Some(session) = load_session(transaction, &identity.node_id)? else {
        return Ok(contract_rejected(contract(
            ContractErrorDetail::MissingAgentSession {
                node_id: identity.node_id,
            },
            "authenticated Node has no current AgentSession",
        )));
    };
    if let Some(error) = session_error(&session, presented_session) {
        return Ok(contract_rejected(error));
    }
    if session.guest_config_digest != *active_guest_config_digest {
        return Ok(contract_rejected(contract(
            ContractErrorDetail::GuestConfigMismatch {
                node_id: session.node_id,
                expected_guest_config_digest: active_guest_config_digest.clone(),
                presented_guest_config_digest: session.guest_config_digest,
            },
            "AgentSession Guest runtime profile does not match the active release",
        )));
    }
    let db_now = database_now(transaction)?;
    if db_now >= session.lease_deadline_unix_ms {
        return Ok(contract_rejected(contract(
            ContractErrorDetail::SessionExpired {
                node_id: session.node_id,
                agent_session_epoch: session.agent_session_epoch,
                lease_deadline_unix_ms: session.lease_deadline_unix_ms,
                server_time_unix_ms: db_now,
            },
            "AgentSession lease has expired",
        )));
    }
    Ok(VolumeTransitionStoreOutcome::Accepted(
        AuthenticatedNodeTransaction {
            node_id: identity.node_id,
            db_now,
        },
    ))
}

fn session_error(session: &AgentSession, presented: &SessionBinding) -> Option<ContractError> {
    let expected = SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    };
    if presented.agent_session_epoch < expected.agent_session_epoch {
        return Some(contract(
            ContractErrorDetail::StaleSession {
                node_id: expected.node_id,
                presented_agent_session_epoch: presented.agent_session_epoch,
                current_agent_session_epoch: expected.agent_session_epoch,
            },
            "AgentSession is stale",
        ));
    }
    (presented != &expected).then(|| {
        contract(
            ContractErrorDetail::WrongSession {
                expected,
                presented: presented.clone(),
            },
            "request is not bound to the current AgentSession",
        )
    })
}

fn identity_rejected<T>() -> VolumeTransitionStoreOutcome<T> {
    VolumeTransitionStoreOutcome::Rejected(VolumeTransitionStoreRejection::IdentityNotEligible)
}

fn contract_rejected<T>(error: ContractError) -> VolumeTransitionStoreOutcome<T> {
    VolumeTransitionStoreOutcome::Rejected(VolumeTransitionStoreRejection::Contract(error))
}

fn contract(detail: ContractErrorDetail, message: impl Into<String>) -> ContractError {
    ContractError {
        version: ContractVersion::V1,
        error: Box::new(detail),
        message: message.into(),
    }
}
