use std::collections::{HashMap, HashSet};

use aws_lc_rs::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use serde::Serialize;

use crate::{
    ActorAction, ActorAuthorityManifest, ActorIdentity, ActorRole, AppendCheckpoint, AppendReceipt,
    AppendReceipts, AuthorityTrustAnchors, RunBinding, TrialRecord, ACTOR_AUTHORITY_SCHEMA,
    APPEND_RECEIPTS_SCHEMA,
};

use super::{
    primitive::{
        canonical_json, document_sha256, is_scoped_id, parse_bounded_json, parse_canonical_utc,
        require, require_bounded_text, require_digest, ValidationError,
    },
    ED25519_PRIVATE_SEED_BYTES, ED25519_PUBLIC_KEY_BYTES, MAX_APPEND_RECEIPTS_DOCUMENT_BYTES,
    MAX_AUTHORITY_DOCUMENT_BYTES, MAX_EVENTS_PER_TRIAL,
};

pub fn actor_authority_signature(
    manifest: &ActorAuthorityManifest,
    private_seed: &[u8],
) -> Result<String, ValidationError> {
    sign_ed25519(
        private_seed,
        &ActorAuthorityPreimage {
            schema: &manifest.schema,
            run_id: &manifest.run_id,
            issuer: &manifest.issuer,
            authority_key_id: &manifest.authority_key_id,
            issued_at: &manifest.issued_at,
            expires_at: &manifest.expires_at,
            actors: &manifest.actors,
        },
    )
}

pub fn append_ledger_root(receipts: &[AppendReceipt]) -> Result<String, ValidationError> {
    super::primitive::canonical_sha256(receipts)
}

pub fn append_checkpoint_signature(
    document: &AppendReceipts,
    private_seed: &[u8],
) -> Result<String, ValidationError> {
    sign_ed25519(
        private_seed,
        &AppendReceiptsPreimage {
            schema: &document.schema,
            run_id: &document.run_id,
            window_id: &document.window_id,
            trial_id: &document.trial_id,
            ledger_authority_key_id: &document.ledger_authority_key_id,
            receipts: &document.receipts,
            checkpoint: AppendCheckpointPreimage::from(&document.checkpoint),
        },
    )
}

pub(super) fn validate_actor_authority(
    bytes: &[u8],
    binding: &RunBinding,
    trust: &AuthorityTrustAnchors<'_>,
) -> Result<ActorAuthorityManifest, ValidationError> {
    validate_trust_anchors(trust)?;
    require(
        document_sha256(bytes) == binding.actor_authority_manifest_sha256,
        "actor authority bytes do not match the run binding",
    )?;
    let manifest: ActorAuthorityManifest = parse_bounded_json(
        bytes,
        MAX_AUTHORITY_DOCUMENT_BYTES,
        "actor authority manifest",
    )?;
    require(
        manifest.schema == ACTOR_AUTHORITY_SCHEMA,
        "unsupported actor-authority schema",
    )?;
    require(
        manifest.run_id == binding.run_id,
        "actor authority run_id binding mismatch",
    )?;
    require_bounded_text(&manifest.issuer, "actor authority issuer")?;
    require(
        manifest.authority_key_id == trust.actor_authority_key_id,
        "actor authority key is not the configured trust anchor",
    )?;
    let issued = parse_canonical_utc(&manifest.issued_at)
        .ok_or_else(|| ValidationError::new("actor authority issued_at is not canonical UTC"))?;
    let expires = parse_canonical_utc(&manifest.expires_at)
        .ok_or_else(|| ValidationError::new("actor authority expires_at is not canonical UTC"))?;
    require(issued < expires, "actor authority validity window is empty")?;
    require(
        is_signature(&manifest.signature_ed25519),
        "actor authority signature_ed25519 must be lowercase 128-hex",
    )?;
    verify_ed25519(
        trust.actor_authority_public_key,
        &ActorAuthorityPreimage {
            schema: &manifest.schema,
            run_id: &manifest.run_id,
            issuer: &manifest.issuer,
            authority_key_id: &manifest.authority_key_id,
            issued_at: &manifest.issued_at,
            expires_at: &manifest.expires_at,
            actors: &manifest.actors,
        },
        &manifest.signature_ed25519,
        "actor authority signature authentication failed",
    )?;
    validate_identities(&manifest.actors)?;
    Ok(manifest)
}

pub(super) fn validate_append_receipts(
    bytes: &[u8],
    record: &TrialRecord,
    actors: &[ActorIdentity],
    trust: &AuthorityTrustAnchors<'_>,
) -> Result<(), ValidationError> {
    require(
        document_sha256(bytes) == record.append_receipts_sha256,
        "append receipt bytes do not match the trial binding",
    )?;
    let document: AppendReceipts = parse_bounded_json(
        bytes,
        MAX_APPEND_RECEIPTS_DOCUMENT_BYTES,
        "append receipt bundle",
    )?;
    require(
        document.schema == APPEND_RECEIPTS_SCHEMA,
        "unsupported append-receipts schema",
    )?;
    require(
        document.run_id == record.binding.run_id
            && document.window_id == record.window_id
            && document.trial_id == record.trial_id,
        "append receipt bundle scope mismatch",
    )?;
    require(
        document.ledger_authority_key_id == trust.append_ledger_key_id,
        "append ledger key is not the configured trust anchor",
    )?;
    require(
        document.receipts.len() == record.events.len()
            && document.receipts.len() <= MAX_EVENTS_PER_TRIAL,
        "append receipt bundle must cover every and only trial event",
    )?;
    let actors: HashMap<&str, &ActorIdentity> = actors
        .iter()
        .map(|actor| (actor.identity_id.as_str(), actor))
        .collect();
    for (receipt, event) in document.receipts.iter().zip(&record.events) {
        let actor = actors
            .get(event.actor_identity_id.as_str())
            .copied()
            .ok_or_else(|| ValidationError::new("append receipt event actor is unauthorized"))?;
        require(
            receipt.ledger_sequence == event.ledger_sequence
                && receipt.event_id == event.event_id
                && receipt.event_record_sha256 == event.immutable_record_sha256,
            "append receipt does not exactly bind event sequence/id/digest",
        )?;
        require(
            receipt.actor_identity_id == actor.identity_id
                && receipt.actor_session_id == actor.session_id
                && receipt.actor_credential_fingerprint_sha256
                    == actor.credential_fingerprint_sha256,
            "append receipt actor session does not match authenticated authority",
        )?;
    }
    validate_checkpoint(&document, record, trust)
}

fn validate_checkpoint(
    document: &AppendReceipts,
    record: &TrialRecord,
    trust: &AuthorityTrustAnchors<'_>,
) -> Result<(), ValidationError> {
    let checkpoint = &document.checkpoint;
    let first = record.events.first().expect("event count validated");
    let last = record.events.last().expect("event count validated");
    require(
        checkpoint.event_count == record.events.len()
            && checkpoint.first_ledger_sequence == first.ledger_sequence
            && checkpoint.last_ledger_sequence == last.ledger_sequence,
        "append checkpoint event count/range mismatch",
    )?;
    require_digest(&checkpoint.ledger_root_sha256, "append ledger root")?;
    require(
        checkpoint.ledger_root_sha256 == append_ledger_root(&document.receipts)?,
        "append checkpoint ledger root mismatch",
    )?;
    require_digest(
        &checkpoint.previous_checkpoint_sha256,
        "previous append checkpoint sha256",
    )?;
    let signed_at = parse_canonical_utc(&checkpoint.signed_at)
        .ok_or_else(|| ValidationError::new("append checkpoint signed_at is not canonical UTC"))?;
    let last_event = parse_canonical_utc(&last.occurred_at)
        .ok_or_else(|| ValidationError::new("last event time is not canonical UTC"))?;
    require(
        signed_at >= last_event,
        "append checkpoint predates its final event",
    )?;
    require(
        is_signature(&checkpoint.signature_ed25519),
        "append checkpoint signature_ed25519 must be lowercase 128-hex",
    )?;
    verify_ed25519(
        trust.append_ledger_public_key,
        &AppendReceiptsPreimage {
            schema: &document.schema,
            run_id: &document.run_id,
            window_id: &document.window_id,
            trial_id: &document.trial_id,
            ledger_authority_key_id: &document.ledger_authority_key_id,
            receipts: &document.receipts,
            checkpoint: AppendCheckpointPreimage::from(&document.checkpoint),
        },
        &checkpoint.signature_ed25519,
        "append checkpoint authentication failed",
    )
}

fn validate_trust_anchors(trust: &AuthorityTrustAnchors<'_>) -> Result<(), ValidationError> {
    require(
        is_scoped_id(trust.actor_authority_key_id),
        "invalid actor authority trust key id",
    )?;
    require(
        is_scoped_id(trust.append_ledger_key_id),
        "invalid append ledger trust key id",
    )?;
    validate_public_key(trust.actor_authority_public_key, "actor authority")?;
    validate_public_key(trust.append_ledger_public_key, "append ledger")
}

fn validate_private_seed(seed: &[u8]) -> Result<(), ValidationError> {
    require(
        seed.len() == ED25519_PRIVATE_SEED_BYTES,
        format!("Ed25519 private seed must be exactly {ED25519_PRIVATE_SEED_BYTES} bytes"),
    )
}

fn validate_public_key(key: &[u8], name: &str) -> Result<(), ValidationError> {
    require(
        key.len() == ED25519_PUBLIC_KEY_BYTES,
        format!("{name} Ed25519 public key must be exactly {ED25519_PUBLIC_KEY_BYTES} bytes"),
    )
}

fn sign_ed25519(private_seed: &[u8], value: &impl Serialize) -> Result<String, ValidationError> {
    validate_private_seed(private_seed)?;
    let key_pair = Ed25519KeyPair::from_seed_unchecked(private_seed)
        .map_err(|_| ValidationError::new("invalid Ed25519 private seed"))?;
    let message = canonical_json(value)?;
    let signature = key_pair
        .try_sign(&message)
        .map_err(|_| ValidationError::new("Ed25519 signing failed"))?;
    Ok(hex::encode(signature.as_ref()))
}

fn verify_ed25519(
    public_key: &[u8],
    value: &impl Serialize,
    signature_hex: &str,
    message: &str,
) -> Result<(), ValidationError> {
    let signature = hex::decode(signature_hex).map_err(|_| ValidationError::new(message))?;
    let canonical = canonical_json(value)?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&canonical, &signature)
        .map_err(|_| ValidationError::new(message))
}

fn is_signature(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn validate_identities(actors: &[ActorIdentity]) -> Result<(), ValidationError> {
    require(
        actors.len() == 5,
        "actor authority must bind exactly five role identities",
    )?;
    let mut roles = HashSet::new();
    let mut identity_ids = HashSet::new();
    let mut principals = HashSet::new();
    let mut sessions = HashSet::new();
    let mut fingerprints = HashSet::new();
    for identity in actors {
        require(is_scoped_id(&identity.identity_id), "invalid identity_id")?;
        require(roles.insert(identity.role), "duplicate actor role")?;
        require(
            identity_ids.insert(identity.identity_id.as_str()),
            "duplicate identity_id",
        )?;
        require_bounded_text(&identity.principal, "actor principal")?;
        require(
            principals.insert(identity.principal.as_str()),
            "roles must use distinct principals",
        )?;
        require(is_scoped_id(&identity.session_id), "invalid session_id")?;
        require(
            sessions.insert(identity.session_id.as_str()),
            "roles must use distinct sessions",
        )?;
        require_digest(
            &identity.credential_fingerprint_sha256,
            "credential_fingerprint_sha256",
        )?;
        require(
            fingerprints.insert(identity.credential_fingerprint_sha256.as_str()),
            "roles must use distinct credential fingerprints",
        )?;
        let actions: HashSet<ActorAction> = identity.allowed_actions.iter().copied().collect();
        let expected: HashSet<ActorAction> = role_actions(identity.role).iter().copied().collect();
        require(
            actions.len() == identity.allowed_actions.len() && actions == expected,
            format!("{:?} has an invalid capability set", identity.role),
        )?;
    }
    require(roles.len() == 5, "missing actor role")
}

pub(super) fn identity_for_role(
    actors: &[ActorIdentity],
    role: ActorRole,
) -> Result<&str, ValidationError> {
    actors
        .iter()
        .find(|identity| identity.role == role)
        .map(|identity| identity.identity_id.as_str())
        .ok_or_else(|| ValidationError::new(format!("missing {role:?} identity")))
}

pub(super) fn role_actions(role: ActorRole) -> &'static [ActorAction] {
    match role {
        ActorRole::Controller => &[ActorAction::BindRun, ActorAction::ScheduleTrial],
        ActorRole::FaultActor => &[ActorAction::ApplyFault, ActorAction::EndFault],
        ActorRole::RecoveryActor => &[
            ActorAction::ArmRecovery,
            ActorAction::ExecuteRecovery,
            ActorAction::RecordCleanup,
        ],
        ActorRole::Observer => &[
            ActorAction::CaptureCalibration,
            ActorAction::CaptureObservation,
            ActorAction::SealEvidence,
        ],
        ActorRole::Verifier => &[ActorAction::VerifyEvidence, ActorAction::IssueTerminal],
    }
}

#[derive(Serialize)]
struct ActorAuthorityPreimage<'a> {
    schema: &'a str,
    run_id: &'a str,
    issuer: &'a str,
    authority_key_id: &'a str,
    issued_at: &'a str,
    expires_at: &'a str,
    actors: &'a [ActorIdentity],
}

#[derive(Serialize)]
struct AppendReceiptsPreimage<'a> {
    schema: &'a str,
    run_id: &'a str,
    window_id: &'a str,
    trial_id: &'a str,
    ledger_authority_key_id: &'a str,
    receipts: &'a [AppendReceipt],
    checkpoint: AppendCheckpointPreimage<'a>,
}

#[derive(Serialize)]
struct AppendCheckpointPreimage<'a> {
    event_count: usize,
    first_ledger_sequence: u64,
    last_ledger_sequence: u64,
    ledger_root_sha256: &'a str,
    previous_checkpoint_sha256: &'a str,
    signed_at: &'a str,
}

impl<'a> From<&'a AppendCheckpoint> for AppendCheckpointPreimage<'a> {
    fn from(value: &'a AppendCheckpoint) -> Self {
        Self {
            event_count: value.event_count,
            first_ledger_sequence: value.first_ledger_sequence,
            last_ledger_sequence: value.last_ledger_sequence,
            ledger_root_sha256: &value.ledger_root_sha256,
            previous_checkpoint_sha256: &value.previous_checkpoint_sha256,
            signed_at: &value.signed_at,
        }
    }
}
