// Each integration-test crate imports only its slice of this shared fixture harness.
#![allow(dead_code)]

use std::{collections::HashMap, sync::OnceLock};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use cats_qualification_protocol::{
    actor_authority_signature, append_checkpoint_signature, append_ledger_root, catalog_sha256,
    document_sha256, event_record_sha256, observation_record_sha256, terminal_record_sha256,
    ActorAuthorityManifest, AppendCheckpoint, AppendReceipt, AppendReceipts, AuthorityTrustAnchors,
    Catalog, CoverageEntry, CoverageLedger, CoveragePhase, EnvironmentProfile,
    ExecutionEnvironment, PhaseOutcome, PlannedTrial, TerminalOutcome, TrialDocument, TrialPlan,
    TrialRecord, APPEND_RECEIPTS_SCHEMA, COVERAGE_SCHEMA, TRIAL_PLAN_SCHEMA,
};

pub(crate) const CATALOG_BYTES: &[u8] = include_bytes!("../../catalog/case-catalog-v1.json");
pub(crate) const TRIAL_BYTES: &[u8] = include_bytes!("../../fixtures/positive/trial-v1.json");
pub(crate) const AUTHORITY_BYTES: &[u8] =
    include_bytes!("../../fixtures/positive/actor-authority-v1.json");
pub(crate) const RECEIPTS_BYTES: &[u8] =
    include_bytes!("../../fixtures/positive/append-receipts-v1.json");
pub(crate) const COVERAGE_BYTES: &[u8] =
    include_bytes!("../../fixtures/positive/functional-zero-of-104.coverage.json");
pub(crate) const EMPTY_PLAN_BYTES: &[u8] =
    include_bytes!("../../fixtures/positive/trial-plan-empty-v1.json");
pub(crate) const ONE_PLAN_BYTES: &[u8] =
    include_bytes!("../../fixtures/positive/trial-plan-one-v1.json");

pub(crate) const ACTOR_SEED: &[u8; 32] = b"actor-authority-test-key-v1-0001";
pub(crate) const APPEND_SEED: &[u8; 32] = b"append-ledger-test-key-v1-000001";
pub(crate) const ACTOR_KEY_ID: &str = "qualification-actor-authority-v1";
pub(crate) const APPEND_KEY_ID: &str = "qualification-append-ledger-v1";

pub(crate) fn trust() -> AuthorityTrustAnchors<'static> {
    AuthorityTrustAnchors {
        actor_authority_key_id: ACTOR_KEY_ID,
        actor_authority_public_key: actor_public_key(),
        append_ledger_key_id: APPEND_KEY_ID,
        append_ledger_public_key: append_public_key(),
    }
}

pub(crate) fn catalog() -> Catalog {
    serde_json::from_slice(CATALOG_BYTES).expect("catalog fixture")
}

pub(crate) fn trial() -> TrialRecord {
    serde_json::from_slice(TRIAL_BYTES).expect("trial fixture")
}

pub(crate) fn authority() -> ActorAuthorityManifest {
    serde_json::from_slice(AUTHORITY_BYTES).expect("authority fixture")
}

pub(crate) fn receipts() -> AppendReceipts {
    serde_json::from_slice(RECEIPTS_BYTES).expect("append receipts fixture")
}

pub(crate) fn coverage() -> CoverageLedger {
    serde_json::from_slice(COVERAGE_BYTES).expect("coverage fixture")
}

pub(crate) fn signed_authority_for_run(run_id: &str) -> (ActorAuthorityManifest, Vec<u8>) {
    let mut manifest = authority();
    manifest.run_id = run_id.to_owned();
    manifest.signature_ed25519 =
        actor_authority_signature(&manifest, ACTOR_SEED).expect("authority signature");
    let bytes = serde_json::to_vec(&manifest).expect("authority bytes");
    (manifest, bytes)
}

pub(crate) fn resign_authority(manifest: &mut ActorAuthorityManifest) -> Vec<u8> {
    manifest.signature_ed25519 =
        actor_authority_signature(manifest, ACTOR_SEED).expect("authority signature");
    serde_json::to_vec(manifest).expect("authority bytes")
}

pub(crate) fn authenticate_trial(
    trial: &mut TrialRecord,
    actors: &ActorAuthorityManifest,
) -> Vec<u8> {
    rehash_trial(trial);
    let actor_by_id: HashMap<&str, _> = actors
        .actors
        .iter()
        .map(|actor| (actor.identity_id.as_str(), actor))
        .collect();
    let receipts = trial
        .events
        .iter()
        .map(|event| {
            let actor = actor_by_id
                .get(event.actor_identity_id.as_str())
                .expect("event actor");
            AppendReceipt {
                ledger_sequence: event.ledger_sequence,
                event_id: event.event_id.clone(),
                event_record_sha256: event.immutable_record_sha256.clone(),
                actor_identity_id: actor.identity_id.clone(),
                actor_session_id: actor.session_id.clone(),
                actor_credential_fingerprint_sha256: actor.credential_fingerprint_sha256.clone(),
            }
        })
        .collect::<Vec<_>>();
    let mut document = AppendReceipts {
        schema: APPEND_RECEIPTS_SCHEMA.to_owned(),
        run_id: trial.binding.run_id.clone(),
        window_id: trial.window_id.clone(),
        trial_id: trial.trial_id.clone(),
        ledger_authority_key_id: APPEND_KEY_ID.to_owned(),
        checkpoint: AppendCheckpoint {
            event_count: receipts.len(),
            first_ledger_sequence: receipts.first().expect("receipt").ledger_sequence,
            last_ledger_sequence: receipts.last().expect("receipt").ledger_sequence,
            ledger_root_sha256: append_ledger_root(&receipts).expect("ledger root"),
            previous_checkpoint_sha256: "0".repeat(64),
            signed_at: "2026-08-06T00:59:59Z".to_owned(),
            signature_ed25519: "0".repeat(128),
        },
        receipts,
    };
    document.checkpoint.signature_ed25519 =
        append_checkpoint_signature(&document, APPEND_SEED).expect("append signature");
    let bytes = serde_json::to_vec(&document).expect("receipt bytes");
    trial.append_receipts_sha256 = document_sha256(&bytes);
    bytes
}

pub(crate) fn rehash_trial(trial: &mut TrialRecord) {
    trial.observation.record_sha256 =
        observation_record_sha256(&trial.observation).expect("observation hash");
    let capture = trial
        .events
        .iter_mut()
        .find(|event| event.event_id == trial.observation.captured_event_id)
        .expect("observation capture");
    capture.subject_id = Some(trial.observation.observation_id.clone());
    capture.subject_sha256 = Some(trial.observation.record_sha256.clone());

    trial.terminal.record_sha256 = terminal_record_sha256(&trial.terminal).expect("terminal hash");
    let issued = trial
        .events
        .iter_mut()
        .find(|event| event.event_id == trial.terminal.issued_event_id)
        .expect("terminal event");
    issued.subject_id = Some(trial.terminal.terminal_id.clone());
    issued.subject_sha256 = Some(trial.terminal.record_sha256.clone());

    for event in &mut trial.events {
        event.immutable_record_sha256 = event_record_sha256(event).expect("event hash");
    }
}

pub(crate) fn retarget_run(trial: &mut TrialRecord, run_id: &str, window_id: &str) {
    trial.binding.run_id = run_id.to_owned();
    trial.window_id = window_id.to_owned();
    for event in &mut trial.events {
        event.run_id = run_id.to_owned();
        event.window_id = window_id.to_owned();
    }
    trial.events[0].subject_id = Some(run_id.to_owned());
    for evidence in &mut trial.evidence {
        evidence.run_id = run_id.to_owned();
        evidence.window_id = window_id.to_owned();
    }
}

pub(crate) fn retarget_case(
    trial: &mut TrialRecord,
    case_id: &str,
    trial_id: &str,
    environment: ExecutionEnvironment,
) {
    trial.case_id = case_id.to_owned();
    trial.trial_id = trial_id.to_owned();
    trial.environment = environment;
    for event in &mut trial.events {
        event.trial_id = trial_id.to_owned();
    }
    trial.events[1].subject_id = Some(trial_id.to_owned());
    for evidence in &mut trial.evidence {
        evidence.trial_id = trial_id.to_owned();
    }
}

pub(crate) fn environment(
    profile: EnvironmentProfile,
    id: &str,
    digest_byte: char,
) -> ExecutionEnvironment {
    ExecutionEnvironment {
        profile,
        environment_id: id.to_owned(),
        environment_manifest_sha256: digest_byte.to_string().repeat(64),
        environment_is_production: false,
    }
}

pub(crate) fn bind_plan(trials: &mut [&mut TrialRecord]) -> Vec<u8> {
    let first = trials.first().expect("phase has a planned trial");
    let plan = TrialPlan {
        schema: TRIAL_PLAN_SCHEMA.to_owned(),
        run_id: first.binding.run_id.clone(),
        catalog_sha256: first.binding.catalog_sha256.clone(),
        planned_trials: trials
            .iter()
            .enumerate()
            .map(|(index, trial)| PlannedTrial {
                sequence: index as u64 + 1,
                trial_id: trial.trial_id.clone(),
                case_id: trial.case_id.clone(),
                environment: trial.environment.clone(),
            })
            .collect(),
    };
    let bytes = serde_json::to_vec(&plan).expect("plan bytes");
    let digest = document_sha256(&bytes);
    for trial in trials {
        trial.binding.trial_plan_sha256.clone_from(&digest);
    }
    bytes
}

pub(crate) fn phase_ledger(
    catalog: &Catalog,
    phase: CoveragePhase,
    binding: cats_qualification_protocol::RunBinding,
) -> CoverageLedger {
    let case_phase = match phase {
        CoveragePhase::Functional => cats_qualification_protocol::CasePhase::Functional,
        CoveragePhase::AwsPerformance => cats_qualification_protocol::CasePhase::AwsPerformance,
        CoveragePhase::CostObservation => cats_qualification_protocol::CasePhase::CostObservation,
    };
    let entries = catalog
        .cases
        .iter()
        .filter(|case| case.phase == case_phase)
        .map(|case| CoverageEntry {
            case_id: case.id.clone(),
            outcome: TerminalOutcome::Unobserved,
            trial_id: None,
            trial_record_sha256: None,
            evidence_ids: Vec::new(),
            verifier_identity_id: None,
            blocker: None,
        })
        .collect::<Vec<_>>();
    CoverageLedger {
        schema: COVERAGE_SCHEMA.to_owned(),
        binding,
        phase,
        expected_total: entries.len(),
        entries,
        phase_outcome: PhaseOutcome::Incomplete,
    }
}

pub(crate) fn set_ledger_trial(ledger: &mut CoverageLedger, trial: &TrialRecord, bytes: &[u8]) {
    let entry = ledger
        .entries
        .iter_mut()
        .find(|entry| entry.case_id == trial.case_id)
        .expect("phase entry");
    entry.outcome = trial.terminal.outcome;
    entry.trial_id = Some(trial.trial_id.clone());
    entry.trial_record_sha256 = Some(document_sha256(bytes));
    entry.evidence_ids.clone_from(&trial.terminal.evidence_ids);
    entry.verifier_identity_id = Some(trial.terminal.verifier_identity_id.clone());
    entry.blocker.clone_from(&trial.terminal.blocker);
}

pub(crate) fn trial_document<'a>(trial: &'a [u8], receipts: &'a [u8]) -> TrialDocument<'a> {
    TrialDocument {
        trial_bytes: trial,
        append_receipts_bytes: receipts,
    }
}

pub(crate) fn catalog_digest() -> String {
    catalog_sha256(CATALOG_BYTES)
}

fn actor_public_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| public_key(ACTOR_SEED))
}

fn append_public_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| public_key(APPEND_SEED))
}

fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    let pair = Ed25519KeyPair::from_seed_unchecked(seed).expect("test Ed25519 seed");
    pair.public_key()
        .as_ref()
        .try_into()
        .expect("Ed25519 public key length")
}
