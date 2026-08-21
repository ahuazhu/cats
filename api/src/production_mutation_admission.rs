//! E13 production product-mutation admission authority.
//!
//! This contract intentionally carries no convenient `enabled` boolean.  The
//! one database singleton starts Closed, and Open is meaningful only together
//! with the exact clean-slate reset, release and terminal-proof binding that
//! authorized it.  Emergency close retains that binding so reopening cannot
//! substitute a different proof set.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::runtime_reconciliation::{
    canonical_ed25519_spki_sha256, Base64UrlNoPad, ContractVersion, Epoch, Id, RandomId128,
    Sha256Digest, UnixMillis, WireU64,
};

pub const PRODUCTION_MUTATION_ADMISSION_COMMANDS_PATH: &str =
    "/v1/admin/production/mutation-admission-commands";
pub const PRODUCTION_MUTATION_ADMISSION_COMMAND_RECEIPT_PATH_PREFIX: &str =
    "/v1/admin/production/mutation-admission-commands/";
pub const PRODUCTION_MUTATION_ADMISSION_DISCOVERY_PATH: &str =
    "/v1/admin/production/mutation-admission-command-discoveries";
pub const PRODUCTION_MUTATION_ADMISSION_STATE_PATH: &str =
    "/v1/admin/production/mutation-admission-state-discoveries";
pub const PRODUCTION_QUALIFICATION_PRODUCT_INVENTORY_PATH: &str =
    "/v1/admin/production/qualification-product-inventory-discoveries";
pub const PRODUCTION_MUTATION_ADMISSION_REQUEST_MAX_WIRE_BYTES: usize = 65_536;
pub const PRODUCTION_MUTATION_ADMISSION_RESPONSE_MAX_WIRE_BYTES: usize = 131_072;
pub const PRODUCTION_MUTATION_ADMISSION_SCHEMA_VERSION: u64 = 18;
pub const PRODUCTION_MUTATION_ADMISSION_METHOD: &str = "POST";
pub const PRODUCTION_CUTOVER_CREDENTIAL_ID_HEADER: &str = "cats-production-cutover-credential-id";
pub const PRODUCTION_CUTOVER_SIGNATURE_HEADER: &str = "cats-production-cutover-signature";
pub const PRODUCTION_CUTOVER_COMMAND_MAX_LIFETIME_MS: u64 = 5 * 60 * 1_000;
pub const PRODUCTION_CUTOVER_CLOCK_SKEW_MS: u64 = 30 * 1_000;
pub const PRODUCTION_QUALIFICATION_MAX_LIFETIME_MS: u64 = 24 * 60 * 60 * 1_000;
pub const PRODUCTION_QUALIFICATION_BEGIN_RECEIPT_FILE: &str =
    "production-mutation-qualification-begin.receipt.json";
pub const PRODUCTION_QUALIFICATION_BEGIN_RECEIPT_KIND: &str =
    "cats.production-mutation-qualification-begin-receipt.v1";
pub const PRODUCTION_QUALIFICATION_TERMINAL_RECEIPT_FILE: &str =
    "production-mutation-qualification-terminal.receipt.json";
pub const PRODUCTION_QUALIFICATION_TERMINAL_RECEIPT_KIND: &str =
    "cats.production-mutation-qualification-terminal-receipt.v1";
pub const PRODUCTION_QUALIFICATION_PRODUCT_INVENTORY_RECEIPT_FILE: &str =
    "production-mutation-qualification-product-inventory.receipt.json";
pub const PRODUCTION_QUALIFICATION_PRODUCT_INVENTORY_RECEIPT_KIND: &str =
    "cats.production-mutation-qualification-product-inventory.v1";

pub const PRODUCTION_QUALIFICATION_MUTATION_CLASSES: [ProductionQualificationMutationClass; 5] = [
    ProductionQualificationMutationClass::CatCreate,
    ProductionQualificationMutationClass::DiskCreate,
    ProductionQualificationMutationClass::DiskDelete,
    ProductionQualificationMutationClass::ObjectWriteAmbiguity,
    ProductionQualificationMutationClass::RuntimeMutation,
];

const SIGNATURE_DOMAIN: &[u8] = b"cats.production-mutation-admission.command.v1";
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const ED25519_SPKI_LEN: usize = ED25519_SPKI_PREFIX.len() + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProductionCutoverAwsPartition {
    #[serde(rename = "aws")]
    Aws,
    #[serde(rename = "aws-us-gov")]
    AwsUsGov,
    #[serde(rename = "aws-cn")]
    AwsCn,
}

impl ProductionCutoverAwsPartition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::AwsUsGov => "aws-us-gov",
            Self::AwsCn => "aws-cn",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionCutoverAwsRoleScope {
    pub aws_partition: ProductionCutoverAwsPartition,
    pub account_id: String,
    pub role_arn: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionCutoverStsPrincipal {
    pub aws_partition: ProductionCutoverAwsPartition,
    pub account_id: String,
    pub role_arn: String,
    pub principal_arn: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionCutoverOperatorCredential {
    pub credential_id: Id,
    pub public_key_spki: Base64UrlNoPad,
    pub scope: ProductionCutoverAwsRoleScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionCutoverOperatorTrustBundle {
    pub version: ContractVersion,
    pub deployment_id: Id,
    pub release_id: Id,
    pub source_commit_sha: String,
    /// The first terminal release has one offline key and requires it.  This
    /// explicit field prevents a later multi-key artifact from silently
    /// weakening the verifier; a threshold other than one is rejected until
    /// a multi-signature wire revision is accepted.
    pub signature_threshold: WireU64,
    pub credentials: Vec<ProductionCutoverOperatorCredential>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionCutoverOperatorPrincipal {
    pub credential_id: Id,
    pub public_key_spki_sha256: Sha256Digest,
    pub trust_bundle_sha256: Sha256Digest,
    pub sts: ProductionCutoverStsPrincipal,
}

/// Exact evidence set installed by the first successful Open command.
///
/// Each digest names canonical producer bytes or, for the two qualification
/// fields, the immutable checksum-closed runner bundle.  The E13 verifier
/// validates producer-specific terminal semantics before submitting this
/// binding; the Control transaction makes the resulting identity inseparable
/// from every admitted product write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionMutationOpenBinding {
    pub reset_id: Id,
    pub deployment_id: Id,
    pub release_id: Id,
    pub source_commit_sha: String,
    pub control_schema_version: WireU64,
    pub source_manifest_sha256: Sha256Digest,
    pub source_bundle_sha256: Sha256Digest,
    pub release_manifest_sha256: Sha256Digest,
    pub qualification_manifest_sha256: Sha256Digest,
    pub qualification_catalog_sha256: Sha256Digest,
    pub proof_set_sha256: Sha256Digest,
    pub fresh_targets_sha256: Sha256Digest,
    pub reset_complete_receipt_sha256: Sha256Digest,
    pub fleet_closed_receipt_sha256: Sha256Digest,
    pub route_v2_rotation_qualification_receipt_sha256: Sha256Digest,
    pub route_v2_rotation_qualification_node_ack_sets_sha256: Sha256Digest,
    pub route_v2_rotation_qualification_transcript_sha256: Sha256Digest,
    pub usage_terminal_receipt_sha256: Sha256Digest,
    pub old_host_coverage_sha256: Sha256Digest,
    pub kernel_nbd_qualification_bundle_sha256: Sha256Digest,
    pub vhost_user_qualification_bundle_sha256: Sha256Digest,
}

/// Exact ADR-0038 cell scope admitted only long enough to produce release
/// qualification evidence.  It intentionally cannot carry any final-reset
/// proof: a qualification cell must be able to qualify the same default-
/// Closed build whose terminal receipts are later consumed by `Open`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionQualificationAdmissionBinding {
    pub qualification_id: Id,
    pub deployment_id: Id,
    pub release_id: Id,
    pub source_commit_sha: String,
    pub control_schema_version: WireU64,
    pub source_manifest_sha256: Sha256Digest,
    pub source_bundle_sha256: Sha256Digest,
    pub build_receipt_sha256: Sha256Digest,
    pub release_manifest_sha256: Sha256Digest,
    pub worker_bundle_sha256: Sha256Digest,
    pub qualification_catalog_sha256: Sha256Digest,
    pub qualification_cell_manifest_sha256: Sha256Digest,
    pub aws_partition: ProductionCutoverAwsPartition,
    pub aws_account_id: String,
    pub aws_region: String,
    pub cell_id: Id,
    pub cell_namespace: String,
    pub cats_account_id: Id,
    pub workspace_id: Id,
    pub allowed_mutation_classes: Vec<ProductionQualificationMutationClass>,
    pub qualification_expires_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionQualificationMutationClass {
    CatCreate,
    DiskCreate,
    DiskDelete,
    ObjectWriteAmbiguity,
    RuntimeMutation,
}

// Cold-path operator admission receipt. Its size is dominated by the fixed
// digest set each binding must carry verbatim; it is constructed a handful of
// times per cutover window, so indirection would only churn authority code.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "binding",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ProductionMutationAdmissionBinding {
    Qualification(ProductionQualificationAdmissionBinding),
    Open(ProductionMutationOpenBinding),
}

impl ProductionMutationAdmissionBinding {
    pub fn deployment_id(&self) -> &Id {
        match self {
            Self::Qualification(binding) => &binding.deployment_id,
            Self::Open(binding) => &binding.deployment_id,
        }
    }

    pub fn release_id(&self) -> &Id {
        match self {
            Self::Qualification(binding) => &binding.release_id,
            Self::Open(binding) => &binding.release_id,
        }
    }

    pub fn source_commit_sha(&self) -> &str {
        match self {
            Self::Qualification(binding) => &binding.source_commit_sha,
            Self::Open(binding) => &binding.source_commit_sha,
        }
    }

    pub fn control_schema_version(&self) -> WireU64 {
        match self {
            Self::Qualification(binding) => binding.control_schema_version,
            Self::Open(binding) => binding.control_schema_version,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProductionMutationAdmissionMutation {
    BeginQualification {
        binding: ProductionQualificationAdmissionBinding,
    },
    EndQualification {
        binding: ProductionQualificationAdmissionBinding,
    },
    Open {
        binding: ProductionMutationOpenBinding,
    },
    EmergencyClose {
        binding: ProductionMutationAdmissionBinding,
    },
}

impl ProductionMutationAdmissionMutation {
    pub fn state_binding(&self) -> ProductionMutationAdmissionBinding {
        match self {
            Self::BeginQualification { binding } | Self::EndQualification { binding } => {
                ProductionMutationAdmissionBinding::Qualification(binding.clone())
            }
            Self::Open { binding } => ProductionMutationAdmissionBinding::Open(binding.clone()),
            Self::EmergencyClose { binding } => binding.clone(),
        }
    }

    pub fn deployment_id(&self) -> &Id {
        match self {
            Self::BeginQualification { binding } | Self::EndQualification { binding } => {
                &binding.deployment_id
            }
            Self::Open { binding } => &binding.deployment_id,
            Self::EmergencyClose { binding } => binding.deployment_id(),
        }
    }

    pub fn release_id(&self) -> &Id {
        match self {
            Self::BeginQualification { binding } | Self::EndQualification { binding } => {
                &binding.release_id
            }
            Self::Open { binding } => &binding.release_id,
            Self::EmergencyClose { binding } => binding.release_id(),
        }
    }

    pub fn source_commit_sha(&self) -> &str {
        match self {
            Self::BeginQualification { binding } | Self::EndQualification { binding } => {
                &binding.source_commit_sha
            }
            Self::Open { binding } => &binding.source_commit_sha,
            Self::EmergencyClose { binding } => binding.source_commit_sha(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionMutationAdmissionCommand {
    pub version: ContractVersion,
    pub command_id: RandomId128,
    pub issued_at_unix_ms: UnixMillis,
    pub expires_at_unix_ms: UnixMillis,
    pub operator: ProductionCutoverStsPrincipal,
    pub expected_revision: Epoch,
    pub mutation: ProductionMutationAdmissionMutation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionMutationAdmissionMode {
    Closed,
    Qualification,
    Open,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionMutationAdmissionState {
    pub version: ContractVersion,
    pub revision: Epoch,
    pub mode: ProductionMutationAdmissionMode,
    pub binding: Option<ProductionMutationAdmissionBinding>,
    pub last_command_id: Option<RandomId128>,
    pub updated_at_unix_ms: UnixMillis,
}

// Cold-path stored outcome mirroring the admission state verbatim; see the
// size note on ProductionMutationAdmissionBinding above.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProductionMutationAdmissionStoredOutcome {
    Applied {
        state: ProductionMutationAdmissionState,
    },
    AuthorityPreconditionFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionMutationAdmissionCommandReceipt {
    pub version: ContractVersion,
    pub command: ProductionMutationAdmissionCommand,
    pub request_sha256: Sha256Digest,
    pub principal: ProductionCutoverOperatorPrincipal,
    pub outcome: ProductionMutationAdmissionStoredOutcome,
    pub committed_at_unix_ms: UnixMillis,
}

/// Framework receipt published only after the official BeginQualification
/// command is durably discoverable.  The receipt does not hash the eventual
/// qualification manifest, which would make the manifest closed set
/// recursive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionQualificationBeginReceipt {
    pub kind: String,
    pub version: ContractVersion,
    /// The exact runner `run_id`; there is no second qualification-run
    /// identity that could be rebound after Begin.
    pub qualification_id: Id,
    pub workspace_id: Id,
    pub release_id: Id,
    pub source_commit_sha: String,
    pub qualification_catalog_sha256: Sha256Digest,
    pub allowed_mutation_classes: Vec<ProductionQualificationMutationClass>,
    pub binding_sha256: Sha256Digest,
    pub begin_command_id: RandomId128,
    pub begin_request_sha256: Sha256Digest,
    pub begin_command_receipt_sha256: Sha256Digest,
    pub resulting_revision: Epoch,
    pub qualification_expires_at_unix_ms: UnixMillis,
}

/// Terminal framework receipt for one successful qualification run.
///
/// EndQualification takes the singleton `FOR UPDATE`, so the final Closed
/// revision is ordered after every admitted cleanup mutation.  The producer
/// must then obtain the two canonical read-only receipts named here.  E9
/// terminalization deliberately follows this boundary and is consumed later
/// by the final Open proof rather than by this receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionQualificationTerminalReceipt {
    pub kind: String,
    pub version: ContractVersion,
    pub qualification_id: Id,
    pub workspace_id: Id,
    pub release_id: Id,
    pub source_commit_sha: String,
    pub qualification_catalog_sha256: Sha256Digest,
    pub allowed_mutation_classes: Vec<ProductionQualificationMutationClass>,
    pub qualification_expires_at_unix_ms: UnixMillis,
    pub binding_sha256: Sha256Digest,
    pub begin_command_id: RandomId128,
    pub begin_request_sha256: Sha256Digest,
    pub begin_command_receipt_sha256: Sha256Digest,
    pub begin_resulting_revision: Epoch,
    pub close_kind: ProductionQualificationCloseKind,
    pub terminal_outcome: ProductionQualificationTerminalOutcome,
    pub close_command_id: RandomId128,
    pub close_request_sha256: Sha256Digest,
    pub close_command_receipt_sha256: Sha256Digest,
    pub final_admission_state_sha256: Sha256Digest,
    pub final_closed_revision: Epoch,
    pub fleet_closed_receipt_sha256: Sha256Digest,
    pub product_inventory_receipt_sha256: Sha256Digest,
    pub cleanup_inventory_receipt_sha256: Sha256Digest,
    pub active_guard_count: WireU64,
    pub product_resource_count: WireU64,
    pub residue_count: WireU64,
    pub completed_at_unix_ms: UnixMillis,
}

/// Complete current-product projection for one qualification Workspace.
///
/// The first seven fields contribute to `product_resource_count`.  Deleted
/// Cat tombstones, terminal Operation rows and exact API idempotency results
/// are retained history and are reported separately rather than becoming a
/// false nonzero product inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionQualificationProductInventoryCounts {
    pub current_cat_count: WireU64,
    pub root_disk_count: WireU64,
    pub persistent_disk_count: WireU64,
    pub disk_snapshot_count: WireU64,
    pub endpoint_count: WireU64,
    pub hostname_endpoint_lookup_count: WireU64,
    pub unresolved_lifecycle_operation_count: WireU64,
    pub deleted_cat_tombstone_count: WireU64,
    pub terminal_lifecycle_operation_history_count: WireU64,
    pub api_idempotency_receipt_count: WireU64,
}

/// Canonical read-only evidence obtained after the exact qualification close.
/// The close command and its immutable Store receipt are carried by digest so
/// this cannot be rebound to a different Closed revision or operator action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionQualificationProductInventoryReceipt {
    pub kind: String,
    pub version: ContractVersion,
    pub qualification_id: Id,
    pub workspace_id: Id,
    pub release_id: Id,
    pub source_commit_sha: String,
    pub qualification_catalog_sha256: Sha256Digest,
    pub binding_sha256: Sha256Digest,
    pub close_kind: ProductionQualificationCloseKind,
    pub close_command_id: RandomId128,
    pub close_request_sha256: Sha256Digest,
    pub close_command_receipt_sha256: Sha256Digest,
    pub closed_revision: Epoch,
    pub evaluated_at_unix_ms: UnixMillis,
    pub complete: bool,
    pub counts: ProductionQualificationProductInventoryCounts,
    pub product_resource_count: WireU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionQualificationCloseKind {
    EndQualification,
    EmergencyClose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionQualificationTerminalOutcome {
    QualifiedClosed,
    EmergencyClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProductionMutationAdmissionContractError {
    #[error("production mutation admission wire body is too large")]
    WireTooLarge,
    #[error("production mutation admission wire body is malformed")]
    Malformed,
    #[error("production mutation admission wire body is not canonical")]
    NonCanonical,
    #[error("production mutation admission value violates the closed contract")]
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionCutoverSignatureProof {
    pub credential_id: String,
    pub signature: String,
}

pub fn decode_production_cutover_operator_trust_bundle(
    body: &[u8],
) -> Result<ProductionCutoverOperatorTrustBundle, ProductionMutationAdmissionContractError> {
    decode_canonical(body, validate_trust_bundle)
}

pub fn encode_production_cutover_operator_trust_bundle(
    trust: &ProductionCutoverOperatorTrustBundle,
) -> Result<Vec<u8>, ProductionMutationAdmissionContractError> {
    validate_trust_bundle(trust)?;
    encode_canonical(trust, PRODUCTION_MUTATION_ADMISSION_REQUEST_MAX_WIRE_BYTES)
}

pub fn sign_production_mutation_admission_command(
    trust: &ProductionCutoverOperatorTrustBundle,
    signer: &crate::agent_registration::Ed25519RequestSigner,
    exact_body: &[u8],
) -> Result<ProductionCutoverSignatureProof, ProductionMutationAdmissionContractError> {
    validate_trust_bundle(trust)?;
    let credential = trust
        .credentials
        .iter()
        .find(|credential| credential.credential_id == *signer.credential_id())
        .ok_or(ProductionMutationAdmissionContractError::Invalid)?;
    let command = decode_production_mutation_admission_command(exact_body)?;
    if !sts_matches_scope(&command.operator, &credential.scope)
        || command.mutation.deployment_id() != &trust.deployment_id
        || command.mutation.release_id() != &trust.release_id
        || command.mutation.source_commit_sha() != trust.source_commit_sha
    {
        return Err(ProductionMutationAdmissionContractError::Invalid);
    }
    let framed = production_mutation_admission_signed_request(
        trust,
        credential.credential_id.as_str(),
        exact_body,
    );
    Ok(ProductionCutoverSignatureProof {
        credential_id: credential.credential_id.to_string(),
        signature: URL_SAFE_NO_PAD.encode(signer.sign_framed(&framed)),
    })
}

pub fn verify_production_mutation_admission_command(
    trust: &ProductionCutoverOperatorTrustBundle,
    credential_id: &str,
    signature: &str,
    exact_body: &[u8],
    now_unix_ms: u64,
) -> Result<ProductionCutoverOperatorPrincipal, ProductionMutationAdmissionContractError> {
    verify_production_mutation_admission_command_inner(
        trust,
        credential_id,
        signature,
        exact_body,
        Some(now_unix_ms),
    )
}

/// Authenticate typed discovery of an exact already-submitted command.  The
/// command expiry is deliberately not re-applied: expiry bounds creation of a
/// new authority result, while an operator must be able to resolve an
/// ambiguous COMMIT indefinitely using the original exact signed bytes.
pub fn verify_production_mutation_admission_command_discovery(
    trust: &ProductionCutoverOperatorTrustBundle,
    credential_id: &str,
    signature: &str,
    exact_body: &[u8],
) -> Result<ProductionCutoverOperatorPrincipal, ProductionMutationAdmissionContractError> {
    verify_production_mutation_admission_command_inner(
        trust,
        credential_id,
        signature,
        exact_body,
        None,
    )
}

fn verify_production_mutation_admission_command_inner(
    trust: &ProductionCutoverOperatorTrustBundle,
    credential_id: &str,
    signature: &str,
    exact_body: &[u8],
    now_unix_ms: Option<u64>,
) -> Result<ProductionCutoverOperatorPrincipal, ProductionMutationAdmissionContractError> {
    validate_trust_bundle(trust)?;
    let command = decode_production_mutation_admission_command(exact_body)?;
    if let Some(now_unix_ms) = now_unix_ms {
        if command.issued_at_unix_ms.get()
            > now_unix_ms.saturating_add(PRODUCTION_CUTOVER_CLOCK_SKEW_MS)
            || command.expires_at_unix_ms.get() <= now_unix_ms
        {
            return Err(ProductionMutationAdmissionContractError::Invalid);
        }
    }
    let credential = trust
        .credentials
        .iter()
        .find(|credential| credential.credential_id.as_str() == credential_id)
        .ok_or(ProductionMutationAdmissionContractError::Invalid)?;
    if !sts_matches_scope(&command.operator, &credential.scope)
        || command.mutation.deployment_id() != &trust.deployment_id
        || command.mutation.release_id() != &trust.release_id
        || command.mutation.source_commit_sha() != trust.source_commit_sha
    {
        return Err(ProductionMutationAdmissionContractError::Invalid);
    }
    let spki = decode_base64url_exact::<ED25519_SPKI_LEN>(credential.public_key_spki.as_str())?;
    if spki[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX {
        return Err(ProductionMutationAdmissionContractError::Invalid);
    }
    let signature = decode_base64url_exact::<64>(signature)?;
    let framed = production_mutation_admission_signed_request(trust, credential_id, exact_body);
    UnparsedPublicKey::new(&ED25519, &spki[ED25519_SPKI_PREFIX.len()..])
        .verify(&framed, &signature)
        .map_err(|_| ProductionMutationAdmissionContractError::Invalid)?;
    let public_key_spki_sha256 = canonical_ed25519_spki_sha256(&credential.public_key_spki)
        .ok_or(ProductionMutationAdmissionContractError::Invalid)?;
    let trust_bundle_sha256 = Sha256Digest::from_bytes(
        sha2::Sha256::digest(encode_production_cutover_operator_trust_bundle(trust)?).into(),
    );
    Ok(ProductionCutoverOperatorPrincipal {
        credential_id: credential.credential_id.clone(),
        public_key_spki_sha256,
        trust_bundle_sha256,
        sts: command.operator,
    })
}

pub fn production_mutation_admission_signed_request(
    trust: &ProductionCutoverOperatorTrustBundle,
    credential_id: &str,
    exact_body: &[u8],
) -> Vec<u8> {
    let mut framed = Vec::with_capacity(512);
    framed.extend_from_slice(SIGNATURE_DOMAIN);
    framed.push(0);
    for value in [
        PRODUCTION_MUTATION_ADMISSION_METHOD.as_bytes(),
        PRODUCTION_MUTATION_ADMISSION_COMMANDS_PATH.as_bytes(),
        crate::agent_registration::JSON_CONTENT_TYPE.as_bytes(),
        trust.deployment_id.as_str().as_bytes(),
        trust.release_id.as_str().as_bytes(),
        trust.source_commit_sha.as_bytes(),
        credential_id.as_bytes(),
    ] {
        framed.extend_from_slice(&(value.len() as u64).to_be_bytes());
        framed.extend_from_slice(value);
    }
    framed.extend_from_slice(&(exact_body.len() as u64).to_be_bytes());
    framed.extend_from_slice(&sha2::Sha256::digest(exact_body));
    framed
}

pub fn decode_production_mutation_admission_command(
    body: &[u8],
) -> Result<ProductionMutationAdmissionCommand, ProductionMutationAdmissionContractError> {
    decode_canonical(body, validate_command)
}

pub fn encode_production_mutation_admission_command(
    command: &ProductionMutationAdmissionCommand,
) -> Result<Vec<u8>, ProductionMutationAdmissionContractError> {
    validate_command(command)?;
    encode_canonical(
        command,
        PRODUCTION_MUTATION_ADMISSION_REQUEST_MAX_WIRE_BYTES,
    )
}

pub fn encode_production_mutation_admission_state(
    state: &ProductionMutationAdmissionState,
) -> Result<Vec<u8>, ProductionMutationAdmissionContractError> {
    validate_state(state)?;
    encode_canonical(state, PRODUCTION_MUTATION_ADMISSION_RESPONSE_MAX_WIRE_BYTES)
}

pub fn encode_production_mutation_admission_command_receipt(
    receipt: &ProductionMutationAdmissionCommandReceipt,
) -> Result<Vec<u8>, ProductionMutationAdmissionContractError> {
    validate_receipt(receipt)?;
    encode_canonical(
        receipt,
        PRODUCTION_MUTATION_ADMISSION_RESPONSE_MAX_WIRE_BYTES,
    )
}

pub fn decode_production_qualification_begin_receipt(
    body: &[u8],
) -> Result<ProductionQualificationBeginReceipt, ProductionMutationAdmissionContractError> {
    decode_canonical(body, validate_qualification_begin_receipt)
}

pub fn encode_production_qualification_begin_receipt(
    receipt: &ProductionQualificationBeginReceipt,
) -> Result<Vec<u8>, ProductionMutationAdmissionContractError> {
    validate_qualification_begin_receipt(receipt)?;
    encode_canonical(
        receipt,
        PRODUCTION_MUTATION_ADMISSION_RESPONSE_MAX_WIRE_BYTES,
    )
}

pub fn decode_production_qualification_terminal_receipt(
    body: &[u8],
) -> Result<ProductionQualificationTerminalReceipt, ProductionMutationAdmissionContractError> {
    decode_canonical(body, validate_qualification_terminal_receipt)
}

pub fn encode_production_qualification_terminal_receipt(
    receipt: &ProductionQualificationTerminalReceipt,
) -> Result<Vec<u8>, ProductionMutationAdmissionContractError> {
    validate_qualification_terminal_receipt(receipt)?;
    encode_canonical(
        receipt,
        PRODUCTION_MUTATION_ADMISSION_RESPONSE_MAX_WIRE_BYTES,
    )
}

pub fn decode_production_qualification_product_inventory_receipt(
    body: &[u8],
) -> Result<ProductionQualificationProductInventoryReceipt, ProductionMutationAdmissionContractError>
{
    decode_canonical(body, validate_qualification_product_inventory_receipt)
}

pub fn encode_production_qualification_product_inventory_receipt(
    receipt: &ProductionQualificationProductInventoryReceipt,
) -> Result<Vec<u8>, ProductionMutationAdmissionContractError> {
    validate_qualification_product_inventory_receipt(receipt)?;
    encode_canonical(
        receipt,
        PRODUCTION_MUTATION_ADMISSION_RESPONSE_MAX_WIRE_BYTES,
    )
}

pub fn production_mutation_admission_command_sha256(
    command: &ProductionMutationAdmissionCommand,
) -> Result<Sha256Digest, ProductionMutationAdmissionContractError> {
    Ok(Sha256Digest::from_bytes(
        sha2::Sha256::digest(encode_production_mutation_admission_command(command)?).into(),
    ))
}

pub fn production_mutation_admission_command_receipt_sha256(
    receipt: &ProductionMutationAdmissionCommandReceipt,
) -> Result<Sha256Digest, ProductionMutationAdmissionContractError> {
    Ok(Sha256Digest::from_bytes(
        sha2::Sha256::digest(encode_production_mutation_admission_command_receipt(
            receipt,
        )?)
        .into(),
    ))
}

pub fn production_mutation_admission_binding_sha256(
    binding: &ProductionMutationAdmissionBinding,
) -> Result<Sha256Digest, ProductionMutationAdmissionContractError> {
    validate_state_binding(binding)?;
    Ok(Sha256Digest::from_bytes(
        sha2::Sha256::digest(encode_canonical(
            binding,
            PRODUCTION_MUTATION_ADMISSION_REQUEST_MAX_WIRE_BYTES,
        )?)
        .into(),
    ))
}

fn decode_canonical<T>(
    body: &[u8],
    validate: fn(&T) -> Result<(), ProductionMutationAdmissionContractError>,
) -> Result<T, ProductionMutationAdmissionContractError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if body.len() > PRODUCTION_MUTATION_ADMISSION_REQUEST_MAX_WIRE_BYTES {
        return Err(ProductionMutationAdmissionContractError::WireTooLarge);
    }
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let value = T::deserialize(&mut decoder)
        .map_err(|_| ProductionMutationAdmissionContractError::Malformed)?;
    decoder
        .end()
        .map_err(|_| ProductionMutationAdmissionContractError::Malformed)?;
    validate(&value)?;
    if encode_canonical(&value, PRODUCTION_MUTATION_ADMISSION_REQUEST_MAX_WIRE_BYTES)?.as_slice()
        != body
    {
        return Err(ProductionMutationAdmissionContractError::NonCanonical);
    }
    Ok(value)
}

fn encode_canonical<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, ProductionMutationAdmissionContractError> {
    let value = serde_json::to_value(value)
        .map_err(|_| ProductionMutationAdmissionContractError::Invalid)?;
    let bytes = crate::runtime_reconciliation::canonical_json_value_bytes(&value);
    if bytes.len() > maximum {
        return Err(ProductionMutationAdmissionContractError::WireTooLarge);
    }
    Ok(bytes)
}

fn validate_command(
    command: &ProductionMutationAdmissionCommand,
) -> Result<(), ProductionMutationAdmissionContractError> {
    if command.version != ContractVersion::V1
        || command.expires_at_unix_ms <= command.issued_at_unix_ms
        || command
            .expires_at_unix_ms
            .get()
            .saturating_sub(command.issued_at_unix_ms.get())
            > PRODUCTION_CUTOVER_COMMAND_MAX_LIFETIME_MS
        || !valid_sts_principal(&command.operator)
    {
        return Err(ProductionMutationAdmissionContractError::Invalid);
    }
    match &command.mutation {
        ProductionMutationAdmissionMutation::BeginQualification { binding } => {
            validate_qualification_binding(binding)?;
            if binding.qualification_expires_at_unix_ms <= command.expires_at_unix_ms
                || binding
                    .qualification_expires_at_unix_ms
                    .get()
                    .saturating_sub(command.issued_at_unix_ms.get())
                    > PRODUCTION_QUALIFICATION_MAX_LIFETIME_MS
            {
                return Err(ProductionMutationAdmissionContractError::Invalid);
            }
            Ok(())
        }
        ProductionMutationAdmissionMutation::EndQualification { binding } => {
            validate_qualification_binding(binding)
        }
        ProductionMutationAdmissionMutation::Open { binding } => validate_open_binding(binding),
        ProductionMutationAdmissionMutation::EmergencyClose { binding } => {
            validate_state_binding(binding)
        }
    }
}

fn validate_trust_bundle(
    trust: &ProductionCutoverOperatorTrustBundle,
) -> Result<(), ProductionMutationAdmissionContractError> {
    if trust.version != ContractVersion::V1
        || trust.signature_threshold.get() != 1
        || trust.credentials.len() != 1
        || trust.source_commit_sha.len() != 40
        || !trust
            .source_commit_sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProductionMutationAdmissionContractError::Invalid);
    }
    let credential = &trust.credentials[0];
    if !valid_role_scope(&credential.scope)
        || canonical_ed25519_spki_sha256(&credential.public_key_spki).is_none()
    {
        return Err(ProductionMutationAdmissionContractError::Invalid);
    }
    Ok(())
}

fn valid_role_scope(scope: &ProductionCutoverAwsRoleScope) -> bool {
    valid_account_id(&scope.account_id)
        && valid_arn(&scope.role_arn)
        && scope.role_arn.starts_with(&format!(
            "arn:{}:iam::{}:role/",
            scope.aws_partition.as_str(),
            scope.account_id
        ))
        && scope
            .role_arn
            .rsplit_once('/')
            .is_some_and(|(_, role_name)| !role_name.is_empty())
}

fn valid_sts_principal(principal: &ProductionCutoverStsPrincipal) -> bool {
    let scope = ProductionCutoverAwsRoleScope {
        aws_partition: principal.aws_partition,
        account_id: principal.account_id.clone(),
        role_arn: principal.role_arn.clone(),
    };
    if !valid_role_scope(&scope) || !valid_arn(&principal.principal_arn) {
        return false;
    }
    let Some((_, role_name)) = principal.role_arn.rsplit_once('/') else {
        return false;
    };
    let expected = format!(
        "arn:{}:sts::{}:assumed-role/{role_name}/",
        principal.aws_partition.as_str(),
        principal.account_id
    );
    principal.principal_arn.starts_with(&expected) && principal.principal_arn.len() > expected.len()
}

fn sts_matches_scope(
    principal: &ProductionCutoverStsPrincipal,
    scope: &ProductionCutoverAwsRoleScope,
) -> bool {
    valid_sts_principal(principal)
        && principal.aws_partition == scope.aws_partition
        && principal.account_id == scope.account_id
        && principal.role_arn == scope.role_arn
}

fn valid_account_id(value: &str) -> bool {
    value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_arn(value: &str) -> bool {
    (1..=2_048).contains(&value.len()) && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn decode_base64url_exact<const N: usize>(
    value: &str,
) -> Result<[u8; N], ProductionMutationAdmissionContractError> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'))
    {
        return Err(ProductionMutationAdmissionContractError::Invalid);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ProductionMutationAdmissionContractError::Invalid)?;
    if decoded.len() != N || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(ProductionMutationAdmissionContractError::Invalid);
    }
    decoded
        .try_into()
        .map_err(|_| ProductionMutationAdmissionContractError::Invalid)
}

fn validate_open_binding(
    binding: &ProductionMutationOpenBinding,
) -> Result<(), ProductionMutationAdmissionContractError> {
    if binding.control_schema_version.get() != PRODUCTION_MUTATION_ADMISSION_SCHEMA_VERSION
        || binding.source_commit_sha.len() != 40
        || !binding
            .source_commit_sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProductionMutationAdmissionContractError::Invalid);
    }
    Ok(())
}

fn validate_qualification_binding(
    binding: &ProductionQualificationAdmissionBinding,
) -> Result<(), ProductionMutationAdmissionContractError> {
    if binding.control_schema_version.get() != PRODUCTION_MUTATION_ADMISSION_SCHEMA_VERSION
        || !valid_source_commit(&binding.source_commit_sha)
        || !valid_account_id(&binding.aws_account_id)
        || !valid_aws_region(&binding.aws_region)
        || !valid_dns_label(&binding.cell_namespace)
        || binding.allowed_mutation_classes.as_slice()
            != PRODUCTION_QUALIFICATION_MUTATION_CLASSES.as_slice()
    {
        return Err(ProductionMutationAdmissionContractError::Invalid);
    }
    Ok(())
}

fn validate_qualification_begin_receipt(
    receipt: &ProductionQualificationBeginReceipt,
) -> Result<(), ProductionMutationAdmissionContractError> {
    if receipt.kind != PRODUCTION_QUALIFICATION_BEGIN_RECEIPT_KIND
        || receipt.version != ContractVersion::V1
        || !valid_source_commit(&receipt.source_commit_sha)
        || receipt.allowed_mutation_classes.as_slice()
            != PRODUCTION_QUALIFICATION_MUTATION_CLASSES.as_slice()
    {
        return Err(ProductionMutationAdmissionContractError::Invalid);
    }
    Ok(())
}

fn validate_qualification_terminal_receipt(
    receipt: &ProductionQualificationTerminalReceipt,
) -> Result<(), ProductionMutationAdmissionContractError> {
    if receipt.kind != PRODUCTION_QUALIFICATION_TERMINAL_RECEIPT_KIND
        || receipt.version != ContractVersion::V1
        || !valid_source_commit(&receipt.source_commit_sha)
        || receipt.allowed_mutation_classes.as_slice()
            != PRODUCTION_QUALIFICATION_MUTATION_CLASSES.as_slice()
        || receipt.begin_command_id == receipt.close_command_id
        || receipt.begin_resulting_revision.get().checked_add(1)
            != Some(receipt.final_closed_revision.get())
        || !matches!(
            (receipt.close_kind, receipt.terminal_outcome),
            (
                ProductionQualificationCloseKind::EndQualification,
                ProductionQualificationTerminalOutcome::QualifiedClosed
            ) | (
                ProductionQualificationCloseKind::EmergencyClose,
                ProductionQualificationTerminalOutcome::EmergencyClosed
            )
        )
        || receipt.active_guard_count.get() != 0
        || receipt.product_resource_count.get() != 0
        || receipt.residue_count.get() != 0
        || receipt.completed_at_unix_ms.get() == 0
    {
        return Err(ProductionMutationAdmissionContractError::Invalid);
    }
    Ok(())
}

fn validate_qualification_product_inventory_receipt(
    receipt: &ProductionQualificationProductInventoryReceipt,
) -> Result<(), ProductionMutationAdmissionContractError> {
    let current_counts = [
        receipt.counts.current_cat_count,
        receipt.counts.root_disk_count,
        receipt.counts.persistent_disk_count,
        receipt.counts.disk_snapshot_count,
        receipt.counts.endpoint_count,
        receipt.counts.hostname_endpoint_lookup_count,
        receipt.counts.unresolved_lifecycle_operation_count,
    ];
    let expected_total = current_counts
        .into_iter()
        .try_fold(0_u64, |total, count| total.checked_add(count.get()));
    if receipt.kind != PRODUCTION_QUALIFICATION_PRODUCT_INVENTORY_RECEIPT_KIND
        || receipt.version != ContractVersion::V1
        || !valid_source_commit(&receipt.source_commit_sha)
        || !receipt.complete
        || receipt.evaluated_at_unix_ms.get() == 0
        || expected_total != Some(receipt.product_resource_count.get())
    {
        return Err(ProductionMutationAdmissionContractError::Invalid);
    }
    Ok(())
}

fn validate_state_binding(
    binding: &ProductionMutationAdmissionBinding,
) -> Result<(), ProductionMutationAdmissionContractError> {
    match binding {
        ProductionMutationAdmissionBinding::Qualification(binding) => {
            validate_qualification_binding(binding)
        }
        ProductionMutationAdmissionBinding::Open(binding) => validate_open_binding(binding),
    }
}

fn valid_source_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_aws_region(value: &str) -> bool {
    (3..=32).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value.contains('-')
}

fn valid_dns_label(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn validate_state(
    state: &ProductionMutationAdmissionState,
) -> Result<(), ProductionMutationAdmissionContractError> {
    if state.version != ContractVersion::V1
        || state
            .binding
            .as_ref()
            .is_some_and(|binding| validate_state_binding(binding).is_err())
        || matches!(state.mode, ProductionMutationAdmissionMode::Qualification)
            && !matches!(
                state.binding.as_ref(),
                Some(ProductionMutationAdmissionBinding::Qualification(_))
            )
        || matches!(state.mode, ProductionMutationAdmissionMode::Open)
            && !matches!(
                state.binding.as_ref(),
                Some(ProductionMutationAdmissionBinding::Open(_))
            )
        || state.binding.is_none() != state.last_command_id.is_none()
        || state.binding.is_none() && state.revision.get() != 1
    {
        return Err(ProductionMutationAdmissionContractError::Invalid);
    }
    Ok(())
}

fn validate_receipt(
    receipt: &ProductionMutationAdmissionCommandReceipt,
) -> Result<(), ProductionMutationAdmissionContractError> {
    validate_command(&receipt.command)?;
    if receipt.version != ContractVersion::V1
        || receipt.principal.sts != receipt.command.operator
        || production_mutation_admission_command_sha256(&receipt.command)? != receipt.request_sha256
    {
        return Err(ProductionMutationAdmissionContractError::Invalid);
    }
    if let ProductionMutationAdmissionStoredOutcome::Applied { state } = &receipt.outcome {
        validate_state(state)?;
        if state.last_command_id.as_ref() != Some(&receipt.command.command_id)
            || state.updated_at_unix_ms != receipt.committed_at_unix_ms
            || state.binding.as_ref() != Some(&receipt.command.mutation.state_binding())
            || match &receipt.command.mutation {
                ProductionMutationAdmissionMutation::BeginQualification { .. } => {
                    state.mode != ProductionMutationAdmissionMode::Qualification
                }
                ProductionMutationAdmissionMutation::EndQualification { .. }
                | ProductionMutationAdmissionMutation::EmergencyClose { .. } => {
                    state.mode != ProductionMutationAdmissionMode::Closed
                }
                ProductionMutationAdmissionMutation::Open { .. } => {
                    state.mode != ProductionMutationAdmissionMode::Open
                }
            }
        {
            return Err(ProductionMutationAdmissionContractError::Invalid);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> Sha256Digest {
        Sha256Digest::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn binding() -> ProductionMutationOpenBinding {
        ProductionMutationOpenBinding {
            reset_id: Id::new("reset_a").unwrap(),
            deployment_id: Id::new("deployment_a").unwrap(),
            release_id: Id::new("release_a").unwrap(),
            source_commit_sha: "a".repeat(40),
            control_schema_version: WireU64::new(PRODUCTION_MUTATION_ADMISSION_SCHEMA_VERSION)
                .unwrap(),
            source_manifest_sha256: digest('0'),
            source_bundle_sha256: digest('1'),
            release_manifest_sha256: digest('2'),
            qualification_manifest_sha256: digest('3'),
            qualification_catalog_sha256: digest('4'),
            proof_set_sha256: digest('5'),
            fresh_targets_sha256: digest('6'),
            reset_complete_receipt_sha256: digest('7'),
            fleet_closed_receipt_sha256: digest('8'),
            route_v2_rotation_qualification_receipt_sha256: digest('9'),
            route_v2_rotation_qualification_node_ack_sets_sha256: digest('a'),
            route_v2_rotation_qualification_transcript_sha256: digest('b'),
            usage_terminal_receipt_sha256: digest('c'),
            old_host_coverage_sha256: digest('d'),
            kernel_nbd_qualification_bundle_sha256: digest('e'),
            vhost_user_qualification_bundle_sha256: digest('f'),
        }
    }

    fn qualification_binding() -> ProductionQualificationAdmissionBinding {
        ProductionQualificationAdmissionBinding {
            qualification_id: Id::new("qualification_a").unwrap(),
            deployment_id: Id::new("deployment_a").unwrap(),
            release_id: Id::new("release_a").unwrap(),
            source_commit_sha: "a".repeat(40),
            control_schema_version: WireU64::new(PRODUCTION_MUTATION_ADMISSION_SCHEMA_VERSION)
                .unwrap(),
            source_manifest_sha256: digest('0'),
            source_bundle_sha256: digest('1'),
            build_receipt_sha256: digest('2'),
            release_manifest_sha256: digest('3'),
            worker_bundle_sha256: digest('4'),
            qualification_catalog_sha256: digest('5'),
            qualification_cell_manifest_sha256: digest('6'),
            aws_partition: ProductionCutoverAwsPartition::Aws,
            aws_account_id: "123456789012".to_owned(),
            aws_region: "us-east-1".to_owned(),
            cell_id: Id::new("qualification-cell-a").unwrap(),
            cell_namespace: "cats-qualification".to_owned(),
            cats_account_id: Id::new("account_a").unwrap(),
            workspace_id: Id::new("workspace_a").unwrap(),
            allowed_mutation_classes: vec![
                ProductionQualificationMutationClass::CatCreate,
                ProductionQualificationMutationClass::DiskCreate,
                ProductionQualificationMutationClass::DiskDelete,
                ProductionQualificationMutationClass::ObjectWriteAmbiguity,
                ProductionQualificationMutationClass::RuntimeMutation,
            ],
            qualification_expires_at_unix_ms: UnixMillis::new(3_600_000).unwrap(),
        }
    }

    fn operator() -> ProductionCutoverStsPrincipal {
        ProductionCutoverStsPrincipal {
            aws_partition: ProductionCutoverAwsPartition::Aws,
            account_id: "123456789012".to_owned(),
            role_arn: "arn:aws:iam::123456789012:role/cats-production-cutover".to_owned(),
            principal_arn:
                "arn:aws:sts::123456789012:assumed-role/cats-production-cutover/session-a"
                    .to_owned(),
        }
    }

    fn trust() -> ProductionCutoverOperatorTrustBundle {
        ProductionCutoverOperatorTrustBundle {
            version: ContractVersion::V1,
            deployment_id: Id::new("deployment_a").unwrap(),
            release_id: Id::new("release_a").unwrap(),
            source_commit_sha: "a".repeat(40),
            signature_threshold: WireU64::new(1).unwrap(),
            credentials: vec![ProductionCutoverOperatorCredential {
                credential_id: Id::new("cutover_a").unwrap(),
                public_key_spki: Base64UrlNoPad::new(
                    "MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
                )
                .unwrap(),
                scope: ProductionCutoverAwsRoleScope {
                    aws_partition: ProductionCutoverAwsPartition::Aws,
                    account_id: "123456789012".to_owned(),
                    role_arn: "arn:aws:iam::123456789012:role/cats-production-cutover".to_owned(),
                },
            }],
        }
    }

    #[test]
    fn command_round_trips_only_as_exact_canonical_bytes() {
        let command = ProductionMutationAdmissionCommand {
            version: ContractVersion::V1,
            command_id: RandomId128::new(format!("{}1", "0".repeat(31))).unwrap(),
            issued_at_unix_ms: UnixMillis::new(1_000).unwrap(),
            expires_at_unix_ms: UnixMillis::new(301_000).unwrap(),
            operator: operator(),
            expected_revision: Epoch::new(1).unwrap(),
            mutation: ProductionMutationAdmissionMutation::Open { binding: binding() },
        };
        let encoded = encode_production_mutation_admission_command(&command).unwrap();
        assert_eq!(
            decode_production_mutation_admission_command(&encoded).unwrap(),
            command
        );
        let mut noncanonical = encoded;
        noncanonical.insert(1, b' ');
        assert_eq!(
            decode_production_mutation_admission_command(&noncanonical),
            Err(ProductionMutationAdmissionContractError::NonCanonical)
        );
    }

    #[test]
    fn qualification_is_a_distinct_bounded_binding_not_a_partial_open() {
        let command = ProductionMutationAdmissionCommand {
            version: ContractVersion::V1,
            command_id: RandomId128::new("2".repeat(32)).unwrap(),
            issued_at_unix_ms: UnixMillis::new(1_000).unwrap(),
            expires_at_unix_ms: UnixMillis::new(61_000).unwrap(),
            operator: operator(),
            expected_revision: Epoch::new(1).unwrap(),
            mutation: ProductionMutationAdmissionMutation::BeginQualification {
                binding: qualification_binding(),
            },
        };
        let encoded = encode_production_mutation_admission_command(&command).unwrap();
        assert_eq!(
            decode_production_mutation_admission_command(&encoded).unwrap(),
            command
        );

        let mut unsorted = qualification_binding();
        unsorted.allowed_mutation_classes.swap(0, 1);
        let invalid = ProductionMutationAdmissionCommand {
            mutation: ProductionMutationAdmissionMutation::BeginQualification { binding: unsorted },
            ..command.clone()
        };
        assert_eq!(
            encode_production_mutation_admission_command(&invalid),
            Err(ProductionMutationAdmissionContractError::Invalid)
        );

        let mut subset = qualification_binding();
        subset.allowed_mutation_classes.pop();
        let invalid = ProductionMutationAdmissionCommand {
            mutation: ProductionMutationAdmissionMutation::BeginQualification { binding: subset },
            ..command
        };
        assert_eq!(
            encode_production_mutation_admission_command(&invalid),
            Err(ProductionMutationAdmissionContractError::Invalid)
        );
    }

    #[test]
    fn qualification_framework_receipts_are_nonrecursive_and_terminal_closed() {
        let begin = ProductionQualificationBeginReceipt {
            kind: PRODUCTION_QUALIFICATION_BEGIN_RECEIPT_KIND.to_owned(),
            version: ContractVersion::V1,
            qualification_id: Id::new("qualification_a").unwrap(),
            workspace_id: Id::new("workspace_a").unwrap(),
            release_id: Id::new("release_a").unwrap(),
            source_commit_sha: "a".repeat(40),
            qualification_catalog_sha256: digest('8'),
            allowed_mutation_classes: PRODUCTION_QUALIFICATION_MUTATION_CLASSES.to_vec(),
            binding_sha256: digest('0'),
            begin_command_id: RandomId128::new("1".repeat(32)).unwrap(),
            begin_request_sha256: digest('1'),
            begin_command_receipt_sha256: digest('2'),
            resulting_revision: Epoch::new(2).unwrap(),
            qualification_expires_at_unix_ms: UnixMillis::new(3_600_000).unwrap(),
        };
        let begin_bytes = encode_production_qualification_begin_receipt(&begin).unwrap();
        assert_eq!(
            decode_production_qualification_begin_receipt(&begin_bytes).unwrap(),
            begin
        );

        let terminal = ProductionQualificationTerminalReceipt {
            kind: PRODUCTION_QUALIFICATION_TERMINAL_RECEIPT_KIND.to_owned(),
            version: ContractVersion::V1,
            qualification_id: begin.qualification_id.clone(),
            workspace_id: begin.workspace_id.clone(),
            release_id: begin.release_id.clone(),
            source_commit_sha: begin.source_commit_sha.clone(),
            qualification_catalog_sha256: begin.qualification_catalog_sha256.clone(),
            allowed_mutation_classes: begin.allowed_mutation_classes.clone(),
            qualification_expires_at_unix_ms: begin.qualification_expires_at_unix_ms,
            binding_sha256: begin.binding_sha256.clone(),
            begin_command_id: begin.begin_command_id.clone(),
            begin_request_sha256: begin.begin_request_sha256.clone(),
            begin_command_receipt_sha256: begin.begin_command_receipt_sha256.clone(),
            begin_resulting_revision: begin.resulting_revision,
            close_kind: ProductionQualificationCloseKind::EndQualification,
            terminal_outcome: ProductionQualificationTerminalOutcome::QualifiedClosed,
            close_command_id: RandomId128::new("2".repeat(32)).unwrap(),
            close_request_sha256: digest('3'),
            close_command_receipt_sha256: digest('4'),
            final_admission_state_sha256: digest('5'),
            final_closed_revision: Epoch::new(3).unwrap(),
            fleet_closed_receipt_sha256: digest('6'),
            product_inventory_receipt_sha256: digest('7'),
            cleanup_inventory_receipt_sha256: digest('8'),
            active_guard_count: WireU64::new(0).unwrap(),
            product_resource_count: WireU64::new(0).unwrap(),
            residue_count: WireU64::new(0).unwrap(),
            completed_at_unix_ms: UnixMillis::new(4_000).unwrap(),
        };
        let terminal_bytes = encode_production_qualification_terminal_receipt(&terminal).unwrap();
        assert_eq!(
            decode_production_qualification_terminal_receipt(&terminal_bytes).unwrap(),
            terminal
        );

        let mut nonzero = terminal;
        nonzero.product_resource_count = WireU64::new(1).unwrap();
        assert_eq!(
            encode_production_qualification_terminal_receipt(&nonzero),
            Err(ProductionMutationAdmissionContractError::Invalid)
        );
    }

    #[test]
    fn qualification_product_inventory_separates_current_rows_from_history() {
        let counts = ProductionQualificationProductInventoryCounts {
            current_cat_count: WireU64::new(1).unwrap(),
            root_disk_count: WireU64::new(1).unwrap(),
            persistent_disk_count: WireU64::new(2).unwrap(),
            disk_snapshot_count: WireU64::new(1).unwrap(),
            endpoint_count: WireU64::new(1).unwrap(),
            hostname_endpoint_lookup_count: WireU64::new(1).unwrap(),
            unresolved_lifecycle_operation_count: WireU64::new(1).unwrap(),
            deleted_cat_tombstone_count: WireU64::new(3).unwrap(),
            terminal_lifecycle_operation_history_count: WireU64::new(4).unwrap(),
            api_idempotency_receipt_count: WireU64::new(5).unwrap(),
        };
        let receipt = ProductionQualificationProductInventoryReceipt {
            kind: PRODUCTION_QUALIFICATION_PRODUCT_INVENTORY_RECEIPT_KIND.to_owned(),
            version: ContractVersion::V1,
            qualification_id: Id::new("qualification_a").unwrap(),
            workspace_id: Id::new("workspace_a").unwrap(),
            release_id: Id::new("release_a").unwrap(),
            source_commit_sha: "a".repeat(40),
            qualification_catalog_sha256: digest('1'),
            binding_sha256: digest('2'),
            close_kind: ProductionQualificationCloseKind::EndQualification,
            close_command_id: RandomId128::new("3".repeat(32)).unwrap(),
            close_request_sha256: digest('3'),
            close_command_receipt_sha256: digest('4'),
            closed_revision: Epoch::new(3).unwrap(),
            evaluated_at_unix_ms: UnixMillis::new(4_000).unwrap(),
            complete: true,
            counts,
            product_resource_count: WireU64::new(8).unwrap(),
        };
        let encoded = encode_production_qualification_product_inventory_receipt(&receipt).unwrap();
        assert_eq!(
            decode_production_qualification_product_inventory_receipt(&encoded).unwrap(),
            receipt
        );

        let mut rebound = receipt;
        rebound.product_resource_count = WireU64::new(20).unwrap();
        assert_eq!(
            encode_production_qualification_product_inventory_receipt(&rebound),
            Err(ProductionMutationAdmissionContractError::Invalid)
        );
    }

    #[test]
    fn dedicated_signature_binds_release_scope_sts_and_exact_command() {
        let command = ProductionMutationAdmissionCommand {
            version: ContractVersion::V1,
            command_id: RandomId128::new("1".repeat(32)).unwrap(),
            issued_at_unix_ms: UnixMillis::new(1_000).unwrap(),
            expires_at_unix_ms: UnixMillis::new(61_000).unwrap(),
            operator: operator(),
            expected_revision: Epoch::new(1).unwrap(),
            mutation: ProductionMutationAdmissionMutation::Open { binding: binding() },
        };
        let body = encode_production_mutation_admission_command(&command).unwrap();
        let mut pkcs8 = hex::decode("302e020100300506032b657004220420").unwrap();
        pkcs8.extend_from_slice(
            &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap(),
        );
        let signer = crate::agent_registration::Ed25519RequestSigner::from_pkcs8_der(
            Id::new("cutover_a").unwrap(),
            &pkcs8,
        )
        .unwrap();
        let proof = sign_production_mutation_admission_command(&trust(), &signer, &body).unwrap();
        let principal = verify_production_mutation_admission_command(
            &trust(),
            &proof.credential_id,
            &proof.signature,
            &body,
            1_001,
        )
        .unwrap();
        assert_eq!(principal.credential_id.as_str(), "cutover_a");
        assert_eq!(principal.sts, operator());

        let mut changed = body;
        *changed.last_mut().unwrap() ^= 1;
        assert!(verify_production_mutation_admission_command_discovery(
            &trust(),
            &proof.credential_id,
            &proof.signature,
            &changed,
        )
        .is_err());
    }
}
