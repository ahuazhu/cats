//! Frozen, non-secret Gateway workload identity authority artifact.
//!
//! The installed artifact is only an installation candidate. PostgreSQL owns
//! the mutable current pointer and exact revision bytes used to authenticate a
//! Gateway request; callers must not treat successful decoding here as current
//! authorization.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::runtime_reconciliation::{
    canonical_ed25519_spki_sha256, Base64UrlNoPad, ContractVersion, Epoch, Id, Sha256Digest,
};

pub const GATEWAY_WORKLOAD_IDENTITY_AUTHORITY_PATH: &str =
    "/etc/cats/route-v2/gateway-workload-authority.v1.json";
pub const GATEWAY_CLIENT_CA_BUNDLE_PATH: &str = "/etc/cats/route-v2/gateway-client-ca-bundle.pem";
pub const CONTROL_MACHINE_SERVER_CERTIFICATE_PATH: &str =
    "/etc/cats/route-v2/control-machine-server-certificate.pem";
pub const CONTROL_MACHINE_SERVER_PRIVATE_KEY_PATH: &str =
    "/etc/cats/route-v2/control-machine-server-private-key.pem";
pub const GATEWAY_WORKLOAD_IDENTITY_AUTHORITY_MAX_WIRE_BYTES: usize = 65_536;
pub const GATEWAY_CLIENT_CA_BUNDLE_MAX_WIRE_BYTES: usize = 65_536;
pub const CONTROL_MACHINE_SERVER_CERTIFICATE_MAX_WIRE_BYTES: usize = 65_536;
pub const CONTROL_MACHINE_SERVER_PRIVATE_KEY_MAX_WIRE_BYTES: usize = 16_384;
pub const MAX_GATEWAY_WORKLOAD_CREDENTIALS: usize = 16;
pub const MAX_GATEWAY_WORKLOAD_SCOPE_WORKSPACES: usize = 256;
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const ED25519_SPKI_LEN: usize = ED25519_SPKI_PREFIX.len() + 32;

/// Extract the exact canonical Ed25519 SubjectPublicKeyInfo from one DER X.509
/// leaf and return its ordinary SHA-256 identity. Certificate naming fields
/// are deliberately ignored; callers must first establish chain/EKU trust.
pub fn canonical_gateway_leaf_spki_sha256(certificate_der: &[u8]) -> Option<Sha256Digest> {
    let certificate = DerTlv::read(certificate_der, 0)?;
    if certificate.tag != 0x30 || certificate.end != certificate_der.len() {
        return None;
    }
    let tbs = DerTlv::read(certificate_der, certificate.value_start)?;
    if tbs.tag != 0x30 {
        return None;
    }
    let mut cursor = tbs.value_start;
    let first = DerTlv::read(certificate_der, cursor)?;
    if first.tag == 0xa0 {
        cursor = first.end;
    }
    for expected_tag in [0x02, 0x30, 0x30, 0x30, 0x30] {
        let field = DerTlv::read(certificate_der, cursor)?;
        if field.tag != expected_tag || field.end > tbs.end {
            return None;
        }
        cursor = field.end;
    }
    let spki = DerTlv::read(certificate_der, cursor)?;
    if spki.tag != 0x30 || spki.end > tbs.end {
        return None;
    }
    let exact_spki = certificate_der.get(spki.start..spki.end)?;
    if exact_spki.len() != ED25519_SPKI_LEN || !exact_spki.starts_with(&ED25519_SPKI_PREFIX) {
        return None;
    }
    Some(Sha256Digest::from_bytes(Sha256::digest(exact_spki).into()))
}

#[derive(Clone, Copy)]
struct DerTlv {
    tag: u8,
    start: usize,
    value_start: usize,
    end: usize,
}

impl DerTlv {
    fn read(input: &[u8], start: usize) -> Option<Self> {
        let tag = *input.get(start)?;
        if tag & 0x1f == 0x1f {
            return None;
        }
        let first_length = *input.get(start.checked_add(1)?)?;
        let (value_start, value_len) = if first_length & 0x80 == 0 {
            (start.checked_add(2)?, usize::from(first_length))
        } else {
            let length_octets = usize::from(first_length & 0x7f);
            if !(1..=std::mem::size_of::<usize>()).contains(&length_octets) {
                return None;
            }
            let length_start = start.checked_add(2)?;
            let length_end = length_start.checked_add(length_octets)?;
            let length_bytes = input.get(length_start..length_end)?;
            if length_bytes.first() == Some(&0) {
                return None;
            }
            let mut value_len = 0_usize;
            for byte in length_bytes {
                value_len = value_len
                    .checked_mul(256)?
                    .checked_add(usize::from(*byte))?;
            }
            if value_len < 128 {
                return None;
            }
            (length_end, value_len)
        };
        let end = value_start.checked_add(value_len)?;
        if end > input.len() {
            return None;
        }
        Some(Self {
            tag,
            start,
            value_start,
            end,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayWorkloadIdentityExpectedPrevious {
    pub policy_revision: Epoch,
    pub policy_sha256: Sha256Digest,
}

/// A credential scope is checked only after the authenticated resolve body has
/// selected a current route and Workspace. TLS authentication alone never
/// turns this value into a Workspace principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GatewayWorkloadCredentialScope {
    Fleet,
    Workspaces { workspace_ids: Vec<Id> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayWorkloadCredentialPolicy {
    pub credential_id: Id,
    pub public_key_spki: Base64UrlNoPad,
    pub scope: GatewayWorkloadCredentialScope,
}

/// Canonical bootstrap/install candidate for one independent Gateway
/// credential lineage. The PostgreSQL revision carrying these exact bytes is
/// the sole runtime-current authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayWorkloadIdentityAuthority {
    pub version: ContractVersion,
    pub authority_id: Id,
    pub fleet_id: Id,
    pub policy_revision: Epoch,
    pub expected_previous: Option<GatewayWorkloadIdentityExpectedPrevious>,
    pub credentials: Vec<GatewayWorkloadCredentialPolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GatewayWorkloadIdentityError {
    #[error("Gateway workload identity artifact exceeds its wire-byte limit")]
    WireTooLarge,
    #[error("Gateway workload identity artifact is malformed")]
    Malformed,
    #[error("Gateway workload identity artifact is not the canonical encoding")]
    NonCanonical,
    #[error("Gateway workload identity artifact version or previous pointer is invalid")]
    InvalidLineage,
    #[error("Gateway workload identity artifact exceeds its credential bound")]
    TooManyCredentials,
    #[error("Gateway workload credentials are not strictly ordered")]
    InvalidCredentialOrder,
    #[error("Gateway workload credential public key is not canonical Ed25519 SPKI")]
    InvalidPublicKey,
    #[error("Gateway workload credential reuses a public key")]
    DuplicatePublicKey,
    #[error("Gateway workload Workspace scope is empty, oversized, or not strictly ordered")]
    InvalidWorkspaceScope,
}

impl GatewayWorkloadIdentityAuthority {
    pub fn validate(&self) -> Result<(), GatewayWorkloadIdentityError> {
        if self.version != ContractVersion::V1 || !previous_policy_is_adjacent(self) {
            return Err(GatewayWorkloadIdentityError::InvalidLineage);
        }
        if self.credentials.len() > MAX_GATEWAY_WORKLOAD_CREDENTIALS {
            return Err(GatewayWorkloadIdentityError::TooManyCredentials);
        }

        let mut previous_credential_id: Option<&Id> = None;
        let mut public_key_digests = Vec::with_capacity(self.credentials.len());
        for credential in &self.credentials {
            if previous_credential_id.is_some_and(|previous| previous >= &credential.credential_id)
            {
                return Err(GatewayWorkloadIdentityError::InvalidCredentialOrder);
            }
            let public_key_digest = canonical_ed25519_spki_sha256(&credential.public_key_spki)
                .ok_or(GatewayWorkloadIdentityError::InvalidPublicKey)?;
            if public_key_digests.contains(&public_key_digest) {
                return Err(GatewayWorkloadIdentityError::DuplicatePublicKey);
            }
            validate_scope(&credential.scope)?;
            public_key_digests.push(public_key_digest);
            previous_credential_id = Some(&credential.credential_id);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Sha256Digest, GatewayWorkloadIdentityError> {
        let bytes = encode_gateway_workload_identity_authority(self)?;
        Ok(Sha256Digest::from_bytes(Sha256::digest(bytes).into()))
    }

    pub fn credential_by_spki_sha256(
        &self,
        public_key_spki_sha256: &Sha256Digest,
    ) -> Option<&GatewayWorkloadCredentialPolicy> {
        self.credentials.iter().find(|credential| {
            canonical_ed25519_spki_sha256(&credential.public_key_spki).as_ref()
                == Some(public_key_spki_sha256)
        })
    }
}

impl GatewayWorkloadCredentialScope {
    pub fn authorizes_workspace(&self, workspace_id: &Id) -> bool {
        match self {
            Self::Fleet => true,
            Self::Workspaces { workspace_ids } => {
                !workspace_ids.is_empty()
                    && workspace_ids.len() <= MAX_GATEWAY_WORKLOAD_SCOPE_WORKSPACES
                    && !workspace_ids.windows(2).any(|pair| pair[0] >= pair[1])
                    && workspace_ids
                        .binary_search_by(|candidate| candidate.cmp(workspace_id))
                        .is_ok()
            }
        }
    }
}

fn previous_policy_is_adjacent(authority: &GatewayWorkloadIdentityAuthority) -> bool {
    match (
        authority.policy_revision.get(),
        &authority.expected_previous,
    ) {
        (1, None) => true,
        (1, Some(_)) | (_, None) => false,
        (revision, Some(previous)) => previous
            .policy_revision
            .get()
            .checked_add(1)
            .is_some_and(|next| next == revision),
    }
}

fn validate_scope(
    scope: &GatewayWorkloadCredentialScope,
) -> Result<(), GatewayWorkloadIdentityError> {
    let GatewayWorkloadCredentialScope::Workspaces { workspace_ids } = scope else {
        return Ok(());
    };
    if workspace_ids.is_empty() || workspace_ids.len() > MAX_GATEWAY_WORKLOAD_SCOPE_WORKSPACES {
        return Err(GatewayWorkloadIdentityError::InvalidWorkspaceScope);
    }
    if workspace_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(GatewayWorkloadIdentityError::InvalidWorkspaceScope);
    }
    Ok(())
}

pub fn encode_gateway_workload_identity_authority(
    authority: &GatewayWorkloadIdentityAuthority,
) -> Result<Vec<u8>, GatewayWorkloadIdentityError> {
    authority.validate()?;
    encode_artifact(authority)
}

pub fn decode_gateway_workload_identity_authority(
    bytes: &[u8],
) -> Result<GatewayWorkloadIdentityAuthority, GatewayWorkloadIdentityError> {
    let authority: GatewayWorkloadIdentityAuthority = decode_artifact(bytes)?;
    authority.validate()?;
    Ok(authority)
}

fn encode_artifact<T: Serialize>(value: &T) -> Result<Vec<u8>, GatewayWorkloadIdentityError> {
    let bytes = serde_json::to_vec(value).map_err(|_| GatewayWorkloadIdentityError::Malformed)?;
    if bytes.len() > GATEWAY_WORKLOAD_IDENTITY_AUTHORITY_MAX_WIRE_BYTES {
        return Err(GatewayWorkloadIdentityError::WireTooLarge);
    }
    Ok(bytes)
}

fn decode_artifact<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, GatewayWorkloadIdentityError> {
    if bytes.len() > GATEWAY_WORKLOAD_IDENTITY_AUTHORITY_MAX_WIRE_BYTES {
        return Err(GatewayWorkloadIdentityError::WireTooLarge);
    }
    let value =
        serde_json::from_slice(bytes).map_err(|_| GatewayWorkloadIdentityError::Malformed)?;
    let canonical =
        serde_json::to_vec(&value).map_err(|_| GatewayWorkloadIdentityError::Malformed)?;
    if canonical != bytes {
        return Err(GatewayWorkloadIdentityError::NonCanonical);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    use super::*;

    const PUBLIC_KEY_SPKI_A: &str = "MCowBQYDK2VwAyEA2-Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8";
    const PUBLIC_KEY_SPKI_B: &str = "MCowBQYDK2VwAyEAJJHj__Po94RauBD2QsCa8LKrwcrVFdomZbKbCGBbvuk";
    const ED25519_SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    fn initial_authority() -> GatewayWorkloadIdentityAuthority {
        GatewayWorkloadIdentityAuthority {
            version: ContractVersion::V1,
            authority_id: Id::new("gateway_authority_a").unwrap(),
            fleet_id: Id::new("fleet_a").unwrap(),
            policy_revision: Epoch::new(1).unwrap(),
            expected_previous: None,
            credentials: vec![
                GatewayWorkloadCredentialPolicy {
                    credential_id: Id::new("gateway_credential_a").unwrap(),
                    public_key_spki: Base64UrlNoPad::new(PUBLIC_KEY_SPKI_A).unwrap(),
                    scope: GatewayWorkloadCredentialScope::Fleet,
                },
                GatewayWorkloadCredentialPolicy {
                    credential_id: Id::new("gateway_credential_b").unwrap(),
                    public_key_spki: Base64UrlNoPad::new(PUBLIC_KEY_SPKI_B).unwrap(),
                    scope: GatewayWorkloadCredentialScope::Workspaces {
                        workspace_ids: vec![
                            Id::new("workspace_a").unwrap(),
                            Id::new("workspace_b").unwrap(),
                        ],
                    },
                },
            ],
        }
    }

    fn generated_credential(index: u8) -> GatewayWorkloadCredentialPolicy {
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        let mut public_key = [0_u8; 32];
        public_key[31] = index;
        der.extend_from_slice(&public_key);
        GatewayWorkloadCredentialPolicy {
            credential_id: Id::new(format!("gateway_{index:02}")).unwrap(),
            public_key_spki: Base64UrlNoPad::new(URL_SAFE_NO_PAD.encode(der)).unwrap(),
            scope: GatewayWorkloadCredentialScope::Fleet,
        }
    }

    #[test]
    fn authority_has_an_exact_canonical_vector() {
        let authority = initial_authority();
        let bytes = encode_gateway_workload_identity_authority(&authority).unwrap();
        assert_eq!(
            bytes,
            br#"{"version":1,"authority_id":"gateway_authority_a","fleet_id":"fleet_a","policy_revision":1,"expected_previous":null,"credentials":[{"credential_id":"gateway_credential_a","public_key_spki":"MCowBQYDK2VwAyEA2-Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8","scope":{"kind":"fleet"}},{"credential_id":"gateway_credential_b","public_key_spki":"MCowBQYDK2VwAyEAJJHj__Po94RauBD2QsCa8LKrwcrVFdomZbKbCGBbvuk","scope":{"kind":"workspaces","workspace_ids":["workspace_a","workspace_b"]}}]}"#
        );
        assert_eq!(
            authority.digest().unwrap().as_str(),
            "sha256:4aec249a69133a48f4f48bad0e125363710e5ec315e0763b385edc2a1b149e60"
        );
        assert_eq!(
            decode_gateway_workload_identity_authority(&bytes).unwrap(),
            authority
        );
    }

    #[test]
    fn credential_and_workspace_bounds_are_closed() {
        let mut empty = initial_authority();
        empty.credentials.clear();
        empty.validate().unwrap();

        let mut maximum = initial_authority();
        maximum.credentials = (0..MAX_GATEWAY_WORKLOAD_CREDENTIALS as u8)
            .map(generated_credential)
            .collect();
        maximum.validate().unwrap();
        maximum.credentials.push(generated_credential(16));
        assert_eq!(
            maximum.validate(),
            Err(GatewayWorkloadIdentityError::TooManyCredentials)
        );

        let mut invalid = initial_authority();
        invalid.credentials[1].scope = GatewayWorkloadCredentialScope::Workspaces {
            workspace_ids: Vec::new(),
        };
        assert_eq!(
            invalid.validate(),
            Err(GatewayWorkloadIdentityError::InvalidWorkspaceScope)
        );
        invalid.credentials[1].scope = GatewayWorkloadCredentialScope::Workspaces {
            workspace_ids: (0..=MAX_GATEWAY_WORKLOAD_SCOPE_WORKSPACES)
                .map(|index| Id::new(format!("workspace_{index:03}")).unwrap())
                .collect(),
        };
        assert_eq!(
            invalid.validate(),
            Err(GatewayWorkloadIdentityError::InvalidWorkspaceScope)
        );
        invalid.credentials[1].scope = GatewayWorkloadCredentialScope::Workspaces {
            workspace_ids: vec![
                Id::new("workspace_b").unwrap(),
                Id::new("workspace_a").unwrap(),
            ],
        };
        assert_eq!(
            invalid.validate(),
            Err(GatewayWorkloadIdentityError::InvalidWorkspaceScope)
        );
    }

    #[test]
    fn lineage_order_and_public_keys_are_exact() {
        let initial = initial_authority();
        let mut successor = initial.clone();
        successor.policy_revision = Epoch::new(2).unwrap();
        assert_eq!(
            successor.validate(),
            Err(GatewayWorkloadIdentityError::InvalidLineage)
        );
        successor.expected_previous = Some(GatewayWorkloadIdentityExpectedPrevious {
            policy_revision: initial.policy_revision,
            policy_sha256: initial.digest().unwrap(),
        });
        successor.validate().unwrap();
        successor.policy_revision = Epoch::new(3).unwrap();
        assert_eq!(
            successor.validate(),
            Err(GatewayWorkloadIdentityError::InvalidLineage)
        );

        let mut invalid = initial_authority();
        invalid.credentials.swap(0, 1);
        assert_eq!(
            invalid.validate(),
            Err(GatewayWorkloadIdentityError::InvalidCredentialOrder)
        );
        invalid = initial_authority();
        invalid.credentials[1].credential_id = invalid.credentials[0].credential_id.clone();
        assert_eq!(
            invalid.validate(),
            Err(GatewayWorkloadIdentityError::InvalidCredentialOrder)
        );
        invalid = initial_authority();
        invalid.credentials[1].public_key_spki = invalid.credentials[0].public_key_spki.clone();
        assert_eq!(
            invalid.validate(),
            Err(GatewayWorkloadIdentityError::DuplicatePublicKey)
        );
        invalid = initial_authority();
        invalid.credentials[0].public_key_spki = Base64UrlNoPad::new("AA").unwrap();
        assert_eq!(
            invalid.validate(),
            Err(GatewayWorkloadIdentityError::InvalidPublicKey)
        );
    }

    #[test]
    fn scope_lookup_uses_the_validated_leaf_spki() {
        let authority = initial_authority();
        let digest =
            canonical_ed25519_spki_sha256(&authority.credentials[1].public_key_spki).unwrap();
        let credential = authority.credential_by_spki_sha256(&digest).unwrap();
        assert_eq!(credential.credential_id.as_str(), "gateway_credential_b");
        assert!(credential
            .scope
            .authorizes_workspace(&Id::new("workspace_a").unwrap()));
        assert!(!credential
            .scope
            .authorizes_workspace(&Id::new("workspace_c").unwrap()));
    }

    #[test]
    fn decoder_rejects_noncanonical_duplicate_unknown_and_oversized_input() {
        let noncanonical = br#"{"authority_id":"gateway_authority_a","version":1,"fleet_id":"fleet_a","policy_revision":1,"expected_previous":null,"credentials":[]}"#;
        assert_eq!(
            decode_gateway_workload_identity_authority(noncanonical),
            Err(GatewayWorkloadIdentityError::NonCanonical)
        );
        let duplicate = br#"{"version":1,"version":1,"authority_id":"gateway_authority_a","fleet_id":"fleet_a","policy_revision":1,"expected_previous":null,"credentials":[]}"#;
        assert_eq!(
            decode_gateway_workload_identity_authority(duplicate),
            Err(GatewayWorkloadIdentityError::Malformed)
        );
        let unknown = br#"{"version":1,"authority_id":"gateway_authority_a","fleet_id":"fleet_a","policy_revision":1,"expected_previous":null,"credentials":[],"unknown":true}"#;
        assert_eq!(
            decode_gateway_workload_identity_authority(unknown),
            Err(GatewayWorkloadIdentityError::Malformed)
        );
        assert_eq!(
            decode_gateway_workload_identity_authority(&vec![
                b'x';
                GATEWAY_WORKLOAD_IDENTITY_AUTHORITY_MAX_WIRE_BYTES
                    + 1
            ]),
            Err(GatewayWorkloadIdentityError::WireTooLarge)
        );
    }

    #[test]
    fn certificate_leaf_identity_parser_is_exact_and_bounded() {
        let pem = include_bytes!(
            "../../control-plane/tests/fixtures/gateway_machine_client_certificate.pem"
        );
        let text = std::str::from_utf8(pem).unwrap();
        let certificate = base64::engine::general_purpose::STANDARD
            .decode(
                text.lines()
                    .filter(|line| !line.starts_with("-----"))
                    .collect::<String>(),
            )
            .unwrap();
        assert_eq!(
            canonical_gateway_leaf_spki_sha256(certificate.as_ref())
                .unwrap()
                .as_str(),
            "sha256:c82f69461d48dda0d056def48aff86908f4f32213163d47de658ea98c6527795"
        );
        assert!(
            canonical_gateway_leaf_spki_sha256(&certificate[..certificate.len() - 1]).is_none()
        );
        assert!(canonical_gateway_leaf_spki_sha256(&ED25519_SPKI_PREFIX).is_none());
    }
}
