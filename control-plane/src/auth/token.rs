use super::*;

#[derive(Debug, Clone)]
pub struct AccessIdentity {
    pub user_id: String,
    pub session_id: String,
    pub organization_id: Option<String>,
    pub role: Option<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct AccessTokenClaims {
    pub(super) sub: String,
    pub(super) sid: String,
    pub(super) client_id: String,
    #[serde(default)]
    pub(super) org_id: Option<String>,
    #[serde(default)]
    pub(super) role: Option<String>,
    #[serde(default)]
    pub(super) permissions: Vec<String>,
    #[serde(rename = "exp")]
    pub(super) _expires_at: u64,
    #[serde(rename = "iss")]
    pub(super) _issuer: String,
}

impl WorkOsConfig {
    /// Verify a CLI bearer token cryptographically and turn its organization
    /// scope into the Cats Account that owns it. A valid token for an unmapped
    /// organization remains authenticated but has no workspace access.
    pub async fn verify_access_token(&self, token: &str) -> Result<AccessIdentity, ApiError> {
        let header = decode_header(token)
            .map_err(|_| ApiError::unauthenticated("invalid WorkOS access token"))?;
        if header.alg != Algorithm::RS256 {
            return Err(ApiError::unauthenticated(
                "unsupported WorkOS access token algorithm",
            ));
        }
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| ApiError::unauthenticated("WorkOS access token has no key ID"))?;
        let keys = self.jwks.fetch().await.map_err(|error| {
            tracing::warn!(error = %error, "WorkOS JWKS fetch failed");
            ApiError::unavailable("WorkOS signing keys are temporarily unavailable")
        })?;
        let jwk = keys
            .keys
            .iter()
            .find(|key| key.kid.as_deref() == Some(kid))
            .ok_or_else(|| ApiError::unauthenticated("unknown WorkOS signing key"))?;
        if jwk.kty.as_deref() != Some("RSA") || jwk.alg.as_deref() != Some("RS256") {
            return Err(ApiError::unauthenticated("invalid WorkOS signing key"));
        }
        let modulus = jwk
            .other
            .get("n")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ApiError::unauthenticated("invalid WorkOS RSA key"))?;
        let exponent = jwk
            .other
            .get("e")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ApiError::unauthenticated("invalid WorkOS RSA key"))?;
        let key = DecodingKey::from_rsa_components(modulus, exponent)
            .map_err(|_| ApiError::unauthenticated("invalid WorkOS RSA key"))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["exp", "iss", "sub"]);
        validation.set_issuer(&[self.issuer_url.as_str()]);
        let claims = decode::<AccessTokenClaims>(token, &key, &validation)
            .map_err(|error| {
                tracing::warn!(
                    error = %error,
                    kid,
                    "WorkOS access token validation failed"
                );
                ApiError::unauthenticated("invalid or expired WorkOS access token")
            })?
            .claims;
        if claims.client_id != self.client_id || claims.sub.is_empty() || claims.sid.is_empty() {
            return Err(ApiError::unauthenticated(
                "WorkOS access token belongs to another application",
            ));
        }
        let organization_id = claims.org_id.filter(|value| !value.is_empty());
        Ok(AccessIdentity {
            user_id: claims.sub,
            session_id: claims.sid,
            organization_id,
            role: claims.role,
            permissions: claims.permissions,
        })
    }
}
