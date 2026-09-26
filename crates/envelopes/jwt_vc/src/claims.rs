// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::base64url_to_bytes;
use serde::{Deserialize, Serialize};

use crate::JwtVcEnvelopeError;

/// JWT payload for a ReallyMe credential envelope carried as `jwt_vc_json`.
///
/// The payload intentionally carries signed credential bytes, not expanded
/// subject claims. OpenID4VCI can therefore return a compact JWT while the
/// authoritative credential semantics remain in the canonical envelope bytes
/// and, when present, their protobuf transport representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtVcPayload {
    /// Issuer DID or issuer identifier.
    pub iss: String,

    /// Subject DID, pairwise subject identifier, or profile-specific subject id.
    pub sub: String,

    /// Not-before time as UTC seconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// Expiration time as UTC seconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// Issued-at time as UTC seconds since the Unix epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// JWT identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// base64url(canonical signed credential envelope CBOR).
    #[serde(rename = "vc_cbor")]
    pub credential_cbor: String,

    /// Optional base64url(protobuf credential transport bytes).
    #[serde(rename = "vc_proto", skip_serializing_if = "Option::is_none")]
    pub credential_proto: Option<String>,
}

/// Validate JWT-VC claim semantics before signing or after verification.
///
/// This checks claim structure only. Verification against the current time is
/// performed by [`crate::verify_jwt_vc`] with explicit verification options.
pub fn validate_jwt_vc_claims(payload: &JwtVcPayload) -> Result<(), JwtVcEnvelopeError> {
    decode_validated_credential_bytes(payload).map(|_| ())
}

/// Decoded credential bytes carried by a structurally valid JWT-VC payload.
pub(crate) struct DecodedJwtVcCredential {
    pub(crate) credential_cbor: Vec<u8>,
    pub(crate) credential_proto: Option<Vec<u8>>,
}

/// Validate JWT-VC claim structure and return the decoded credential bytes so
/// verification does not decode the base64url payload twice.
pub(crate) fn decode_validated_credential_bytes(
    payload: &JwtVcPayload,
) -> Result<DecodedJwtVcCredential, JwtVcEnvelopeError> {
    if payload.iss.is_empty() || payload.sub.is_empty() || payload.credential_cbor.is_empty() {
        return Err(JwtVcEnvelopeError::InvalidPayload);
    }

    let not_before = numeric_date(payload.nbf)?;
    let expires = numeric_date(payload.exp)?;
    numeric_date(payload.iat)?;

    if let (Some(not_before), Some(expires)) = (not_before, expires) {
        if expires <= not_before {
            return Err(JwtVcEnvelopeError::InvalidPayload);
        }
    }

    let credential_cbor = base64url_to_bytes(&payload.credential_cbor)?;
    if credential_cbor.is_empty() {
        return Err(JwtVcEnvelopeError::InvalidPayload);
    }

    let credential_proto = match &payload.credential_proto {
        Some(proto) => {
            let proto_bytes = base64url_to_bytes(proto)?;
            if proto_bytes.is_empty() {
                return Err(JwtVcEnvelopeError::InvalidPayload);
            }
            Some(proto_bytes)
        }
        None => None,
    };

    Ok(DecodedJwtVcCredential {
        credential_cbor,
        credential_proto,
    })
}

/// Convert an optional JWT NumericDate claim into non-negative Unix seconds.
pub(crate) fn numeric_date(value: Option<i64>) -> Result<Option<u64>, JwtVcEnvelopeError> {
    value
        .map(|seconds| u64::try_from(seconds).map_err(|_| JwtVcEnvelopeError::InvalidTemporalClaim))
        .transpose()
}
