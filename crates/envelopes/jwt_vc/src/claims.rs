// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::base64url_to_bytes;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::JwtVcEnvelopeError;

const MAX_CREDENTIAL_CBOR_BYTES: usize = 1024 * 1024;
const MAX_CREDENTIAL_PROTO_BYTES: usize = 1024 * 1024;

fn maximum_base64url_len(decoded_limit: usize) -> Result<usize, JwtVcEnvelopeError> {
    decoded_limit
        .checked_add(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_mul(4))
        .ok_or(JwtVcEnvelopeError::ResourceLimit)
}

/// JWT payload for a ReallyMe credential envelope carried as `jwt_vc_json`.
///
/// The payload intentionally carries signed credential bytes, not expanded
/// subject claims. OpenID4VCI can therefore return a compact JWT while the
/// authoritative credential semantics remain in the canonical envelope bytes
/// and, when present, their protobuf transport representation.
#[derive(PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
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

impl core::fmt::Debug for JwtVcPayload {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("JwtVcPayload")
            .field("iss", &"<redacted>")
            .field("sub", &"<redacted>")
            .field("nbf", &self.nbf)
            .field("exp", &self.exp)
            .field("iat", &self.iat)
            .field("jti", &"<redacted>")
            .field("credential_cbor", &"<redacted>")
            .field("credential_proto", &"<redacted>")
            .finish()
    }
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

    if payload.credential_cbor.len() > maximum_base64url_len(MAX_CREDENTIAL_CBOR_BYTES)? {
        return Err(JwtVcEnvelopeError::ResourceLimit);
    }
    let credential_cbor = base64url_to_bytes(&payload.credential_cbor)?;
    if credential_cbor.is_empty() {
        return Err(JwtVcEnvelopeError::InvalidPayload);
    }
    reallyme_codec::cbor::decode_dag_cbor(&credential_cbor)
        .map_err(|_| JwtVcEnvelopeError::InvalidCredentialCbor)?;

    let credential_proto = match &payload.credential_proto {
        Some(proto) => {
            if proto.len() > maximum_base64url_len(MAX_CREDENTIAL_PROTO_BYTES)? {
                return Err(JwtVcEnvelopeError::ResourceLimit);
            }
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
