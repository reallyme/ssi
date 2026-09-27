// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};

use codec_base64url::{base64url_to_bytes, bytes_to_base64url};

use crypto_signer::Signer;
use envelopes_jwk::Jwk;
use envelopes_jwt::jwt::{
    decode_verify_jwt_signature_only, encode_signed_jwt, encode_signed_jwt_with_signer,
};

use reallyme_credential::committed::{
    model::CredentialEnvelope, signed_envelope::encode_signed_envelope_cbor,
};

use crate::validate_temporal::{validate_vc_jwt_temporal_claims, validate_verification_options};
use crate::{VcJwtError, VcJwtVerificationOptions};

/// VC-JWT payload.
///
/// Registered JWT claims identify the parties and validity interval. The
/// credential is carried as canonical CBOR bytes, with optional protobuf bytes
/// for dual-format transport. Subject claim values remain protected by the
/// credential's Merkle commitment and are not copied into this payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcJwtPayload {
    /// Issuer identifier carried by `iss`.
    pub iss: String,
    /// Subject identifier carried by `sub`.
    pub sub: String,

    /// Earliest accepted time from the registered `nbf` claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Expiration time from the registered `exp` claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Issuance time from the registered `iat` claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// Optional JWT identifier carried by `jti`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Base64url-encoded canonical CBOR signed-envelope wrapper.
    pub vc_se: String,

    /// Optional base64url-encoded protobuf representation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vc_proto: Option<String>,
}

/// Encodes and signs a VC-JWT.
///
/// - Uses `envelopes-jwt::encode_signed_jwt` for signing.
/// - Embeds the signed VC envelope as `vc_cbor` (base64url).
/// - Optionally embeds `vc_proto`.
pub fn encode_vc_jwt(
    envelope: &CredentialEnvelope,
    issuer_did: &str,
    subject_id: &str,
    issuer_jwk: &Jwk,
    issuer_private_key: &[u8],
    vc_proto_bytes: Option<&[u8]>,
) -> Result<String, VcJwtError> {
    let se_bytes = encode_signed_envelope_cbor(envelope).map_err(|_| VcJwtError::VcCore)?;

    let payload = VcJwtPayload {
        iss: issuer_did.to_string(),
        sub: subject_id.to_string(),
        nbf: Some(envelope.valid_from),
        exp: Some(envelope.valid_until),
        iat: None,
        jti: None,
        vc_se: bytes_to_base64url(&se_bytes),
        vc_proto: vc_proto_bytes.map(bytes_to_base64url),
    };

    encode_signed_jwt(&payload, issuer_jwk, issuer_private_key).map_err(|_| VcJwtError::Jwt)
}

/// Encodes a VC-JWT through an external signing provider.
pub fn encode_vc_jwt_with_signer(
    envelope: &CredentialEnvelope,
    issuer_did: &str,
    subject_id: &str,
    issuer_jwk: &Jwk,
    signer: &dyn Signer,
    vc_proto_bytes: Option<&[u8]>,
) -> Result<String, VcJwtError> {
    let se_bytes = encode_signed_envelope_cbor(envelope).map_err(|_| VcJwtError::VcCore)?;

    let payload = VcJwtPayload {
        iss: issuer_did.to_string(),
        sub: subject_id.to_string(),
        nbf: Some(envelope.valid_from),
        exp: Some(envelope.valid_until),
        iat: None,
        jti: None,
        vc_se: bytes_to_base64url(&se_bytes),
        vc_proto: vc_proto_bytes.map(bytes_to_base64url),
    };

    encode_signed_jwt_with_signer(&payload, issuer_jwk, signer).map_err(|_| VcJwtError::Jwt)
}

/// Verifies and decodes a VC-JWT into its payload and canonical credential bytes.
///
/// This verifies the JWT signature using `envelopes-jwt`, validates the `exp`,
/// `nbf`, and `iat` claims against the caller-supplied verification time, and
/// then returns the decoded VC payload.
/// (Reconstructing a full `CredentialEnvelope` from canonical bytes is a separate step,
/// and depends on whether the caller uses a CBOR envelope schema or protobuf schema.)
pub fn decode_verify_vc_jwt(
    jwt: &str,
    issuer_jwk: &Jwk,
    issuer_public_key: &[u8],
    options: &VcJwtVerificationOptions,
) -> Result<(VcJwtPayload, Vec<u8>), VcJwtError> {
    validate_verification_options(options)?;

    let payload: VcJwtPayload =
        decode_verify_jwt_signature_only(jwt, issuer_jwk, issuer_public_key)
            .map_err(|_| VcJwtError::Jwt)?;

    validate_vc_jwt_temporal_claims(&payload, options)?;

    if payload.vc_se.is_empty() {
        return Err(VcJwtError::MissingField);
    }

    let se_bytes = base64url_to_bytes(&payload.vc_se).map_err(|_| VcJwtError::Base64Url)?;

    Ok((payload, se_bytes))
}
