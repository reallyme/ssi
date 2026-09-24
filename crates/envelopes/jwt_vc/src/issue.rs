// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::jwk::Jwk;
use reallyme_crypto::signer::Signer;
use reallyme_jose::jwt::{
    encode_signed_jwt_with_header_options, encode_signed_jwt_with_signer_and_header_options,
    JwtHeaderEncodeOptions,
};

use crate::{validate_jwt_vc_claims, JwtVcEnvelopeError, JwtVcPayload};

const JWT_VC_JSON_TYP: &str = "vc+jwt";

/// Input for issuing a JWT-VC over already-issued credential bytes.
#[derive(Debug, Clone, Copy)]
pub struct JwtVcIssueInput<'a> {
    /// Issuer DID or issuer identifier.
    pub issuer: &'a str,

    /// Subject DID, pairwise subject identifier, or profile-specific subject id.
    pub subject: &'a str,

    /// Canonical signed credential envelope CBOR bytes.
    pub credential_cbor: &'a [u8],

    /// Optional protobuf credential transport bytes.
    pub credential_proto: Option<&'a [u8]>,

    /// Not-before time as UTC seconds since the Unix epoch.
    pub not_before_unix: Option<i64>,

    /// Expiration time as UTC seconds since the Unix epoch.
    pub expires_at_unix: Option<i64>,

    /// Optional JWT identifier.
    pub jwt_id: Option<&'a str>,

    /// Public JWK corresponding to the issuer signing key.
    pub issuer_jwk: &'a Jwk,

    /// Issuer private key bytes for local signing.
    pub issuer_private_key: &'a [u8],
}

/// Issue a JWT-VC over canonical credential bytes.
pub fn issue_jwt_vc(input: &JwtVcIssueInput<'_>) -> Result<String, JwtVcEnvelopeError> {
    if input.issuer_private_key.is_empty() {
        return Err(JwtVcEnvelopeError::InvalidInput);
    }

    let payload = build_payload(input)?;
    encode_signed_jwt_with_header_options(
        &payload,
        input.issuer_jwk,
        input.issuer_private_key,
        &JwtHeaderEncodeOptions::new(Some(JWT_VC_JSON_TYP.to_owned())),
    )
    .map_err(JwtVcEnvelopeError::from)
}

/// Issue a JWT-VC with an injected signer such as an HSM or QSCD.
pub fn issue_jwt_vc_with_signer(
    input: &JwtVcIssueInput<'_>,
    signer: &dyn Signer,
) -> Result<String, JwtVcEnvelopeError> {
    let payload = build_payload(input)?;
    encode_signed_jwt_with_signer_and_header_options(
        &payload,
        input.issuer_jwk,
        signer,
        &JwtHeaderEncodeOptions::new(Some(JWT_VC_JSON_TYP.to_owned())),
    )
    .map_err(JwtVcEnvelopeError::from)
}

fn build_payload(input: &JwtVcIssueInput<'_>) -> Result<JwtVcPayload, JwtVcEnvelopeError> {
    if input.issuer.is_empty() || input.subject.is_empty() || input.credential_cbor.is_empty() {
        return Err(JwtVcEnvelopeError::InvalidInput);
    }

    if let Some(proto) = input.credential_proto {
        if proto.is_empty() {
            return Err(JwtVcEnvelopeError::InvalidInput);
        }
    }

    let payload = JwtVcPayload {
        iss: input.issuer.to_owned(),
        sub: input.subject.to_owned(),
        nbf: input.not_before_unix,
        exp: input.expires_at_unix,
        jti: input.jwt_id.map(str::to_owned),
        credential_cbor: bytes_to_base64url(input.credential_cbor),
        credential_proto: input.credential_proto.map(bytes_to_base64url),
    };
    validate_jwt_vc_claims(&payload)?;

    Ok(payload)
}
