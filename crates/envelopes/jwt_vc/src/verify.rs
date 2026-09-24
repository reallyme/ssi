// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::base64url_to_bytes;
use reallyme_crypto::jwk::Jwk;
use reallyme_jose::jwt::{
    decode_verify_jwt_signature_only_with_header_validation, JwtHeaderValidationOptions,
};

use crate::{validate_jwt_vc_claims, JwtVcEnvelopeError, JwtVcPayload};

// `vc+jwt` is the canonical type emitted by this crate. Legacy VC-JWT
// deployments commonly used the generic `JWT` value, so verification retains
// that compatibility value. This does not make the verifier generic: `typ` is
// still mandatory, and the signed claims must decode into and satisfy the
// required `JwtVcPayload` profile before credential bytes are returned.
const JWT_VC_TYP_VALUES: &[&str] = &["vc+jwt", "JWT"];

/// Verified JWT-VC payload and decoded credential bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedJwtVc {
    /// Verified JWT payload.
    pub payload: JwtVcPayload,

    /// Canonical signed credential envelope CBOR bytes.
    pub credential_cbor: Vec<u8>,

    /// Optional protobuf credential transport bytes.
    pub credential_proto: Option<Vec<u8>>,
}

/// Verify a JWT-VC signature and decode its credential bytes.
pub fn verify_jwt_vc(
    jwt: &str,
    issuer_jwk: &Jwk,
    issuer_public_key: &[u8],
) -> Result<VerifiedJwtVc, JwtVcEnvelopeError> {
    let payload: JwtVcPayload = decode_verify_jwt_signature_only_with_header_validation(
        jwt,
        issuer_jwk,
        issuer_public_key,
        &JwtHeaderValidationOptions::new(false, false, JWT_VC_TYP_VALUES),
    )?;
    validate_jwt_vc_claims(&payload)?;

    let credential_cbor = base64url_to_bytes(&payload.credential_cbor)?;
    let credential_proto = payload
        .credential_proto
        .as_deref()
        .map(base64url_to_bytes)
        .transpose()?;

    Ok(VerifiedJwtVc {
        payload,
        credential_cbor,
        credential_proto,
    })
}
