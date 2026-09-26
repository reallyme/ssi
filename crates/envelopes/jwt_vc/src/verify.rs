// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::jwk::Jwk;
use reallyme_jose::jwt::{
    decode_verify_jwt_signature_only_with_header_validation, JwtHeaderValidationOptions,
};

use super::validate_temporal::{validate_jwt_vc_temporal_claims, validate_verification_options};
use crate::claims::decode_validated_credential_bytes;
use crate::{JwtVcEnvelopeError, JwtVcPayload};

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

/// Verifier policy for JWT-VC temporal claim validation.
///
/// There is no default: callers must supply the current time explicitly so a
/// missing clock can never silently disable expiry checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JwtVcVerificationOptions {
    /// Current verifier time as UTC seconds since the Unix epoch. Zero is
    /// rejected with [`JwtVcEnvelopeError::InvalidVerificationTime`].
    pub now_unix: u64,

    /// Tolerated clock skew in seconds, applied to `exp`, `nbf`, and `iat`.
    /// Values above [`crate::MAX_JWT_VC_CLOCK_SKEW_SECONDS`] are rejected with
    /// [`JwtVcEnvelopeError::InvalidVerificationTime`].
    pub clock_skew_seconds: u64,
}

/// Verify a JWT-VC signature, its temporal claims against the supplied
/// verification time, and decode its credential bytes.
pub fn verify_jwt_vc(
    jwt: &str,
    issuer_jwk: &Jwk,
    issuer_public_key: &[u8],
    options: &JwtVcVerificationOptions,
) -> Result<VerifiedJwtVc, JwtVcEnvelopeError> {
    validate_verification_options(options)?;

    let payload: JwtVcPayload = decode_verify_jwt_signature_only_with_header_validation(
        jwt,
        issuer_jwk,
        issuer_public_key,
        &JwtHeaderValidationOptions::new(false, false, JWT_VC_TYP_VALUES),
    )?;
    let decoded = decode_validated_credential_bytes(&payload)?;
    validate_jwt_vc_temporal_claims(&payload, options)?;

    Ok(VerifiedJwtVc {
        payload,
        credential_cbor: decoded.credential_cbor,
        credential_proto: decoded.credential_proto,
    })
}
