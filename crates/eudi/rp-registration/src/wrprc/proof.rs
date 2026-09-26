// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Proof-only WRPRC authentication without issuer or certification-path trust.

use identity_trust_jades::{
    authenticate_compact_jades, AuthenticatedCompactJws, CompactJwsVerificationError,
    CompactJwsVerificationErrorReason, CompactJwsVerifier, JadesAuthenticationInput, JadesError,
    JadesErrorReason, JadesSignatureAlgorithm, JadesVerificationKey,
};
use time::OffsetDateTime;

use super::parse::parse_registration_certificate_claims;
use super::{
    parse_registration_certificate, ParsedRegistrationCertificate, RegistrationCertificateFormat,
    RegistrationCertificateProof, MAX_REPRESENTATION_BYTES, MAX_SIGNER_CERTIFICATE_BYTES,
};
use crate::json::MAX_JSON_BYTES;
use crate::{RegistrationError, RegistrationErrorReason};

pub use identity_trust_jades::JadesPolicy as RegistrationCertificateJadesPolicy;

mod cbor;
mod cose;
mod cwt;
mod jades_profile;

/// Tolerated forward clock skew between the WRPRC issuer and the evaluator
/// when judging a signed `iat`, in seconds. Expiry is enforced without skew.
const WRPRC_CLOCK_SKEW_SECONDS: u64 = 60;

/// Exact COSE signature algorithms admitted for a WRPRC representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationCertificateCoseAlgorithm {
    /// COSE algorithm `-7`, ECDSA with P-256 and SHA-256.
    Es256,
    /// COSE algorithm `-8`, EdDSA with an Ed25519 key.
    Ed25519,
}

/// Borrowed input to proof-only compact JAdES WRPRC authentication.
pub struct RegistrationCertificateJadesAuthenticationInput<'a> {
    /// Exact compact JWS bytes returned by the WRPRC authority.
    pub compact_jws: &'a [u8],
    /// Exact leaf certificate expected to authenticate the signature.
    pub expected_signer_certificate_der: &'a [u8],
    /// Trusted evaluation time used for JAdES claimed-signing-time policy and
    /// for the signed WRPRC `iat`/`exp` validity period.
    pub evaluation_time: OffsetDateTime,
    /// Explicit versioned JAdES algorithm and time policy.
    pub policy: &'a RegistrationCertificateJadesPolicy,
}

/// Borrowed input to proof-only attached COSE_Sign1 WRPRC authentication.
pub struct RegistrationCertificateCoseAuthenticationInput<'a> {
    /// Exact attached-payload COSE_Sign1 bytes returned by the authority.
    pub cose_sign1: &'a [u8],
    /// Exact leaf certificate whose public key must verify the signature.
    pub expected_signer_certificate_der: &'a [u8],
    /// Trusted evaluation time for the signed CWT `iat`/`exp` validity period.
    pub evaluation_time: OffsetDateTime,
    /// Non-empty exact COSE algorithm allowlist for this authority profile.
    pub allowed_algorithms: &'a [RegistrationCertificateCoseAlgorithm],
}

/// Authenticates one compact JAdES WRPRC representation without asserting trust.
pub fn authenticate_wrprc_jades(
    input: RegistrationCertificateJadesAuthenticationInput<'_>,
) -> Result<RegistrationCertificateProof, RegistrationError> {
    validate_representation_and_certificate(
        input.compact_jws,
        input.expected_signer_certificate_der,
    )?;
    let compact = core::str::from_utf8(input.compact_jws).map_err(|_error| {
        RegistrationError::from_reason(RegistrationErrorReason::InvalidCompactJws)
    })?;
    let certificate = reallyme_trust_x509::parse_cert_der(input.expected_signer_certificate_der)
        .map_err(|_error| {
            RegistrationError::from_reason(RegistrationErrorReason::InvalidCertificate)
        })?;
    jades_profile::validate_wrprc_jades_header(compact)?;
    let authenticated = authenticate_compact_jades(
        JadesAuthenticationInput {
            compact,
            expected_signing_certificate: &certificate,
            evaluation_time: input.evaluation_time,
            policy: input.policy,
        },
        &JoseJadesVerifier,
    )
    .map_err(map_jades_error)?;
    validate_authenticated_payload(authenticated.payload())?;
    let parsed = parse_registration_certificate(authenticated.payload())?;
    validate_validity_period(&parsed, input.evaluation_time)?;
    RegistrationCertificateProof::from_verified(
        RegistrationCertificateFormat::JadesJwt,
        input.compact_jws,
        parsed,
        input.expected_signer_certificate_der,
    )
}

/// Authenticates one attached COSE_Sign1 WRPRC representation without asserting trust.
pub fn authenticate_wrprc_cose_sign1(
    input: RegistrationCertificateCoseAuthenticationInput<'_>,
) -> Result<RegistrationCertificateProof, RegistrationError> {
    validate_representation_and_certificate(
        input.cose_sign1,
        input.expected_signer_certificate_der,
    )?;
    validate_algorithm_allowlist(input.allowed_algorithms)?;
    let authenticated_payload = cose::authenticate_attached_cose_sign1(
        input.cose_sign1,
        input.expected_signer_certificate_der,
        input.allowed_algorithms,
    )?;
    validate_authenticated_payload(authenticated_payload)?;
    // ETSI TS 119 475 `rc-wrp+cwt` payloads are RFC 8392 CWT claims sets:
    // a CBOR map, never JSON.
    let claims = cwt::decode_cwt_claims(authenticated_payload)?;
    let parsed = parse_registration_certificate_claims(&claims, authenticated_payload)?;
    validate_validity_period(&parsed, input.evaluation_time)?;
    RegistrationCertificateProof::from_verified(
        RegistrationCertificateFormat::CoseCwt,
        input.cose_sign1,
        parsed,
        input.expected_signer_certificate_der,
    )
}

fn validate_representation_and_certificate(
    representation: &[u8],
    certificate_der: &[u8],
) -> Result<(), RegistrationError> {
    if representation.is_empty() || representation.len() > MAX_REPRESENTATION_BYTES {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InputTooLarge,
        ));
    }
    if certificate_der.is_empty() || certificate_der.len() > MAX_SIGNER_CERTIFICATE_BYTES {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::MissingSignerCertificate,
        ));
    }
    Ok(())
}

fn validate_algorithm_allowlist(
    algorithms: &[RegistrationCertificateCoseAlgorithm],
) -> Result<(), RegistrationError> {
    const MAX_ALGORITHMS: usize = 2;
    if algorithms.is_empty()
        || algorithms.len() > MAX_ALGORITHMS
        || algorithms
            .iter()
            .enumerate()
            .any(|(index, algorithm)| algorithms[..index].contains(algorithm))
    {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::UnsupportedProfile,
        ));
    }
    Ok(())
}

/// Enforces `iat <= now + skew` and `now < exp` at the trusted evaluation time.
fn validate_validity_period(
    parsed: &ParsedRegistrationCertificate,
    evaluation_time: OffsetDateTime,
) -> Result<(), RegistrationError> {
    let now = u64::try_from(evaluation_time.unix_timestamp()).map_err(|_error| {
        RegistrationError::from_reason(RegistrationErrorReason::OutsideValidityPeriod)
    })?;
    let latest_issue = now.checked_add(WRPRC_CLOCK_SKEW_SECONDS).ok_or_else(|| {
        RegistrationError::from_reason(RegistrationErrorReason::OutsideValidityPeriod)
    })?;
    if parsed.issued_at() > latest_issue || now >= parsed.expires_at() {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::OutsideValidityPeriod,
        ));
    }
    Ok(())
}

fn validate_authenticated_payload(payload: &[u8]) -> Result<(), RegistrationError> {
    if payload.is_empty() || payload.len() > MAX_JSON_BYTES {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InputTooLarge,
        ));
    }
    Ok(())
}

struct JoseJadesVerifier;

impl CompactJwsVerifier for JoseJadesVerifier {
    fn verify(
        &self,
        compact: &str,
        algorithm: JadesSignatureAlgorithm,
        key: JadesVerificationKey<'_>,
    ) -> Result<AuthenticatedCompactJws, CompactJwsVerificationError> {
        let mut segments = compact.split('.');
        let protected_segment = segments.next().ok_or_else(invalid_jws_signature)?;
        let payload_segment = segments.next().ok_or_else(invalid_jws_signature)?;
        let signature_segment = segments.next().ok_or_else(invalid_jws_signature)?;
        if segments.next().is_some() {
            return Err(invalid_jws_signature());
        }
        let signing_input_length = protected_segment
            .len()
            .checked_add(1)
            .and_then(|value| value.checked_add(payload_segment.len()))
            .ok_or_else(invalid_jws_signature)?;
        let signing_input = compact
            .as_bytes()
            .get(..signing_input_length)
            .ok_or_else(invalid_jws_signature)?;
        let signature = zeroize::Zeroizing::new(
            reallyme_codec::base64url::base64url_to_bytes(signature_segment)
                .map_err(|_error| invalid_jws_signature())?,
        );
        match (algorithm, key) {
            (JadesSignatureAlgorithm::Es256, JadesVerificationKey::P256Sec1(public_key)) => {
                reallyme_jose::jws::suites::es256::verify_p256_jose_prehash(
                    signature.as_slice(),
                    signing_input,
                    public_key,
                )
                .map_err(|_error| invalid_jws_signature())?;
            }
            (JadesSignatureAlgorithm::EdDsa, JadesVerificationKey::Ed25519(public_key)) => {
                reallyme_crypto::ed25519::verify_ed25519(
                    public_key,
                    signing_input,
                    signature.as_slice(),
                )
                .map_err(|_error| invalid_jws_signature())?;
            }
            _ => {
                return Err(CompactJwsVerificationError::new(
                    CompactJwsVerificationErrorReason::UnsupportedAlgorithm,
                ));
            }
        }
        let protected_header = reallyme_codec::base64url::base64url_to_bytes(protected_segment)
            .map_err(|_error| invalid_jws_signature())?;
        let payload = zeroize::Zeroizing::new(
            reallyme_codec::base64url::base64url_to_bytes(payload_segment)
                .map_err(|_error| invalid_jws_signature())?,
        );
        Ok(AuthenticatedCompactJws::new(
            zeroize::Zeroizing::new(protected_header),
            payload,
        ))
    }
}

const fn invalid_jws_signature() -> CompactJwsVerificationError {
    CompactJwsVerificationError::new(CompactJwsVerificationErrorReason::InvalidSignature)
}

const fn map_jades_error(error: JadesError) -> RegistrationError {
    let reason = match error.reason() {
        JadesErrorReason::InvalidCompactSerialization
        | JadesErrorReason::InvalidProtectedHeader => RegistrationErrorReason::InvalidCompactJws,
        JadesErrorReason::UnsupportedSignatureAlgorithm
        | JadesErrorReason::UnsupportedDigestAlgorithm => {
            RegistrationErrorReason::UnsupportedProfile
        }
        JadesErrorReason::InvalidSignature => RegistrationErrorReason::SignatureVerificationFailed,
        JadesErrorReason::MissingClaimedSigningTime
        | JadesErrorReason::InvalidClaimedSigningTime => RegistrationErrorReason::InvalidField,
        JadesErrorReason::SigningTimeOutsidePolicy => {
            RegistrationErrorReason::InvalidValidityInterval
        }
        JadesErrorReason::MissingSigningCertificateReference
        | JadesErrorReason::InvalidCertificateReference
        | JadesErrorReason::SigningCertificateMismatch => {
            RegistrationErrorReason::AuthenticationReceiptMismatch
        }
        JadesErrorReason::InvalidSigningCertificate => RegistrationErrorReason::InvalidCertificate,
        JadesErrorReason::CertificatePathRejected
        | JadesErrorReason::CertificatePathIndeterminate => {
            RegistrationErrorReason::AuthenticationReceiptMismatch
        }
        JadesErrorReason::ResourceLimit => RegistrationErrorReason::ResourceLimitExceeded,
    };
    RegistrationError::from_reason(reason)
}
