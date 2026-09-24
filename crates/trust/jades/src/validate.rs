// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_revocation_core::StatusChecker;
use reallyme_codec::base64url::base64url_to_bytes;
use reallyme_trust_core::{
    evaluate_trust_decision, SignatureVerifier, TrustOutcome, TrustPolicyId, TrustPurpose,
};
use zeroize::Zeroizing;

use crate::certificate::{
    borrowed_verification_key, resolve_presented_certificates, validate_certificate_references,
    verification_key,
};
use crate::header::parse_protected_header;
use crate::time_policy::validate_claimed_signing_time;
use crate::{
    AuthenticatedJades, CompactJwsVerificationErrorReason, CompactJwsVerifier,
    JadesAuthenticationInput, JadesError, JadesErrorReason, JadesValidationInput, ValidatedJades,
    MAX_JADES_COMPACT_BYTES, MAX_JADES_PROTECTED_HEADER_BYTES,
};

/// Authenticates compact JAdES Baseline-B without asserting issuer or path trust.
///
/// The returned receipt is bound to the exact expected leaf certificate. Path
/// construction and trust remain a separate authorization operation.
pub fn authenticate_compact_jades(
    input: JadesAuthenticationInput<'_>,
    jws_verifier: &dyn CompactJwsVerifier,
) -> Result<AuthenticatedJades, JadesError> {
    authenticate_compact_jades_inner(
        input.compact,
        std::slice::from_ref(input.expected_signing_certificate),
        Some(input.expected_signing_certificate),
        input.evaluation_time,
        input.policy,
        jws_verifier,
    )
}

/// Validates compact JAdES Baseline-B, its signing-certificate binding, and
/// the signer's SSI X.509 path and status.
///
/// The protected header is first parsed under strict resource bounds only to
/// select the embedded certificate and signature suite. JAdES policy is not
/// accepted until the JOSE backend returns the exact same decoded header in an
/// authenticated receipt. This prevents a verified-envelope/authorized-header
/// split at the trust boundary.
pub fn validate_compact_jades(
    input: JadesValidationInput<'_>,
    jws_verifier: &dyn CompactJwsVerifier,
    certificate_signature_verifier: &dyn SignatureVerifier,
    status_checker: Option<&dyn StatusChecker>,
) -> Result<ValidatedJades, JadesError> {
    if input.trust_config.evaluation.purpose != TrustPurpose::JadesSigner
        || input.trust_config.evaluation.policy_id != TrustPolicyId::EtsiJadesBaselineBV1
    {
        return Err(JadesError::new(JadesErrorReason::CertificatePathRejected));
    }

    let authenticated = authenticate_compact_jades_inner(
        input.compact,
        input.presented_certificates,
        None,
        input.trust_config.now,
        input.policy,
        jws_verifier,
    )?;

    let trust_decision = evaluate_trust_decision(
        authenticated.certificates(),
        input.trust_config,
        certificate_signature_verifier,
        status_checker,
    )
    .map_err(|_| JadesError::new(JadesErrorReason::CertificatePathRejected))?;
    match trust_decision.outcome {
        TrustOutcome::Trusted => {}
        TrustOutcome::Rejected => {
            return Err(JadesError::new(JadesErrorReason::CertificatePathRejected));
        }
        TrustOutcome::Indeterminate => {
            return Err(JadesError::new(
                JadesErrorReason::CertificatePathIndeterminate,
            ));
        }
    }

    let (payload, signing_certificate, claimed_signing_time, signature_algorithm) = authenticated
        .into_validated_parts()
        .ok_or_else(|| JadesError::new(JadesErrorReason::InvalidSigningCertificate))?;
    Ok(ValidatedJades::new(
        payload,
        signing_certificate,
        claimed_signing_time,
        signature_algorithm,
        trust_decision,
    ))
}

fn authenticate_compact_jades_inner(
    compact: &str,
    presented_certificates: &[envelopes_x509::X509Certificate],
    expected_signing_certificate: Option<&envelopes_x509::X509Certificate>,
    evaluation_time: time::OffsetDateTime,
    policy: &crate::JadesPolicy,
    jws_verifier: &dyn CompactJwsVerifier,
) -> Result<AuthenticatedJades, JadesError> {
    if compact.is_empty() || compact.len() > MAX_JADES_COMPACT_BYTES {
        return Err(JadesError::new(
            JadesErrorReason::InvalidCompactSerialization,
        ));
    }

    let (protected_segment, payload_segment) = compact_segments(compact)?;
    let protected_header_bytes = Zeroizing::new(
        base64url_to_bytes(protected_segment)
            .map_err(|_| JadesError::new(JadesErrorReason::InvalidProtectedHeader))?,
    );
    if protected_header_bytes.is_empty()
        || protected_header_bytes.len() > MAX_JADES_PROTECTED_HEADER_BYTES
    {
        return Err(JadesError::new(JadesErrorReason::ResourceLimit));
    }
    let payload_bytes = Zeroizing::new(
        base64url_to_bytes(payload_segment)
            .map_err(|_| JadesError::new(JadesErrorReason::InvalidCompactSerialization))?,
    );
    if payload_bytes.len() > MAX_JADES_COMPACT_BYTES {
        return Err(JadesError::new(JadesErrorReason::ResourceLimit));
    }

    let header = parse_protected_header(protected_header_bytes.as_slice())?;
    let algorithm = header.signature_algorithm()?;
    if !policy.allowed_signature_algorithms.contains(&algorithm) {
        return Err(JadesError::new(
            JadesErrorReason::UnsupportedSignatureAlgorithm,
        ));
    }

    let certificates = if expected_signing_certificate.is_some() && header.x5c.is_some() {
        resolve_presented_certificates(&header, &[])?
    } else {
        resolve_presented_certificates(&header, presented_certificates)?
    };
    let signing_certificate = certificates
        .first()
        .ok_or_else(|| JadesError::new(JadesErrorReason::InvalidSigningCertificate))?;
    if expected_signing_certificate
        .is_some_and(|expected| expected.der.as_slice() != signing_certificate.der.as_slice())
    {
        return Err(JadesError::new(
            JadesErrorReason::SigningCertificateMismatch,
        ));
    }
    let key_material = verification_key(signing_certificate, algorithm)?;
    let authenticated = jws_verifier
        .verify(
            compact,
            algorithm,
            borrowed_verification_key(&key_material)?,
        )
        .map_err(map_jws_error)?;
    if authenticated.protected_header_json() != protected_header_bytes.as_slice()
        || authenticated.payload() != payload_bytes.as_slice()
    {
        return Err(JadesError::new(JadesErrorReason::InvalidSignature));
    }

    // ETSI TS 119 182-1 v1.2.1 §§5.1.6-5.1.8 and 5.2.2 require
    // signing-certificate identifiers to be protected and to match the exact
    // signing certificate. Every identifier present is checked; conflicting
    // identifiers cannot be used as alternatives.
    validate_certificate_references(&header, &certificates)?;
    let claimed_signing_time = validate_claimed_signing_time(&header, evaluation_time, policy)?;
    if claimed_signing_time.value < signing_certificate.not_before
        || claimed_signing_time.value > signing_certificate.not_after
    {
        return Err(JadesError::new(JadesErrorReason::SigningTimeOutsidePolicy));
    }

    Ok(AuthenticatedJades::new(
        authenticated.into_payload(),
        certificates,
        claimed_signing_time,
        algorithm,
    ))
}

fn compact_segments(compact: &str) -> Result<(&str, &str), JadesError> {
    let mut segments = compact.split('.');
    let protected = segments
        .next()
        .ok_or_else(|| JadesError::new(JadesErrorReason::InvalidCompactSerialization))?;
    let payload = segments
        .next()
        .ok_or_else(|| JadesError::new(JadesErrorReason::InvalidCompactSerialization))?;
    let signature = segments
        .next()
        .ok_or_else(|| JadesError::new(JadesErrorReason::InvalidCompactSerialization))?;
    if protected.is_empty()
        || payload.is_empty()
        || signature.is_empty()
        || segments.next().is_some()
    {
        return Err(JadesError::new(
            JadesErrorReason::InvalidCompactSerialization,
        ));
    }
    Ok((protected, payload))
}

const fn map_jws_error(error: crate::CompactJwsVerificationError) -> JadesError {
    match error.reason() {
        CompactJwsVerificationErrorReason::UnsupportedAlgorithm => {
            JadesError::new(JadesErrorReason::UnsupportedSignatureAlgorithm)
        }
        CompactJwsVerificationErrorReason::InvalidSignature => {
            JadesError::new(JadesErrorReason::InvalidSignature)
        }
        CompactJwsVerificationErrorReason::InvalidInput
        | CompactJwsVerificationErrorReason::BackendFailure => {
            JadesError::new(JadesErrorReason::InvalidSignature)
        }
    }
}
