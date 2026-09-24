// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{
    AuthenticatedJws, RegistrarCertificateChain, RegistryJwsVerifier,
    MAX_SIGNER_CERTIFICATE_CHAIN_LENGTH,
};
use crate::json::{canonical_json, deserialize_strict, StrictValue};
use crate::{RegistrationError, RegistrationErrorReason};

const MAX_JWKS_BYTES: usize = 131_072;
const MAX_JWKS_KEYS: usize = 16;
const MAX_JWK_BYTES: usize = 16_384;
const MAX_JWKS_REDIRECTS: u8 = 3;
const MAX_PROTECTED_HEADER_BYTES: usize = 16_384;
const MAX_KEY_ID_BYTES: usize = 1_024;
const MAX_JWKS_URI_BYTES: usize = 4_096;
const MAX_CONTENT_TYPE_BYTES: usize = 256;

/// Redirect-safe, content-type checked JWKS response.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ValidatedJwks {
    body: Vec<u8>,
}

impl ValidatedJwks {
    /// Validates a resolved JWKS response against the application-accepted URL.
    pub fn try_new(
        accepted_url: &str,
        final_url: &str,
        redirect_count: u8,
        content_type: &str,
        body: &[u8],
    ) -> Result<Self, RegistrationError> {
        if body.is_empty()
            || body.len() > MAX_JWKS_BYTES
            || redirect_count > MAX_JWKS_REDIRECTS
            || accepted_url.len() > MAX_JWKS_URI_BYTES
            || final_url.len() > MAX_JWKS_URI_BYTES
            || content_type.len() > MAX_CONTENT_TYPE_BYTES
        {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::ResourceLimitExceeded,
            ));
        }
        let essence = content_type.split(';').next().map(str::trim);
        if !essence.is_some_and(|value| {
            value.eq_ignore_ascii_case("application/jwk-set+json")
                || value.eq_ignore_ascii_case("application/json")
        }) {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::InvalidField,
            ));
        }
        let accepted = strict_https_url(accepted_url)?;
        let final_value = strict_https_url(final_url)?;
        if accepted.scheme() != final_value.scheme()
            || accepted.host_str() != final_value.host_str()
            || accepted.port_or_known_default() != final_value.port_or_known_default()
        {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::SemanticBindingMismatch,
            ));
        }
        let document: JwksDocument = deserialize_strict(body)?;
        if document.keys.is_empty() || document.keys.len() > MAX_JWKS_KEYS {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::ResourceLimitExceeded,
            ));
        }
        for key in &document.keys {
            if !matches!(key, StrictValue::Object(_)) || canonical_json(key)?.len() > MAX_JWK_BYTES
            {
                return Err(RegistrationError::from_reason(
                    RegistrationErrorReason::ResourceLimitExceeded,
                ));
            }
        }
        Ok(Self {
            body: body.to_vec(),
        })
    }

    /// Borrows the strictly validated JWKS bytes for the cryptographic backend.
    #[must_use]
    pub fn expose_body(&self) -> &[u8] {
        &self.body
    }
}
/// In-process JOSE verifier for bounded registrar JWKS responses.
#[derive(Clone, Copy, Debug, Default)]
pub struct JoseRegistryJwsVerifier;

impl RegistryJwsVerifier for JoseRegistryJwsVerifier {
    fn verify(
        &self,
        compact_jws: &[u8],
        jwks: &ValidatedJwks,
    ) -> Result<AuthenticatedJws, RegistrationError> {
        let compact_text = core::str::from_utf8(compact_jws).map_err(|_error| {
            RegistrationError::from_reason(RegistrationErrorReason::InvalidCompactJws)
        })?;
        let header = parse_protected_header(compact_jws)?;
        let document: JwksDocument = deserialize_strict(jwks.expose_body())?;
        let (jwk, certificate_chain) = select_signing_key(document, &header)?;
        let public_key = Zeroizing::new(jwk.public_key_bytes().map_err(|_error| {
            RegistrationError::from_reason(RegistrationErrorReason::InvalidField)
        })?);
        let policy = reallyme_jose::jwt::JwtHeaderValidationOptions::standard_jwt();
        let payload = reallyme_jose::jwt::decode_verify_jwt_claims_json_signature_only_with_header_validation(
            compact_text,
            &jwk,
            &public_key,
            &policy,
        )
        .map_err(|_error| {
            RegistrationError::from_reason(RegistrationErrorReason::SignatureVerificationFailed)
        })?;
        let mut certificates_der = certificate_chain.into_der_certificates();
        AuthenticatedJws::try_new(
            compact_jws,
            payload.as_slice(),
            core::mem::take(&mut *certificates_der),
        )
    }
}
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(super) struct JwksDocument {
    pub(super) keys: Vec<StrictValue>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(super) struct ProtectedHeader {
    alg: String,
    kid: String,
    pub(super) typ: Option<String>,
}

pub(super) fn parse_protected_header(compact: &[u8]) -> Result<ProtectedHeader, RegistrationError> {
    let encoded = compact.split(|byte| *byte == b'.').next().ok_or_else(|| {
        RegistrationError::from_reason(RegistrationErrorReason::InvalidCompactJws)
    })?;
    let decoded =
        reallyme_codec::base64url::base64url_bytes_to_bytes(encoded).map_err(|_error| {
            RegistrationError::from_reason(RegistrationErrorReason::InvalidCompactJws)
        })?;
    if decoded.is_empty() || decoded.len() > MAX_PROTECTED_HEADER_BYTES {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::ResourceLimitExceeded,
        ));
    }
    let header: ProtectedHeader = deserialize_strict(&decoded)?;
    if header.alg != "ES256" && header.alg != "EdDSA" {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::UnsupportedProfile,
        ));
    }
    if header.kid.is_empty()
        || header.kid.len() > MAX_KEY_ID_BYTES
        || header.typ.as_deref().is_some_and(|value| {
            !(value.eq_ignore_ascii_case("JWT") || value.eq_ignore_ascii_case("application/jwt"))
        })
    {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidCompactJws,
        ));
    }
    Ok(header)
}

pub(super) fn select_signing_key(
    mut document: JwksDocument,
    header: &ProtectedHeader,
) -> Result<(reallyme_jose::Jwk, RegistrarCertificateChain), RegistrationError> {
    let mut selected = None;
    for mut key in core::mem::take(&mut document.keys) {
        let Some(mut members) = key.take_object() else {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::InvalidField,
            ));
        };
        let key_id_matches = matches!(
            members.get("kid"),
            Some(StrictValue::String(value)) if value == &header.kid
        );
        if !key_id_matches {
            continue;
        }
        if selected.is_some() {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::InvalidField,
            ));
        }
        if !matches!(
            members.get("alg"),
            Some(StrictValue::String(value)) if value == &header.alg
        ) {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::InvalidField,
            ));
        }
        let certificate_chain = extract_certificate_chain(members.remove("x5c"))?;
        validate_key_operations(members.remove("key_ops"))?;
        let encoded_key = Zeroizing::new(canonical_json(&StrictValue::Object(members))?);
        let jwk: reallyme_jose::Jwk = serde_json::from_slice(&encoded_key).map_err(|_error| {
            RegistrationError::from_reason(RegistrationErrorReason::InvalidField)
        })?;
        bind_jwk_to_certificate(&jwk, certificate_chain.leaf_der()?, &header.alg)?;
        selected = Some((jwk, certificate_chain));
    }
    selected.ok_or_else(|| RegistrationError::from_reason(RegistrationErrorReason::InvalidField))
}

pub(super) fn validate_key_operations(value: Option<StrictValue>) -> Result<(), RegistrationError> {
    let Some(mut value) = value else {
        return Ok(());
    };
    let Some(mut operations) = value.take_array() else {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidField,
        ));
    };
    if operations.len() != 1 {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidField,
        ));
    }
    let Some(operation) = operations.first_mut().and_then(StrictValue::take_string) else {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidField,
        ));
    };
    if operation != "verify" {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidField,
        ));
    }
    Ok(())
}

pub(super) fn bind_jwk_to_certificate(
    jwk: &reallyme_jose::Jwk,
    certificate_der: &[u8],
    algorithm: &str,
) -> Result<(), RegistrationError> {
    let jwk_public_key = jwk
        .public_key_bytes()
        .map_err(|_error| RegistrationError::from_reason(RegistrationErrorReason::InvalidField))?;
    let certificate_key = reallyme_trust_x509::certificate_subject_public_key_info(certificate_der)
        .map_err(|_error| {
            RegistrationError::from_reason(RegistrationErrorReason::InvalidCertificate)
        })?;
    let algorithm_matches = matches!(
        (algorithm, certificate_key.algorithm),
        (
            "ES256",
            reallyme_trust_x509::SubjectPublicKeyAlgorithm::P256
        ) | (
            "EdDSA",
            reallyme_trust_x509::SubjectPublicKeyAlgorithm::Ed25519
        )
    );
    let key_matches = match algorithm {
        "ES256" => compress_p256_sec1(&certificate_key.public_key)
            .is_some_and(|certificate_public_key| jwk_public_key == certificate_public_key),
        "EdDSA" => jwk_public_key == certificate_key.public_key,
        _ => false,
    };
    if !algorithm_matches || !key_matches {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::AuthenticationReceiptMismatch,
        ));
    }
    Ok(())
}

fn compress_p256_sec1(uncompressed: &[u8]) -> Option<[u8; 33]> {
    const UNCOMPRESSED_P256_BYTES: usize = 65;
    const COMPRESSED_P256_BYTES: usize = 33;
    const X_COORDINATE_END: usize = 33;
    const UNCOMPRESSED_PREFIX: u8 = 0x04;
    const COMPRESSED_EVEN_Y_PREFIX: u8 = 0x02;
    const COMPRESSED_ODD_Y_PREFIX: u8 = 0x03;

    if uncompressed.len() != UNCOMPRESSED_P256_BYTES
        || uncompressed.first().copied() != Some(UNCOMPRESSED_PREFIX)
    {
        return None;
    }
    let x_coordinate = uncompressed.get(1..X_COORDINATE_END)?;
    let y_last = uncompressed.last().copied()?;
    let mut compressed = [0_u8; COMPRESSED_P256_BYTES];
    compressed[0] = if y_last & 1 == 0 {
        COMPRESSED_EVEN_Y_PREFIX
    } else {
        COMPRESSED_ODD_Y_PREFIX
    };
    compressed.get_mut(1..)?.copy_from_slice(x_coordinate);
    Some(compressed)
}

fn extract_certificate_chain(
    value: Option<StrictValue>,
) -> Result<RegistrarCertificateChain, RegistrationError> {
    let Some(mut value) = value else {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::MissingSignerCertificate,
        ));
    };
    let Some(mut chain) = value.take_array() else {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::MissingSignerCertificate,
        ));
    };
    if chain.is_empty() || chain.len() > MAX_SIGNER_CERTIFICATE_CHAIN_LENGTH {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::ResourceLimitExceeded,
        ));
    }
    let mut certificates_der = Vec::new();
    certificates_der
        .try_reserve_exact(chain.len())
        .map_err(|_error| {
            RegistrationError::from_reason(RegistrationErrorReason::CapacityUnavailable)
        })?;
    for value in &mut chain {
        let Some(encoded) = value.take_string() else {
            certificates_der.zeroize();
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::InvalidCertificate,
            ));
        };
        let encoded = Zeroizing::new(encoded);
        let certificate_der = match reallyme_codec::base64::base64_to_bytes(&encoded) {
            Ok(value) => value,
            Err(_error) => {
                certificates_der.zeroize();
                return Err(RegistrationError::from_reason(
                    RegistrationErrorReason::InvalidCertificate,
                ));
            }
        };
        certificates_der.push(certificate_der);
    }
    RegistrarCertificateChain::try_from_der(certificates_der)
}

fn strict_https_url(value: &str) -> Result<url::Url, RegistrationError> {
    let parsed = url::Url::parse(value)
        .map_err(|_error| RegistrationError::from_reason(RegistrationErrorReason::InvalidUri))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidUri,
        ));
    }
    Ok(parsed)
}
