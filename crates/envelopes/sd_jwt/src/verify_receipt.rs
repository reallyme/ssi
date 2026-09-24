// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Issuance-receipt verification for holder-bound SD-JWT credentials.

use core::fmt;

use reallyme_codec::{base64url::base64url_to_bytes, jcs::canonicalize_json_text};
use reallyme_crypto::jwk::{p256_public_key_to_jwk, Jwk, JwkOptions};
use reallyme_jose::jwt::{
    decode_verify_jwt_signature_only_with_header_validation, JwtHeaderValidationOptions,
};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::sensitive::{zeroize_json_value, zeroize_strings};
use crate::{
    parse_sd_jwt_or_kb_compact, process_sd_jwt_payload, SdJwtEnvelopeError, SdJwtOrKbCompact,
    SdJwtProcessingPolicy,
};

/// Maximum exact issuer or credential-type claim length accepted by receipt policy.
pub const MAX_SD_JWT_EXPECTED_CLAIM_BYTES: usize = 2_048;
const MAX_RECEIPT_CLOCK_SKEW_SECONDS: u64 = 300;
const MAX_RECEIPT_AGE_SECONDS: u64 = 86_400;
const DEFAULT_ISSUER_TYP_VALUES: &[&str] = &["dc+sd-jwt", "vc+sd-jwt"];
const MAX_PROTECTED_HEADER_BYTES: usize = 16 * 1024;
const MAX_X5C_CERTIFICATES: usize = 10;
const MAX_X5C_CERTIFICATE_BYTES: usize = 256 * 1024;

/// Caller-owned policy for validating a just-issued SD-JWT credential.
#[derive(Debug, Clone, Copy)]
pub struct SdJwtReceiptVerificationPolicy<'a> {
    pub expected_issuer: &'a str,
    pub expected_vct: &'a str,
    pub expected_holder_jwk: &'a Jwk,
    pub expected_holder_public_key: &'a [u8],
    pub now_unix: u64,
    pub maximum_age_seconds: u64,
    pub clock_skew_seconds: u64,
    pub issuer_allow_missing_typ: bool,
    /// Permit a certificate chain in the issuer JWS protected header.
    ///
    /// Callers must not set this without also resolving and validating the
    /// exact authenticated `x5c` chain. Prefer [`verify_sd_jwt_receipt_with_x5c`].
    pub issuer_allow_embedded_key_header: bool,
    pub issuer_accepted_typ_values: &'a [&'a str],
    pub processing_policy: SdJwtProcessingPolicy,
}

impl<'a> SdJwtReceiptVerificationPolicy<'a> {
    /// Construct the bounded default receipt policy for a known issuance session.
    #[must_use]
    pub fn new(
        expected_issuer: &'a str,
        expected_vct: &'a str,
        expected_holder_jwk: &'a Jwk,
        expected_holder_public_key: &'a [u8],
        now_unix: u64,
        maximum_age_seconds: u64,
    ) -> Self {
        Self {
            expected_issuer,
            expected_vct,
            expected_holder_jwk,
            expected_holder_public_key,
            now_unix,
            maximum_age_seconds,
            clock_skew_seconds: 60,
            issuer_allow_missing_typ: false,
            issuer_allow_embedded_key_header: false,
            issuer_accepted_typ_values: DEFAULT_ISSUER_TYP_VALUES,
            processing_policy: SdJwtProcessingPolicy::default(),
        }
    }
}

/// Holder binding authenticated from the issuer-signed `cnf.jwk` claim.
pub struct ValidatedSdJwtHolderBinding {
    public_key: Zeroizing<Vec<u8>>,
}

impl ValidatedSdJwtHolderBinding {
    /// Borrow the validated canonical public-key bytes.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        self.public_key.as_slice()
    }
}

impl fmt::Debug for ValidatedSdJwtHolderBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidatedSdJwtHolderBinding([REDACTED])")
    }
}

/// A credential receipt whose issuer signature, disclosures, claims, and
/// issuance-session holder binding have all been validated.
pub struct VerifiedSdJwtReceipt {
    issuer_signed_jwt: String,
    issuer_payload: Value,
    resolved_payload: Value,
    disclosures: Vec<String>,
    holder_binding: ValidatedSdJwtHolderBinding,
}

impl VerifiedSdJwtReceipt {
    #[must_use]
    pub fn issuer_signed_jwt(&self) -> &str {
        self.issuer_signed_jwt.as_str()
    }

    #[must_use]
    pub const fn issuer_payload(&self) -> &Value {
        &self.issuer_payload
    }

    #[must_use]
    pub const fn resolved_payload(&self) -> &Value {
        &self.resolved_payload
    }

    #[must_use]
    pub fn disclosures(&self) -> &[String] {
        self.disclosures.as_slice()
    }

    #[must_use]
    pub const fn holder_binding(&self) -> &ValidatedSdJwtHolderBinding {
        &self.holder_binding
    }
}

impl fmt::Debug for VerifiedSdJwtReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedSdJwtReceipt([REDACTED])")
    }
}

impl Zeroize for VerifiedSdJwtReceipt {
    fn zeroize(&mut self) {
        self.issuer_signed_jwt.zeroize();
        zeroize_json_value(&mut self.issuer_payload);
        zeroize_json_value(&mut self.resolved_payload);
        zeroize_strings(&mut self.disclosures);
        self.holder_binding.public_key.zeroize();
    }
}

impl Drop for VerifiedSdJwtReceipt {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedSdJwtReceipt {}

/// Verify a holder-bound SD-JWT credential at wallet import time.
///
/// This entry point intentionally rejects an appended KB-JWT. A KB-JWT proves
/// a later presentation to a verifier; issuance receipt instead authenticates
/// the issuer-signed `cnf.jwk` against the proof key already fixed by the
/// wallet's issuance session.
pub fn verify_sd_jwt_receipt(
    compact: &str,
    issuer_jwk: &Jwk,
    issuer_public_key: &[u8],
    policy: &SdJwtReceiptVerificationPolicy<'_>,
) -> Result<VerifiedSdJwtReceipt, SdJwtEnvelopeError> {
    validate_policy(policy)?;
    let parsed = parse_sd_jwt_or_kb_compact(compact)?;
    let mut compact = match parsed {
        SdJwtOrKbCompact::SdJwt(compact) => compact,
        SdJwtOrKbCompact::SdJwtWithKb(_) => {
            return Err(SdJwtEnvelopeError::UnexpectedReceiptKeyBindingJwt);
        }
    };
    let issuer_signed_jwt = core::mem::take(&mut compact.issuer_signed_jwt);
    let disclosures = core::mem::take(&mut compact.disclosures);
    let issuer_payload: Value = decode_verify_jwt_signature_only_with_header_validation(
        &issuer_signed_jwt,
        issuer_jwk,
        issuer_public_key,
        &JwtHeaderValidationOptions::new(
            policy.issuer_allow_missing_typ,
            policy.issuer_allow_embedded_key_header,
            policy.issuer_accepted_typ_values,
        ),
    )?;
    validate_receipt_claims(&issuer_payload, policy)?;
    let holder_binding = validate_holder_binding(&issuer_payload, policy)?;
    let resolved_payload = process_sd_jwt_payload(
        issuer_payload.clone(),
        &disclosures,
        policy.processing_policy,
    )?;

    Ok(VerifiedSdJwtReceipt {
        issuer_signed_jwt,
        issuer_payload,
        resolved_payload,
        disclosures,
        holder_binding,
    })
}

/// Verify an SD-JWT issuance receipt whose issuer key is authenticated by an
/// `x5c` protected-header chain.
///
/// The resolver must perform full X.509 path/profile/time validation against
/// deployment-controlled trust anchors before returning the leaf P-256 SEC1
/// public key. The presented chain is never treated as a trust source.
pub fn verify_sd_jwt_receipt_with_x5c(
    compact: &str,
    policy: &SdJwtReceiptVerificationPolicy<'_>,
    certificate_path_resolver: impl FnOnce(&[Vec<u8>]) -> Option<Vec<u8>>,
) -> Result<VerifiedSdJwtReceipt, SdJwtEnvelopeError> {
    let certificate_chain = parse_sd_jwt_issuer_x5c(compact)?;
    let issuer_public_key = certificate_path_resolver(&certificate_chain)
        .ok_or(SdJwtEnvelopeError::InvalidIssuerJwt)?;
    let issuer_jwk = Jwk::Ec(
        p256_public_key_to_jwk(
            &issuer_public_key,
            JwkOptions {
                alg: true,
                use_sig: true,
                use_enc: false,
                kid: None,
            },
        )
        .map_err(|_| SdJwtEnvelopeError::InvalidIssuerJwt)?,
    );
    // X.509 SubjectPublicKeyInfo conventionally carries an uncompressed SEC1
    // point, while ReallyMe JWKs use the canonical compressed representation.
    // Re-derive the verification bytes from the authenticated JWK so strict
    // JWK/raw-key binding compares one canonical representation of the same
    // curve point rather than treating valid SEC1 encodings as different keys.
    let canonical_issuer_public_key = Zeroizing::new(
        issuer_jwk
            .public_key_bytes()
            .map_err(|_| SdJwtEnvelopeError::InvalidIssuerJwt)?,
    );
    let mut x5c_policy = *policy;
    x5c_policy.issuer_allow_embedded_key_header = true;
    verify_sd_jwt_receipt(
        compact,
        &issuer_jwk,
        &canonical_issuer_public_key,
        &x5c_policy,
    )
}

/// Parse the bounded leaf-first `x5c` chain from an SD-JWT issuer JWS.
///
/// This performs only strict structural and size validation. Callers must
/// validate the returned path against deployment-controlled trust anchors and
/// bind the resulting leaf key back to the issuer signature.
pub fn parse_sd_jwt_issuer_x5c(compact: &str) -> Result<Vec<Vec<u8>>, SdJwtEnvelopeError> {
    let issuer_signed_jwt = compact
        .split('~')
        .next()
        .ok_or(SdJwtEnvelopeError::InvalidCompactSerialization)?;
    let mut components = issuer_signed_jwt.split('.');
    let protected = components
        .next()
        .ok_or(SdJwtEnvelopeError::InvalidIssuerJwt)?;
    if components.next().is_none() || components.next().is_none() || components.next().is_some() {
        return Err(SdJwtEnvelopeError::InvalidIssuerJwt);
    }
    let protected =
        base64url_to_bytes(protected).map_err(|_| SdJwtEnvelopeError::InvalidIssuerJwt)?;
    if protected.is_empty() || protected.len() > MAX_PROTECTED_HEADER_BYTES {
        return Err(SdJwtEnvelopeError::InvalidIssuerJwt);
    }
    let protected =
        core::str::from_utf8(&protected).map_err(|_| SdJwtEnvelopeError::InvalidIssuerJwt)?;
    let canonical =
        canonicalize_json_text(protected).map_err(|_| SdJwtEnvelopeError::InvalidIssuerJwt)?;
    let header: Value =
        serde_json::from_str(&canonical).map_err(|_| SdJwtEnvelopeError::InvalidIssuerJwt)?;
    let object = header
        .as_object()
        .ok_or(SdJwtEnvelopeError::InvalidIssuerJwt)?;
    if object.contains_key("jwk") {
        return Err(SdJwtEnvelopeError::InvalidIssuerJwt);
    }
    let encoded_chain = object
        .get("x5c")
        .and_then(Value::as_array)
        .ok_or(SdJwtEnvelopeError::InvalidIssuerJwt)?;
    if encoded_chain.is_empty() || encoded_chain.len() > MAX_X5C_CERTIFICATES {
        return Err(SdJwtEnvelopeError::InvalidIssuerJwt);
    }
    let mut chain = Vec::with_capacity(encoded_chain.len());
    for encoded in encoded_chain {
        let encoded = encoded
            .as_str()
            .ok_or(SdJwtEnvelopeError::InvalidIssuerJwt)?;
        let der = reallyme_codec::base64::base64_to_bytes(encoded)
            .map_err(|_| SdJwtEnvelopeError::InvalidIssuerJwt)?;
        if der.is_empty() || der.len() > MAX_X5C_CERTIFICATE_BYTES {
            return Err(SdJwtEnvelopeError::InvalidIssuerJwt);
        }
        chain.push(der);
    }
    Ok(chain)
}

fn validate_policy(policy: &SdJwtReceiptVerificationPolicy<'_>) -> Result<(), SdJwtEnvelopeError> {
    if policy.expected_issuer.trim().is_empty()
        || policy.expected_issuer.len() > MAX_SD_JWT_EXPECTED_CLAIM_BYTES
        || policy.expected_vct.trim().is_empty()
        || policy.expected_vct.len() > MAX_SD_JWT_EXPECTED_CLAIM_BYTES
        || policy.now_unix == 0
        || policy.maximum_age_seconds == 0
        || policy.maximum_age_seconds > MAX_RECEIPT_AGE_SECONDS
        || policy.clock_skew_seconds > MAX_RECEIPT_CLOCK_SKEW_SECONDS
        || policy.issuer_accepted_typ_values.is_empty()
    {
        return Err(SdJwtEnvelopeError::InvalidReceiptPolicy);
    }
    Ok(())
}

fn validate_receipt_claims(
    payload: &Value,
    policy: &SdJwtReceiptVerificationPolicy<'_>,
) -> Result<(), SdJwtEnvelopeError> {
    let object = payload
        .as_object()
        .ok_or(SdJwtEnvelopeError::InvalidIssuerJwt)?;
    if object.get("iss").and_then(Value::as_str) != Some(policy.expected_issuer)
        || object.get("vct").and_then(Value::as_str) != Some(policy.expected_vct)
    {
        return Err(SdJwtEnvelopeError::ReceiptClaimMismatch);
    }
    let issued_at = object
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or(SdJwtEnvelopeError::InvalidReceiptTemporalClaim)?;
    let not_before = optional_numeric_date(object.get("nbf"))?;
    let expires_at = optional_numeric_date(object.get("exp"))?;
    if expires_at.is_some_and(|value| value <= issued_at)
        || matches!((not_before, expires_at), (Some(start), Some(end)) if start >= end)
    {
        return Err(SdJwtEnvelopeError::InvalidReceiptTemporalClaim);
    }
    let latest_issued_at = policy
        .now_unix
        .checked_add(policy.clock_skew_seconds)
        .ok_or(SdJwtEnvelopeError::InvalidReceiptTemporalClaim)?;
    let stale_after = issued_at
        .checked_add(policy.maximum_age_seconds)
        .and_then(|value| value.checked_add(policy.clock_skew_seconds))
        .ok_or(SdJwtEnvelopeError::InvalidReceiptTemporalClaim)?;
    if issued_at > latest_issued_at || stale_after < policy.now_unix {
        return Err(SdJwtEnvelopeError::InvalidReceiptTemporalClaim);
    }
    if not_before.is_some_and(|value| value > latest_issued_at)
        || expires_at
            .is_some_and(|value| policy.now_unix.saturating_sub(policy.clock_skew_seconds) >= value)
    {
        return Err(SdJwtEnvelopeError::ReceiptExpired);
    }
    Ok(())
}

fn optional_numeric_date(value: Option<&Value>) -> Result<Option<u64>, SdJwtEnvelopeError> {
    value
        .map(|value| {
            value
                .as_u64()
                .ok_or(SdJwtEnvelopeError::InvalidReceiptTemporalClaim)
        })
        .transpose()
}

fn validate_holder_binding(
    payload: &Value,
    policy: &SdJwtReceiptVerificationPolicy<'_>,
) -> Result<ValidatedSdJwtHolderBinding, SdJwtEnvelopeError> {
    let confirmation = payload
        .get("cnf")
        .and_then(Value::as_object)
        .ok_or(SdJwtEnvelopeError::MissingReceiptHolderBinding)?;
    if confirmation.len() != 1 {
        return Err(SdJwtEnvelopeError::InvalidReceiptHolderBinding);
    }
    let confirmation_jwk: Jwk = serde_json::from_value(
        confirmation
            .get("jwk")
            .cloned()
            .ok_or(SdJwtEnvelopeError::MissingReceiptHolderBinding)?,
    )
    .map_err(|_| SdJwtEnvelopeError::InvalidReceiptHolderBinding)?;
    let confirmation_public_key = Zeroizing::new(
        confirmation_jwk
            .public_key_bytes()
            .map_err(|_| SdJwtEnvelopeError::InvalidReceiptHolderBinding)?,
    );
    let expected_jwk_public_key = Zeroizing::new(
        policy
            .expected_holder_jwk
            .public_key_bytes()
            .map_err(|_| SdJwtEnvelopeError::InvalidReceiptPolicy)?,
    );
    if confirmation_public_key.as_slice() != policy.expected_holder_public_key
        || expected_jwk_public_key.as_slice() != policy.expected_holder_public_key
    {
        return Err(SdJwtEnvelopeError::ReceiptHolderBindingMismatch);
    }
    Ok(ValidatedSdJwtHolderBinding {
        public_key: confirmation_public_key,
    })
}
