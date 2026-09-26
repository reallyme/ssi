// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded policies for issuance-time and presentation-time SD-JWT validation.

use reallyme_crypto::jwk::Jwk;
use serde_json::Value;

use crate::{SdJwtEnvelopeError, SdJwtProcessingPolicy};

/// Application-owned verifier for an authenticated SD-JWT `status` claim.
///
/// Implementations resolve and authenticate the referenced status material,
/// enforce freshness, and return a typed status error. Network I/O remains
/// outside the envelope parser so callers can inject a bounded resolver and
/// cache appropriate to their deployment.
pub trait SdJwtCredentialStatusVerifier: Sync {
    fn verify_status(&self, status: &Value, now_unix: u64) -> Result<(), SdJwtEnvelopeError>;
}

/// Maximum exact issuer or credential-type claim length accepted by policy.
pub const MAX_SD_JWT_EXPECTED_CLAIM_BYTES: usize = 2_048;
pub(super) const MAX_RECEIPT_CLOCK_SKEW_SECONDS: u64 = 300;
pub(super) const MAX_RECEIPT_AGE_SECONDS: u64 = 86_400;
const DEFAULT_ISSUER_TYP_VALUES: &[&str] = &["dc+sd-jwt", "vc+sd-jwt"];

/// Caller-owned policy for validating a just-issued SD-JWT credential.
#[derive(Clone, Copy)]
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
    /// exact authenticated `x5c` chain. Prefer
    /// [`crate::verify_sd_jwt_receipt_with_x5c`].
    pub issuer_allow_embedded_key_header: bool,
    pub issuer_accepted_typ_values: &'a [&'a str],
    pub processing_policy: SdJwtProcessingPolicy,
    pub status_verifier: Option<&'a dyn SdJwtCredentialStatusVerifier>,
    pub require_status: bool,
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
            status_verifier: None,
            require_status: false,
        }
    }
}

/// Caller-owned policy for validating a stored holder-bound SD-JWT credential.
///
/// Unlike issuance-receipt policy, this policy does not impose an artificial
/// maximum age after issuance. It validates the credential's own temporal
/// bounds at presentation time while retaining issuer, type, holder-binding,
/// protected-header, and disclosure verification.
#[derive(Clone, Copy)]
pub struct SdJwtCredentialVerificationPolicy<'a> {
    pub expected_issuer: &'a str,
    pub expected_vct: &'a str,
    pub expected_holder_jwk: &'a Jwk,
    pub expected_holder_public_key: &'a [u8],
    pub now_unix: u64,
    pub clock_skew_seconds: u64,
    pub issuer_allow_missing_typ: bool,
    /// Permit an absent issuer claim when the authenticated `x5c` leaf
    /// certificate conveys the issuer identity.
    ///
    /// This option is honored only by
    /// [`crate::verify_sd_jwt_credential_with_x5c`]. A present `iss` claim
    /// must still equal `expected_issuer`, and the certificate-path resolver
    /// must bind the leaf certificate identity to that expected issuer.
    pub x5c_allow_missing_issuer_claim: bool,
    /// Permit a certificate chain in the issuer JWS protected header.
    ///
    /// Callers must not set this without validating the exact authenticated
    /// `x5c` chain. Prefer [`crate::verify_sd_jwt_credential_with_x5c`].
    pub issuer_allow_embedded_key_header: bool,
    pub issuer_accepted_typ_values: &'a [&'a str],
    pub processing_policy: SdJwtProcessingPolicy,
    pub status_verifier: Option<&'a dyn SdJwtCredentialStatusVerifier>,
    pub require_status: bool,
}

impl<'a> SdJwtCredentialVerificationPolicy<'a> {
    /// Construct strict presentation-time policy for a stored credential.
    #[must_use]
    pub fn new(
        expected_issuer: &'a str,
        expected_vct: &'a str,
        expected_holder_jwk: &'a Jwk,
        expected_holder_public_key: &'a [u8],
        now_unix: u64,
    ) -> Self {
        Self {
            expected_issuer,
            expected_vct,
            expected_holder_jwk,
            expected_holder_public_key,
            now_unix,
            clock_skew_seconds: 60,
            issuer_allow_missing_typ: false,
            x5c_allow_missing_issuer_claim: false,
            issuer_allow_embedded_key_header: false,
            issuer_accepted_typ_values: DEFAULT_ISSUER_TYP_VALUES,
            processing_policy: SdJwtProcessingPolicy::default(),
            status_verifier: None,
            require_status: false,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct BoundCredentialVerificationPolicy<'a> {
    pub(super) expected_issuer: &'a str,
    pub(super) expected_vct: &'a str,
    pub(super) expected_holder_jwk: &'a Jwk,
    pub(super) expected_holder_public_key: &'a [u8],
    pub(super) now_unix: u64,
    pub(super) maximum_age_seconds: Option<u64>,
    pub(super) clock_skew_seconds: u64,
    pub(super) issuer_allow_missing_typ: bool,
    pub(super) x5c_allow_missing_issuer_claim: bool,
    pub(super) issuer_allow_embedded_key_header: bool,
    pub(super) issuer_accepted_typ_values: &'a [&'a str],
    pub(super) processing_policy: SdJwtProcessingPolicy,
    pub(super) status_verifier: Option<&'a dyn SdJwtCredentialStatusVerifier>,
    pub(super) require_status: bool,
}

impl<'a> From<&SdJwtReceiptVerificationPolicy<'a>> for BoundCredentialVerificationPolicy<'a> {
    fn from(policy: &SdJwtReceiptVerificationPolicy<'a>) -> Self {
        Self {
            expected_issuer: policy.expected_issuer,
            expected_vct: policy.expected_vct,
            expected_holder_jwk: policy.expected_holder_jwk,
            expected_holder_public_key: policy.expected_holder_public_key,
            now_unix: policy.now_unix,
            maximum_age_seconds: Some(policy.maximum_age_seconds),
            clock_skew_seconds: policy.clock_skew_seconds,
            issuer_allow_missing_typ: policy.issuer_allow_missing_typ,
            x5c_allow_missing_issuer_claim: false,
            issuer_allow_embedded_key_header: policy.issuer_allow_embedded_key_header,
            issuer_accepted_typ_values: policy.issuer_accepted_typ_values,
            processing_policy: policy.processing_policy,
            status_verifier: policy.status_verifier,
            require_status: policy.require_status,
        }
    }
}

impl<'a> From<&SdJwtCredentialVerificationPolicy<'a>> for BoundCredentialVerificationPolicy<'a> {
    fn from(policy: &SdJwtCredentialVerificationPolicy<'a>) -> Self {
        Self {
            expected_issuer: policy.expected_issuer,
            expected_vct: policy.expected_vct,
            expected_holder_jwk: policy.expected_holder_jwk,
            expected_holder_public_key: policy.expected_holder_public_key,
            now_unix: policy.now_unix,
            maximum_age_seconds: None,
            clock_skew_seconds: policy.clock_skew_seconds,
            issuer_allow_missing_typ: policy.issuer_allow_missing_typ,
            x5c_allow_missing_issuer_claim: policy.x5c_allow_missing_issuer_claim,
            issuer_allow_embedded_key_header: policy.issuer_allow_embedded_key_header,
            issuer_accepted_typ_values: policy.issuer_accepted_typ_values,
            processing_policy: policy.processing_policy,
            status_verifier: policy.status_verifier,
            require_status: policy.require_status,
        }
    }
}
