// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Inputs used to sign a holder key-binding JWT.
pub struct KbJwtBuildParams<'a> {
    /// Holder public JWK whose parameters identify the key-binding key.
    pub holder_jwk: &'a Jwk,
    /// Holder private-key bytes used only to create the key-binding signature.
    pub holder_private_key: &'a [u8],
    /// Audience bound into the key-binding JWT.
    pub audience: &'a str,
    /// Verifier nonce bound into the key-binding JWT.
    pub nonce: &'a str,
    /// `iat` as seconds since the Unix epoch.
    pub iat_unix: u64,
}

impl fmt::Debug for KbJwtBuildParams<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KbJwtBuildParams([REDACTED])")
    }
}

/// Expected transaction and holder key for key-binding verification.
pub struct KbJwtVerifyParams<'a> {
    /// Holder public JWK whose parameters identify the key-binding key.
    pub holder_jwk: &'a Jwk,
    /// Holder public-key bytes used to verify the key-binding signature.
    pub holder_public_key: &'a [u8],
    /// Audience value that the authenticated key-binding JWT must match exactly.
    pub expected_audience: &'a str,
    /// Verifier nonce that the authenticated key-binding JWT must match exactly.
    pub expected_nonce: &'a str,
    /// Verification time as seconds since the Unix epoch.
    pub now_unix: u64,
    /// Maximum age accepted for the mandatory KB-JWT `iat` claim.
    pub max_iat_age_seconds: u64,
    /// Maximum accepted future skew for the KB-JWT `iat` claim.
    pub max_future_iat_skew_seconds: u64,
}

impl fmt::Debug for KbJwtVerifyParams<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KbJwtVerifyParams([REDACTED])")
    }
}

/// Verified issuer payload, resolved claims, and accepted disclosures.
pub struct VerifiedRfc9901 {
    /// Issuer-signed payload exactly as authenticated.
    payload: Value,
    /// Payload with every provided disclosure applied and SD-JWT structural
    /// members removed.
    resolved_payload: Value,
    /// Accepted disclosure arrays in original serialization order.
    provided_disclosures: Vec<Value>,
}

impl VerifiedRfc9901 {
    /// Borrow the authenticated issuer payload.
    #[must_use]
    pub const fn payload(&self) -> &Value {
        &self.payload
    }

    /// Borrow the payload reconstructed from authenticated disclosures.
    #[must_use]
    pub const fn resolved_payload(&self) -> &Value {
        &self.resolved_payload
    }

    /// Borrow accepted disclosure arrays in serialization order.
    #[must_use]
    pub fn provided_disclosures(&self) -> &[Value] {
        &self.provided_disclosures
    }
}

impl fmt::Debug for VerifiedRfc9901 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedRfc9901([REDACTED])")
    }
}

impl Zeroize for VerifiedRfc9901 {
    fn zeroize(&mut self) {
        zeroize_json_value(&mut self.payload);
        zeroize_json_value(&mut self.resolved_payload);
        for disclosure in &mut self.provided_disclosures {
            zeroize_json_value(disclosure);
        }
        self.provided_disclosures.clear();
    }
}

impl Drop for VerifiedRfc9901 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedRfc9901 {}
