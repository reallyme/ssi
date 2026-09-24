// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use envelopes_x509::X509Certificate;
use reallyme_trust_core::{TrustConfig, TrustDecision};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::CompactJwsVerificationError;

/// Maximum compact JWS size accepted before any decoding or JSON parsing.
pub const MAX_JADES_COMPACT_BYTES: usize = 1_048_576;
/// Maximum decoded protected-header size.
pub const MAX_JADES_PROTECTED_HEADER_BYTES: usize = 786_432;

/// JWS algorithms admitted by the versioned JAdES policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JadesSignatureAlgorithm {
    /// ECDSA using P-256 and SHA-256 (RFC 7518 §3.4).
    Es256,
    /// EdDSA using Ed25519 (RFC 8037 §3.1).
    EdDsa,
}

/// Public-key representation passed to the cryptographic JOSE backend.
#[derive(Clone, Copy)]
pub enum JadesVerificationKey<'a> {
    /// SEC1-encoded P-256 public point.
    P256Sec1(&'a [u8]),
    /// Raw 32-octet Ed25519 public key.
    Ed25519(&'a [u8]),
}

/// Header and payload bytes released by a trusted backend only after JWS
/// signature verification succeeds.
pub struct AuthenticatedCompactJws {
    protected_header_json: Zeroizing<Vec<u8>>,
    payload: Zeroizing<Vec<u8>>,
}

impl AuthenticatedCompactJws {
    /// Constructs a receipt at the trusted cryptographic-backend boundary.
    ///
    /// Implementers of [`CompactJwsVerifier`] must call this only after the
    /// signature over the exact compact header and payload segments succeeds.
    #[must_use]
    pub const fn new(
        protected_header_json: Zeroizing<Vec<u8>>,
        payload: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self {
            protected_header_json,
            payload,
        }
    }

    pub(crate) fn protected_header_json(&self) -> &[u8] {
        self.protected_header_json.as_slice()
    }

    pub(crate) fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }

    pub(crate) fn into_payload(self) -> Zeroizing<Vec<u8>> {
        self.payload
    }
}

/// Trusted compact-JWS cryptographic verifier injected by the application.
pub trait CompactJwsVerifier {
    /// Verifies the exact compact input with the selected certificate key.
    fn verify(
        &self,
        compact: &str,
        algorithm: JadesSignatureAlgorithm,
        key: JadesVerificationKey<'_>,
    ) -> Result<AuthenticatedCompactJws, CompactJwsVerificationError>;
}

/// Which protected JAdES parameter supplied the claimed signing time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimedSigningTimeKind {
    /// RFC 7519 NumericDate `iat`, required for newly created signatures from
    /// 2025-07-15 by ETSI TS 119 182-1 v1.2.1 §5.1.11.
    IssuedAt,
    /// Legacy RFC 3339 `sigT` from ETSI TS 119 182-1 §5.2.1.
    LegacySignatureTime,
}

/// Validated claimed signing time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimedSigningTime {
    /// Protected parameter that carried the claim.
    pub kind: ClaimedSigningTimeKind,
    /// Parsed UTC instant.
    pub value: OffsetDateTime,
}

/// Versioned reusable JAdES Baseline-B policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JadesPolicy {
    /// Explicit signature-algorithm allowlist. An empty list rejects all input.
    pub allowed_signature_algorithms: Vec<JadesSignatureAlgorithm>,
    /// Maximum accepted future clock skew for a claimed signing time.
    pub maximum_future_skew_seconds: u32,
}

impl Default for JadesPolicy {
    fn default() -> Self {
        Self {
            // ETSI TS 119 182-1 §5.1.2 delegates algorithm suitability to
            // ETSI TS 119 312. This profile deliberately admits only the
            // implemented non-legacy JOSE suites; it never falls back to `none`
            // or RSA PKCS#1 v1.5.
            allowed_signature_algorithms: vec![
                JadesSignatureAlgorithm::Es256,
                JadesSignatureAlgorithm::EdDsa,
            ],
            maximum_future_skew_seconds: 300,
        }
    }
}

/// Borrowed input to one JAdES validation operation.
pub struct JadesValidationInput<'a> {
    /// Exact compact JWS serialization to authenticate.
    pub compact: &'a str,
    /// Required when the protected header identifies, but does not embed, the
    /// signing certificate. If `x5c` is present, a non-empty supplied chain must
    /// match it byte-for-byte and in the same order.
    pub presented_certificates: &'a [X509Certificate],
    /// Purpose-scoped roots, status policy, source provenance, and evaluation time.
    pub trust_config: &'a TrustConfig,
    /// Versioned JAdES signature and time policy.
    pub policy: &'a JadesPolicy,
}

/// Borrowed input to proof-only JAdES authentication.
///
/// This operation authenticates the compact signature, protected-header
/// policy, certificate references, claimed signing time, and exact expected
/// leaf. It deliberately does not evaluate issuer or certification-path trust.
pub struct JadesAuthenticationInput<'a> {
    /// Exact compact JWS serialization to authenticate.
    pub compact: &'a str,
    /// Exact leaf certificate expected to authenticate the compact signature.
    pub expected_signing_certificate: &'a X509Certificate,
    /// Trusted evaluation time used only for claimed-signing-time policy.
    pub evaluation_time: OffsetDateTime,
    /// Versioned JAdES signature and time policy.
    pub policy: &'a JadesPolicy,
}

/// Proof-only JAdES receipt with no issuer or path-trust assertion.
pub struct AuthenticatedJades {
    payload: Zeroizing<Vec<u8>>,
    certificates: Vec<X509Certificate>,
    claimed_signing_time: ClaimedSigningTime,
    signature_algorithm: JadesSignatureAlgorithm,
}

impl AuthenticatedJades {
    pub(crate) const fn new(
        payload: Zeroizing<Vec<u8>>,
        certificates: Vec<X509Certificate>,
        claimed_signing_time: ClaimedSigningTime,
        signature_algorithm: JadesSignatureAlgorithm,
    ) -> Self {
        Self {
            payload,
            certificates,
            claimed_signing_time,
            signature_algorithm,
        }
    }

    /// Borrows the authenticated JWS payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }

    /// Borrows the exact leaf certificate that authenticated the signature.
    #[must_use]
    pub fn signing_certificate(&self) -> Option<&X509Certificate> {
        self.certificates.first()
    }

    /// Returns the validated claimed signing time.
    #[must_use]
    pub const fn claimed_signing_time(&self) -> ClaimedSigningTime {
        self.claimed_signing_time
    }

    /// Returns the protected signature algorithm admitted by policy.
    #[must_use]
    pub const fn signature_algorithm(&self) -> JadesSignatureAlgorithm {
        self.signature_algorithm
    }

    pub(crate) fn certificates(&self) -> &[X509Certificate] {
        &self.certificates
    }

    pub(crate) fn into_validated_parts(
        mut self,
    ) -> Option<(
        Zeroizing<Vec<u8>>,
        X509Certificate,
        ClaimedSigningTime,
        JadesSignatureAlgorithm,
    )> {
        if self.certificates.is_empty() {
            return None;
        }
        let signing_certificate = self.certificates.remove(0);
        Some((
            self.payload,
            signing_certificate,
            self.claimed_signing_time,
            self.signature_algorithm,
        ))
    }
}

/// Successful, audit-facing JAdES validation receipt.
pub struct ValidatedJades {
    payload: Zeroizing<Vec<u8>>,
    signing_certificate: X509Certificate,
    claimed_signing_time: ClaimedSigningTime,
    signature_algorithm: JadesSignatureAlgorithm,
    trust_decision: TrustDecision,
}

impl ValidatedJades {
    pub(crate) const fn new(
        payload: Zeroizing<Vec<u8>>,
        signing_certificate: X509Certificate,
        claimed_signing_time: ClaimedSigningTime,
        signature_algorithm: JadesSignatureAlgorithm,
        trust_decision: TrustDecision,
    ) -> Self {
        Self {
            payload,
            signing_certificate,
            claimed_signing_time,
            signature_algorithm,
            trust_decision,
        }
    }

    /// Borrows the authenticated JWS payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }

    /// Borrows the exact leaf certificate bound to the signature and trust path.
    #[must_use]
    pub const fn signing_certificate(&self) -> &X509Certificate {
        &self.signing_certificate
    }

    /// Returns the validated claimed signing time.
    #[must_use]
    pub const fn claimed_signing_time(&self) -> ClaimedSigningTime {
        self.claimed_signing_time
    }

    /// Returns the protected signature algorithm admitted by policy.
    #[must_use]
    pub const fn signature_algorithm(&self) -> JadesSignatureAlgorithm {
        self.signature_algorithm
    }

    /// Borrows the complete SSI X.509 path and status decision.
    #[must_use]
    pub const fn trust_decision(&self) -> &TrustDecision {
        &self.trust_decision
    }

    /// Transfers the authenticated payload to the caller.
    #[must_use]
    pub fn into_payload(self) -> Zeroizing<Vec<u8>> {
        self.payload
    }
}
