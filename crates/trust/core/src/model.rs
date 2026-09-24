// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;
use time::OffsetDateTime;

use envelopes_x509::{policy::X509Policy, X509Certificate, X509Chain};

//
// ------------------------------------------------------------
// Trust configuration & decision
// ------------------------------------------------------------
//

/// Input configuration for trust evaluation.
#[derive(Debug, Clone)]
pub struct TrustConfig {
    /// Trust anchors (root certificates)
    pub trust_roots: Vec<X509Certificate>,

    /// Evaluation time
    pub now: OffsetDateTime,

    /// ETSI / eIDAS policy to apply
    pub policy: X509Policy,

    /// Deterministic chain-linking rules (AKI/SKI, DN continuity)
    pub link_policy: ChainLinkPolicy,

    /// Typed evaluation context retained in the resulting evidence receipt.
    pub evaluation: TrustEvaluationContext,

    /// Explicit, purpose-scoped end-entity trust entries.
    pub direct_trust: Vec<DirectTrustEntry>,
}

/// Result of trust evaluation.
#[derive(Debug, Clone)]
pub struct TrustDecision {
    /// Typed outcome. Callers must not infer indeterminate as rejection.
    pub outcome: TrustOutcome,

    /// Backward-compatible projection of `outcome == Trusted`.
    pub accepted: bool,

    /// The validated chain (leaf → root), if accepted
    pub chain: Option<X509Chain>,

    /// Fixed failure reasons, if rejected.
    pub failures: Vec<TrustFailureReason>,

    /// Audit evidence explaining the evaluation context and selected path.
    pub evidence: TrustEvidence,
}

/// Three-state trust result used at security-sensitive authorization boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustOutcome {
    /// A complete path or explicit direct-trust entry satisfied all requirements.
    Trusted,
    /// Available evidence conclusively violated trust policy.
    Rejected,
    /// Trust could not be concluded because required evidence or capability was unavailable.
    Indeterminate,
}

/// Stable purpose for which trust is being evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustPurpose {
    /// Generic X.509 validation without a protocol-specific authorization purpose.
    Generic,
    /// Qualified electronic attestation issuer authorization.
    QeaaIssuer,
    /// Qualified website authentication certificate server authorization.
    QwacTlsServer,
    /// Qualified electronic seal signer authorization.
    QsealSigner,
    /// Trusted-list XML signing authorization.
    TrustedListSigner,
    /// OAuth wallet-attestation issuer authorization.
    WalletAttestationIssuer,
    /// JAdES Baseline signer authorization.
    JadesSigner,
    /// PID issuance signer authorization.
    PidIssuance,
    /// PID status signer authorization.
    PidStatus,
    /// EUDI wallet-provider attestation signer authorization.
    EudiWalletProviderAttestation,
    /// EUDI wallet or key-storage status signer authorization.
    EudiWalletOrKeyStorageStatus,
    /// Wallet-relying-party access-certificate authorization.
    WalletRelyingPartyAccessCertificate,
    /// Wallet-relying-party registration-certificate authorization.
    WalletRelyingPartyRegistrationCertificate,
    /// Wallet-relying-party registration-certificate status authorization.
    WalletRelyingPartyRegistrationCertificateStatus,
    /// National TS5 wallet-relying-party registry-response signer authorization.
    WalletRelyingPartyRegistrySigning,
}

/// Stable policy identifier retained in a trust receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustPolicyId {
    /// Baseline X.509 policy supplied directly by the caller.
    GenericX509V1,
    /// EU qualified electronic attestation policy.
    EuQeaaV1,
    /// EU qualified website authentication policy.
    EuQwacV1,
    /// EU qualified electronic seal policy.
    EuQsealV1,
    /// EU trusted-list signer policy.
    EuTrustedListSignerV1,
    /// Wallet-attestation issuer policy.
    WalletAttestationIssuerV1,
    /// ETSI TS 119 182-1 JAdES Baseline-B signer policy.
    EtsiJadesBaselineBV1,
    /// ETSI TS 119 412-6 PID-provider signing-certificate policy.
    EtsiTs1194126PidProviderV1,
    /// Versioned PID status policy identity; the status format remains caller-selected.
    EudiPidStatusV1,
    /// ETSI TS 119 412-6 wallet-provider signing-certificate policy.
    EtsiTs1194126WalletProviderV1,
    /// Versioned wallet/key-storage status policy identity.
    EudiWalletOrKeyStorageStatusV1,
    /// ETSI TS 119 411-8 wallet-relying-party access-certificate policy.
    EtsiTs1194118WrpacV1,
    /// ETSI TS 119 475 wallet-relying-party registration-certificate policy.
    EtsiTs119475WrprcV1,
    /// ETSI TS 119 475 registration-certificate status policy.
    EtsiTs119475WrprcStatusV1,
    /// EUDI TS5 v1.5 national registry-response signing policy.
    EudiTs5RegistryResponseSigningV1,
}

/// Identity of the externally supplied trust metadata snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustSourceEvidence {
    /// Stable source identifier selected by the boundary owner.
    pub source_id: [u8; 32],
    /// Digest or immutable identifier of the exact source snapshot.
    pub snapshot_id: [u8; 32],
}

/// Whether status must be established for a certificate position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusRequirement {
    /// A configured status checker must return good.
    Required,
    /// Check status when a checker is configured, without requiring one.
    Optional,
    /// Status is intentionally not checked for this position.
    Exempt,
}

/// Per-position certificate status policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateStatusPolicy {
    /// Leaf certificate status requirement.
    pub leaf: StatusRequirement,
    /// Intermediate certificate status requirement.
    pub intermediates: StatusRequirement,
    /// Trust-anchor status requirement.
    pub trust_anchor: StatusRequirement,
}

impl Default for CertificateStatusPolicy {
    fn default() -> Self {
        Self {
            leaf: StatusRequirement::Optional,
            intermediates: StatusRequirement::Optional,
            trust_anchor: StatusRequirement::Exempt,
        }
    }
}

/// Context and revocation policy applied to one evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustEvaluationContext {
    /// Authorization purpose.
    pub purpose: TrustPurpose,
    /// Stable policy profile identifier.
    pub policy_id: TrustPolicyId,
    /// Per-position status requirements.
    pub status_policy: CertificateStatusPolicy,
    /// Optional source and snapshot identity supplied by the boundary owner.
    pub source: Option<TrustSourceEvidence>,
}

impl Default for TrustEvaluationContext {
    fn default() -> Self {
        Self {
            purpose: TrustPurpose::Generic,
            policy_id: TrustPolicyId::GenericX509V1,
            status_policy: CertificateStatusPolicy::default(),
            source: None,
        }
    }
}

impl TrustEvaluationContext {
    /// Whether the purpose is paired with its versioned policy profile.
    #[must_use]
    pub const fn purpose_policy_is_consistent(&self) -> bool {
        matches!(
            (self.purpose, self.policy_id),
            (TrustPurpose::Generic, TrustPolicyId::GenericX509V1)
                | (TrustPurpose::QeaaIssuer, TrustPolicyId::EuQeaaV1)
                | (TrustPurpose::QwacTlsServer, TrustPolicyId::EuQwacV1)
                | (TrustPurpose::QsealSigner, TrustPolicyId::EuQsealV1)
                | (
                    TrustPurpose::TrustedListSigner,
                    TrustPolicyId::EuTrustedListSignerV1
                )
                | (
                    TrustPurpose::WalletAttestationIssuer,
                    TrustPolicyId::WalletAttestationIssuerV1
                )
                | (
                    TrustPurpose::JadesSigner,
                    TrustPolicyId::EtsiJadesBaselineBV1
                )
                | (
                    TrustPurpose::PidIssuance,
                    TrustPolicyId::EtsiTs1194126PidProviderV1
                )
                | (TrustPurpose::PidStatus, TrustPolicyId::EudiPidStatusV1)
                | (
                    TrustPurpose::EudiWalletProviderAttestation,
                    TrustPolicyId::EtsiTs1194126WalletProviderV1
                )
                | (
                    TrustPurpose::EudiWalletOrKeyStorageStatus,
                    TrustPolicyId::EudiWalletOrKeyStorageStatusV1
                )
                | (
                    TrustPurpose::WalletRelyingPartyAccessCertificate,
                    TrustPolicyId::EtsiTs1194118WrpacV1
                )
                | (
                    TrustPurpose::WalletRelyingPartyRegistrationCertificate,
                    TrustPolicyId::EtsiTs119475WrprcV1
                )
                | (
                    TrustPurpose::WalletRelyingPartyRegistrationCertificateStatus,
                    TrustPolicyId::EtsiTs119475WrprcStatusV1
                )
                | (
                    TrustPurpose::WalletRelyingPartyRegistrySigning,
                    TrustPolicyId::EudiTs5RegistryResponseSigningV1
                )
        )
    }
}

/// Purpose- and policy-scoped direct trust in an exact end-entity certificate.
#[derive(Clone)]
pub struct DirectTrustEntry {
    /// Exact certificate bytes accepted by this entry.
    pub certificate: X509Certificate,
    /// Purpose for which this entry is valid.
    pub purpose: TrustPurpose,
    /// Policy under which this entry was provisioned.
    pub policy_id: TrustPolicyId,
    /// Exact external trust source and immutable snapshot that provisioned the entry.
    pub source: TrustSourceEvidence,
}

impl core::fmt::Debug for DirectTrustEntry {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DirectTrustEntry")
            .field("certificate", &"<redacted>")
            .field("purpose", &self.purpose)
            .field("policy_id", &self.policy_id)
            .field("source", &self.source)
            .finish()
    }
}

/// Position of a certificate in an evaluated path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificatePosition {
    /// End-entity certificate.
    Leaf,
    /// Zero-based intermediate position after the leaf.
    Intermediate(u8),
    /// Terminal trust anchor.
    TrustAnchor,
}

/// Typed status result retained as audit evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateStatus {
    /// Status evidence established that the certificate is good.
    Good,
    /// Certificate is revoked.
    Revoked,
    /// Certificate is suspended.
    Suspended,
    /// Status is unknown to the authoritative source.
    Unknown,
    /// Status evidence could not be obtained.
    Unavailable,
    /// Status evidence was stale.
    Stale,
    /// Status evidence was not yet valid.
    NotYetValid,
    /// Status evidence was malformed or internally inconsistent.
    Malformed,
    /// Status evidence signature was invalid.
    InvalidSignature,
    /// The advertised status mechanism is unsupported.
    Unsupported,
    /// Policy explicitly exempted this certificate position.
    Exempt,
}

/// Status evidence for one certificate position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateStatusEvidence {
    /// Position in the selected or most relevant candidate path.
    pub position: CertificatePosition,
    /// Typed status result.
    pub status: CertificateStatus,
}

/// Kind of configured trust anchor that terminated evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustAnchorKind {
    /// A configured CA trust root terminated a certificate path.
    RootCertificate,
    /// An exact purpose-scoped end-entity entry terminated evaluation.
    DirectEndEntity,
}

/// Non-secret identity of the selected configured trust entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustAnchorEvidence {
    /// Kind of trust entry.
    pub kind: TrustAnchorKind,
    /// Zero-based index in the caller's configured trust collection.
    pub configured_index: u16,
}

/// Evidence retained for every trust decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustEvidence {
    /// Purpose evaluated.
    pub purpose: TrustPurpose,
    /// Policy profile evaluated.
    pub policy_id: TrustPolicyId,
    /// Caller-supplied evaluation time.
    pub evaluated_at: OffsetDateTime,
    /// External trust source/snapshot identity, when supplied.
    pub source: Option<TrustSourceEvidence>,
    /// Selected trust anchor for trusted decisions.
    pub trust_anchor: Option<TrustAnchorEvidence>,
    /// Per-position status evidence for the selected or most relevant path.
    pub certificate_status: Vec<CertificateStatusEvidence>,
}

/// Fixed, non-secret trust failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustFailureReason {
    /// No valid path reached a configured trust root.
    NoValidPath,

    /// Chain-link policy failed.
    ChainLinkPolicy,

    /// Certificate profile, time, or policy screening failed.
    Policy,

    /// Revocation or status checking failed.
    Status,

    /// A certificate was conclusively revoked.
    StatusRevoked,

    /// A certificate was conclusively suspended.
    StatusSuspended,

    /// Required status was unknown.
    StatusUnknown,

    /// Required status evidence was unavailable.
    StatusUnavailable,

    /// Required status evidence was stale.
    StatusStale,

    /// Required status evidence was not yet valid.
    StatusNotYetValid,

    /// Required status evidence was malformed.
    StatusMalformed,

    /// Required status evidence had an invalid signature.
    StatusInvalidSignature,

    /// The required status mechanism was unsupported.
    StatusUnsupported,

    /// Certificate signature verification failed.
    Signature,

    /// Signature verification could not run for a supported security decision.
    SignatureIndeterminate,

    /// Evaluation time could not be represented at a status boundary.
    InvalidEvaluationTime,

    /// The bounded candidate-path search budget was exhausted.
    PathSearchLimit,
}

//
// ------------------------------------------------------------
// AKI/SKI validation
// ------------------------------------------------------------
//

/// Chain linking policy (non-crypto).
#[derive(Debug, Clone)]
pub struct ChainLinkPolicy {
    /// Require subject/issuer DN continuity for each hop.
    pub require_dn_continuity: bool,

    /// If true: require AKI present on non-root certs and SKI present on issuers, and require matches.
    /// If false: if either side missing, skip AKI/SKI check for that hop.
    pub require_aki_ski_when_present: bool,
}

impl Default for ChainLinkPolicy {
    fn default() -> Self {
        Self {
            require_dn_continuity: true,
            require_aki_ski_when_present: true,
        }
    }
}

//
// ------------------------------------------------------------
// Signature verification abstraction
// ------------------------------------------------------------
//

/// Signature verification failures produced by a concrete backend.
#[derive(Debug, Error)]
pub enum SignatureVerifyError {
    /// Signature bytes did not verify for the signed certificate data.
    #[error("signature verification failed")]
    InvalidSignature,

    /// Certificate signature algorithm is unsupported by the backend.
    #[error("unsupported or unknown algorithm")]
    UnsupportedAlgorithm,

    /// Backend parser or verifier failed without exposing implementation details.
    #[error("backend verification failure")]
    BackendFailure,
}

include!("model/error_mapping.rs");

/// Trait for cryptographic signature verification.
///
/// Implemented by:
/// - OpenSSL backend
/// - RustCrypto / rustls backend
/// - WASM / browser backend
pub trait SignatureVerifier {
    /// Verify signatures across a parsed certificate chain.
    fn verify_chain(
        &self,
        chain: &X509Chain,
        now: OffsetDateTime,
    ) -> Result<(), SignatureVerifyError>;
}

#[cfg(test)]
#[path = "model_proto_error_tests.rs"]
mod proto_error_tests;
