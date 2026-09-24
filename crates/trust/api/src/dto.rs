// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{EnumValue, Enumeration};
use reallyme_ssi_proto::generated::proto::identity::trust::v1 as trust_pb;
use zeroize::{Zeroize, ZeroizeOnDrop};

include!("dto/error.rs");

const MAX_TRUST_DECISION_FAILURES: usize = 32;
const MAX_TRUST_DECISION_PATH_CERTIFICATES: usize = 10;

/// Trust evaluation result for Rust callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustDecision {
    /// Whether the trust decision accepted the chain and policy.
    pub accepted: bool,
    /// Authoritative three-state outcome.
    pub outcome: TrustDecisionOutcome,
    /// Fixed, non-secret failure reasons.
    pub failures: Vec<TrustDecisionFailure>,
    /// Reproducible, non-secret trust evidence.
    pub evidence: TrustDecisionEvidence,
}

/// Authoritative three-state trust outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDecisionOutcome {
    /// Trust was conclusively established.
    Trusted,
    /// Trust policy was conclusively violated.
    Rejected,
    /// Required evidence or verification capability was unavailable.
    Indeterminate,
}

/// Stable trust-purpose identifier retained in decision evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustPurpose {
    /// Generic X.509 validation.
    Generic,
    /// Qualified electronic attestation issuer authorization.
    QeaaIssuer,
    /// Qualified website authentication server authorization.
    QwacTlsServer,
    /// Qualified electronic seal signer authorization.
    QsealSigner,
    /// Trusted-list XML signer authorization.
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

/// Stable trust-policy identifier retained in decision evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustPolicyId {
    /// Baseline caller-supplied X.509 policy.
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
    /// PID status policy identity.
    EudiPidStatusV1,
    /// ETSI TS 119 412-6 wallet-provider signing-certificate policy.
    EtsiTs1194126WalletProviderV1,
    /// Wallet/key-storage status policy identity.
    EudiWalletOrKeyStorageStatusV1,
    /// ETSI TS 119 411-8 WRPAC policy.
    EtsiTs1194118WrpacV1,
    /// ETSI TS 119 475 WRPRC policy.
    EtsiTs119475WrprcV1,
    /// ETSI TS 119 475 WRPRC status policy.
    EtsiTs119475WrprcStatusV1,
    /// EUDI TS5 v1.5 national registry-response signing policy.
    EudiTs5RegistryResponseSigningV1,
}

/// Identity of the trust source snapshot used for evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustSourceEvidence {
    /// Stable source identity.
    pub source_id: [u8; 32],
    /// Immutable source snapshot identity.
    pub snapshot_id: [u8; 32],
}

/// Kind of configured trust entry that terminated evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustAnchorKind {
    /// Configured root certificate.
    RootCertificate,
    /// Exact, purpose-scoped end-entity certificate.
    DirectEndEntity,
}

/// Identity of the configured trust entry selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustAnchorEvidence {
    /// Kind of trust entry.
    pub kind: TrustAnchorKind,
    /// Index in the caller's configured collection.
    pub configured_index: u16,
}

/// Certificate position in the selected path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificatePosition {
    /// End-entity certificate.
    Leaf,
    /// Zero-based intermediate index.
    Intermediate(u8),
    /// Terminal trust anchor.
    TrustAnchor,
}

/// Typed certificate-status evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateStatus {
    /// Positive status evidence.
    Good,
    /// Certificate is revoked.
    Revoked,
    /// Certificate is suspended.
    Suspended,
    /// Authoritative responder does not know the certificate.
    Unknown,
    /// Status evidence could not be obtained.
    Unavailable,
    /// Status evidence is stale.
    Stale,
    /// Status evidence is not yet valid.
    NotYetValid,
    /// Status evidence is malformed.
    Malformed,
    /// Status signature is invalid.
    InvalidSignature,
    /// Status mechanism is unsupported.
    Unsupported,
    /// Position is explicitly exempt by policy.
    Exempt,
}

/// Status evidence for one selected-path certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateStatusEvidence {
    /// Position in the selected path.
    pub position: CertificatePosition,
    /// Status result.
    pub status: CertificateStatus,
}

/// Evidence retained by a public trust decision receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustDecisionEvidence {
    /// Authorization purpose.
    pub purpose: TrustPurpose,
    /// Applied policy profile.
    pub policy_id: TrustPolicyId,
    /// Caller-supplied evaluation time in Unix seconds.
    pub evaluated_at_unix: i64,
    /// External source identity, when applicable.
    pub source: Option<TrustSourceEvidence>,
    /// Selected configured trust entry, when trusted.
    pub trust_anchor: Option<TrustAnchorEvidence>,
    /// Per-position status results.
    pub certificate_status: Vec<CertificateStatusEvidence>,
    /// SHA-256 certificate fingerprints in leaf-to-anchor order.
    pub selected_path_certificate_sha256: Vec<[u8; 32]>,
}

/// Fixed trust-decision failure reason for JSON/API callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDecisionFailure {
    /// No valid path reached a configured trust root.
    NoValidPath,

    /// Chain-link policy failed.
    ChainLinkPolicy,

    /// Certificate profile, time, or policy screening failed.
    Policy,

    /// Revocation or status checking failed.
    Status,

    /// Certificate signature verification failed.
    Signature,

    /// Certificate was revoked.
    StatusRevoked,

    /// Certificate was suspended.
    StatusSuspended,

    /// Status was unknown.
    StatusUnknown,

    /// Status evidence was unavailable.
    StatusUnavailable,

    /// Status evidence was stale.
    StatusStale,

    /// Status evidence was not yet valid.
    StatusNotYetValid,

    /// Status evidence was malformed.
    StatusMalformed,

    /// Status evidence had an invalid signature.
    StatusInvalidSignature,

    /// Status mechanism was unsupported.
    StatusUnsupported,

    /// Signature verification capability was unavailable or unsupported.
    SignatureIndeterminate,

    /// Evaluation time was invalid for a required boundary.
    InvalidEvaluationTime,

    /// The bounded candidate-path search budget was exhausted.
    PathSearchLimit,
}

impl From<TrustDecisionFailure> for trust_pb::TrustDecisionFailure {
    fn from(failure: TrustDecisionFailure) -> Self {
        match failure {
            TrustDecisionFailure::NoValidPath => Self::TRUST_DECISION_FAILURE_NO_VALID_PATH,
            TrustDecisionFailure::ChainLinkPolicy => Self::TRUST_DECISION_FAILURE_CHAIN_LINK_POLICY,
            TrustDecisionFailure::Policy => Self::TRUST_DECISION_FAILURE_POLICY,
            TrustDecisionFailure::Status => Self::TRUST_DECISION_FAILURE_STATUS,
            TrustDecisionFailure::Signature => Self::TRUST_DECISION_FAILURE_SIGNATURE,
            TrustDecisionFailure::StatusRevoked => Self::TRUST_DECISION_FAILURE_STATUS_REVOKED,
            TrustDecisionFailure::StatusSuspended => Self::TRUST_DECISION_FAILURE_STATUS_SUSPENDED,
            TrustDecisionFailure::StatusUnknown => Self::TRUST_DECISION_FAILURE_STATUS_UNKNOWN,
            TrustDecisionFailure::StatusUnavailable => {
                Self::TRUST_DECISION_FAILURE_STATUS_UNAVAILABLE
            }
            TrustDecisionFailure::StatusStale => Self::TRUST_DECISION_FAILURE_STATUS_STALE,
            TrustDecisionFailure::StatusNotYetValid => {
                Self::TRUST_DECISION_FAILURE_STATUS_NOT_YET_VALID
            }
            TrustDecisionFailure::StatusMalformed => Self::TRUST_DECISION_FAILURE_STATUS_MALFORMED,
            TrustDecisionFailure::StatusInvalidSignature => {
                Self::TRUST_DECISION_FAILURE_STATUS_INVALID_SIGNATURE
            }
            TrustDecisionFailure::StatusUnsupported => {
                Self::TRUST_DECISION_FAILURE_STATUS_UNSUPPORTED
            }
            TrustDecisionFailure::SignatureIndeterminate => {
                Self::TRUST_DECISION_FAILURE_SIGNATURE_INDETERMINATE
            }
            TrustDecisionFailure::InvalidEvaluationTime => {
                Self::TRUST_DECISION_FAILURE_INVALID_EVALUATION_TIME
            }
            TrustDecisionFailure::PathSearchLimit => Self::TRUST_DECISION_FAILURE_PATH_SEARCH_LIMIT,
        }
    }
}

impl TryFrom<EnumValue<trust_pb::TrustDecisionFailure>> for TrustDecisionFailure {
    type Error = TrustProtoError;

    fn try_from(value: EnumValue<trust_pb::TrustDecisionFailure>) -> Result<Self, Self::Error> {
        match trust_pb::TrustDecisionFailure::from_i32(value.to_i32()) {
            Some(trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_NO_VALID_PATH) => {
                Ok(Self::NoValidPath)
            }
            Some(trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_CHAIN_LINK_POLICY) => {
                Ok(Self::ChainLinkPolicy)
            }
            Some(trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_POLICY) => Ok(Self::Policy),
            Some(trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_STATUS) => Ok(Self::Status),
            Some(trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_SIGNATURE) => {
                Ok(Self::Signature)
            }
            Some(trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_STATUS_REVOKED) => {
                Ok(Self::StatusRevoked)
            }
            Some(trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_STATUS_SUSPENDED) => {
                Ok(Self::StatusSuspended)
            }
            Some(trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_STATUS_UNKNOWN) => {
                Ok(Self::StatusUnknown)
            }
            Some(trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_STATUS_UNAVAILABLE) => {
                Ok(Self::StatusUnavailable)
            }
            Some(trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_STATUS_STALE) => {
                Ok(Self::StatusStale)
            }
            Some(trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_STATUS_NOT_YET_VALID) => {
                Ok(Self::StatusNotYetValid)
            }
            Some(trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_STATUS_MALFORMED) => {
                Ok(Self::StatusMalformed)
            }
            Some(
                trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_STATUS_INVALID_SIGNATURE,
            ) => Ok(Self::StatusInvalidSignature),
            Some(trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_STATUS_UNSUPPORTED) => {
                Ok(Self::StatusUnsupported)
            }
            Some(
                trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_SIGNATURE_INDETERMINATE,
            ) => Ok(Self::SignatureIndeterminate),
            Some(
                trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_INVALID_EVALUATION_TIME,
            ) => Ok(Self::InvalidEvaluationTime),
            Some(trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_PATH_SEARCH_LIMIT) => {
                Ok(Self::PathSearchLimit)
            }
            _ => Err(TrustProtoError::UnknownDecisionFailure),
        }
    }
}

impl From<TrustDecisionOutcome> for trust_pb::TrustDecisionOutcome {
    fn from(outcome: TrustDecisionOutcome) -> Self {
        match outcome {
            TrustDecisionOutcome::Trusted => Self::TRUST_DECISION_OUTCOME_TRUSTED,
            TrustDecisionOutcome::Rejected => Self::TRUST_DECISION_OUTCOME_REJECTED,
            TrustDecisionOutcome::Indeterminate => Self::TRUST_DECISION_OUTCOME_INDETERMINATE,
        }
    }
}

fn decision_outcome_from_proto(
    value: EnumValue<trust_pb::TrustDecisionOutcome>,
) -> Result<TrustDecisionOutcome, TrustProtoError> {
    match trust_pb::TrustDecisionOutcome::from_i32(value.to_i32()) {
        Some(trust_pb::TrustDecisionOutcome::TRUST_DECISION_OUTCOME_TRUSTED) => {
            Ok(TrustDecisionOutcome::Trusted)
        }
        Some(trust_pb::TrustDecisionOutcome::TRUST_DECISION_OUTCOME_REJECTED) => {
            Ok(TrustDecisionOutcome::Rejected)
        }
        Some(trust_pb::TrustDecisionOutcome::TRUST_DECISION_OUTCOME_INDETERMINATE) => {
            Ok(TrustDecisionOutcome::Indeterminate)
        }
        _ => Err(TrustProtoError::UnknownDecisionOutcome),
    }
}

impl From<TrustPurpose> for trust_pb::TrustPurpose {
    fn from(purpose: TrustPurpose) -> Self {
        match purpose {
            TrustPurpose::Generic => Self::TRUST_PURPOSE_GENERIC,
            TrustPurpose::QeaaIssuer => Self::TRUST_PURPOSE_QEAA_ISSUER,
            TrustPurpose::QwacTlsServer => Self::TRUST_PURPOSE_QWAC_TLS_SERVER,
            TrustPurpose::QsealSigner => Self::TRUST_PURPOSE_QSEAL_SIGNER,
            TrustPurpose::TrustedListSigner => Self::TRUST_PURPOSE_TRUSTED_LIST_SIGNER,
            TrustPurpose::WalletAttestationIssuer => Self::TRUST_PURPOSE_WALLET_ATTESTATION_ISSUER,
            TrustPurpose::JadesSigner => Self::TRUST_PURPOSE_JADES_SIGNER,
            TrustPurpose::PidIssuance => Self::TRUST_PURPOSE_PID_ISSUANCE,
            TrustPurpose::PidStatus => Self::TRUST_PURPOSE_PID_STATUS,
            TrustPurpose::EudiWalletProviderAttestation => {
                Self::TRUST_PURPOSE_EUDI_WALLET_PROVIDER_ATTESTATION
            }
            TrustPurpose::EudiWalletOrKeyStorageStatus => {
                Self::TRUST_PURPOSE_EUDI_WALLET_OR_KEY_STORAGE_STATUS
            }
            TrustPurpose::WalletRelyingPartyAccessCertificate => {
                Self::TRUST_PURPOSE_WALLET_RELYING_PARTY_ACCESS_CERTIFICATE
            }
            TrustPurpose::WalletRelyingPartyRegistrationCertificate => {
                Self::TRUST_PURPOSE_WALLET_RELYING_PARTY_REGISTRATION_CERTIFICATE
            }
            TrustPurpose::WalletRelyingPartyRegistrationCertificateStatus => {
                Self::TRUST_PURPOSE_WALLET_RELYING_PARTY_REGISTRATION_CERTIFICATE_STATUS
            }
            TrustPurpose::WalletRelyingPartyRegistrySigning => {
                Self::TRUST_PURPOSE_WALLET_RELYING_PARTY_REGISTRY_SIGNING
            }
        }
    }
}

fn trust_purpose_from_proto(
    value: EnumValue<trust_pb::TrustPurpose>,
) -> Result<TrustPurpose, TrustProtoError> {
    match trust_pb::TrustPurpose::from_i32(value.to_i32()) {
        Some(trust_pb::TrustPurpose::TRUST_PURPOSE_GENERIC) => Ok(TrustPurpose::Generic),
        Some(trust_pb::TrustPurpose::TRUST_PURPOSE_QEAA_ISSUER) => Ok(TrustPurpose::QeaaIssuer),
        Some(trust_pb::TrustPurpose::TRUST_PURPOSE_QWAC_TLS_SERVER) => {
            Ok(TrustPurpose::QwacTlsServer)
        }
        Some(trust_pb::TrustPurpose::TRUST_PURPOSE_QSEAL_SIGNER) => Ok(TrustPurpose::QsealSigner),
        Some(trust_pb::TrustPurpose::TRUST_PURPOSE_TRUSTED_LIST_SIGNER) => {
            Ok(TrustPurpose::TrustedListSigner)
        }
        Some(trust_pb::TrustPurpose::TRUST_PURPOSE_WALLET_ATTESTATION_ISSUER) => {
            Ok(TrustPurpose::WalletAttestationIssuer)
        }
        Some(trust_pb::TrustPurpose::TRUST_PURPOSE_JADES_SIGNER) => Ok(TrustPurpose::JadesSigner),
        Some(trust_pb::TrustPurpose::TRUST_PURPOSE_PID_ISSUANCE) => Ok(TrustPurpose::PidIssuance),
        Some(trust_pb::TrustPurpose::TRUST_PURPOSE_PID_STATUS) => Ok(TrustPurpose::PidStatus),
        Some(trust_pb::TrustPurpose::TRUST_PURPOSE_EUDI_WALLET_PROVIDER_ATTESTATION) => {
            Ok(TrustPurpose::EudiWalletProviderAttestation)
        }
        Some(trust_pb::TrustPurpose::TRUST_PURPOSE_EUDI_WALLET_OR_KEY_STORAGE_STATUS) => {
            Ok(TrustPurpose::EudiWalletOrKeyStorageStatus)
        }
        Some(trust_pb::TrustPurpose::TRUST_PURPOSE_WALLET_RELYING_PARTY_ACCESS_CERTIFICATE) => {
            Ok(TrustPurpose::WalletRelyingPartyAccessCertificate)
        }
        Some(
            trust_pb::TrustPurpose::TRUST_PURPOSE_WALLET_RELYING_PARTY_REGISTRATION_CERTIFICATE,
        ) => Ok(TrustPurpose::WalletRelyingPartyRegistrationCertificate),
        Some(
            trust_pb::TrustPurpose::TRUST_PURPOSE_WALLET_RELYING_PARTY_REGISTRATION_CERTIFICATE_STATUS,
        ) => Ok(TrustPurpose::WalletRelyingPartyRegistrationCertificateStatus),
        Some(trust_pb::TrustPurpose::TRUST_PURPOSE_WALLET_RELYING_PARTY_REGISTRY_SIGNING) => {
            Ok(TrustPurpose::WalletRelyingPartyRegistrySigning)
        }
        _ => Err(TrustProtoError::UnknownTrustPurpose),
    }
}

include!("dto/convert.rs");
include!("dto/semantics.rs");
