// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use envelopes_x509::model::X509Certificate;
use time::OffsetDateTime;

use reallyme_trust_core::{
    evaluate_trust_decision as core_evaluate_trust, CertificatePosition as CoreCertificatePosition,
    CertificateStatus as CoreCertificateStatus, ChainLinkPolicy, ChainLinkPolicyViolation,
    SignatureVerifier, TrustAnchorKind as CoreTrustAnchorKind, TrustConfig,
    TrustDecision as CoreTrustDecision, TrustError, TrustEvaluationContext, TrustFailureReason,
    TrustOutcome as CoreTrustOutcome, TrustPolicyId as CoreTrustPolicyId,
    TrustPurpose as CoreTrustPurpose,
};

use identity_revocation_core::StatusChecker;
use identity_trust_tsl_core::TrustedList;

use crate::{
    AuthorizationPurpose, CertificatePosition, CertificateStatus, CertificateStatusEvidence,
    TrustAnchorEvidence, TrustAnchorKind, TrustApiError, TrustApiResult, TrustDecision,
    TrustDecisionEvidence, TrustDecisionFailure, TrustDecisionOutcome, TrustPolicyErrorReason,
    TrustPolicyId, TrustPurpose, TrustSourceEvidence,
};

use crate::authorize::authorize_issuer;

fn baseline_rfc5280_policy() -> envelopes_x509::policy::X509Policy {
    envelopes_x509::policy::X509Policy {
        require_leaf_digital_signature: true,
        trust_anchor_requirement: envelopes_x509::policy::TrustAnchorRequirement::Rfc5280Ca,
        ..Default::default()
    }
}

/// ---------------------------------------------------------------------------
/// Typed trust evaluation (NO JSON, NO IO)
/// ---------------------------------------------------------------------------
pub fn evaluate_trust_api(
    chain: Vec<X509Certificate>,
    trust_roots: Vec<X509Certificate>,
    sig_verifier: &dyn SignatureVerifier,
    status_checker: Option<&dyn StatusChecker>,
    now: OffsetDateTime,
) -> TrustApiResult<TrustDecision> {
    let cfg = TrustConfig {
        trust_roots,
        now,
        policy: baseline_rfc5280_policy(),
        link_policy: ChainLinkPolicy::default(),
        evaluation: Default::default(),
        direct_trust: Vec::new(),
    };

    evaluate_trust_configured_api(chain, cfg, sig_verifier, status_checker)
}

/// Evaluate a caller-supplied, fully typed trust configuration.
///
/// This is the audit-facing entry point for purpose/source-scoped PKIX and
/// direct end-entity trust. Unlike the compatibility helper, it preserves
/// rejected and indeterminate decisions as values rather than collapsing them
/// into a Boolean or generic error.
pub fn evaluate_trust_configured_api(
    presented: Vec<X509Certificate>,
    config: TrustConfig,
    sig_verifier: &dyn SignatureVerifier,
    status_checker: Option<&dyn StatusChecker>,
) -> TrustApiResult<TrustDecision> {
    let decision = core_evaluate_trust(&presented, &config, sig_verifier, status_checker)
        .map_err(map_trust_error)?;
    Ok(map_core_decision(decision))
}

fn core_context_for_authorization(purpose: AuthorizationPurpose) -> TrustEvaluationContext {
    let (purpose, policy_id) = match purpose {
        AuthorizationPurpose::QeaaIssuer => {
            (CoreTrustPurpose::QeaaIssuer, CoreTrustPolicyId::EuQeaaV1)
        }
        AuthorizationPurpose::QwacTlsServer => {
            (CoreTrustPurpose::QwacTlsServer, CoreTrustPolicyId::EuQwacV1)
        }
        AuthorizationPurpose::QsealSigner => {
            (CoreTrustPurpose::QsealSigner, CoreTrustPolicyId::EuQsealV1)
        }
    };
    TrustEvaluationContext {
        purpose,
        policy_id,
        ..Default::default()
    }
}

/// ---------------------------------------------------------------------------
/// Typed trust evaluation + optional TSL authorization
/// ---------------------------------------------------------------------------
pub fn verify_credential_trust_api(
    chain: Vec<X509Certificate>,
    trust_roots: Vec<X509Certificate>,
    sig_verifier: &dyn SignatureVerifier,
    status_checker: Option<&dyn StatusChecker>,
    tsl: Option<&TrustedList>,
    purpose: Option<AuthorizationPurpose>,
    now: OffsetDateTime,
) -> TrustApiResult<TrustDecision> {
    let cfg = TrustConfig {
        trust_roots,
        now,
        policy: baseline_rfc5280_policy(),
        link_policy: ChainLinkPolicy::default(),
        evaluation: purpose
            .map(core_context_for_authorization)
            .unwrap_or_default(),
        direct_trust: Vec::new(),
    };

    let decision: CoreTrustDecision =
        core_evaluate_trust(&chain, &cfg, sig_verifier, status_checker).map_err(map_trust_error)?;

    if let (Some(tsl), Some(purpose)) = (tsl, purpose) {
        authorize_issuer(&decision, tsl, purpose)?;
    }

    Ok(map_core_decision(decision))
}

/// ---------------------------------------------------------------------------
/// Core → API error mapping
/// ---------------------------------------------------------------------------
fn map_trust_error(e: TrustError) -> TrustApiError {
    match e {
        TrustError::Revoked => TrustApiError::Revoked,
        TrustError::InvalidSignature => TrustApiError::InvalidSignature,
        TrustError::ChainLinkPolicy(reason) => TrustApiError::Policy(map_chain_link_reason(reason)),
        TrustError::ResourceLimit(_) | TrustError::PurposePolicyMismatch => {
            TrustApiError::InvalidInput
        }
        _ => TrustApiError::NotTrusted,
    }
}

fn map_chain_link_reason(reason: ChainLinkPolicyViolation) -> TrustPolicyErrorReason {
    match reason {
        ChainLinkPolicyViolation::IssuerDistinguishedNameMismatch => {
            TrustPolicyErrorReason::IssuerDistinguishedNameMismatch
        }
        ChainLinkPolicyViolation::AuthorityKeyIdentifierMismatch => {
            TrustPolicyErrorReason::AuthorityKeyIdentifierMismatch
        }
        ChainLinkPolicyViolation::MissingAuthorityKeyIdentifier => {
            TrustPolicyErrorReason::MissingAuthorityKeyIdentifier
        }
        ChainLinkPolicyViolation::MissingSubjectKeyIdentifier => {
            TrustPolicyErrorReason::MissingSubjectKeyIdentifier
        }
        ChainLinkPolicyViolation::MissingKeyIdentifiers => {
            TrustPolicyErrorReason::MissingKeyIdentifiers
        }
    }
}

fn map_trust_failure_reason(reason: TrustFailureReason) -> TrustDecisionFailure {
    match reason {
        TrustFailureReason::NoValidPath => TrustDecisionFailure::NoValidPath,
        TrustFailureReason::ChainLinkPolicy => TrustDecisionFailure::ChainLinkPolicy,
        TrustFailureReason::Policy => TrustDecisionFailure::Policy,
        TrustFailureReason::Status => TrustDecisionFailure::Status,
        TrustFailureReason::StatusRevoked => TrustDecisionFailure::StatusRevoked,
        TrustFailureReason::StatusSuspended => TrustDecisionFailure::StatusSuspended,
        TrustFailureReason::StatusUnknown => TrustDecisionFailure::StatusUnknown,
        TrustFailureReason::StatusUnavailable => TrustDecisionFailure::StatusUnavailable,
        TrustFailureReason::StatusStale => TrustDecisionFailure::StatusStale,
        TrustFailureReason::StatusNotYetValid => TrustDecisionFailure::StatusNotYetValid,
        TrustFailureReason::StatusMalformed => TrustDecisionFailure::StatusMalformed,
        TrustFailureReason::StatusInvalidSignature => TrustDecisionFailure::StatusInvalidSignature,
        TrustFailureReason::StatusUnsupported => TrustDecisionFailure::StatusUnsupported,
        TrustFailureReason::Signature => TrustDecisionFailure::Signature,
        TrustFailureReason::SignatureIndeterminate => TrustDecisionFailure::SignatureIndeterminate,
        TrustFailureReason::InvalidEvaluationTime => TrustDecisionFailure::InvalidEvaluationTime,
        TrustFailureReason::PathSearchLimit => TrustDecisionFailure::PathSearchLimit,
    }
}

fn map_core_decision(decision: CoreTrustDecision) -> TrustDecision {
    let selected_path_certificate_sha256 = decision
        .chain
        .as_ref()
        .map(|chain| {
            chain
                .certs
                .iter()
                .map(|certificate| reallyme_crypto::sha2::digest(&certificate.der).into_bytes())
                .collect()
        })
        .unwrap_or_default();
    let evidence = TrustDecisionEvidence {
        purpose: map_core_purpose(decision.evidence.purpose),
        policy_id: map_core_policy(decision.evidence.policy_id),
        evaluated_at_unix: decision.evidence.evaluated_at.unix_timestamp(),
        source: decision.evidence.source.map(|source| TrustSourceEvidence {
            source_id: source.source_id,
            snapshot_id: source.snapshot_id,
        }),
        trust_anchor: decision
            .evidence
            .trust_anchor
            .map(|anchor| TrustAnchorEvidence {
                kind: match anchor.kind {
                    CoreTrustAnchorKind::RootCertificate => TrustAnchorKind::RootCertificate,
                    CoreTrustAnchorKind::DirectEndEntity => TrustAnchorKind::DirectEndEntity,
                },
                configured_index: anchor.configured_index,
            }),
        certificate_status: decision
            .evidence
            .certificate_status
            .into_iter()
            .map(|item| CertificateStatusEvidence {
                position: match item.position {
                    CoreCertificatePosition::Leaf => CertificatePosition::Leaf,
                    CoreCertificatePosition::Intermediate(index) => {
                        CertificatePosition::Intermediate(index)
                    }
                    CoreCertificatePosition::TrustAnchor => CertificatePosition::TrustAnchor,
                },
                status: map_core_status(item.status),
            })
            .collect(),
        selected_path_certificate_sha256,
    };

    TrustDecision {
        accepted: decision.accepted,
        outcome: match decision.outcome {
            CoreTrustOutcome::Trusted => TrustDecisionOutcome::Trusted,
            CoreTrustOutcome::Rejected => TrustDecisionOutcome::Rejected,
            CoreTrustOutcome::Indeterminate => TrustDecisionOutcome::Indeterminate,
        },
        failures: decision
            .failures
            .into_iter()
            .map(map_trust_failure_reason)
            .collect(),
        evidence,
    }
}

fn map_core_purpose(purpose: CoreTrustPurpose) -> TrustPurpose {
    match purpose {
        CoreTrustPurpose::Generic => TrustPurpose::Generic,
        CoreTrustPurpose::QeaaIssuer => TrustPurpose::QeaaIssuer,
        CoreTrustPurpose::QwacTlsServer => TrustPurpose::QwacTlsServer,
        CoreTrustPurpose::QsealSigner => TrustPurpose::QsealSigner,
        CoreTrustPurpose::TrustedListSigner => TrustPurpose::TrustedListSigner,
        CoreTrustPurpose::WalletAttestationIssuer => TrustPurpose::WalletAttestationIssuer,
        CoreTrustPurpose::JadesSigner => TrustPurpose::JadesSigner,
        CoreTrustPurpose::PidIssuance => TrustPurpose::PidIssuance,
        CoreTrustPurpose::PidStatus => TrustPurpose::PidStatus,
        CoreTrustPurpose::EudiWalletProviderAttestation => {
            TrustPurpose::EudiWalletProviderAttestation
        }
        CoreTrustPurpose::EudiWalletOrKeyStorageStatus => {
            TrustPurpose::EudiWalletOrKeyStorageStatus
        }
        CoreTrustPurpose::WalletRelyingPartyAccessCertificate => {
            TrustPurpose::WalletRelyingPartyAccessCertificate
        }
        CoreTrustPurpose::WalletRelyingPartyRegistrationCertificate => {
            TrustPurpose::WalletRelyingPartyRegistrationCertificate
        }
        CoreTrustPurpose::WalletRelyingPartyRegistrationCertificateStatus => {
            TrustPurpose::WalletRelyingPartyRegistrationCertificateStatus
        }
        CoreTrustPurpose::WalletRelyingPartyRegistrySigning => {
            TrustPurpose::WalletRelyingPartyRegistrySigning
        }
    }
}

fn map_core_policy(policy: CoreTrustPolicyId) -> TrustPolicyId {
    match policy {
        CoreTrustPolicyId::GenericX509V1 => TrustPolicyId::GenericX509V1,
        CoreTrustPolicyId::EuQeaaV1 => TrustPolicyId::EuQeaaV1,
        CoreTrustPolicyId::EuQwacV1 => TrustPolicyId::EuQwacV1,
        CoreTrustPolicyId::EuQsealV1 => TrustPolicyId::EuQsealV1,
        CoreTrustPolicyId::EuTrustedListSignerV1 => TrustPolicyId::EuTrustedListSignerV1,
        CoreTrustPolicyId::WalletAttestationIssuerV1 => TrustPolicyId::WalletAttestationIssuerV1,
        CoreTrustPolicyId::EtsiJadesBaselineBV1 => TrustPolicyId::EtsiJadesBaselineBV1,
        CoreTrustPolicyId::EtsiTs1194126PidProviderV1 => TrustPolicyId::EtsiTs1194126PidProviderV1,
        CoreTrustPolicyId::EudiPidStatusV1 => TrustPolicyId::EudiPidStatusV1,
        CoreTrustPolicyId::EtsiTs1194126WalletProviderV1 => {
            TrustPolicyId::EtsiTs1194126WalletProviderV1
        }
        CoreTrustPolicyId::EudiWalletOrKeyStorageStatusV1 => {
            TrustPolicyId::EudiWalletOrKeyStorageStatusV1
        }
        CoreTrustPolicyId::EtsiTs1194118WrpacV1 => TrustPolicyId::EtsiTs1194118WrpacV1,
        CoreTrustPolicyId::EtsiTs119475WrprcV1 => TrustPolicyId::EtsiTs119475WrprcV1,
        CoreTrustPolicyId::EtsiTs119475WrprcStatusV1 => TrustPolicyId::EtsiTs119475WrprcStatusV1,
        CoreTrustPolicyId::EudiTs5RegistryResponseSigningV1 => {
            TrustPolicyId::EudiTs5RegistryResponseSigningV1
        }
    }
}

fn map_core_status(status: CoreCertificateStatus) -> CertificateStatus {
    match status {
        CoreCertificateStatus::Good => CertificateStatus::Good,
        CoreCertificateStatus::Revoked => CertificateStatus::Revoked,
        CoreCertificateStatus::Suspended => CertificateStatus::Suspended,
        CoreCertificateStatus::Unknown => CertificateStatus::Unknown,
        CoreCertificateStatus::Unavailable => CertificateStatus::Unavailable,
        CoreCertificateStatus::Stale => CertificateStatus::Stale,
        CoreCertificateStatus::NotYetValid => CertificateStatus::NotYetValid,
        CoreCertificateStatus::Malformed => CertificateStatus::Malformed,
        CoreCertificateStatus::InvalidSignature => CertificateStatus::InvalidSignature,
        CoreCertificateStatus::Unsupported => CertificateStatus::Unsupported,
        CoreCertificateStatus::Exempt => CertificateStatus::Exempt,
    }
}
