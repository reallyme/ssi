// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use envelopes_x509::{
    parse_cert_der, policy::TrustAnchorRequirement, X509Certificate, X509Policy,
    MAX_X509_CHAIN_CERTIFICATES,
};
use reallyme_revocation::StatusChecker;
use reallyme_trust_core::{
    evaluate_trust_decision, CertificatePosition as CoreCertificatePosition,
    CertificateStatus as CoreCertificateStatus, ChainLinkPolicy, SignatureVerifier,
    TrustAnchorKind as CoreTrustAnchorKind, TrustConfig, TrustDecision as CoreTrustDecision,
    TrustFailureReason, TrustOutcome as CoreTrustOutcome, TrustPolicyId as CoreTrustPolicyId,
    TrustPurpose as CoreTrustPurpose, MAX_DIRECT_TRUST_ENTRIES, MAX_TRUST_ROOTS,
};
use time::OffsetDateTime;

use crate::dto::{
    CertificatePosition, CertificateStatus, CertificateStatusEvidence, TrustAnchorEvidence,
    TrustAnchorKind, TrustDecision, TrustDecisionEvidence, TrustDecisionFailure,
    TrustDecisionOutcome, TrustPolicyId, TrustPurpose, TrustSourceEvidence,
};
use crate::{TrustApiError, TrustApiResult};

fn baseline_rfc5280_policy() -> X509Policy {
    X509Policy {
        require_leaf_digital_signature: true,
        trust_anchor_requirement: TrustAnchorRequirement::Rfc5280Ca,
        ..Default::default()
    }
}

/// Evaluate a presented certificate set against configured roots using the
/// fixed RFC 5280 CA baseline. The caller supplies the signature backend and
/// optional status verifier; no network or platform provider is selected.
pub fn evaluate_trust_api(
    presented: Vec<X509Certificate>,
    trust_roots: Vec<X509Certificate>,
    sig_verifier: &dyn SignatureVerifier,
    status_checker: Option<&dyn StatusChecker>,
    now: OffsetDateTime,
) -> TrustApiResult<TrustDecision> {
    let config = TrustConfig {
        trust_roots,
        now,
        policy: baseline_rfc5280_policy(),
        link_policy: ChainLinkPolicy::default(),
        evaluation: Default::default(),
        direct_trust: Vec::new(),
    };
    evaluate_trust_configured_api(presented, config, sig_verifier, status_checker)
}

/// Evaluate a typed purpose, policy, time, trust source, and per-position status
/// policy. Required status evidence is enforced by the trust core and produces
/// an indeterminate decision when its checker or evidence is unavailable.
pub fn evaluate_trust_configured_api(
    presented: Vec<X509Certificate>,
    config: TrustConfig,
    sig_verifier: &dyn SignatureVerifier,
    status_checker: Option<&dyn StatusChecker>,
) -> TrustApiResult<TrustDecision> {
    if presented.len() > MAX_X509_CHAIN_CERTIFICATES
        || config.trust_roots.len() > MAX_TRUST_ROOTS
        || config.direct_trust.len() > MAX_DIRECT_TRUST_ENTRIES
    {
        return Err(TrustApiError::InputLimit);
    }
    // X509Certificate exposes its parsed projection for callers. The core
    // screens those fields, while the backend authenticates DER. Reparse at
    // this public boundary so altered validity or policy fields cannot make a
    // different certificate appear to have passed the screened path.
    for certificate in presented
        .iter()
        .chain(config.trust_roots.iter())
        .chain(config.direct_trust.iter().map(|entry| &entry.certificate))
    {
        let canonical =
            parse_cert_der(&certificate.der).map_err(|_| TrustApiError::InvalidCertificate)?;
        if &canonical != certificate {
            return Err(TrustApiError::InvalidCertificate);
        }
    }
    let decision = evaluate_trust_decision(&presented, &config, sig_verifier, status_checker)?;
    map_core_decision(decision)
}

fn map_trust_failure_reason(reason: TrustFailureReason) -> TrustApiResult<TrustDecisionFailure> {
    Ok(match reason {
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
        // The core enum is non-exhaustive. A newly added reason must not be
        // relabeled as an older policy failure in an audit receipt.
        _ => return Err(TrustApiError::UnsupportedDecision),
    })
}

fn map_core_decision(decision: CoreTrustDecision) -> TrustApiResult<TrustDecision> {
    let selected_path_certificate_sha256 = decision
        .chain()
        .map(|chain| {
            chain
                .certs
                .iter()
                .map(|certificate| reallyme_crypto::sha2::digest(&certificate.der).into_bytes())
                .collect()
        })
        .unwrap_or_default();
    let evidence = TrustDecisionEvidence {
        purpose: map_core_purpose(decision.evidence().purpose)?,
        policy_id: map_core_policy(decision.evidence().policy_id)?,
        evaluated_at_unix: decision.evidence().evaluated_at.unix_timestamp(),
        source: decision
            .evidence()
            .source
            .map(|source| TrustSourceEvidence {
                source_id: source.source_id,
                snapshot_id: source.snapshot_id,
            }),
        trust_anchor: decision
            .evidence()
            .trust_anchor
            .map(|anchor| {
                let kind = match anchor.kind {
                    CoreTrustAnchorKind::RootCertificate => TrustAnchorKind::RootCertificate,
                    CoreTrustAnchorKind::DirectEndEntity => TrustAnchorKind::DirectEndEntity,
                    _ => return Err(TrustApiError::UnsupportedDecision),
                };
                Ok(TrustAnchorEvidence {
                    kind,
                    configured_index: anchor.configured_index,
                })
            })
            .transpose()?,
        certificate_status: decision
            .evidence()
            .certificate_status
            .iter()
            .map(|item| {
                let position = match item.position {
                    CoreCertificatePosition::Leaf => CertificatePosition::Leaf,
                    CoreCertificatePosition::Intermediate(index) => {
                        CertificatePosition::Intermediate(index)
                    }
                    CoreCertificatePosition::TrustAnchor => CertificatePosition::TrustAnchor,
                    _ => return Err(TrustApiError::UnsupportedDecision),
                };
                Ok(CertificateStatusEvidence {
                    position,
                    status: map_core_status(item.status)?,
                })
            })
            .collect::<TrustApiResult<Vec<_>>>()?,
        selected_path_certificate_sha256,
    };

    Ok(TrustDecision {
        accepted: decision.is_accepted(),
        outcome: match decision.outcome() {
            CoreTrustOutcome::Trusted => TrustDecisionOutcome::Trusted,
            CoreTrustOutcome::Rejected => TrustDecisionOutcome::Rejected,
            CoreTrustOutcome::Indeterminate => TrustDecisionOutcome::Indeterminate,
            _ => return Err(TrustApiError::UnsupportedDecision),
        },
        failures: decision
            .failures()
            .iter()
            .copied()
            .map(map_trust_failure_reason)
            .collect::<TrustApiResult<Vec<_>>>()?,
        evidence,
    })
}

fn map_core_purpose(purpose: CoreTrustPurpose) -> TrustApiResult<TrustPurpose> {
    Ok(match purpose {
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
        _ => return Err(TrustApiError::UnsupportedDecision),
    })
}

fn map_core_policy(policy: CoreTrustPolicyId) -> TrustApiResult<TrustPolicyId> {
    Ok(match policy {
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
        _ => return Err(TrustApiError::UnsupportedDecision),
    })
}

fn map_core_status(status: CoreCertificateStatus) -> TrustApiResult<CertificateStatus> {
    Ok(match status {
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
        CoreCertificateStatus::NotChecked => CertificateStatus::NotChecked,
        CoreCertificateStatus::Exempt => CertificateStatus::Exempt,
        _ => return Err(TrustApiError::UnsupportedDecision),
    })
}
