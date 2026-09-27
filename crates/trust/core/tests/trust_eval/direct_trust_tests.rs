// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{mock_cert, AllowAllSignatures, AllowAllStatus, RejectAllSignatures};
use envelopes_x509::{
    eu_policy, eudi_policy, policy::X509Policy, EuPreset, EudiCertificateProfile,
};
use reallyme_trust_core::{
    evaluate_trust_decision, CertificateStatusPolicy, DirectTrustEntry, StatusRequirement,
    TrustAnchorKind, TrustConfig, TrustError, TrustEvaluationContext, TrustOutcome, TrustPolicyId,
    TrustPurpose, TrustSourceEvidence,
};
use time::OffsetDateTime;

#[test]
fn direct_end_entity_trust_is_exact_and_context_scoped() {
    let leaf = mock_cert("CN=Direct", "CN=Direct", false, None, None);
    let source = TrustSourceEvidence {
        source_id: [7; 32],
        snapshot_id: [8; 32],
    };
    let cfg = TrustConfig {
        trust_roots: Vec::new(),
        now: OffsetDateTime::UNIX_EPOCH,
        policy: X509Policy::default(),
        link_policy: Default::default(),
        evaluation: TrustEvaluationContext {
            purpose: TrustPurpose::WalletAttestationIssuer,
            policy_id: TrustPolicyId::WalletAttestationIssuerV1,
            status_policy: CertificateStatusPolicy {
                leaf: StatusRequirement::Required,
                intermediates: StatusRequirement::Required,
                trust_anchor: StatusRequirement::Exempt,
            },
            source: Some(source),
        },
        direct_trust: vec![DirectTrustEntry {
            certificate: leaf.clone(),
            purpose: TrustPurpose::WalletAttestationIssuer,
            policy_id: TrustPolicyId::WalletAttestationIssuerV1,
            source,
        }],
    };

    let decision =
        evaluate_trust_decision(&[leaf], &cfg, &RejectAllSignatures, Some(&AllowAllStatus))
            .unwrap();

    assert_eq!(decision.outcome(), TrustOutcome::Trusted);
    assert_eq!(decision.evidence().source, Some(source));
    assert_eq!(
        decision.evidence().trust_anchor.unwrap().kind,
        TrustAnchorKind::DirectEndEntity
    );
}

#[test]
fn direct_end_entity_trust_rejects_a_different_policy_context() {
    let leaf = mock_cert("CN=Direct", "CN=Direct", false, None, None);
    let mut cfg = TrustConfig {
        trust_roots: Vec::new(),
        now: OffsetDateTime::UNIX_EPOCH,
        policy: X509Policy::default(),
        link_policy: Default::default(),
        evaluation: TrustEvaluationContext {
            purpose: TrustPurpose::WalletAttestationIssuer,
            policy_id: TrustPolicyId::WalletAttestationIssuerV1,
            source: Some(TrustSourceEvidence {
                source_id: [7; 32],
                snapshot_id: [8; 32],
            }),
            ..Default::default()
        },
        direct_trust: vec![DirectTrustEntry {
            certificate: leaf.clone(),
            purpose: TrustPurpose::WalletAttestationIssuer,
            policy_id: TrustPolicyId::WalletAttestationIssuerV1,
            source: TrustSourceEvidence {
                source_id: [7; 32],
                snapshot_id: [8; 32],
            },
        }],
    };
    cfg.evaluation.policy_id = TrustPolicyId::EuQeaaV1;

    let result =
        evaluate_trust_decision(std::slice::from_ref(&leaf), &cfg, &AllowAllSignatures, None);

    assert_eq!(result.err(), Some(TrustError::PurposePolicyMismatch));
}

#[test]
fn named_qwac_policy_rejects_a_baseline_policy_configuration() {
    let leaf = mock_cert("CN=Direct", "CN=Direct", false, None, None);
    let source = TrustSourceEvidence {
        source_id: [21; 32],
        snapshot_id: [22; 32],
    };
    let mut cfg = TrustConfig {
        trust_roots: Vec::new(),
        now: OffsetDateTime::UNIX_EPOCH,
        policy: X509Policy::default(),
        link_policy: Default::default(),
        evaluation: TrustEvaluationContext {
            purpose: TrustPurpose::QwacTlsServer,
            policy_id: TrustPolicyId::EuQwacV1,
            status_policy: CertificateStatusPolicy {
                leaf: StatusRequirement::Required,
                intermediates: StatusRequirement::Required,
                trust_anchor: StatusRequirement::Exempt,
            },
            source: Some(source),
        },
        direct_trust: vec![DirectTrustEntry {
            certificate: leaf.clone(),
            purpose: TrustPurpose::QwacTlsServer,
            policy_id: TrustPolicyId::EuQwacV1,
            source,
        }],
    };

    let result =
        evaluate_trust_decision(std::slice::from_ref(&leaf), &cfg, &AllowAllSignatures, None);
    assert_eq!(result.err(), Some(TrustError::PurposePolicyMismatch));

    cfg.policy = eu_policy(EuPreset::Qwac);
    let decision = evaluate_trust_decision(&[leaf], &cfg, &AllowAllSignatures, None)
        .expect("the named QWAC policy must accept its exact X.509 profile");
    assert_eq!(decision.outcome(), TrustOutcome::Rejected);
    assert_eq!(
        decision.failures(),
        &[reallyme_trust_core::TrustFailureReason::Policy]
    );
}

#[test]
fn composite_policy_labels_reject_modified_pkix_components() {
    let leaf = mock_cert("CN=Direct", "CN=Direct", false, None, None);
    let source = TrustSourceEvidence {
        source_id: [31; 32],
        snapshot_id: [32; 32],
    };
    for (purpose, policy_id) in [
        (TrustPurpose::QeaaIssuer, TrustPolicyId::EuQeaaV1),
        (
            TrustPurpose::TrustedListSigner,
            TrustPolicyId::EuTrustedListSignerV1,
        ),
        (
            TrustPurpose::WalletAttestationIssuer,
            TrustPolicyId::WalletAttestationIssuerV1,
        ),
        (
            TrustPurpose::WalletRelyingPartyRegistrationCertificate,
            TrustPolicyId::EtsiTs119475WrprcV1,
        ),
        (
            TrustPurpose::JadesSigner,
            TrustPolicyId::EtsiJadesBaselineBV1,
        ),
        (TrustPurpose::PidStatus, TrustPolicyId::EudiPidStatusV1),
        (
            TrustPurpose::EudiWalletOrKeyStorageStatus,
            TrustPolicyId::EudiWalletOrKeyStorageStatusV1,
        ),
        (
            TrustPurpose::WalletRelyingPartyRegistrationCertificateStatus,
            TrustPolicyId::EtsiTs119475WrprcStatusV1,
        ),
        (
            TrustPurpose::WalletRelyingPartyRegistrySigning,
            TrustPolicyId::EudiTs5RegistryResponseSigningV1,
        ),
    ] {
        let config = TrustConfig {
            trust_roots: Vec::new(),
            now: OffsetDateTime::UNIX_EPOCH,
            policy: X509Policy {
                reject_unknown_critical_extensions: false,
                ..X509Policy::default()
            },
            link_policy: Default::default(),
            evaluation: TrustEvaluationContext {
                purpose,
                policy_id,
                source: Some(source),
                ..Default::default()
            },
            direct_trust: vec![DirectTrustEntry {
                certificate: leaf.clone(),
                purpose,
                policy_id,
                source,
            }],
        };
        assert_eq!(
            evaluate_trust_decision(
                std::slice::from_ref(&leaf),
                &config,
                &AllowAllSignatures,
                None,
            )
            .err(),
            Some(TrustError::PurposePolicyMismatch)
        );
    }
}

#[test]
fn direct_end_entity_trust_does_not_cross_eudi_purpose_boundaries() {
    let leaf = mock_cert("CN=EUDI", "CN=EUDI", false, None, None);
    let source = TrustSourceEvidence {
        source_id: [11; 32],
        snapshot_id: [12; 32],
    };
    let cfg = TrustConfig {
        trust_roots: Vec::new(),
        now: OffsetDateTime::UNIX_EPOCH,
        policy: eudi_policy(EudiCertificateProfile::WalletProviderSignerV1),
        link_policy: Default::default(),
        evaluation: TrustEvaluationContext {
            purpose: TrustPurpose::EudiWalletProviderAttestation,
            policy_id: TrustPolicyId::EtsiTs1194126WalletProviderV1,
            status_policy: CertificateStatusPolicy {
                leaf: StatusRequirement::Required,
                intermediates: StatusRequirement::Required,
                trust_anchor: StatusRequirement::Exempt,
            },
            source: Some(source),
        },
        direct_trust: vec![DirectTrustEntry {
            certificate: leaf.clone(),
            purpose: TrustPurpose::PidIssuance,
            policy_id: TrustPolicyId::EtsiTs1194126PidProviderV1,
            source,
        }],
    };

    let decision = evaluate_trust_decision(&[leaf], &cfg, &RejectAllSignatures, None).unwrap();

    assert_eq!(decision.outcome(), TrustOutcome::Rejected);
    assert!(!decision.is_accepted());
}

#[test]
fn direct_end_entity_trust_rejects_a_different_source_snapshot() {
    let leaf = mock_cert("CN=Direct", "CN=Direct", false, None, None);
    let mut cfg = TrustConfig {
        trust_roots: Vec::new(),
        now: OffsetDateTime::UNIX_EPOCH,
        policy: X509Policy::default(),
        link_policy: Default::default(),
        evaluation: TrustEvaluationContext {
            purpose: TrustPurpose::WalletAttestationIssuer,
            policy_id: TrustPolicyId::WalletAttestationIssuerV1,
            status_policy: CertificateStatusPolicy {
                leaf: StatusRequirement::Required,
                intermediates: StatusRequirement::Required,
                trust_anchor: StatusRequirement::Exempt,
            },
            source: Some(TrustSourceEvidence {
                source_id: [7; 32],
                snapshot_id: [8; 32],
            }),
        },
        direct_trust: vec![DirectTrustEntry {
            certificate: leaf.clone(),
            purpose: TrustPurpose::WalletAttestationIssuer,
            policy_id: TrustPolicyId::WalletAttestationIssuerV1,
            source: TrustSourceEvidence {
                source_id: [7; 32],
                snapshot_id: [9; 32],
            },
        }],
    };

    let decision =
        evaluate_trust_decision(std::slice::from_ref(&leaf), &cfg, &AllowAllSignatures, None)
            .unwrap();

    assert_eq!(decision.outcome(), TrustOutcome::Rejected);
    assert!(!decision.is_accepted());

    cfg.evaluation.source = None;
    let decision = evaluate_trust_decision(&[leaf], &cfg, &AllowAllSignatures, None).unwrap();
    assert_eq!(decision.outcome(), TrustOutcome::Rejected);
    assert!(!decision.is_accepted());
}
