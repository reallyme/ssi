// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    trust_pb, AuthorizationPurpose, TrustDecision, TrustDecisionEvidence, TrustDecisionFailure,
    TrustDecisionOutcome, TrustPolicyId, TrustProtoError, TrustPurpose,
};
use buffa::{EnumValue, Enumeration};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn trust_decision_failure_round_trips_through_proto_enum() {
    let proto = trust_pb::TrustDecisionFailure::from(TrustDecisionFailure::Status);

    assert_eq!(
        TrustDecisionFailure::try_from(EnumValue::from(proto)),
        Ok(TrustDecisionFailure::Status)
    );
}

#[test]
fn authorization_purpose_round_trips_through_proto_enum() {
    let proto = trust_pb::AuthorizationPurpose::from(AuthorizationPurpose::QwacTlsServer);

    assert_eq!(
        AuthorizationPurpose::try_from(EnumValue::from(proto)),
        Ok(AuthorizationPurpose::QwacTlsServer)
    );
}

#[test]
fn trust_proto_unknown_values_fail_closed() {
    assert_eq!(
        TrustDecisionFailure::try_from(EnumValue::<trust_pb::TrustDecisionFailure>::from(65_535)),
        Err(TrustProtoError::UnknownDecisionFailure)
    );
    assert_eq!(
        TrustDecisionFailure::try_from(EnumValue::from(
            trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_UNSPECIFIED
        )),
        Err(TrustProtoError::UnknownDecisionFailure)
    );
    assert_eq!(
        AuthorizationPurpose::try_from(EnumValue::<trust_pb::AuthorizationPurpose>::from(65_535)),
        Err(TrustProtoError::UnknownAuthorizationPurpose)
    );
}

#[test]
fn trust_proto_error_maps_to_identity_core_reason() {
    let cases = [
        (
            TrustProtoError::UnknownDecisionFailure,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_UNKNOWN_DECISION_FAILURE,
        ),
        (
            TrustProtoError::UnknownAuthorizationPurpose,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_UNKNOWN_AUTHORIZATION_PURPOSE,
        ),
        (
            TrustProtoError::UnknownDecisionOutcome,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_UNKNOWN_DECISION_OUTCOME,
        ),
        (
            TrustProtoError::UnknownTrustPurpose,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_UNKNOWN_TRUST_PURPOSE,
        ),
        (
            TrustProtoError::UnknownTrustPolicy,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_UNKNOWN_TRUST_POLICY,
        ),
        (
            TrustProtoError::UnknownTrustAnchorKind,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_UNKNOWN_TRUST_ANCHOR_KIND,
        ),
        (
            TrustProtoError::UnknownCertificateStatus,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_UNKNOWN_CERTIFICATE_STATUS,
        ),
        (
            TrustProtoError::UnknownCertificatePosition,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_UNKNOWN_CERTIFICATE_POSITION,
        ),
        (
            TrustProtoError::InvalidDecisionEvidence,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_INVALID_DECISION_EVIDENCE,
        ),
        (
            TrustProtoError::InconsistentDecisionOutcome,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_INCONSISTENT_DECISION_OUTCOME,
        ),
        (
            TrustProtoError::InconsistentPurposePolicy,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_INCONSISTENT_PURPOSE_POLICY,
        ),
        (
            TrustProtoError::ResourceLimit,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_RESOURCE_LIMIT,
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}

#[test]
fn trust_proto_rejects_unknown_enums_with_field_specific_errors() {
    let unknown_outcome = trust_pb::TrustDecision {
        outcome: EnumValue::from(65_535),
        ..Default::default()
    };
    assert_eq!(
        TrustDecision::try_from(unknown_outcome),
        Err(TrustProtoError::UnknownDecisionOutcome)
    );

    let unknown_purpose = trust_pb::TrustDecision {
        accepted: false,
        outcome: EnumValue::from(trust_pb::TrustDecisionOutcome::TRUST_DECISION_OUTCOME_REJECTED),
        failures: vec![EnumValue::from(
            trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_POLICY,
        )],
        evidence: buffa::MessageField::some(trust_pb::TrustDecisionEvidence {
            purpose: EnumValue::from(65_535),
            policy_id: EnumValue::from(trust_pb::TrustPolicyId::TRUST_POLICY_ID_GENERIC_X509_V1),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(
        TrustDecision::try_from(unknown_purpose),
        Err(TrustProtoError::UnknownTrustPurpose)
    );
}

#[test]
fn trust_proto_rejects_mismatched_purpose_and_policy() {
    let proto = trust_pb::TrustDecision {
        accepted: false,
        outcome: EnumValue::from(trust_pb::TrustDecisionOutcome::TRUST_DECISION_OUTCOME_REJECTED),
        failures: vec![EnumValue::from(
            trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_POLICY,
        )],
        evidence: buffa::MessageField::some(trust_pb::TrustDecisionEvidence {
            purpose: EnumValue::from(trust_pb::TrustPurpose::TRUST_PURPOSE_QWAC_TLS_SERVER),
            policy_id: EnumValue::from(trust_pb::TrustPolicyId::TRUST_POLICY_ID_EU_QSEAL_V1),
            ..Default::default()
        }),
        ..Default::default()
    };

    assert_eq!(
        TrustDecision::try_from(proto),
        Err(TrustProtoError::InconsistentPurposePolicy)
    );
}

#[test]
fn trust_decision_converts_to_and_from_proto() {
    let decision = TrustDecision {
        accepted: false,
        outcome: TrustDecisionOutcome::Rejected,
        failures: vec![
            TrustDecisionFailure::NoValidPath,
            TrustDecisionFailure::Signature,
        ],
        evidence: TrustDecisionEvidence {
            purpose: TrustPurpose::Generic,
            policy_id: TrustPolicyId::GenericX509V1,
            evaluated_at_unix: 1_700_000_000,
            source: None,
            trust_anchor: None,
            certificate_status: Vec::new(),
            selected_path_certificate_sha256: Vec::new(),
        },
    };

    let proto = trust_pb::TrustDecision::from(&decision);

    assert!(!proto.accepted);
    assert_eq!(
        proto.failures[0].to_i32(),
        trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_NO_VALID_PATH.to_i32()
    );

    let roundtrip = TrustDecision::try_from(proto);
    assert_eq!(roundtrip, Ok(decision));
}

#[test]
fn eudi_purpose_policy_pairs_round_trip_without_generic_fallback() {
    let pairs = [
        (
            TrustPurpose::PidIssuance,
            TrustPolicyId::EtsiTs1194126PidProviderV1,
        ),
        (TrustPurpose::PidStatus, TrustPolicyId::EudiPidStatusV1),
        (
            TrustPurpose::EudiWalletProviderAttestation,
            TrustPolicyId::EtsiTs1194126WalletProviderV1,
        ),
        (
            TrustPurpose::EudiWalletOrKeyStorageStatus,
            TrustPolicyId::EudiWalletOrKeyStorageStatusV1,
        ),
        (
            TrustPurpose::WalletRelyingPartyAccessCertificate,
            TrustPolicyId::EtsiTs1194118WrpacV1,
        ),
        (
            TrustPurpose::WalletRelyingPartyRegistrationCertificate,
            TrustPolicyId::EtsiTs119475WrprcV1,
        ),
        (
            TrustPurpose::WalletRelyingPartyRegistrationCertificateStatus,
            TrustPolicyId::EtsiTs119475WrprcStatusV1,
        ),
        (
            TrustPurpose::WalletRelyingPartyRegistrySigning,
            TrustPolicyId::EudiTs5RegistryResponseSigningV1,
        ),
    ];

    for (purpose, policy_id) in pairs {
        let decision = TrustDecision {
            accepted: false,
            outcome: TrustDecisionOutcome::Rejected,
            failures: vec![TrustDecisionFailure::Policy],
            evidence: TrustDecisionEvidence {
                purpose,
                policy_id,
                evaluated_at_unix: 1_700_000_000,
                source: None,
                trust_anchor: None,
                certificate_status: Vec::new(),
                selected_path_certificate_sha256: Vec::new(),
            },
        };
        let proto = trust_pb::TrustDecision::from(&decision);
        assert_eq!(TrustDecision::try_from(proto), Ok(decision));
    }
}

#[test]
fn eudi_proto_rejects_cross_purpose_policy_reuse() {
    let proto = trust_pb::TrustDecision {
        accepted: false,
        outcome: EnumValue::from(trust_pb::TrustDecisionOutcome::TRUST_DECISION_OUTCOME_REJECTED),
        failures: vec![EnumValue::from(
            trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_POLICY,
        )],
        evidence: buffa::MessageField::some(trust_pb::TrustDecisionEvidence {
            purpose: EnumValue::from(trust_pb::TrustPurpose::TRUST_PURPOSE_PID_ISSUANCE),
            policy_id: EnumValue::from(
                trust_pb::TrustPolicyId::TRUST_POLICY_ID_ETSI_TS_119_412_6_WALLET_PROVIDER_V1,
            ),
            ..Default::default()
        }),
        ..Default::default()
    };

    assert_eq!(
        TrustDecision::try_from(proto),
        Err(TrustProtoError::InconsistentPurposePolicy)
    );
}

#[test]
fn ts5_registry_signing_proto_rejects_cross_identity_aliases() {
    let invalid_pairs = [
        (
            trust_pb::TrustPurpose::TRUST_PURPOSE_WALLET_RELYING_PARTY_REGISTRY_SIGNING,
            trust_pb::TrustPolicyId::TRUST_POLICY_ID_GENERIC_X509_V1,
        ),
        (
            trust_pb::TrustPurpose::TRUST_PURPOSE_WALLET_RELYING_PARTY_REGISTRY_SIGNING,
            trust_pb::TrustPolicyId::TRUST_POLICY_ID_ETSI_JADES_BASELINE_B_V1,
        ),
        (
            trust_pb::TrustPurpose::TRUST_PURPOSE_WALLET_RELYING_PARTY_REGISTRY_SIGNING,
            trust_pb::TrustPolicyId::TRUST_POLICY_ID_ETSI_TS_119_475_WRPRC_V1,
        ),
        (
            trust_pb::TrustPurpose::TRUST_PURPOSE_GENERIC,
            trust_pb::TrustPolicyId::TRUST_POLICY_ID_EUDI_TS5_REGISTRY_RESPONSE_SIGNING_V1,
        ),
        (
            trust_pb::TrustPurpose::TRUST_PURPOSE_JADES_SIGNER,
            trust_pb::TrustPolicyId::TRUST_POLICY_ID_EUDI_TS5_REGISTRY_RESPONSE_SIGNING_V1,
        ),
        (
            trust_pb::TrustPurpose::TRUST_PURPOSE_WALLET_RELYING_PARTY_REGISTRATION_CERTIFICATE,
            trust_pb::TrustPolicyId::TRUST_POLICY_ID_EUDI_TS5_REGISTRY_RESPONSE_SIGNING_V1,
        ),
    ];

    for (purpose, policy_id) in invalid_pairs {
        let proto = trust_pb::TrustDecision {
            accepted: false,
            outcome: EnumValue::from(
                trust_pb::TrustDecisionOutcome::TRUST_DECISION_OUTCOME_REJECTED,
            ),
            failures: vec![EnumValue::from(
                trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_POLICY,
            )],
            evidence: buffa::MessageField::some(trust_pb::TrustDecisionEvidence {
                purpose: EnumValue::from(purpose),
                policy_id: EnumValue::from(policy_id),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(
            TrustDecision::try_from(proto),
            Err(TrustProtoError::InconsistentPurposePolicy)
        );
    }
}

#[test]
fn trusted_proto_requires_consistent_anchor_path_and_status_evidence() {
    let proto = trust_pb::TrustDecision {
        accepted: true,
        outcome: EnumValue::from(trust_pb::TrustDecisionOutcome::TRUST_DECISION_OUTCOME_TRUSTED),
        evidence: buffa::MessageField::some(trust_pb::TrustDecisionEvidence {
            purpose: EnumValue::from(trust_pb::TrustPurpose::TRUST_PURPOSE_GENERIC),
            policy_id: EnumValue::from(trust_pb::TrustPolicyId::TRUST_POLICY_ID_GENERIC_X509_V1),
            ..Default::default()
        }),
        ..Default::default()
    };

    assert_eq!(
        TrustDecision::try_from(proto),
        Err(TrustProtoError::InvalidDecisionEvidence)
    );
}

#[test]
fn trusted_proto_rejects_non_good_status_and_repeated_path_certificates() {
    let trusted = || trust_pb::TrustDecision {
        accepted: true,
        outcome: EnumValue::from(trust_pb::TrustDecisionOutcome::TRUST_DECISION_OUTCOME_TRUSTED),
        evidence: buffa::MessageField::some(trust_pb::TrustDecisionEvidence {
            purpose: EnumValue::from(trust_pb::TrustPurpose::TRUST_PURPOSE_GENERIC),
            policy_id: EnumValue::from(trust_pb::TrustPolicyId::TRUST_POLICY_ID_GENERIC_X509_V1),
            trust_anchor: buffa::MessageField::some(trust_pb::TrustAnchorEvidence {
                kind: EnumValue::from(
                    trust_pb::TrustAnchorKind::TRUST_ANCHOR_KIND_ROOT_CERTIFICATE,
                ),
                ..Default::default()
            }),
            certificate_status: vec![
                trust_pb::CertificateStatusEvidence {
                    position: EnumValue::from(
                        trust_pb::CertificatePosition::CERTIFICATE_POSITION_LEAF,
                    ),
                    status: EnumValue::from(
                        trust_pb::CertificateStatus::CERTIFICATE_STATUS_GOOD,
                    ),
                    ..Default::default()
                },
                trust_pb::CertificateStatusEvidence {
                    position: EnumValue::from(
                        trust_pb::CertificatePosition::CERTIFICATE_POSITION_TRUST_ANCHOR,
                    ),
                    status: EnumValue::from(
                        trust_pb::CertificateStatus::CERTIFICATE_STATUS_EXEMPT,
                    ),
                    ..Default::default()
                },
            ],
            selected_path_certificate_sha256: vec![vec![1; 32], vec![2; 32]],
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut revoked = trusted();
    if let Some(evidence) = revoked.evidence.as_option_mut() {
        evidence.certificate_status[0].status =
            EnumValue::from(trust_pb::CertificateStatus::CERTIFICATE_STATUS_REVOKED);
    }
    assert_eq!(
        TrustDecision::try_from(revoked),
        Err(TrustProtoError::InvalidDecisionEvidence)
    );

    let mut repeated_path = trusted();
    if let Some(evidence) = repeated_path.evidence.as_option_mut() {
        evidence.selected_path_certificate_sha256[1] = vec![1; 32];
    }
    assert_eq!(
        TrustDecision::try_from(repeated_path),
        Err(TrustProtoError::InvalidDecisionEvidence)
    );
}

#[test]
fn trust_proto_repeated_fields_are_bounded_before_projection() {
    let proto = trust_pb::TrustDecision {
        accepted: false,
        outcome: EnumValue::from(trust_pb::TrustDecisionOutcome::TRUST_DECISION_OUTCOME_REJECTED),
        failures: vec![
            EnumValue::from(
                trust_pb::TrustDecisionFailure::TRUST_DECISION_FAILURE_NO_VALID_PATH,
            );
            33
        ],
        evidence: buffa::MessageField::some(trust_pb::TrustDecisionEvidence {
            purpose: EnumValue::from(trust_pb::TrustPurpose::TRUST_PURPOSE_GENERIC),
            policy_id: EnumValue::from(trust_pb::TrustPolicyId::TRUST_POLICY_ID_GENERIC_X509_V1),
            ..Default::default()
        }),
        ..Default::default()
    };

    assert_eq!(
        TrustDecision::try_from(proto),
        Err(TrustProtoError::ResourceLimit)
    );
}
