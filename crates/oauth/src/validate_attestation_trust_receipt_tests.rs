// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_trust_core::{
    CertificatePosition, CertificateStatus, CertificateStatusEvidence, TrustAnchorKind,
    TrustPolicyId, TrustPurpose,
};

use super::{
    evidence_cardinality_is_valid, trust_scope_matches, valid_path_shape,
    validate_trusted_status_evidence,
};
use crate::attestation_trust_receipt::MAX_ATTESTATION_PATH_CERTIFICATES;
use crate::error::Reason;

#[test]
fn scope_requires_the_wallet_attestation_purpose_and_policy_independently() {
    assert!(trust_scope_matches(
        TrustPurpose::WalletAttestationIssuer,
        TrustPolicyId::WalletAttestationIssuerV1,
    ));
    assert!(!trust_scope_matches(
        TrustPurpose::Generic,
        TrustPolicyId::WalletAttestationIssuerV1,
    ));
    assert!(!trust_scope_matches(
        TrustPurpose::WalletAttestationIssuer,
        TrustPolicyId::GenericX509V1,
    ));
}

#[test]
fn receipt_evidence_requires_status_and_forbids_failures() {
    assert!(evidence_cardinality_is_valid(1, 0));
    assert!(!evidence_cardinality_is_valid(0, 0));
    assert!(!evidence_cardinality_is_valid(1, 1));
}

#[test]
fn receipt_path_shape_matches_the_authenticated_anchor_kind() {
    assert!(valid_path_shape(TrustAnchorKind::DirectEndEntity, 1));
    assert!(!valid_path_shape(TrustAnchorKind::DirectEndEntity, 2));
    assert!(valid_path_shape(TrustAnchorKind::RootCertificate, 2));
    assert!(!valid_path_shape(TrustAnchorKind::RootCertificate, 1));
}

#[test]
fn receipt_rejects_unknown_and_revoked_status_evidence() {
    for status in [CertificateStatus::Unknown, CertificateStatus::Revoked] {
        let evidence = [CertificateStatusEvidence {
            position: CertificatePosition::Leaf,
            status,
        }];
        assert_eq!(
            validate_trusted_status_evidence(&evidence, 1)
                .err()
                .map(|error| error.reason()),
            Some(Reason::InvalidAttestationReceipt)
        );
    }
}

#[test]
fn receipt_rejects_status_evidence_above_the_path_limit() {
    let evidence = vec![
        CertificateStatusEvidence {
            position: CertificatePosition::Leaf,
            status: CertificateStatus::Good,
        };
        MAX_ATTESTATION_PATH_CERTIFICATES + 1
    ];
    assert_eq!(
        validate_trusted_status_evidence(&evidence, evidence.len())
            .err()
            .map(|error| error.reason()),
        Some(Reason::InvalidAttestationReceipt)
    );
}
