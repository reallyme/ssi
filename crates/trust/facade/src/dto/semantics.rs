// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn validate_decision_semantics(decision: &TrustDecision) -> Result<(), TrustProtoError> {
    if !purpose_policy_pair_is_valid(decision.evidence.purpose, decision.evidence.policy_id) {
        return Err(TrustProtoError::InconsistentPurposePolicy);
    }
    for (index, failure) in decision.failures.iter().enumerate() {
        let remaining_index = index.checked_add(1).ok_or(TrustProtoError::ResourceLimit)?;
        let remaining = decision
            .failures
            .get(remaining_index..)
            .ok_or(TrustProtoError::InvalidDecisionEvidence)?;
        if remaining.contains(failure) {
            return Err(TrustProtoError::InvalidDecisionEvidence);
        }
    }

    match decision.outcome {
        TrustDecisionOutcome::Trusted => {
            let anchor = decision
                .evidence
                .trust_anchor
                .ok_or(TrustProtoError::InvalidDecisionEvidence)?;
            let path = &decision.evidence.selected_path_certificate_sha256;
            if !decision.failures.is_empty()
                || path.is_empty()
                || decision.evidence.certificate_status.len() != path.len()
            {
                return Err(TrustProtoError::InvalidDecisionEvidence);
            }
            let path_shape_is_valid = match anchor.kind {
                TrustAnchorKind::RootCertificate => path.len() >= 2,
                TrustAnchorKind::DirectEndEntity => path.len() == 1,
            };
            if !path_shape_is_valid {
                return Err(TrustProtoError::InvalidDecisionEvidence);
            }
            let trust_anchor_index = path
                .len()
                .checked_sub(1)
                .ok_or(TrustProtoError::InvalidDecisionEvidence)?;
            for (index, status) in decision.evidence.certificate_status.iter().enumerate() {
                let expected = if index == 0 {
                    CertificatePosition::Leaf
                } else if index == trust_anchor_index {
                    CertificatePosition::TrustAnchor
                } else {
                    let intermediate_index = index
                        .checked_sub(1)
                        .and_then(|value| u8::try_from(value).ok())
                        .ok_or(TrustProtoError::InvalidDecisionEvidence)?;
                    CertificatePosition::Intermediate(intermediate_index)
                };
                // The generic policy permits optional status verification. The
                // purpose-specific profiles require leaf and intermediate
                // checks, while the anchor remains caller-configurable.
                let optional_status_is_permitted =
                    decision.evidence.policy_id == TrustPolicyId::GenericX509V1
                        || expected == CertificatePosition::TrustAnchor;
                let status_is_valid = status.status == CertificateStatus::Good
                    || (optional_status_is_permitted
                        && matches!(
                            status.status,
                            CertificateStatus::Exempt | CertificateStatus::NotChecked
                        ));
                if status.position != expected || !status_is_valid {
                    return Err(TrustProtoError::InvalidDecisionEvidence);
                }
            }
            for (index, fingerprint) in path.iter().enumerate() {
                let remaining_index = index
                    .checked_add(1)
                    .ok_or(TrustProtoError::ResourceLimit)?;
                let remaining = path
                    .get(remaining_index..)
                    .ok_or(TrustProtoError::InvalidDecisionEvidence)?;
                if remaining.contains(fingerprint) {
                    return Err(TrustProtoError::InvalidDecisionEvidence);
                }
            }
        }
        TrustDecisionOutcome::Rejected | TrustDecisionOutcome::Indeterminate => {
            if decision.failures.is_empty() {
                return Err(TrustProtoError::InvalidDecisionEvidence);
            }
        }
    }
    Ok(())
}

fn purpose_policy_pair_is_valid(purpose: TrustPurpose, policy: TrustPolicyId) -> bool {
    matches!(
        (purpose, policy),
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
