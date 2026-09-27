// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Structural validation for wallet-attestation trust receipts.

use reallyme_trust_core::{
    CertificatePosition, CertificateStatus, CertificateStatusEvidence, TrustAnchorKind,
    TrustPolicyId, TrustPurpose,
};

use super::MAX_ATTESTATION_PATH_CERTIFICATES;
use crate::error::{OauthError, OauthResult, Reason};

pub(super) const fn trust_scope_matches(purpose: TrustPurpose, policy_id: TrustPolicyId) -> bool {
    matches!(
        (purpose, policy_id),
        (
            TrustPurpose::WalletAttestationIssuer,
            TrustPolicyId::WalletAttestationIssuerV1
        )
    )
}

pub(super) const fn evidence_cardinality_is_valid(
    status_count: usize,
    failure_count: usize,
) -> bool {
    status_count > 0 && status_count <= MAX_ATTESTATION_PATH_CERTIFICATES && failure_count == 0
}

pub(super) const fn valid_path_shape(
    anchor_kind: TrustAnchorKind,
    certificate_count: usize,
) -> bool {
    match anchor_kind {
        TrustAnchorKind::RootCertificate => certificate_count >= 2,
        TrustAnchorKind::DirectEndEntity => certificate_count == 1,
        _ => false,
    }
}

pub(super) fn validate_trusted_status_evidence(
    statuses: &[CertificateStatusEvidence],
    path_len: usize,
) -> OauthResult<()> {
    if statuses.is_empty()
        || statuses.len() > MAX_ATTESTATION_PATH_CERTIFICATES
        || statuses.len() != path_len
    {
        return Err(OauthError::new(Reason::InvalidAttestationReceipt));
    }
    let trust_anchor_index = path_len
        .checked_sub(1)
        .ok_or(OauthError::new(Reason::InvalidAttestationReceipt))?;
    for (index, status) in statuses.iter().enumerate() {
        let expected_position = if index == 0 {
            CertificatePosition::Leaf
        } else if index == trust_anchor_index {
            CertificatePosition::TrustAnchor
        } else {
            let intermediate_index = index
                .checked_sub(1)
                .and_then(|value| u8::try_from(value).ok())
                .ok_or(OauthError::new(Reason::InvalidAttestationReceipt))?;
            CertificatePosition::Intermediate(intermediate_index)
        };
        let status_allowed = match expected_position {
            CertificatePosition::TrustAnchor => matches!(
                status.status,
                CertificateStatus::Good | CertificateStatus::Exempt
            ),
            CertificatePosition::Leaf | CertificatePosition::Intermediate(_) => {
                status.status == CertificateStatus::Good
            }
            _ => false,
        };
        if status.position != expected_position || !status_allowed {
            return Err(OauthError::new(Reason::InvalidAttestationReceipt));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "validate_attestation_trust_receipt_tests.rs"]
mod tests;
