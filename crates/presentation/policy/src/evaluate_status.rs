// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{EvaluationContext, StatusContext};
use crate::{error::VpPolicyError, model::VpPolicy};
use identity_credential_status_core::{CredentialStatusError, StatusPurpose};
use identity_presentation_vp_core::model::Presentation;
use reallyme_credential::{CredentialEnvelope, CredentialError, CredentialStatusReason};

pub(super) fn validate_verified_credential_status(
    policy: &VpPolicy,
    ctx: &EvaluationContext<'_>,
    status: &StatusContext<'_>,
    credential: &CredentialEnvelope,
    errors: &mut Vec<VpPolicyError>,
) {
    match reallyme_credential::verify_credential_status(
        credential,
        status.list,
        ctx.now_unix,
        status.verifier,
    ) {
        Ok(()) => {
            if !status_age_within_policy(policy, status, ctx.now_unix) {
                errors.push(VpPolicyError::StatusTooOld);
            }
        }
        Err(CredentialError::Status(CredentialStatusReason::Revoked)) => {
            errors.push(VpPolicyError::CredentialRevoked);
        }
        Err(CredentialError::Status(CredentialStatusReason::Suspended)) => {
            errors.push(VpPolicyError::CredentialSuspended);
        }
        Err(CredentialError::Status(CredentialStatusReason::Expired)) => {
            errors.push(VpPolicyError::StatusTooOld);
        }
        Err(_) => {
            errors.push(VpPolicyError::StatusCheckFailed);
        }
    }
}

pub(super) struct PresentationStatusReference<'a> {
    issuer_did: &'a str,
    status_list_id: [u8; 32],
    status_list_index: u64,
    purpose: identity_presentation_vp_core::model::StatusPurpose,
}

pub(super) fn validate_bound_status(
    policy: &VpPolicy,
    ctx: &EvaluationContext<'_>,
    status: &StatusContext<'_>,
    reference: &PresentationStatusReference<'_>,
    errors: &mut Vec<VpPolicyError>,
) {
    let expected_purpose = map_status_purpose(reference.purpose);
    if status.list.issuer != reference.issuer_did
        || status.list.list_id != Some(reference.status_list_id)
        || expected_purpose.is_none_or(|purpose| status.list.purpose != purpose)
    {
        errors.push(VpPolicyError::StatusCheckFailed);
        return;
    }
    match identity_credential_status_core::verify_status(
        status.list,
        reference.status_list_index,
        ctx.now_unix,
        status.verifier,
    ) {
        Ok(()) => {
            let signer_matches = matches!(
                status.verifier.verified_signer(),
                reallyme_credential::PartyReference::Did(ref signer)
                    if signer == reference.issuer_did
            );
            if !signer_matches {
                errors.push(VpPolicyError::StatusCheckFailed);
            } else if !status_age_within_policy(policy, status, ctx.now_unix) {
                errors.push(VpPolicyError::StatusTooOld);
            }
        }
        Err(CredentialStatusError::Revoked) => {
            errors.push(VpPolicyError::CredentialRevoked);
        }
        Err(CredentialStatusError::Suspended) => {
            errors.push(VpPolicyError::CredentialSuspended);
        }
        Err(CredentialStatusError::Expired) => {
            errors.push(VpPolicyError::StatusTooOld);
        }
        Err(_) => {
            errors.push(VpPolicyError::StatusCheckFailed);
        }
    }
}

pub(super) fn presentation_status_reference(
    presentation: &Presentation,
) -> Option<PresentationStatusReference<'_>> {
    match presentation {
        Presentation::Zk(presentation) => match presentation.as_ref() {
            identity_presentation_vp_core::model::ZkPresentation::Credential(value) => {
                Some(PresentationStatusReference {
                    issuer_did: value.credential.issuer_did.as_str(),
                    status_list_id: value.credential.status.status_list_id,
                    status_list_index: value.credential.status.status_list_index,
                    purpose: value.credential.status.purpose,
                })
            }
            identity_presentation_vp_core::model::ZkPresentation::Persona(_)
            | identity_presentation_vp_core::model::ZkPresentation::CommonRoot(_) => None,
            // A future proof statement needs an explicit status binding.
            _ => None,
        },
        Presentation::SdJwtVc(_) | Presentation::Mdoc(_) => None,
        _ => None,
    }
}

fn map_status_purpose(
    purpose: identity_presentation_vp_core::model::StatusPurpose,
) -> Option<StatusPurpose> {
    match purpose {
        identity_presentation_vp_core::model::StatusPurpose::Revocation => {
            Some(StatusPurpose::Revocation)
        }
        identity_presentation_vp_core::model::StatusPurpose::Suspension => {
            Some(StatusPurpose::Suspension)
        }
        identity_presentation_vp_core::model::StatusPurpose::Unspecified => None,
        _ => None,
    }
}

/// Enforce `max_status_age_seconds` against the verified list's `issued_at`.
///
/// `verify_status` has already rejected lists issued in the future, so a
/// failed subtraction can only mean inconsistent input and is treated as stale.
fn status_age_within_policy(policy: &VpPolicy, status: &StatusContext<'_>, now_unix: u64) -> bool {
    let Some(max_age) = policy.max_status_age_seconds else {
        return true;
    };
    match now_unix.checked_sub(status.list.issued_at) {
        Some(age) => age < max_age,
        None => false,
    }
}
