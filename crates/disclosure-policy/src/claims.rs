// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_credential_claims::{
    validate_disclosure, validate_registry, ClaimsError, ClaimsRegistry,
    DisclosureMode as ClaimDisclosureMode,
};
use reallyme_vp_core::DisclosureMode;

use crate::{VpPolicy, VpPolicyError};

/// Validate policy-required claims against a concrete credential claim registry.
///
/// Policy evaluation receives disclosures extracted from already-verified
/// envelopes. This preflight keeps verifier policy construction honest before
/// envelope-specific code spends work assembling disclosure or derivation plans:
/// every required claim must be a canonical registry path, and the requested
/// disclosure mode must be allowed by that claim definition.
pub fn validate_policy_claims_against_registry(
    policy: &VpPolicy,
    registry: &ClaimsRegistry,
) -> Result<(), VpPolicyError> {
    validate_registry(registry).map_err(map_registry_error)?;
    validate_claimset_allow_list(policy, registry)?;

    for required in &policy.required_claims {
        validate_disclosure(
            registry,
            required.claim_path.as_str(),
            disclosure_mode_for_claims(required.mode),
        )
        .map_err(map_required_claim_error)?;
    }

    Ok(())
}

fn validate_claimset_allow_list(
    policy: &VpPolicy,
    registry: &ClaimsRegistry,
) -> Result<(), VpPolicyError> {
    if let Some(allowed) = &policy.allowed_claimsets {
        if !allowed
            .iter()
            .any(|claimset_id| claimset_id == &registry.claimset_id)
        {
            return Err(VpPolicyError::ClaimsetNotAllowed);
        }
    }

    Ok(())
}

fn disclosure_mode_for_claims(mode: DisclosureMode) -> ClaimDisclosureMode {
    match mode {
        DisclosureMode::Unspecified => ClaimDisclosureMode::Unspecified,
        DisclosureMode::Hidden => ClaimDisclosureMode::Hidden,
        DisclosureMode::Reveal => ClaimDisclosureMode::Reveal,
        DisclosureMode::Eq => ClaimDisclosureMode::Eq,
        DisclosureMode::Gte => ClaimDisclosureMode::Gte,
        DisclosureMode::Lte => ClaimDisclosureMode::Lte,
        DisclosureMode::Range => ClaimDisclosureMode::Range,
        DisclosureMode::MemberOfSet => ClaimDisclosureMode::MemberOfSet,
    }
}

fn map_registry_error(_error: ClaimsError) -> VpPolicyError {
    VpPolicyError::ClaimRegistryInvalid
}

fn map_required_claim_error(error: ClaimsError) -> VpPolicyError {
    match error {
        ClaimsError::DisclosureNotAllowed | ClaimsError::PredicateNotAllowed => {
            VpPolicyError::DisclosureModeNotAllowed
        }
        ClaimsError::UnknownClaim | ClaimsError::InvalidInput(_) => {
            VpPolicyError::RequiredClaimInvalid
        }
    }
}
