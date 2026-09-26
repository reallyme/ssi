// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_core_primitives::Algorithm;
use reallyme_vp_core::{DisclosureMode, Presentation};

use crate::error::{PolicyDecision, VpPolicyError};
use crate::model::VpPolicy;

/// Maximum number of extracted disclosures evaluated against policy.
///
/// Requirement matching is `required_claims x disclosures`; bounding the
/// caller-supplied side keeps evaluation cost linear in the policy size.
pub const MAX_EVALUATED_DISCLOSURES: usize = 4_096;

/// Maximum number of required claims evaluated for one policy.
pub const MAX_EVALUATED_REQUIRED_CLAIMS: usize = 256;

/// Disclosure facts extracted by an envelope-specific verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedDisclosure {
    /// Canonical claim path.
    pub claim_path: String,

    /// Disclosure mode satisfied by the presentation.
    pub mode: DisclosureMode,
}

/// Already-resolved credential status facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusContext {
    /// Whether status was checked successfully.
    pub checked: bool,

    /// Whether the credential was revoked.
    pub revoked: bool,

    /// Whether the credential was suspended.
    pub suspended: bool,

    /// Age, in seconds, of the status material used for the check.
    pub age_seconds: Option<u64>,
}

/// Already-validated QEAA facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QeaaContext<'a> {
    /// Whether QEAA evidence was validated.
    pub verified: bool,

    /// Validated QEAA policy profile identifier.
    pub profile: Option<&'a str>,

    /// Identity proofing rank.
    pub identity_proofing_rank: Option<u32>,
}

/// Inputs required to evaluate a presentation against policy.
pub struct EvaluationContext<'a> {
    /// Whether protocol-level holder binding was already validated.
    pub binding_ok: bool,

    /// Current time as Unix seconds.
    pub now_unix: u64,

    /// Presentation format being evaluated.
    pub presentation: &'a Presentation,

    /// Algorithm used by the issuer to sign the credential.
    pub issuer_algorithm: Algorithm,

    /// Algorithm used by the holder for holder binding.
    pub holder_algorithm: Algorithm,

    /// Credential claimset identifier.
    pub claimset_id: &'a str,

    /// Disclosures extracted by the envelope verifier.
    pub disclosures: &'a [ExtractedDisclosure],

    /// Optional status context.
    pub status: Option<StatusContext>,

    /// Optional QEAA context.
    pub qeaa: Option<QeaaContext<'a>>,
}

/// Evaluate a presentation against verifier policy.
///
/// This function performs no I/O and no cryptography. Envelope verifiers must
/// supply already-verified binding, disclosure, status, and QEAA facts.
pub fn evaluate(policy: &VpPolicy, ctx: &EvaluationContext<'_>) -> PolicyDecision {
    let mut errors = Vec::new();

    if !ctx.binding_ok {
        errors.push(VpPolicyError::InvalidBinding);
    }

    validate_format(policy, ctx.presentation, &mut errors);
    validate_algorithms(policy, ctx, &mut errors);
    validate_claimset(policy, ctx.claimset_id, &mut errors);
    validate_required_claims(policy, ctx.disclosures, &mut errors);
    validate_status(policy, ctx.status, &mut errors);
    validate_qeaa(policy, ctx.qeaa.as_ref(), &mut errors);

    if errors.is_empty() {
        PolicyDecision::Accept
    } else {
        PolicyDecision::Reject(errors)
    }
}

fn validate_format(
    policy: &VpPolicy,
    presentation: &Presentation,
    errors: &mut Vec<VpPolicyError>,
) {
    match presentation {
        Presentation::SdJwtVc(_) if !policy.allow_sd_jwt => {
            errors.push(VpPolicyError::PresentationFormatNotAllowed);
        }
        Presentation::Zk(_) if !policy.allow_zk => {
            errors.push(VpPolicyError::PresentationFormatNotAllowed);
        }
        Presentation::Mdoc(_) if !policy.allow_mdoc => {
            errors.push(VpPolicyError::PresentationFormatNotAllowed);
        }
        _ => {}
    }
}

fn validate_algorithms(
    policy: &VpPolicy,
    ctx: &EvaluationContext<'_>,
    errors: &mut Vec<VpPolicyError>,
) {
    if !policy
        .allowed_issuer_algorithms
        .contains(&ctx.issuer_algorithm)
    {
        errors.push(VpPolicyError::AlgorithmNotAllowed);
    }

    if !policy
        .allowed_holder_algorithms
        .contains(&ctx.holder_algorithm)
    {
        errors.push(VpPolicyError::AlgorithmNotAllowed);
    }
}

fn validate_claimset(policy: &VpPolicy, claimset_id: &str, errors: &mut Vec<VpPolicyError>) {
    if let Some(allowed) = &policy.allowed_claimsets {
        if !allowed.iter().any(|candidate| candidate == claimset_id) {
            errors.push(VpPolicyError::ClaimsetNotAllowed);
        }
    }
}

fn validate_required_claims(
    policy: &VpPolicy,
    disclosures: &[ExtractedDisclosure],
    errors: &mut Vec<VpPolicyError>,
) {
    if policy.required_claims.len() > MAX_EVALUATED_REQUIRED_CLAIMS {
        errors.push(VpPolicyError::RequiredClaimInvalid);
        return;
    }
    if disclosures.len() > MAX_EVALUATED_DISCLOSURES {
        errors.push(VpPolicyError::ProofInvalid);
        return;
    }
    for required in &policy.required_claims {
        let Some(disclosed) = disclosures
            .iter()
            .find(|claim| claim.claim_path == required.claim_path)
        else {
            errors.push(VpPolicyError::MissingClaim);
            continue;
        };

        if disclosed.mode != required.mode {
            errors.push(VpPolicyError::DisclosureModeNotAllowed);
        }
    }
    if !policy.required_claims.is_empty() {
        for disclosed in disclosures {
            if !policy
                .required_claims
                .iter()
                .any(|required| required.claim_path == disclosed.claim_path)
            {
                errors.push(VpPolicyError::UnexpectedDisclosure);
            }
        }
    }
}

fn validate_status(
    policy: &VpPolicy,
    status: Option<StatusContext>,
    errors: &mut Vec<VpPolicyError>,
) {
    if !policy.require_status {
        return;
    }

    let Some(status) = status else {
        errors.push(VpPolicyError::StatusCheckFailed);
        return;
    };

    if !status.checked {
        errors.push(VpPolicyError::StatusCheckFailed);
    }
    if status.revoked {
        errors.push(VpPolicyError::CredentialRevoked);
    }
    if status.suspended {
        errors.push(VpPolicyError::CredentialSuspended);
    }

    // A configured freshness bound cannot be satisfied by status material of
    // unknown age; missing age is treated as too old.
    if let Some(max_age) = policy.max_status_age_seconds {
        match status.age_seconds {
            Some(age) if age <= max_age => {}
            _ => errors.push(VpPolicyError::StatusTooOld),
        }
    }
}

fn validate_qeaa(
    policy: &VpPolicy,
    qeaa: Option<&QeaaContext<'_>>,
    errors: &mut Vec<VpPolicyError>,
) {
    if !policy.require_qeaa {
        return;
    }

    let Some(qeaa) = qeaa else {
        errors.push(VpPolicyError::QeaaRequired);
        return;
    };

    if !qeaa.verified {
        errors.push(VpPolicyError::QeaaRequired);
    }

    if let Some(required_profile) = policy.min_qeaa_profile.as_deref() {
        if qeaa.profile != Some(required_profile) {
            errors.push(VpPolicyError::QeaaProfileMismatch);
        }
    }

    if let Some(min_rank) = policy.min_identity_proofing_level {
        match qeaa.identity_proofing_rank {
            Some(rank) if rank >= min_rank => {}
            _ => errors.push(VpPolicyError::QeaaLevelInsufficient),
        }
    }
}
