// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    error::{PolicyDecision, VpPolicyError},
    model::VpPolicy,
};

use identity_core_primitives::Algorithm;
use identity_credential_claims_core::{validate_disclosure, ClaimsRegistry};
use identity_credential_status_core::{CredentialStatusError, StatusList, StatusListVerifier};
use identity_presentation_vp_core::model::Presentation;
use reallyme_credential_audit::QeaaCompliance;

/// Maximum number of presentation disclosures evaluated against policy.
///
/// Requirement matching is `required_claims x disclosures`; bounding the
/// untrusted side keeps evaluation cost linear in the policy size.
pub const MAX_POLICY_DISCLOSURES: usize = 4_096;

/// Maximum number of required claims a verifier policy may declare.
pub const MAX_POLICY_REQUIRED_CLAIMS: usize = 256;

/// All inputs required to evaluate a presentation.
///
/// This struct is intentionally explicit and closed over:
/// evaluation must not depend on any external or implicit state.
pub struct EvaluationContext<'a> {
    // ---------------------------------------------------------------------
    /// Whether freshness / audience binding was already validated
    // ---------------------------------------------------------------------
    pub binding_ok: bool,
    /// Current verifier time as Unix seconds.
    pub now_unix: u64,

    // ---------------------------------------------------------------------
    // Presentation & cryptography
    // ---------------------------------------------------------------------
    /// Presentation being evaluated.
    pub presentation: &'a Presentation,

    /// Algorithm used by the issuer to sign the credential.
    pub issuer_algorithm: Algorithm,

    /// Algorithm used by the holder (SD-JWT kb_jwt or ZK freshness sig).
    pub holder_algorithm: Algorithm,

    // ---------------------------------------------------------------------
    // Claims
    // ---------------------------------------------------------------------
    /// Registry defining claim paths and disclosure permissions.
    pub claims_registry: &'a ClaimsRegistry,
    /// Claimset identifier carried by the credential.
    pub claimset_id: &'a str,

    // ---------------------------------------------------------------------
    // Status / revocation
    // ---------------------------------------------------------------------
    /// Already-resolved credential status context, if verifier policy requires it.
    pub status: Option<StatusContext<'a>>,

    // ---------------------------------------------------------------------
    // QEAA / audit
    // ---------------------------------------------------------------------
    /// Raw QEAA metadata from the VC (optional)
    pub qeaa: Option<&'a reallyme_credential_audit::QeaaCompliance>,

    /// QEAA audit validation result (present only if audit succeeded)
    pub qeaa_audit_ok: Option<&'a QeaaCompliance>,
}

/// Status evaluation inputs.
///
/// Policy never fetches or parses status lists; it only
/// evaluates already-resolved information.
pub struct StatusContext<'a> {
    /// Status list used for the credential.
    pub list: &'a StatusList,
    /// Credential index in the status list.
    pub index: u64,
    /// Injected verifier for status-list signatures and freshness.
    pub verifier: &'a dyn StatusListVerifier,
}

/// Evaluate a presentation against verifier policy.
///
/// This function:
/// - performs no I/O
/// - performs no cryptography directly
/// - makes all accept/reject decisions explicit
pub fn evaluate(policy: &VpPolicy, ctx: &EvaluationContext) -> PolicyDecision {
    let mut errors = Vec::new();

    // ---------------------------------------------------------------------
    // 1. Don't evaluate the OpenID4VP binding here, just determine if it has been
    // ---------------------------------------------------------------------
    if !ctx.binding_ok {
        errors.push(VpPolicyError::InvalidBinding);
    }

    // ---------------------------------------------------------------------
    // 2. Presentation format
    // ---------------------------------------------------------------------
    match ctx.presentation {
        Presentation::SdJwtVc(_) if !policy.allow_sd_jwt => {
            errors.push(VpPolicyError::PresentationFormatNotAllowed);
        }
        Presentation::Zk(_) if !policy.allow_zk => {
            errors.push(VpPolicyError::PresentationFormatNotAllowed);
        }
        Presentation::Mdoc(_) => {
            // mdoc does not participate in VP policy evaluation (handled by delivery/mdoc).
            errors.push(VpPolicyError::PresentationFormatNotAllowed);
        }
        _ => {}
    }

    // ---------------------------------------------------------------------
    // 3. Algorithm allow-lists
    // ---------------------------------------------------------------------
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

    // ---------------------------------------------------------------------
    // 4. Claimset allow-list
    // ---------------------------------------------------------------------
    if let Some(allowed) = &policy.allowed_claimsets {
        if !allowed.iter().any(|c| c == ctx.claimset_id) {
            errors.push(VpPolicyError::ClaimsetNotAllowed);
        }
    }

    // ---------------------------------------------------------------------
    // 5. Required claims & actual disclosure enforcement
    // ---------------------------------------------------------------------

    // Extract what the holder actually disclosed (format-agnostic)
    let disclosed = match crate::disclosure::extract_disclosed_claims(ctx.presentation) {
        Ok(v) if v.len() <= MAX_POLICY_DISCLOSURES => v,
        Ok(_) | Err(_) => {
            errors.push(VpPolicyError::ProofInvalid);
            Vec::new()
        }
    };

    let required_claims = if policy.required_claims.len() > MAX_POLICY_REQUIRED_CLAIMS {
        errors.push(VpPolicyError::PolicyMisconfiguration);
        &[][..]
    } else {
        policy.required_claims.as_slice()
    };

    if !required_claims.is_empty() {
        for disclosed_claim in &disclosed {
            if !required_claims
                .iter()
                .any(|required| required.claim_path == disclosed_claim.claim_path)
            {
                errors.push(VpPolicyError::UnexpectedDisclosure);
            }
        }
    }

    for req in required_claims {
        // Find a disclosed claim matching this requirement
        let disclosed_claim = disclosed.iter().find(|d| d.claim_path == req.claim_path);

        let disclosed_claim = match disclosed_claim {
            Some(d) => d,
            None => {
                errors.push(VpPolicyError::MissingClaim);
                continue;
            }
        };

        // Enforce registry semantics (allowed disclosure modes)
        match validate_disclosure(ctx.claims_registry, &req.claim_path, disclosed_claim.mode) {
            Ok(()) => {}
            Err(identity_credential_claims_core::ClaimsError::DisclosureNotAllowed) => {
                errors.push(VpPolicyError::DisclosureNotAllowed);
                continue;
            }
            Err(identity_credential_claims_core::ClaimsError::PredicateNotAllowed) => {
                errors.push(VpPolicyError::PredicateNotSatisfied);
                continue;
            }
            Err(identity_credential_claims_core::ClaimsError::UnknownClaim) => {
                errors.push(VpPolicyError::MissingClaim);
                continue;
            }
            Err(identity_credential_claims_core::ClaimsError::InvalidInput(
                identity_credential_claims_core::ClaimsInvalidReason::InvalidDisclosureMode,
            )) => {
                // verifier policy misconfiguration
                errors.push(VpPolicyError::PolicyMisconfiguration);
                continue;
            }
            Err(identity_credential_claims_core::ClaimsError::InvalidInput(_)) => {
                errors.push(VpPolicyError::PolicyMisconfiguration);
                continue;
            }
        };

        // Enforce that the disclosed mode satisfies the required mode
        if disclosed_claim.mode != req.mode {
            errors.push(VpPolicyError::PredicateNotSatisfied);
        }
    }

    // ---------------------------------------------------------------------
    // 6. Status / revocation
    // ---------------------------------------------------------------------
    if policy.require_status {
        match &ctx.status {
            Some(sc) => {
                match identity_credential_status_core::verify_status(
                    sc.list,
                    sc.index,
                    ctx.now_unix,
                    sc.verifier,
                ) {
                    Ok(()) => {
                        if !status_age_within_policy(policy, sc, ctx.now_unix) {
                            errors.push(VpPolicyError::StatusTooOld);
                        }
                    }
                    Err(CredentialStatusError::Revoked) => {
                        errors.push(VpPolicyError::CredentialRevoked);
                    }
                    Err(CredentialStatusError::Suspended) => {
                        errors.push(VpPolicyError::CredentialSuspended);
                    }
                    Err(_) => {
                        errors.push(VpPolicyError::StatusCheckFailed);
                    }
                }
            }
            None => {
                errors.push(VpPolicyError::StatusCheckFailed);
            }
        }
    }

    // ---------------------------------------------------------------------
    // 7. QEAA / audit
    // ---------------------------------------------------------------------
    if policy.require_qeaa {
        match ctx.qeaa_audit_ok {
            Some(qeaa) => {
                // Optional profile match
                if let Some(required_profile) = &policy.min_qeaa_profile {
                    if qeaa.policies.policy_id != *required_profile {
                        errors.push(VpPolicyError::QeaaProfileMismatch);
                    }
                }

                // Optional LOIP enforcement
                if let Some(min_loip) = policy.min_identity_proofing_level {
                    if u32::from(qeaa.identity_proofing.loip.rank()) < min_loip {
                        errors.push(VpPolicyError::QeaaLevelInsufficient);
                    }
                }
            }

            None => {
                errors.push(VpPolicyError::QeaaRequired);
            }
        }
    }

    // ---------------------------------------------------------------------
    // Final decision
    // ---------------------------------------------------------------------
    if errors.is_empty() {
        PolicyDecision::Accept
    } else {
        PolicyDecision::Reject(errors)
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
        Some(age) => age <= max_age,
        None => false,
    }
}
