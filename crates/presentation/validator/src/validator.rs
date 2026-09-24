// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Core, protocol-agnostic VP validation logic (policy/semantic).
//!
//! This module evaluates a Presentation against a selected policy using
//! cryptographic facts, status information, QEAA context, and a caller-supplied
//! binding result.
//!
//! It does **not** perform cryptographic verification of issuer/holder proofs.
//! It also does **not** depend on any delivery or transport protocol (OpenID4VP,
//! Web, mdoc, etc.).

use identity_presentation_vp_policy::{
    evaluate, selector::policy_for_claimset, EvaluationContext, PolicyDecision, StatusContext,
};

use identity_core_primitives::Algorithm;
use identity_credential_claims_core::ClaimsRegistry;
use identity_presentation_vp_core::model::Presentation;
use reallyme_credential_audit::{
    validate_qeaa_compliance_with_policy, IdentityProofingLevel, QeaaCompliance,
    QeaaValidationPolicy, DEFAULT_MAX_STATUS_AGE_SECONDS,
};

use crate::{error::VpValidationError, oidc_error::map_policy_decision};

/// Cryptographic facts relevant for policy evaluation.
///
/// These describe *how* the issuer and holder proofs were produced.
/// They are policy inputs, not protocol concerns.
#[derive(Debug, Clone, Copy)]
pub struct CryptoContext {
    /// Algorithm used for the issuer credential proof.
    pub issuer_algorithm: Algorithm,
    /// Algorithm used for the holder presentation proof.
    pub holder_algorithm: Algorithm,
}

/// QEAA-related inputs to verification.
///
/// QEAA validation is treated as **policy input**, not a hard failure.
/// If validation fails, `qeaa_audit_ok` becomes `None` and policy decides.
#[derive(Debug, Clone, Copy)]
pub struct QeaaContext<'a> {
    /// QEAA metadata extracted from the credential, if present.
    pub qeaa_from_vc: Option<&'a QeaaCompliance>,
}

/// Inputs required to verify a Verifiable Presentation.
///
/// All dependencies are resolved externally.
/// This struct is protocol-agnostic and stable across delivery mechanisms.
pub struct VpValidationInput<'a> {
    /// Presentation already decoded / parsed
    pub presentation: &'a Presentation,

    /// Claims and policy selection
    pub claims_registry: &'a ClaimsRegistry,
    /// Claimset identifier used to select verifier policy.
    pub claimset_id: &'a str,

    /// Cryptographic facts
    pub crypto: CryptoContext,

    /// Optional credential status context
    pub status: Option<StatusContext<'a>>,

    /// Optional QEAA context extracted from VC
    pub qeaa: QeaaContext<'a>,

    /// Result of external binding validation
    pub binding_ok: bool,

    /// Current time (unix seconds)
    pub now_unix: u64,
}

/// Verify a Verifiable Presentation against policy.
///
/// This function is:
/// - protocol-agnostic
/// - side-effect free
/// - reusable across OpenID4VP, Web, mdoc, QR, etc.
///
/// # Returns
/// - `PolicyDecision::Accept` on success
/// - `VpValidationError` mapped from policy rejection otherwise
pub fn validate_presentation<'a>(
    input: VpValidationInput<'a>,
) -> Result<PolicyDecision, VpValidationError> {
    // ---------------------------------------------------------------------
    // 1) Select policy for the requested claimset
    // ---------------------------------------------------------------------

    let policy =
        policy_for_claimset(input.claimset_id).ok_or(VpValidationError::UnsupportedClaimset)?;

    // ---------------------------------------------------------------------
    // 2) Validate QEAA audit material if present
    //
    // IMPORTANT:
    // - Missing QEAA must be treated as a failure *when required*
    // - qeaa_audit_ok uses presence as the success signal
    // - profile-specific LOIP thresholds belong to policy evaluation below
    // ---------------------------------------------------------------------

    let qeaa_audit_policy = QeaaValidationPolicy {
        now_unix: input.now_unix,
        min_identity_proofing_level: IdentityProofingLevel::Unspecified,
        max_status_age_seconds: DEFAULT_MAX_STATUS_AGE_SECONDS,
        require_current_audit_period: true,
    };

    let qeaa_audit_ok = match input.qeaa.qeaa_from_vc {
        Some(q) => {
            // QEAA provided: audit evidence must pass. Presentation policy
            // still owns whether the evidence level is sufficient for the
            // selected claimset/profile.
            validate_qeaa_compliance_with_policy(q, qeaa_audit_policy)
                .ok()
                .map(|_| q)
        }

        None => {
            // QEAA missing: always treated as audit failure
            None
        }
    };

    // ---------------------------------------------------------------------
    // 3) Build policy evaluation context
    //
    // This context is format- and protocol-agnostic.
    // ---------------------------------------------------------------------

    let ctx = EvaluationContext {
        // Binding result comes from the caller (OID4VP, Web, etc.)
        binding_ok: input.binding_ok,

        now_unix: input.now_unix,
        presentation: input.presentation,

        // Cryptographic facts
        issuer_algorithm: input.crypto.issuer_algorithm,
        holder_algorithm: input.crypto.holder_algorithm,

        // Claims & policy selection
        claims_registry: input.claims_registry,
        claimset_id: input.claimset_id,

        // Status checking delegated to policy
        status: input.status,

        // QEAA inputs
        qeaa: input.qeaa.qeaa_from_vc,
        qeaa_audit_ok,
    };

    // ---------------------------------------------------------------------
    // 4) Evaluate policy
    // ---------------------------------------------------------------------

    let decision = evaluate(&policy, &ctx);

    // ---------------------------------------------------------------------
    // 5) Canonical mapping from policy decision to validator error
    //
    // This ensures consistent semantics across all delivery mechanisms.
    // ---------------------------------------------------------------------

    map_policy_decision(decision.clone())?;

    // ---------------------------------------------------------------------
    // 6) Return decision for protocol / UX layers
    // ---------------------------------------------------------------------

    Ok(decision)
}
