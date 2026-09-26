// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reusable disclosure policies for verifiable presentation evaluation.
//!
//! This crate owns verifier acceptance policy: allowed algorithms,
//! presentation formats, status freshness, QEAA requirements, and disclosure
//! requirements. It deliberately does not know about OpenID4VP transport,
//! protocol messages, HTTP, QR, BLE, or resolver I/O.

/// Claims registry policy preflight.
pub mod claims;

/// Policy evaluation.
pub mod evaluate;

/// Fixed policy error categories.
pub mod error;

/// Policy model types.
pub mod model;

/// Built-in eIDAS-oriented policy profiles.
pub mod profiles;

/// Claim satisfaction planning.
pub mod satisfaction;

/// Claimset selector for built-in profiles.
pub mod selector;

pub use claims::validate_policy_claims_against_registry;
pub use error::{PolicyDecision, VpPolicyError};
pub use evaluate::{
    evaluate, EvaluationContext, ExtractedDisclosure, QeaaContext, StatusContext,
    MAX_EVALUATED_DISCLOSURES, MAX_EVALUATED_REQUIRED_CLAIMS,
};
pub use model::{RequiredClaim, VpPolicy};
pub use profiles::{
    eu_address_policy, eu_age_policy, eu_company_policy, eu_diploma_policy,
    eu_driving_license_policy, eu_eaa_policy, eu_eidas_vid_policy, eu_health_policy, eu_kyc_policy,
    eu_passport_policy, eu_pid_baseline_policy, eu_pid_policy, eu_professional_license_policy,
    eu_tax_policy,
};
pub use satisfaction::{plan_satisfaction, DerivationInput, DerivationPlan, SatisfactionPlan};
pub use selector::policy_for_claimset;
