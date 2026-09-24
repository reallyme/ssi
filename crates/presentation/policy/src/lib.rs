// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

//! Verifiable Presentation policy engine.
//!
//! This crate decides whether a presentation is acceptable
//! given verifier policy, claims registry, status information,
//! and QEAA audit results.
//!
//! It is protocol-agnostic and side-effect free.

/// Disclosure extraction used by policy evaluation.
pub mod disclosure;
/// Fixed, non-PII policy errors and decisions.
pub mod error;
/// Pure policy evaluation entry points.
pub mod evaluate;
/// Verifier policy model types.
pub mod model;
/// Planning helpers for satisfying disclosure requirements.
pub mod plan;
/// Built-in reusable policy constructors.
pub mod policy;
pub mod profiles;
/// Claimset-to-policy selector helpers.
pub mod selector;

pub use disclosure::{extract_disclosed_claims, DisclosedClaim};
pub use error::{PolicyDecision, VpPolicyError};
pub use evaluate::{evaluate, EvaluationContext, StatusContext};
pub use model::{RequiredClaim, VpPolicy};
pub use plan::{plan_satisfaction, DerivationInput, DerivationPlan, SatisfactionPlan};
pub use selector::policy_for_claimset;

pub use profiles::{
    eu_address_policy, eu_age_policy, eu_company_policy, eu_diploma_policy,
    eu_driving_license_policy, eu_eaa_policy, eu_eidas_vid_policy, eu_health_policy, eu_kyc_policy,
    eu_passport_policy, eu_pid_baseline_policy, eu_pid_policy, eu_professional_license_policy,
    eu_tax_policy,
};
