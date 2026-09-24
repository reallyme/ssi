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

//! Trust evaluation core.
//!
//! Overview: Deterministic trust decisions over already-parsed X.509 certificates.
//!
//! Scope:
//! - builds candidate chains
//! - applies eIDAS / ETSI policy
//! - invokes pluggable crypto + status verifiers
//!
//! Non-goals:
//! - DER parsing.
//! - Fetching intermediates.
//! - Managing trust stores.
//! - Performing cryptographic operations directly.

/// Typed trust-evaluation errors.
pub mod error;
pub use error::{ChainLinkPolicyViolation, TrustError, TrustResourceLimit};

/// Trust configuration, decision, and verifier traits.
pub mod model;
pub use model::{
    CertificatePosition, CertificateStatus, CertificateStatusEvidence, CertificateStatusPolicy,
    ChainLinkPolicy, DirectTrustEntry, SignatureVerifier, SignatureVerifyError, StatusRequirement,
    TrustAnchorEvidence, TrustAnchorKind, TrustConfig, TrustDecision, TrustEvaluationContext,
    TrustEvidence, TrustFailureReason, TrustOutcome, TrustPolicyId, TrustPurpose,
    TrustSourceEvidence,
};

/// Trust-evaluation engine.
pub mod evaluate;
pub use evaluate::{
    evaluate_trust, evaluate_trust_decision, MAX_DIRECT_TRUST_ENTRIES, MAX_TRUST_ROOTS,
};

/// Chain-link validation helpers.
pub mod link;
pub use link::{validate_certificate_link, validate_chain_links};
