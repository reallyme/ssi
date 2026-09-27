// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protocol-neutral presentation policy-evaluation API.
//!
//! This crate does not verify signatures, proofs, or transaction bindings. It
//! evaluates facts produced by a protocol-specific verifier against disclosure
//! policy and returns a truth-first report. Applications must not treat this
//! policy report as cryptographic verification evidence.

/// SDK-facing presentation commands.
pub mod commands;

/// API error types.
pub mod error;

/// Verification report and failure classification types.
pub mod report;

/// Validation entry points.
pub mod validate;

pub use commands::{
    create_presentation_request, evaluate_presentation_policy, present, PresentationCheckCode,
    PresentationCheckName, PresentationCheckOutcome, PresentationCheckResult,
    PresentationCheckSeverity, PresentationCommandIssue, PresentationCredentialResult,
    PresentationDecision, PresentationDisclosureFact, PresentationExpected,
    PresentationPresentRequest, PresentationQeaaFact, PresentationRecord,
    PresentationRequestCreateRequest, PresentationRequestRecord, PresentationStatusFact,
    PresentationVerificationContext, PresentationVerificationFacts, PresentationVerificationResult,
    PresentationVerifyRequest,
};
pub use error::VpApiError;
pub use reallyme_vp_core::DisclosureMode;
pub use report::{
    classify_failures, VpFailureClass, VpReportProtoError, VpVerificationOutcome,
    VpVerificationReport,
};
pub use validate::{validate_vp, validate_vp_strict};
