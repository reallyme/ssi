// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protocol-neutral verifiable presentation API.
//!
//! This crate is the reusable VP API boundary. It accepts already-verified
//! envelope facts, evaluates them against disclosure policy, and returns a
//! stable truth-first report that delivery protocols can map into OpenID4VP,
//! SIOP, web, mdoc, or SDK-specific responses.

/// SDK-facing presentation commands.
pub mod commands;

/// API error types.
pub mod error;

/// Verification report and failure classification types.
pub mod report;

/// Validation entry points.
pub mod validate;

pub use commands::{
    create_presentation_request, present, verify_presentation, PresentationCheckCode,
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
