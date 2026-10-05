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

//! Public trust capabilities. Certificate path validation is the first domain;
//! source-specific trust services can be added without coupling their state or
//! policy to certificate verification.

/// Certificate path evaluation and its portable verification backend.
pub mod certificate;

/// Validated public decision and protobuf boundary types.
pub mod dto;
/// Typed facade failures.
pub mod error;
/// Trust evaluation entry points.
pub mod evaluate;
/// Optional native OpenSSL certificate-signature backend.
#[cfg(all(feature = "openssl", not(target_arch = "wasm32")))]
pub mod openssl;
/// Portable certificate-signature backend.
pub mod portable;

pub use dto::{
    CertificatePosition, CertificateStatus, CertificateStatusEvidence, TrustAnchorEvidence,
    TrustAnchorKind, TrustDecision, TrustDecisionEvidence, TrustDecisionFailure,
    TrustDecisionOutcome, TrustPolicyId, TrustProtoError, TrustPurpose, TrustSourceEvidence,
};
pub use envelopes_x509::{X509Certificate, X509Chain, X509Policy};
pub use error::TrustApiError;
pub use evaluate::{evaluate_trust_api, evaluate_trust_configured_api};
#[cfg(all(feature = "openssl", not(target_arch = "wasm32")))]
pub use openssl::OpenSslSignatureVerifier;
pub use portable::PortableSignatureVerifier;
pub use reallyme_revocation::StatusChecker;
pub use reallyme_trust_core::{
    CertificateStatusPolicy, ChainLinkPolicy, DirectTrustEntry, SignatureVerifier,
    SignatureVerifyError, StatusRequirement, TrustConfig, TrustEvaluationContext,
};

/// Result returned by trust facade operations.
pub type TrustApiResult<T> = Result<T, TrustApiError>;
