// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Certificate path decisions and their explicit portable backend.

pub use crate::dto::{
    CertificatePosition, CertificateStatus, CertificateStatusEvidence, TrustAnchorEvidence,
    TrustAnchorKind, TrustDecision, TrustDecisionEvidence, TrustDecisionFailure,
    TrustDecisionOutcome, TrustPolicyId, TrustProtoError, TrustPurpose, TrustSourceEvidence,
};
pub use crate::error::TrustApiError;
pub use crate::evaluate::{evaluate_trust_api, evaluate_trust_configured_api};
#[cfg(all(feature = "openssl", not(target_arch = "wasm32")))]
pub use crate::openssl::OpenSslSignatureVerifier;
pub use crate::portable::PortableSignatureVerifier;
pub use crate::TrustApiResult;
pub use envelopes_x509::{X509Certificate, X509Chain, X509Policy};
pub use reallyme_revocation::StatusChecker;
pub use reallyme_trust_core::{
    CertificateStatusPolicy, ChainLinkPolicy, DirectTrustEntry, SignatureVerifier,
    SignatureVerifyError, StatusRequirement, TrustConfig, TrustEvaluationContext,
};
