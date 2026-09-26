// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! JWT-VC identity envelope support.
//!
//! This crate owns the credential-envelope JWT wrapper used by OpenID4VCI
//! encoders. Protocol request state, nonce services, offers, OAuth metadata,
//! and HTTP error shapes stay in the protocol repositories.
//!
//! [`JwtVcPayload`] is the W3C JWT-VC envelope profile. It is not wire
//! compatible with the legacy credential-model JWT adapter in
//! `identity-vc-jwt`; callers must select this profile from authenticated
//! protocol metadata before decoding.

mod envelope;

pub use envelope::{
    claims, issue, issue_jwt_vc, issue_jwt_vc_with_signer, jwt_vc_envelope_status,
    validate_jwt_vc_claims, verify, verify_jwt_vc, JwtVcEnvelopeError, JwtVcEnvelopeStatus,
    JwtVcIssueInput, JwtVcPayload, JwtVcVerificationOptions, VerifiedJwtVc,
    MAX_JWT_VC_CLOCK_SKEW_SECONDS,
};
