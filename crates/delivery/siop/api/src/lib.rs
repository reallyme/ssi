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
//! Typed SIOP API facade.
//!
//! Protocol-defined JWT serialization remains owned by the SIOP verifier and
//! JOSE layers. This crate deliberately exposes the typed request, response,
//! and verification operations directly; it does not define a parallel JSON
//! DTO contract or perform network I/O and resolver discovery.

pub use identity_presentation_delivery_siop_core::{
    build_siop_authentication_request, validate_siop_authentication_request,
    BuildSiopAuthenticationRequestInput, SiopAuthenticationRequest, SiopAuthenticationResponse,
    SiopDeliveryError, SiopIdTokenClaims, SiopSubjectJwk,
};
pub use identity_presentation_delivery_siop_verifier::{
    verify_siop_authentication_response, verify_siop_authentication_response_with_state,
    verify_siop_id_token_jwt, SiopKeyResolver, SiopVerifierError, VerifiedSiopIdToken,
};
