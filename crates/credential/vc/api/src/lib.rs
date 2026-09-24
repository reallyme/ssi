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
// This source-only support crate is consumed through the root identity facade.
// Keep workspace missing-docs enforcement active by default while avoiding
// filler rustdoc on transitional DTO fields that are not the public SDK surface.
#![allow(missing_docs)]

//! High-level VC issuance API.
//!
//! Overview: A high-level issuance and verification API for VC envelopes.
//!
//! Scope:
//! - Claim registry validation
//! - QEAA validation (optional / profile-controlled)
//! - Merkle-committed issuance via `reallyme-credential::committed`
//! - Optional encoding into transport formats (JWT-VC, IETF SD-JWT VC)
//!
//! Non-goals:
//! - Network I/O and protocol-specific HTTP endpoints.

pub mod error;
pub use error::{ClaimValueErrorReason, VcApiError};

pub mod model;
#[cfg(feature = "ietf-sd-jwt")]
pub use model::IetfSdJwtIssuerConfig;
#[cfg(feature = "jwt")]
pub use model::JwtIssuerConfig;
pub use model::{
    CredentialProfile, CustomProfile, IssueCredentialRequest, IssuedAndEncoded, IssuedCredential,
    IssuerSigning, PublicFormat,
};

pub mod issue;
pub use issue::{
    issue_and_encode_with_os_rng, issue_and_encode_with_rng,
    issue_and_encode_with_signer_with_os_rng, issue_and_encode_with_signer_with_rng,
    issue_with_os_rng, issue_with_rng, issue_with_signer_with_os_rng, issue_with_signer_with_rng,
    PublicEncoderConfigs,
};

pub mod verify;
pub use verify::{validate_credential, verify_credential_merkle_root, verify_credential_signature};
pub use verify::{
    validate_credential_with_identity_algorithm,
    verify_credential_signature_with_identity_algorithm,
};
