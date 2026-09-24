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

//! Native-only TSL / LOTL XMLDSig verification.
//!
//! This crate depends on system XML security libraries.
//! It is NOT available on WASM, iOS, or Android.
//!
//! Use pre-verified trust metadata on those platforms.
//! ETSI TSL / LOTL verification backend (OpenSSL).
//!
//! Responsibilities:
//! - verify XMLDSig on TSL / LOTL documents
//! - validate signer certificate chain
//! - enforce trust anchors
//! - output a verified `TrustedList`
//!
//! This crate:
//! - does NOT fetch XML
//! - does NOT apply policy
//! - does NOT interpret QTSP semantics
//!
//! It is the cryptographic perimeter for TSL ingestion.

/// Typed errors for native TSL verification.
pub mod error;
mod signer_profile;
mod trust_roots;
/// OpenSSL/xmlsec-backed TSL verification entry points.
pub mod verify;

#[cfg(test)]
#[path = "verify_tests.rs"]
mod verify_tests;

pub use error::{
    TslOpenSslError, TslSignatureProfileFailureReason, TslSignerProfileFailureReason,
    TslTrustRootErrorReason,
};
pub use signer_profile::{
    TslSignatureAlgorithm, TslSignerIssuerSource, TslSignerProfileEvidence,
    MAX_TSL_SIGNER_COMMUNITY_LISTS, TSL_SIGNING_EXTENDED_KEY_USAGE_OID,
};
pub use trust_roots::{
    validate_tsl_trust_roots, MAX_TSL_TRUST_ROOTS, MAX_TSL_TRUST_ROOT_DER_BYTES,
    MAX_TSL_TRUST_ROOT_PEM_BUNDLE_BYTES,
};
pub use verify::{
    verify_tsl_xml_openssl, verify_tsl_xml_openssl_with_community_lists,
    verify_tsl_xml_openssl_with_external_signer, TslSignerAuthorizationEvidence,
    VerifiedTrustedList,
};
