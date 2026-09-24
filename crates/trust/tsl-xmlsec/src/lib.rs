// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Safe XMLDSig verification wrapper for ETSI TSL/LOTL documents.
//!
//! This crate is intentionally small:
//! - it enforces strict URI constraints for TSL/LOTL (same-document only)
//! - it delegates signature math to a backend:
//! - `xmlsec-ffi` feature: libxmlsec1 via a tiny C shim
//!
//! NOTE: This verifies XMLDSig only. Certificate trust-chain validation is handled elsewhere.

/// Typed errors returned by TSL XMLDSig verification.
pub mod error;
/// TSL-specific XMLDSig verification entry points.
pub mod verify;

pub use error::{XmlSecError, XmlSecPolicyViolationReason};
pub use verify::{
    verify_tsl_xmldsig_xmlsec, verify_tsl_xmldsig_xmlsec_with_exact_signer,
    TslXmlSignatureAlgorithm, VerifiedXmlSignature,
};
