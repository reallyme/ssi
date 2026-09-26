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
//!
//! # Threading model
//!
//! The verification entry points are safe to call from any thread. The native
//! backend initializes libxml2, libxslt, and xmlsec process-wide state exactly
//! once and records the outcome; an initialization failure is reported as
//! [`XmlSecError::Internal`] on every later call without retrying. Native
//! verification calls are additionally serialized behind a process-wide lock,
//! so concurrent callers wait rather than share library state.

/// Typed errors returned by TSL XMLDSig verification.
pub mod error;
/// TSL-specific XMLDSig verification entry points.
pub mod verify;

pub use error::{XmlSecError, XmlSecPolicyViolationReason, XmlSecTrustRootErrorReason};
pub use verify::{
    verify_tsl_xmldsig_xmlsec, verify_tsl_xmldsig_xmlsec_with_exact_signers,
    TslXmlSignatureAlgorithm, VerifiedXmlSignature, MAX_TSL_XMLSEC_TRUSTED_ROOTS,
    MAX_TSL_XMLSEC_TRUSTED_ROOT_DER_BYTES,
};
