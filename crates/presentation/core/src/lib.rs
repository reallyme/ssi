// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protocol-agnostic verifiable presentation models.
//!
//! The types in this crate deliberately avoid OpenID4VP, QR, BLE, and other
//! delivery concerns. They represent the reusable presentation layer that can be
//! bound to a verifier challenge and carried by multiple protocols.

mod protect_model;

/// Holder-binding and freshness primitives.
pub mod binding;

/// VP core error types.
pub mod error;

/// Presentation model types.
pub mod model;

pub use binding::PresentationBinding;
pub use error::VpError;
pub use model::{
    ClaimDisclosure, CredentialReference, CredentialStatusRef, DisclosureMode, MdocPresentation,
    Presentation, PresentationFreshness, QeaaVerifierHints, Range, SdJwtVcPresentation,
    StatusPurpose, ValueSet, ZkPresentation, ZkProof, ZkProofSuite,
};
