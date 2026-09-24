// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ETSI TS 119 182-1 JAdES Baseline-B validation.
//!
//! JOSE backends authenticate the compact envelope. This crate owns the
//! reusable JAdES policy applied to the authenticated protected header and the
//! SSI X.509 trust decision. Application profiles such as ETSI TS 119 602 keep
//! their document-specific signer-identity rules outside this crate.

mod certificate;
mod error;
mod header;
mod model;
mod time_policy;
mod validate;

pub use error::{
    CompactJwsVerificationError, CompactJwsVerificationErrorReason, JadesError, JadesErrorReason,
};
pub use model::{
    AuthenticatedCompactJws, AuthenticatedJades, ClaimedSigningTime, ClaimedSigningTimeKind,
    CompactJwsVerifier, JadesAuthenticationInput, JadesPolicy, JadesSignatureAlgorithm,
    JadesValidationInput, JadesVerificationKey, ValidatedJades, MAX_JADES_COMPACT_BYTES,
    MAX_JADES_PROTECTED_HEADER_BYTES,
};
pub use validate::{authenticate_compact_jades, validate_compact_jades};
