// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical credential signing representation.
//!
//! The package-owned credential crate is the sole canonicalization authority.
//! This adapter keeps the established VC-core error boundary while delegating
//! the representation itself, preventing protocol adapters from signing a
//! subtly different credential graph.

use crate::committed::{error::VcError, model::CredentialEnvelope};

/// Produce the canonical CBOR bytes covered by the issuer signature.
pub fn canonical_credential_bytes(envelope: &CredentialEnvelope) -> Result<Vec<u8>, VcError> {
    crate::validate_credential_unsigned_envelope(envelope)
        .map_err(|_| VcError::InvalidCredential)?;
    crate::credential_signing_payload(envelope).map_err(|_| VcError::Canonicalization)
}
