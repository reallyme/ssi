// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! JSON-facing DID document model used by ReallyMe DID generation and transport.
//!
//! These types intentionally preserve DID JSON shapes because most credential ecosystems still
//! exchange DID documents as JSON, even when ReallyMe also supports protobuf transport.

mod model;

pub use model::{
    Attestation, Controller, DIDDocument, DNSBinding, DataIntegrityProof, DomainVerification,
    Service, UpdatePolicy, VerificationMethod, WellKnownBinding,
};

/// Parse an untrusted did:me document through the bounded, duplicate-rejecting
/// JSON boundary before constructing the typed model.
pub fn parse_did_document_json(
    bytes: &[u8],
) -> Result<DIDDocument, identity_core_primitives::validate_json::JsonBoundaryError> {
    identity_core_primitives::validate_json::validate_json(bytes)?;
    serde_json::from_slice(bytes)
        .map_err(|_| identity_core_primitives::validate_json::JsonBoundaryError::invalid_document())
}

#[cfg(test)]
mod json_boundary_tests {
    use super::parse_did_document_json;

    #[test]
    fn did_document_json_rejects_duplicate_members_and_oversized_input() {
        assert!(parse_did_document_json(br#"{"id":"did:me:a","id":"did:me:b"}"#).is_err());
        assert!(parse_did_document_json(&vec![b' '; 1_048_577]).is_err());
    }
}
