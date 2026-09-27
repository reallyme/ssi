// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::DIDDocument;

/// Parse an untrusted did:me document through the bounded, duplicate-rejecting
/// JSON boundary before constructing the typed model.
pub fn parse_did_document_json(
    bytes: &[u8],
) -> Result<DIDDocument, identity_core_primitives::validate_json::JsonBoundaryError> {
    identity_core_primitives::validate_json::validate_json(bytes)?;
    serde_json::from_slice(bytes)
        .map_err(|_| identity_core_primitives::validate_json::JsonBoundaryError::invalid_document())
}
