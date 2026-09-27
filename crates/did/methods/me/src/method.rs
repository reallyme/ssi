// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pub use reallyme_did_core::identifier::{
    derive_identifier_payload, generate_did_me, genesis_binding_cbor, is_valid_did_me,
    parse_did_me, verify_genesis_core_identifier, DidMeError, DidMeErrorReason, DidMeIdentifier,
    CORE_SIGNATURE_DOMAIN_TAG, GENESIS_DOMAIN_TAG, GENESIS_NONCE_LEN,
};

/// Build the byte string signed by did:me core attestation keys.
pub fn core_signature_input(core_bytes: &[u8]) -> Result<Vec<u8>, DidMeError> {
    reallyme_did_core::identifier::core_signature_input(core_bytes).map_err(|_| DidMeError {
        reason: DidMeErrorReason::CanonicalEncoding,
    })
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
