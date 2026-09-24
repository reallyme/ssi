// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! did:me method-specific identifier helpers.
//!
//! This crate owns the did:me method boundary, including the v1 genesis
//! commitment from the did:me specification Section 2.5. The generic DID core
//! crate supplies typed core structures, but it deliberately does not derive or
//! validate method-specific identifiers.

mod method;

pub use method::{
    core_signature_input, derive_identifier_payload, generate_did_me, genesis_binding_cbor,
    is_valid_did_me, parse_did_me, verify_genesis_core_identifier, DidMeError, DidMeErrorReason,
    DidMeIdentifier, CORE_SIGNATURE_DOMAIN_TAG, GENESIS_DOMAIN_TAG, GENESIS_NONCE_LEN,
};
