// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! did:jwk method helpers.
//!
//! The method-specific identifier is the unpadded base64url encoding of a
//! public JWK JSON serialization. Validation rejects private key members at
//! this boundary because leaking a private JWK into a DID would make the secret
//! permanently public.

mod method;

pub use method::{
    did_jwk_url, generate_did_jwk, generate_did_jwk_from_json_bytes, is_valid_did_jwk,
    parse_did_jwk, DidJwkError, DidJwkErrorReason, DidJwkIdentifier,
};
