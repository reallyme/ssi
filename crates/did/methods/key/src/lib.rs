// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! did:key method helpers.
//!
//! The method-specific identifier is a multibase-encoded multicodec public key.
//! This crate validates the identifier envelope and the public-key byte lengths
//! listed in the did:key method specification. It does not import keys into a
//! crypto backend; curve membership checks remain provider-specific.

mod method;

pub use method::{
    did_key_url, generate_did_key, is_valid_did_key, parse_did_key, DidKeyError, DidKeyErrorReason,
    DidKeyIdentifier, DidKeyMultibase, DidKeyMulticodec,
};
