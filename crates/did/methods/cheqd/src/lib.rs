// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! did:cheqd method syntax helpers.
//!
//! cheqd DIDs are ledger-backed identifiers with an optional namespace segment
//! and either a UUID-style or Indy-style unique identifier. This crate validates
//! the DID string shape and identifier family only; ledger resolution and DID
//! document transaction semantics are intentionally out of scope.

mod method;

pub use method::{
    effective_namespace, generate_did_cheqd, is_valid_did_cheqd, parse_did_cheqd,
    CheqdDidIdentifier, CheqdIdentifierKind, DidCheqdError, DidCheqdErrorReason,
};
