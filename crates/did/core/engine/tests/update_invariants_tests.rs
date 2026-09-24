// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_core::update::error::UpdateError;
use reallyme_did_core::update::invariants::validate_chain;

#[test]
fn valid_sequence_and_prev_passes() {
    let old_seq = 3;
    let new_seq = 4;
    let old_cid = "bafyold";
    let prev = "bafyold";

    assert!(validate_chain(old_seq, new_seq, old_cid, Some(prev)).is_ok());
}

#[test]
fn invalid_sequence_fails() {
    let err = validate_chain(3, 5, "cid", Some("cid")).unwrap_err();
    assert!(matches!(err, UpdateError::InvalidSequence));
}

#[test]
fn invalid_prev_fails() {
    let err = validate_chain(3, 4, "cid1", Some("cid2")).unwrap_err();
    assert!(matches!(err, UpdateError::InvalidPrev));
}

#[test]
fn missing_prev_fails_when_sequence_advances() {
    let err = validate_chain(3, 4, "cid1", None).unwrap_err();
    assert!(matches!(err, UpdateError::InvalidPrev));
}

#[test]
fn first_sequence_allows_no_prev() {
    assert!(validate_chain(0, 1, "", None).is_ok());
}
