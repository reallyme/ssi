// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_core::update::error::UpdateError;
use reallyme_did_core::update::policy::validate_update_policy;

#[test]
fn threshold_within_allowed_methods_is_valid() {
    let allowed = vec!["#k1".into(), "#k2".into()];

    assert!(validate_update_policy(&allowed, Some(2)).is_ok());
}

#[test]
fn missing_threshold_defaults_to_one() {
    let allowed = vec!["#k1".into()];

    assert!(validate_update_policy(&allowed, None).is_ok());
}

#[test]
fn empty_allowed_methods_fails() {
    let allowed: Vec<String> = vec![];

    let err = validate_update_policy(&allowed, None).unwrap_err();
    assert!(matches!(err, UpdateError::PolicyViolation));
}

#[test]
fn zero_threshold_fails() {
    let allowed = vec!["#k1".into()];

    let err = validate_update_policy(&allowed, Some(0)).unwrap_err();
    assert!(matches!(err, UpdateError::PolicyViolation));
}

#[test]
fn threshold_above_allowed_methods_fails() {
    let allowed = vec!["#k1".into()];

    let err = validate_update_policy(&allowed, Some(2)).unwrap_err();
    assert!(matches!(err, UpdateError::PolicyViolation));
}
