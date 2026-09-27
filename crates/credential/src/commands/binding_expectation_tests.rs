// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    binding_expectation_check, CredentialCheckCode, CredentialCheckName, CredentialCheckOutcome,
};

#[test]
fn absent_binding_expectation_is_optional_and_skipped() {
    let result = binding_expectation_check(CredentialCheckName::Nonce, None);
    assert_eq!(result.name, CredentialCheckName::Nonce);
    assert_eq!(result.outcome, CredentialCheckOutcome::Skipped);
    assert!(!result.mandatory);
}

#[test]
fn empty_binding_expectation_is_a_typed_failure() {
    let result = binding_expectation_check(CredentialCheckName::Audience, Some("  "));
    assert_eq!(result.name, CredentialCheckName::Audience);
    assert_eq!(result.outcome, CredentialCheckOutcome::Fail);
    assert_eq!(result.code, CredentialCheckCode::InvalidCredential);
    assert!(result.mandatory);
}

#[test]
fn supplied_binding_expectation_is_mandatory_and_indeterminate() {
    let result = binding_expectation_check(CredentialCheckName::Nonce, Some("expected-nonce"));
    assert_eq!(result.name, CredentialCheckName::Nonce);
    assert_eq!(result.outcome, CredentialCheckOutcome::Indeterminate);
    assert!(result.mandatory);
}
