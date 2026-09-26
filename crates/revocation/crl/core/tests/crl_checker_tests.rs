// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Tests for portable CRL status checking.

use identity_revocation_core::{StatusCheckError, StatusChecker};
use identity_revocation_crl_core::{CrlChecker, ParsedCrl};

use envelopes_x509::parse_cert_der;

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

#[test]
fn crl_checker_detects_revocation() {
    let leaf_der = read("tests/fixtures/leaf.der");

    let leaf = parse_cert_der(&leaf_der).unwrap();

    let issuer_key = leaf.authority_key_identifier.as_ref().unwrap().clone();

    let revoked_serial = leaf.serial.clone();

    let crl = ParsedCrl {
        issuer_key,
        revoked_serials: vec![revoked_serial],
        suspended_serials: Vec::new(),
        this_update_unix: 1_700_000_000,
        next_update_unix: 1_800_000_000,
    };

    let checker = CrlChecker::new(vec![crl]);

    let err = checker.check(&leaf, 1_750_000_000).unwrap_err();

    assert!(matches!(err, StatusCheckError::Revoked));
}

#[test]
fn crl_checker_allows_non_revoked() {
    let leaf_der = read("tests/fixtures/leaf.der");

    let leaf = parse_cert_der(&leaf_der).unwrap();

    let issuer_key = leaf.authority_key_identifier.as_ref().unwrap().clone();

    let crl = ParsedCrl {
        issuer_key,
        revoked_serials: vec![b"\xAA\xBB\xCC".to_vec()],
        suspended_serials: Vec::new(),
        this_update_unix: 1_700_000_000,
        next_update_unix: 1_800_000_000,
    };

    let checker = CrlChecker::new(vec![crl]);

    checker.check(&leaf, 1_750_000_000).unwrap();
}

fn leaf() -> envelopes_x509::X509Certificate {
    parse_cert_der(&read("tests/fixtures/leaf.der")).unwrap()
}

fn crl_for(
    leaf: &envelopes_x509::X509Certificate,
    revoked: Vec<Vec<u8>>,
    this_update_unix: u64,
    next_update_unix: u64,
) -> ParsedCrl {
    ParsedCrl {
        issuer_key: leaf.authority_key_identifier.as_ref().unwrap().clone(),
        revoked_serials: revoked,
        suspended_serials: Vec::new(),
        this_update_unix,
        next_update_unix,
    }
}

#[test]
fn crl_checker_reports_certificate_hold_as_suspended() {
    let leaf = leaf();
    let mut crl = crl_for(&leaf, Vec::new(), 1_000, 2_000);
    crl.suspended_serials.push(leaf.serial.clone());

    assert_eq!(
        CrlChecker::new(vec![crl]).check(&leaf, 1_500),
        Err(StatusCheckError::Suspended)
    );
}

#[test]
fn crl_checker_rejects_stale_crl_as_expired() {
    let leaf = leaf();
    let checker =
        CrlChecker::new(vec![crl_for(&leaf, Vec::new(), 1_000, 2_000)]).with_allowed_skew_secs(10);

    assert_eq!(checker.check(&leaf, 2_010), Ok(()));
    assert_eq!(checker.check(&leaf, 2_011), Err(StatusCheckError::Expired));
}

#[test]
fn crl_checker_rejects_future_this_update_as_not_yet_valid() {
    let leaf = leaf();
    let checker =
        CrlChecker::new(vec![crl_for(&leaf, Vec::new(), 1_000, 2_000)]).with_allowed_skew_secs(10);

    assert_eq!(checker.check(&leaf, 990), Ok(()));
    assert_eq!(
        checker.check(&leaf, 989),
        Err(StatusCheckError::NotYetValid)
    );
}

#[test]
fn crl_checker_rejects_inverted_window_and_overflow_as_invalid() {
    let leaf = leaf();
    let inverted = CrlChecker::new(vec![crl_for(&leaf, Vec::new(), 2_000, 1_000)]);
    assert_eq!(
        inverted.check(&leaf, 1_500),
        Err(StatusCheckError::InvalidList)
    );

    let overflow = CrlChecker::new(vec![crl_for(&leaf, Vec::new(), 1_000, u64::MAX)])
        .with_allowed_skew_secs(1);
    assert_eq!(
        overflow.check(&leaf, 1_500),
        Err(StatusCheckError::InvalidList)
    );
}

#[test]
fn crl_checker_matches_serial_with_sign_padding() {
    let leaf = leaf();
    let mut padded = vec![0, 0];
    padded.extend_from_slice(&leaf.serial);
    let checker = CrlChecker::new(vec![crl_for(&leaf, vec![padded], 1_000, 2_000)]);

    assert_eq!(checker.check(&leaf, 1_500), Err(StatusCheckError::Revoked));
}

#[test]
fn crl_checker_revocation_wins_regardless_of_crl_order() {
    let leaf = leaf();
    let clean = crl_for(&leaf, Vec::new(), 1_000, 2_000);
    let revoked = crl_for(&leaf, vec![leaf.serial.clone()], 1_000, 2_000);
    let stale = crl_for(&leaf, Vec::new(), 100, 200);

    let orders = [
        vec![clean.clone(), revoked.clone(), stale.clone()],
        vec![stale.clone(), revoked.clone(), clean.clone()],
        vec![revoked.clone(), clean.clone(), stale.clone()],
    ];
    for order in orders {
        assert_eq!(
            CrlChecker::new(order).check(&leaf, 1_500),
            Err(StatusCheckError::Revoked)
        );
    }
}

#[test]
fn crl_checker_ignores_stale_revocation_and_accepts_fresh_clean_crl() {
    let leaf = leaf();
    let stale_revoked = crl_for(&leaf, vec![leaf.serial.clone()], 100, 200);
    let clean = crl_for(&leaf, Vec::new(), 1_000, 2_000);

    for order in [
        vec![stale_revoked.clone(), clean.clone()],
        vec![clean.clone(), stale_revoked.clone()],
    ] {
        assert_eq!(CrlChecker::new(order).check(&leaf, 1_500), Ok(()));
    }
}

#[test]
fn crl_checker_reports_deterministic_error_when_every_crl_is_unusable() {
    let leaf = leaf();
    let expired = crl_for(&leaf, Vec::new(), 100, 200);
    let future = crl_for(&leaf, Vec::new(), 5_000, 6_000);

    for order in [
        vec![expired.clone(), future.clone()],
        vec![future.clone(), expired.clone()],
    ] {
        assert_eq!(
            CrlChecker::new(order).check(&leaf, 1_500),
            Err(StatusCheckError::NotYetValid)
        );
    }
}

#[test]
fn crl_checker_without_matching_issuer_is_unavailable() {
    let leaf = leaf();
    let mut crl = crl_for(&leaf, Vec::new(), 1_000, 2_000);
    crl.issuer_key = vec![0xFF];

    assert_eq!(
        CrlChecker::new(vec![crl]).check(&leaf, 1_500),
        Err(StatusCheckError::Unavailable)
    );
}
