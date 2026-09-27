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
//! Tests for portable OCSP status checking.

use envelopes_x509::{parse_cert_der, X509Certificate};
use identity_revocation_core::{StatusCheckError, StatusChecker};
use identity_revocation_ocsp_core::{
    bind_response_to_certificates, OcspCertStatus, OcspChecker, OcspError, OcspPolicy,
    ParsedOcspResponse, UnverifiedOcspResponse,
};
use time::OffsetDateTime;

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../openssl/tests/fixtures")
        .join(name);
    std::fs::read(path).unwrap()
}

fn mock_cert(_serial: Vec<u8>, _issuer_key: Vec<u8>) -> X509Certificate {
    parse_cert_der(&fixture("leaf.der")).unwrap()
}

fn response(
    _serial: Vec<u8>,
    _issuer_key: Vec<u8>,
    status: OcspCertStatus,
    this_update: u64,
    next_update: Option<u64>,
) -> ParsedOcspResponse {
    let cert = parse_cert_der(&fixture("leaf.der")).unwrap();
    let issuer = parse_cert_der(&fixture("issuer.der")).unwrap();
    let projected = UnverifiedOcspResponse::new(
        issuer.rfc5280_method_one_key_identifier().unwrap().to_vec(),
        cert.serial.clone(),
        status,
        this_update,
        next_update,
        None,
        None,
    );
    bind_response_to_certificates(projected, &fixture("leaf.der"), &fixture("issuer.der")).unwrap()
}

#[test]
fn ocsp_allows_good_cert() {
    let issuer_key = vec![0xAA, 0xBB, 0xCC];
    let serial = vec![1];
    let now = 1_700_000_000;

    let cert = mock_cert(serial.clone(), issuer_key.clone());

    let resp = response(
        serial,
        issuer_key,
        OcspCertStatus::Good,
        now - 10,
        Some(now + 100),
    );

    let checker = OcspChecker::new(vec![resp]);
    checker.check(&cert, now).unwrap();
}

#[test]
fn ocsp_detects_revocation() {
    let issuer_key = vec![0xAA, 0xBB, 0xCC];
    let serial = vec![2];
    let now = 1_700_000_000;

    let cert = mock_cert(serial.clone(), issuer_key.clone());

    let resp = response(
        serial,
        issuer_key,
        OcspCertStatus::Revoked,
        now - 10,
        Some(now + 100),
    );

    let checker = OcspChecker::new(vec![resp]);
    let err = checker.check(&cert, now).unwrap_err();

    assert_eq!(err, StatusCheckError::Revoked);
}

#[test]
fn strict_policy_requires_next_update() {
    let issuer_key = vec![0xAA, 0xBB, 0xCC];
    let serial = vec![3];
    let now = 1_700_000_000;

    let cert = mock_cert(serial.clone(), issuer_key.clone());

    let resp = response(
        serial.clone(),
        issuer_key.clone(),
        OcspCertStatus::Good,
        now - 10,
        None,
    );

    let checker = OcspChecker::new(vec![resp]).with_policy(OcspPolicy {
        require_next_update: true,
        max_age_secs: None,
        allowed_skew_secs: 0,
    });

    let err = checker.check(&cert, now).unwrap_err();
    assert_eq!(err, StatusCheckError::InvalidList);
}

#[test]
fn default_policy_bounds_responses_without_next_update() {
    let issuer_key = vec![0x16];
    let cert = mock_cert(vec![10], issuer_key.clone());
    let checker = OcspChecker::new(vec![response(
        vec![10],
        issuer_key,
        OcspCertStatus::Good,
        1_000,
        None,
    )]);

    assert_eq!(checker.check(&cert, 87_701), Err(StatusCheckError::Expired));
}

#[test]
fn rejects_this_update_beyond_the_allowed_future_skew() {
    let issuer_key = vec![0x10];
    let cert = mock_cert(vec![4], issuer_key.clone());
    let checker = OcspChecker::new(vec![response(
        vec![4],
        issuer_key,
        OcspCertStatus::Good,
        1_021,
        Some(1_100),
    )])
    .with_policy(OcspPolicy {
        allowed_skew_secs: 20,
        ..OcspPolicy::default()
    });

    assert_eq!(
        checker.check(&cert, 1_000),
        Err(StatusCheckError::InvalidList)
    );
}

#[test]
fn accepts_freshness_at_the_inclusive_skew_boundaries() {
    let issuer_key = vec![0x11];
    let cert = mock_cert(vec![5], issuer_key.clone());
    let policy = OcspPolicy {
        allowed_skew_secs: 20,
        ..OcspPolicy::default()
    };
    let future_this_update = OcspChecker::new(vec![response(
        vec![0, 5],
        issuer_key.clone(),
        OcspCertStatus::Good,
        1_020,
        Some(1_100),
    )])
    .with_policy(policy);
    let past_next_update = OcspChecker::new(vec![response(
        vec![0, 5],
        issuer_key,
        OcspCertStatus::Good,
        900,
        Some(980),
    )])
    .with_policy(policy);

    assert_eq!(future_this_update.check(&cert, 1_000), Ok(()));
    assert_eq!(past_next_update.check(&cert, 1_000), Ok(()));
    assert_eq!(
        past_next_update.check(&cert, 1_001),
        Err(StatusCheckError::Expired)
    );
}

#[test]
fn rejects_response_older_than_checked_maximum_age() {
    let issuer_key = vec![0x12];
    let cert = mock_cert(vec![6], issuer_key.clone());
    let checker = OcspChecker::new(vec![response(
        vec![6],
        issuer_key,
        OcspCertStatus::Good,
        900,
        Some(1_100),
    )])
    .with_policy(OcspPolicy {
        max_age_secs: Some(50),
        allowed_skew_secs: 20,
        ..OcspPolicy::default()
    });

    assert_eq!(checker.check(&cert, 971), Err(StatusCheckError::Expired));
}

#[test]
fn timestamp_overflow_fails_closed_as_invalid_evidence() {
    let issuer_key = vec![0x13];
    let cert = mock_cert(vec![7], issuer_key.clone());
    let checker = OcspChecker::new(vec![response(
        vec![7],
        issuer_key,
        OcspCertStatus::Good,
        1_000,
        Some(u64::MAX),
    )])
    .with_policy(OcspPolicy {
        allowed_skew_secs: 1,
        ..OcspPolicy::default()
    });

    assert_eq!(
        checker.check(&cert, 1_000),
        Err(StatusCheckError::InvalidList)
    );
}

#[test]
fn unknown_status_is_not_reported_as_revocation() {
    let issuer_key = vec![0x14];
    let cert = mock_cert(vec![8], issuer_key.clone());
    let checker = OcspChecker::new(vec![response(
        vec![8],
        issuer_key,
        OcspCertStatus::Unknown,
        999,
        Some(1_100),
    )]);

    assert_eq!(checker.check(&cert, 1_000), Err(StatusCheckError::Unknown));
}

#[test]
fn revoked_response_wins_regardless_of_response_order() {
    let issuer_key = vec![0x20];
    let cert = mock_cert(vec![0x21], issuer_key.clone());
    for order in [
        [
            OcspCertStatus::Good,
            OcspCertStatus::Revoked,
            OcspCertStatus::Unknown,
        ],
        [
            OcspCertStatus::Unknown,
            OcspCertStatus::Good,
            OcspCertStatus::Revoked,
        ],
        [
            OcspCertStatus::Revoked,
            OcspCertStatus::Unknown,
            OcspCertStatus::Good,
        ],
    ] {
        let responses = order
            .into_iter()
            .map(|status| response(vec![0x21], issuer_key.clone(), status, 999, Some(1_100)))
            .collect();
        assert_eq!(
            OcspChecker::new(responses).check(&cert, 1_000),
            Err(StatusCheckError::Revoked)
        );
    }
}

#[test]
fn stale_revocation_does_not_mask_fresh_good_response() {
    let issuer_key = vec![0x22];
    let cert = mock_cert(vec![0x23], issuer_key.clone());
    for stale_first in [true, false] {
        let fresh_good = response(
            vec![0x23],
            issuer_key.clone(),
            OcspCertStatus::Good,
            999,
            Some(1_100),
        );
        let stale_revoked = response(
            vec![0x23],
            issuer_key.clone(),
            OcspCertStatus::Revoked,
            100,
            Some(200),
        );
        let order = if stale_first {
            vec![stale_revoked, fresh_good]
        } else {
            vec![fresh_good, stale_revoked]
        };
        assert_eq!(OcspChecker::new(order).check(&cert, 1_000), Ok(()));
    }
}

#[test]
fn good_response_wins_over_unknown_regardless_of_order() {
    let issuer_key = vec![0x24];
    let cert = mock_cert(vec![0x25], issuer_key.clone());
    for order in [
        [OcspCertStatus::Unknown, OcspCertStatus::Good],
        [OcspCertStatus::Good, OcspCertStatus::Unknown],
    ] {
        let responses = order
            .into_iter()
            .map(|status| response(vec![0x25], issuer_key.clone(), status, 999, Some(1_100)))
            .collect();
        assert_eq!(OcspChecker::new(responses).check(&cert, 1_000), Ok(()));
    }
}

#[test]
fn unusable_responses_report_expired() {
    let issuer_key = vec![0x26];
    let cert = mock_cert(vec![0x27], issuer_key.clone());
    let expired = response(
        vec![0x27],
        issuer_key.clone(),
        OcspCertStatus::Good,
        100,
        Some(200),
    );
    assert_eq!(
        OcspChecker::new(vec![expired]).check(&cert, 1_000),
        Err(StatusCheckError::Expired)
    );
}

#[test]
fn next_update_before_this_update_is_invalid() {
    let cert = parse_cert_der(&fixture("leaf.der")).unwrap();
    let issuer = parse_cert_der(&fixture("issuer.der")).unwrap();
    let projected = UnverifiedOcspResponse::new(
        issuer.rfc5280_method_one_key_identifier().unwrap().to_vec(),
        cert.serial.clone(),
        OcspCertStatus::Good,
        999,
        Some(998),
        None,
        None,
    );

    assert_eq!(
        bind_response_to_certificates(projected, &fixture("leaf.der"), &fixture("issuer.der"))
            .unwrap_err(),
        OcspError::InvalidResponse
    );
}

#[test]
fn composite_policy_ocsp_section_governs_checker() {
    let issuer_key = vec![0x2A];
    let cert = mock_cert(vec![0x2B], issuer_key.clone());
    let strict_response = response(
        vec![0x2B],
        issuer_key.clone(),
        OcspCertStatus::Good,
        1_000,
        None,
    );
    let default_response = response(vec![0x2B], issuer_key, OcspCertStatus::Good, 1_000, None);
    let mut policy = identity_revocation_core::hybrid_fallback(OffsetDateTime::UNIX_EPOCH)
        .expect("Unix epoch is representable");
    policy.ocsp.require_next_update = true;

    assert_eq!(
        OcspChecker::new(vec![default_response]).check(&cert, 1_000),
        Ok(())
    );
    assert_eq!(
        OcspChecker::from_composite_policy(vec![strict_response], &policy).check(&cert, 1_000),
        Err(StatusCheckError::InvalidList)
    );
}
