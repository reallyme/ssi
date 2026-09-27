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
use identity_revocation_ocsp_core::{OcspCertStatus, OcspPolicy};
use time::OffsetDateTime;

use crate::{OcspChecker, ParsedOcspResponse};

impl ParsedOcspResponse {
    fn for_test(
        certificate_sha256: [u8; 32],
        serial: Vec<u8>,
        status: OcspCertStatus,
        this_update: u64,
        next_update: Option<u64>,
    ) -> Self {
        Self {
            issuer_key: Vec::new(),
            certificate_sha256,
            serial,
            status,
            this_update,
            next_update,
            response_nonce: None,
        }
    }
}

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../openssl/tests/fixtures")
        .join(name);
    std::fs::read(path).unwrap()
}

fn mock_cert() -> X509Certificate {
    parse_cert_der(&fixture("leaf.der")).unwrap()
}

fn response(
    status: OcspCertStatus,
    this_update: u64,
    next_update: Option<u64>,
) -> ParsedOcspResponse {
    let cert = parse_cert_der(&fixture("leaf.der")).unwrap();
    ParsedOcspResponse::for_test(
        *reallyme_crypto::sha2::digest(cert.der.as_slice()).as_bytes(),
        cert.serial.clone(),
        status,
        this_update,
        next_update,
    )
}

fn fixture_response(
    certificate_name: &str,
    _issuer_name: &str,
    status: OcspCertStatus,
    this_update: u64,
    next_update: Option<u64>,
) -> ParsedOcspResponse {
    let certificate_der = fixture(certificate_name);
    let certificate = parse_cert_der(&certificate_der).unwrap();
    ParsedOcspResponse::for_test(
        *reallyme_crypto::sha2::digest(&certificate_der).as_bytes(),
        certificate.serial.clone(),
        status,
        this_update,
        next_update,
    )
}

#[test]
fn good_response_for_one_certificate_does_not_match_another() {
    let now = 1_800_000_000;
    let certificate_b = parse_cert_der(&fixture("sha256-leaf.der")).unwrap();
    let response_a = fixture_response(
        "leaf.der",
        "issuer.der",
        OcspCertStatus::Good,
        now - 1,
        Some(now + 100),
    );

    assert_eq!(
        OcspChecker::new(vec![response_a]).check(&certificate_b, now),
        Err(StatusCheckError::Unavailable)
    );
}

#[test]
fn another_certificates_good_response_cannot_mask_revocation() {
    let now = 1_800_000_000;
    let certificate_b = parse_cert_der(&fixture("sha256-leaf.der")).unwrap();
    let response_a = fixture_response(
        "leaf.der",
        "issuer.der",
        OcspCertStatus::Good,
        now - 1,
        Some(now + 100),
    );
    let response_b = fixture_response(
        "sha256-leaf.der",
        "sha256-issuer.der",
        OcspCertStatus::Revoked,
        now - 1,
        Some(now + 100),
    );

    assert_eq!(
        OcspChecker::new(vec![response_a, response_b]).check(&certificate_b, now),
        Err(StatusCheckError::Revoked)
    );
}

#[test]
fn ocsp_allows_good_cert() {
    let now = 1_700_000_000;

    let cert = mock_cert();

    let resp = response(OcspCertStatus::Good, now - 10, Some(now + 100));

    let checker = OcspChecker::new(vec![resp]);
    checker.check(&cert, now).unwrap();
}

#[test]
fn ocsp_detects_revocation() {
    let now = 1_700_000_000;

    let cert = mock_cert();

    let resp = response(OcspCertStatus::Revoked, now - 10, Some(now + 100));

    let checker = OcspChecker::new(vec![resp]);
    let err = checker.check(&cert, now).unwrap_err();

    assert_eq!(err, StatusCheckError::Revoked);
}

#[test]
fn strict_policy_requires_next_update() {
    let now = 1_700_000_000;

    let cert = mock_cert();

    let resp = response(OcspCertStatus::Good, now - 10, None);

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
    let cert = mock_cert();
    let checker = OcspChecker::new(vec![response(OcspCertStatus::Good, 1_000, None)]);

    assert_eq!(checker.check(&cert, 87_701), Err(StatusCheckError::Expired));
}

#[test]
fn rejects_this_update_beyond_the_allowed_future_skew() {
    let cert = mock_cert();
    let checker = OcspChecker::new(vec![response(OcspCertStatus::Good, 1_021, Some(1_100))])
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
    let cert = mock_cert();
    let policy = OcspPolicy {
        allowed_skew_secs: 20,
        ..OcspPolicy::default()
    };
    let future_this_update =
        OcspChecker::new(vec![response(OcspCertStatus::Good, 1_020, Some(1_100))])
            .with_policy(policy);
    let past_next_update =
        OcspChecker::new(vec![response(OcspCertStatus::Good, 900, Some(980))]).with_policy(policy);

    assert_eq!(future_this_update.check(&cert, 1_000), Ok(()));
    assert_eq!(past_next_update.check(&cert, 1_000), Ok(()));
    assert_eq!(
        past_next_update.check(&cert, 1_001),
        Err(StatusCheckError::Expired)
    );
}

#[test]
fn rejects_response_older_than_checked_maximum_age() {
    let cert = mock_cert();
    let checker = OcspChecker::new(vec![response(OcspCertStatus::Good, 900, Some(1_100))])
        .with_policy(OcspPolicy {
            max_age_secs: Some(50),
            allowed_skew_secs: 20,
            ..OcspPolicy::default()
        });

    assert_eq!(checker.check(&cert, 971), Err(StatusCheckError::Expired));
}

#[test]
fn timestamp_overflow_fails_closed_as_invalid_evidence() {
    let cert = mock_cert();
    let checker = OcspChecker::new(vec![response(OcspCertStatus::Good, 1_000, Some(u64::MAX))])
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
    let cert = mock_cert();
    let checker = OcspChecker::new(vec![response(OcspCertStatus::Unknown, 999, Some(1_100))]);

    assert_eq!(checker.check(&cert, 1_000), Err(StatusCheckError::Unknown));
}

#[test]
fn revoked_response_wins_regardless_of_response_order() {
    let cert = mock_cert();
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
            .map(|status| response(status, 999, Some(1_100)))
            .collect();
        assert_eq!(
            OcspChecker::new(responses).check(&cert, 1_000),
            Err(StatusCheckError::Revoked)
        );
    }
}

#[test]
fn stale_revocation_does_not_mask_fresh_good_response() {
    let cert = mock_cert();
    for stale_first in [true, false] {
        let fresh_good = response(OcspCertStatus::Good, 999, Some(1_100));
        let stale_revoked = response(OcspCertStatus::Revoked, 100, Some(200));
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
    let cert = mock_cert();
    for order in [
        [OcspCertStatus::Unknown, OcspCertStatus::Good],
        [OcspCertStatus::Good, OcspCertStatus::Unknown],
    ] {
        let responses = order
            .into_iter()
            .map(|status| response(status, 999, Some(1_100)))
            .collect();
        assert_eq!(OcspChecker::new(responses).check(&cert, 1_000), Ok(()));
    }
}

#[test]
fn unusable_responses_report_expired() {
    let cert = mock_cert();
    let expired = response(OcspCertStatus::Good, 100, Some(200));
    assert_eq!(
        OcspChecker::new(vec![expired]).check(&cert, 1_000),
        Err(StatusCheckError::Expired)
    );
}

#[test]
fn next_update_before_this_update_is_invalid() {
    let cert = parse_cert_der(&fixture("leaf.der")).unwrap();
    let malformed = ParsedOcspResponse::for_test(
        *reallyme_crypto::sha2::digest(cert.der.as_slice()).as_bytes(),
        cert.serial.clone(),
        OcspCertStatus::Good,
        999,
        Some(998),
    );

    assert_eq!(
        OcspChecker::new(vec![malformed]).check(&cert, 999),
        Err(StatusCheckError::InvalidList)
    );
}

#[test]
fn composite_policy_ocsp_section_governs_checker() {
    let cert = mock_cert();
    let strict_response = response(OcspCertStatus::Good, 1_000, None);
    let default_response = response(OcspCertStatus::Good, 1_000, None);
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
