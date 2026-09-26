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

use envelopes_x509::X509Certificate;
use identity_revocation_core::{StatusCheckError, StatusChecker};
use identity_revocation_ocsp_core::{OcspCertStatus, OcspChecker, OcspPolicy, ParsedOcspResponse};
use time::OffsetDateTime;

fn mock_cert(serial: Vec<u8>, issuer_key: Vec<u8>) -> X509Certificate {
    X509Certificate {
        der: vec![],
        subject: "CN=Leaf".into(),
        issuer: "CN=Root".into(),
        subject_der: b"CN=Leaf".to_vec(),
        issuer_der: b"CN=Root".to_vec(),
        serial,
        not_before: OffsetDateTime::UNIX_EPOCH,
        not_after: OffsetDateTime::UNIX_EPOCH,
        spki_der: vec![],
        signature_algorithm_oid: "1.2.3".into(),
        basic_constraints: None,
        key_usage: None,
        extended_key_usage: None,
        subject_key_identifier: None,

        // OK THIS IS REQUIRED FOR OCSP
        authority_key_identifier: Some(issuer_key),

        san_dns: vec![],
        san_ip: vec![],
        certificate_policies: vec![],
        qc_statements: Default::default(),
        profile: Default::default(),
    }
}

fn response(
    serial: Vec<u8>,
    issuer_key: Vec<u8>,
    status: OcspCertStatus,
    this_update: u64,
    next_update: Option<u64>,
) -> ParsedOcspResponse {
    ParsedOcspResponse {
        issuer_key,
        serial,
        status,
        this_update,
        next_update,
        signature_valid: Some(true),
        responder_authorized: Some(true),
        responder_eku_ocsp_signing: Some(true),
        extensions: None,
    }
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

    let resp = ParsedOcspResponse {
        issuer_key: issuer_key.clone(),
        serial: serial.clone(),
        status: OcspCertStatus::Good,
        this_update: now - 10,
        next_update: None,
        signature_valid: Some(true),
        responder_authorized: Some(true),
        responder_eku_ocsp_signing: Some(true),
        extensions: None,
    };

    let checker = OcspChecker::new(vec![resp]).with_policy(OcspPolicy {
        require_next_update: true,
        max_age_secs: None,
        allowed_skew_secs: 0,
        require_verified: true,
    });

    let err = checker.check(&cert, now).unwrap_err();
    assert_eq!(err, StatusCheckError::InvalidList);
}

#[test]
fn default_policy_rejects_unverified_ocsp_evidence() {
    let issuer_key = vec![0x15];
    let cert = mock_cert(vec![9], issuer_key.clone());
    let mut unverified = response(vec![9], issuer_key, OcspCertStatus::Good, 999, Some(1_100));
    unverified.signature_valid = None;
    let checker = OcspChecker::new(vec![unverified]);

    assert_eq!(
        checker.check(&cert, 1_000),
        Err(StatusCheckError::InvalidSignature)
    );
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
    let good = response(
        vec![0x21],
        issuer_key.clone(),
        OcspCertStatus::Good,
        999,
        Some(1_100),
    );
    let revoked = response(
        vec![0x21],
        issuer_key.clone(),
        OcspCertStatus::Revoked,
        990,
        Some(1_100),
    );
    let unknown = response(
        vec![0x21],
        issuer_key,
        OcspCertStatus::Unknown,
        995,
        Some(1_100),
    );

    for order in [
        vec![good.clone(), revoked.clone(), unknown.clone()],
        vec![unknown.clone(), good.clone(), revoked.clone()],
        vec![revoked.clone(), unknown.clone(), good.clone()],
    ] {
        assert_eq!(
            OcspChecker::new(order).check(&cert, 1_000),
            Err(StatusCheckError::Revoked)
        );
    }
}

#[test]
fn stale_or_unverified_revocation_does_not_mask_fresh_good_response() {
    let issuer_key = vec![0x22];
    let cert = mock_cert(vec![0x23], issuer_key.clone());
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
    let mut unverified_revoked = response(
        vec![0x23],
        issuer_key,
        OcspCertStatus::Revoked,
        999,
        Some(1_100),
    );
    unverified_revoked.responder_authorized = Some(false);

    for order in [
        vec![
            stale_revoked.clone(),
            unverified_revoked.clone(),
            fresh_good.clone(),
        ],
        vec![
            fresh_good.clone(),
            stale_revoked.clone(),
            unverified_revoked.clone(),
        ],
    ] {
        assert_eq!(OcspChecker::new(order).check(&cert, 1_000), Ok(()));
    }
}

#[test]
fn good_response_wins_over_unknown_regardless_of_order() {
    let issuer_key = vec![0x24];
    let cert = mock_cert(vec![0x25], issuer_key.clone());
    let good = response(
        vec![0x25],
        issuer_key.clone(),
        OcspCertStatus::Good,
        999,
        Some(1_100),
    );
    let unknown = response(
        vec![0x25],
        issuer_key,
        OcspCertStatus::Unknown,
        999,
        Some(1_100),
    );

    for order in [
        vec![unknown.clone(), good.clone()],
        vec![good.clone(), unknown.clone()],
    ] {
        assert_eq!(OcspChecker::new(order).check(&cert, 1_000), Ok(()));
    }
}

#[test]
fn unusable_responses_report_deterministic_error_regardless_of_order() {
    let issuer_key = vec![0x26];
    let cert = mock_cert(vec![0x27], issuer_key.clone());
    let expired = response(
        vec![0x27],
        issuer_key.clone(),
        OcspCertStatus::Good,
        100,
        Some(200),
    );
    let mut unverified = response(
        vec![0x27],
        issuer_key,
        OcspCertStatus::Good,
        999,
        Some(1_100),
    );
    unverified.signature_valid = Some(false);

    for order in [
        vec![expired.clone(), unverified.clone()],
        vec![unverified.clone(), expired.clone()],
    ] {
        assert_eq!(
            OcspChecker::new(order).check(&cert, 1_000),
            Err(StatusCheckError::InvalidSignature)
        );
    }
}

#[test]
fn next_update_before_this_update_is_invalid() {
    let issuer_key = vec![0x28];
    let cert = mock_cert(vec![0x29], issuer_key.clone());
    let checker = OcspChecker::new(vec![response(
        vec![0x29],
        issuer_key,
        OcspCertStatus::Good,
        999,
        Some(998),
    )]);

    assert_eq!(
        checker.check(&cert, 1_000),
        Err(StatusCheckError::InvalidList)
    );
}

#[test]
fn composite_policy_ocsp_section_governs_checker() {
    let issuer_key = vec![0x2A];
    let cert = mock_cert(vec![0x2B], issuer_key.clone());
    let responses = vec![response(
        vec![0x2B],
        issuer_key,
        OcspCertStatus::Good,
        1_000,
        None,
    )];
    let mut policy = identity_revocation_core::hybrid_fallback(OffsetDateTime::UNIX_EPOCH)
        .expect("Unix epoch is representable");
    policy.ocsp.require_next_update = true;

    assert_eq!(
        OcspChecker::new(responses.clone()).check(&cert, 1_000),
        Ok(())
    );
    assert_eq!(
        OcspChecker::from_composite_policy(responses, &policy).check(&cert, 1_000),
        Err(StatusCheckError::InvalidList)
    );
}
