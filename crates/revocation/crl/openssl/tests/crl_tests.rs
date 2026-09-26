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
//! Tests for OpenSSL-backed CRL parsing.

#[path = "support/crl_builder.rs"]
mod crl_builder;

use crl_builder::{
    build_crl, integer, name_der, test_ca, CrlSpec, Entry, Extension, NEXT_UPDATE,
    OID_AUTHORITY_KEY_IDENTIFIER, OID_CERTIFICATE_ISSUER, OID_CRL_NUMBER, OID_DELTA_CRL_INDICATOR,
    OID_ISSUING_DISTRIBUTION_POINT, OID_REASON_CODE, OID_UNKNOWN, THIS_UPDATE,
};
use identity_revocation_crl_core::{CrlChecker, ParsedCrl};
use identity_revocation_crl_openssl::{
    parse_crl_der_with_env_issuer, parse_crl_pem_with_env_issuer, CrlError, MAX_CRL_DER_BYTES,
};

use identity_revocation_core::{StatusCheckError, StatusChecker};

use envelopes_x509::parse_cert_der;
use openssl::x509::X509;

/// 2026-01-06T00:00:00Z, inside the fixture CRL validity window.
const FIXTURE_NOW: u64 = 1_767_657_600;
/// 2026-01-13T00:00:00Z, after the fixture CRL `nextUpdate`.
const FIXTURE_STALE: u64 = 1_768_262_400;

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

fn fixture_crl(name: &str) -> ParsedCrl {
    let root = X509::from_der(&read("tests/fixtures/root.der")).unwrap();
    parse_crl_der_with_env_issuer(&read(name), root)
        .unwrap()
        .into()
}

fn parse_built(spec: &CrlSpec) -> Result<ParsedCrl, CrlError> {
    let ca = test_ca("CRL Test CA");
    let der = build_crl(&ca, spec);
    parse_crl_der_with_env_issuer(&der, ca.cert).map(Into::into)
}

#[test]
fn crl_checker_detects_revocation() {
    let leaf_env = parse_cert_der(&read("tests/fixtures/leaf.der")).unwrap();
    let checker = CrlChecker::new(vec![fixture_crl("tests/fixtures/revoked.crl.der")]);

    let err = checker.check(&leaf_env, FIXTURE_NOW).unwrap_err();

    assert!(matches!(err, StatusCheckError::Revoked));
}

#[test]
fn crl_checker_allows_non_revoked() {
    let leaf_env = parse_cert_der(&read("tests/fixtures/leaf.der")).unwrap();
    let checker = CrlChecker::new(vec![fixture_crl("tests/fixtures/clean.crl.der")]);

    checker.check(&leaf_env, FIXTURE_NOW).unwrap();
}

#[test]
fn parsed_crl_carries_validity_window() {
    let crl = fixture_crl("tests/fixtures/clean.crl.der");

    assert!(crl.this_update_unix > 0);
    assert_eq!(crl.next_update_unix - crl.this_update_unix, 7 * 86_400);
}

#[test]
fn stale_fixture_crl_is_rejected_as_expired() {
    let leaf_env = parse_cert_der(&read("tests/fixtures/leaf.der")).unwrap();
    let checker = CrlChecker::new(vec![fixture_crl("tests/fixtures/clean.crl.der")]);

    assert_eq!(
        checker.check(&leaf_env, FIXTURE_STALE),
        Err(StatusCheckError::Expired)
    );
}

#[test]
fn pem_and_der_paths_agree() {
    let root = X509::from_der(&read("tests/fixtures/root.der")).unwrap();
    let crl = openssl::x509::X509Crl::from_der(&read("tests/fixtures/revoked.crl.der")).unwrap();
    let pem = crl.to_pem().unwrap();

    let parsed: ParsedCrl = parse_crl_pem_with_env_issuer(&pem, root).unwrap().into();
    let expected = fixture_crl("tests/fixtures/revoked.crl.der");

    assert_eq!(parsed.revoked_serials, expected.revoked_serials);
    assert_eq!(parsed.this_update_unix, expected.this_update_unix);
    assert_eq!(parsed.next_update_unix, expected.next_update_unix);
}

#[test]
fn built_crl_parses_with_times_and_normalized_serials() {
    let spec = CrlSpec {
        entries: vec![Entry {
            serial: vec![0x80, 0x01],
            extensions: vec![Extension::new(
                OID_REASON_CODE,
                false,
                vec![0x0A, 0x01, 0x01],
            )],
        }],
        ..CrlSpec::default()
    };

    let parsed = parse_built(&spec).unwrap();

    assert_eq!(parsed.revoked_serials, vec![vec![0x80, 0x01]]);
    assert_eq!(parsed.this_update_unix, u64::try_from(THIS_UPDATE).unwrap());
    assert_eq!(parsed.next_update_unix, u64::try_from(NEXT_UPDATE).unwrap());
}

#[test]
fn certificate_hold_is_parsed_as_suspension() {
    let spec = CrlSpec {
        entries: vec![Entry {
            serial: vec![0x2A],
            extensions: vec![Extension::new(
                OID_REASON_CODE,
                false,
                vec![0x0A, 0x01, 0x06],
            )],
        }],
        ..CrlSpec::default()
    };

    let parsed = parse_built(&spec).unwrap();
    assert!(parsed.revoked_serials.is_empty());
    assert_eq!(parsed.suspended_serials, vec![vec![0x2A]]);
}

#[test]
fn crl_authority_key_identifier_must_match_issuer_ski() {
    // AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING }
    let spec = CrlSpec {
        extensions: vec![
            Extension::crl_number(),
            Extension::new(
                OID_AUTHORITY_KEY_IDENTIFIER,
                false,
                vec![0x30, 0x03, 0x80, 0x01, 0xFF],
            ),
        ],
        ..CrlSpec::default()
    };

    assert_eq!(parse_built(&spec).unwrap_err(), CrlError::IssuerMismatch);
}

#[test]
fn missing_next_update_is_rejected() {
    let spec = CrlSpec {
        next_update: None,
        ..CrlSpec::default()
    };

    assert_eq!(parse_built(&spec).unwrap_err(), CrlError::InvalidTime);
}

#[test]
fn next_update_before_this_update_is_rejected() {
    let spec = CrlSpec {
        next_update: Some(THIS_UPDATE - 1),
        ..CrlSpec::default()
    };

    assert_eq!(parse_built(&spec).unwrap_err(), CrlError::InvalidTime);
}

#[test]
fn delta_crl_is_rejected() {
    let spec = CrlSpec {
        extensions: vec![
            Extension::crl_number(),
            Extension::new(OID_DELTA_CRL_INDICATOR, true, integer(&[1])),
        ],
        ..CrlSpec::default()
    };

    assert_eq!(parse_built(&spec).unwrap_err(), CrlError::UnsupportedScope);
}

#[test]
fn scoped_issuing_distribution_point_is_rejected() {
    // IssuingDistributionPoint { onlyContainsUserCerts [1] TRUE }
    let spec = CrlSpec {
        extensions: vec![
            Extension::crl_number(),
            Extension::new(
                OID_ISSUING_DISTRIBUTION_POINT,
                true,
                vec![0x30, 0x03, 0x81, 0x01, 0xFF],
            ),
        ],
        ..CrlSpec::default()
    };

    assert_eq!(parse_built(&spec).unwrap_err(), CrlError::UnsupportedScope);
}

#[test]
fn indirect_issuing_distribution_point_is_rejected() {
    // IssuingDistributionPoint { indirectCRL [4] TRUE }
    let spec = CrlSpec {
        extensions: vec![
            Extension::crl_number(),
            Extension::new(
                OID_ISSUING_DISTRIBUTION_POINT,
                true,
                vec![0x30, 0x03, 0x84, 0x01, 0xFF],
            ),
        ],
        ..CrlSpec::default()
    };

    assert_eq!(parse_built(&spec).unwrap_err(), CrlError::UnsupportedScope);
}

#[test]
fn unknown_critical_crl_extension_is_rejected() {
    let spec = CrlSpec {
        extensions: vec![
            Extension::crl_number(),
            Extension::new(OID_UNKNOWN, true, vec![0x05, 0x00]),
        ],
        ..CrlSpec::default()
    };

    assert_eq!(
        parse_built(&spec).unwrap_err(),
        CrlError::UnsupportedCriticalExtension
    );
}

#[test]
fn unknown_non_critical_crl_extension_is_accepted() {
    let spec = CrlSpec {
        extensions: vec![
            Extension::crl_number(),
            Extension::new(OID_UNKNOWN, false, vec![0x05, 0x00]),
        ],
        ..CrlSpec::default()
    };

    assert!(parse_built(&spec).is_ok());
}

#[test]
fn duplicate_crl_extension_is_rejected() {
    let spec = CrlSpec {
        extensions: vec![
            Extension::crl_number(),
            Extension::new(OID_CRL_NUMBER, false, integer(&[2])),
        ],
        ..CrlSpec::default()
    };

    assert_eq!(parse_built(&spec).unwrap_err(), CrlError::InvalidCrl);
}

#[test]
fn indirect_certificate_issuer_entry_extension_is_rejected() {
    // GeneralNames { dNSName "x" }
    let spec = CrlSpec {
        entries: vec![Entry {
            serial: vec![0x01],
            extensions: vec![Extension::new(
                OID_CERTIFICATE_ISSUER,
                true,
                vec![0x30, 0x03, 0x82, 0x01, 0x78],
            )],
        }],
        ..CrlSpec::default()
    };

    assert_eq!(parse_built(&spec).unwrap_err(), CrlError::UnsupportedScope);
}

#[test]
fn unknown_critical_entry_extension_is_rejected() {
    let spec = CrlSpec {
        entries: vec![Entry {
            serial: vec![0x01],
            extensions: vec![Extension::new(OID_UNKNOWN, true, vec![0x05, 0x00])],
        }],
        ..CrlSpec::default()
    };

    assert_eq!(
        parse_built(&spec).unwrap_err(),
        CrlError::UnsupportedCriticalExtension
    );
}

#[test]
fn tampered_signature_is_rejected() {
    let ca = test_ca("CRL Test CA");
    let mut der = build_crl(&ca, &CrlSpec::default());
    let last = der.len() - 1;
    der[last] ^= 0x01;

    assert_eq!(
        parse_crl_der_with_env_issuer(&der, ca.cert).unwrap_err(),
        CrlError::BadSignature
    );
}

#[test]
fn crl_signed_by_another_key_is_rejected() {
    let signer = test_ca("CRL Test CA");
    let other = test_ca("CRL Test CA");
    let der = build_crl(&signer, &CrlSpec::default());

    assert_eq!(
        parse_crl_der_with_env_issuer(&der, other.cert).unwrap_err(),
        CrlError::BadSignature
    );
}

#[test]
fn crl_issuer_name_must_match_issuer_certificate() {
    let spec = CrlSpec {
        issuer_name_der: Some(name_der("Somebody Else")),
        ..CrlSpec::default()
    };

    assert_eq!(parse_built(&spec).unwrap_err(), CrlError::IssuerMismatch);
}

#[test]
fn empty_and_oversized_encodings_are_rejected() {
    let ca = test_ca("CRL Test CA");
    assert_eq!(
        parse_crl_der_with_env_issuer(&[], ca.cert.clone()).unwrap_err(),
        CrlError::InvalidCrl
    );
    assert_eq!(
        parse_crl_der_with_env_issuer(&vec![0_u8; MAX_CRL_DER_BYTES + 1], ca.cert).unwrap_err(),
        CrlError::TooLarge
    );
}
