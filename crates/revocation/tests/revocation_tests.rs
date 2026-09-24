// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
//! Test coverage for this crate.

use reallyme_credential_status::{
    CredentialStatusError, StatusList, StatusListAlgorithm, StatusListSignature,
    StatusListVerifier, StatusPurpose,
};
use reallyme_revocation::{
    eu_qtsp_x509, hybrid_fallback, vc_statuslist, CompositeStatusChecker, InMemoryRevocationCache,
    RevocationEvidenceCache, RevocationEvidenceMeta, RevocationSource, StatusCheckError,
    StatusChecker, StatusListChecker,
};
use reallyme_trust_x509::{BasicConstraints, KeyUsage, QcStatements, X509Certificate};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

struct StaticChecker {
    result: Result<(), StatusCheckError>,
}

impl StatusChecker for StaticChecker {
    fn check(&self, _cert: &X509Certificate, _now_unix: u64) -> Result<(), StatusCheckError> {
        self.result
    }
}

struct AcceptVerifier;

impl StatusListVerifier for AcceptVerifier {
    fn verify_status_list(
        &self,
        _issuer: &str,
        _alg: StatusListAlgorithm,
        _payload: &[u8],
        _signature: &[u8],
    ) -> Result<(), CredentialStatusError> {
        Ok(())
    }
}

fn instant(day: u8) -> OffsetDateTime {
    PrimitiveDateTime::new(
        Date::from_calendar_date(2026, Month::January, day).unwrap(),
        Time::MIDNIGHT,
    )
    .assume_utc()
}

fn cert() -> X509Certificate {
    X509Certificate {
        der: vec![0x30, 0x03, 0x01],
        subject: "CN=leaf".to_owned(),
        issuer: "CN=issuer".to_owned(),
        serial: vec![1, 2, 3],
        not_before: instant(1),
        not_after: instant(31),
        spki_der: vec![0x30, 0x02, 0x02],
        signature_algorithm_oid: "1.3.101.112".to_owned(),
        basic_constraints: Some(BasicConstraints {
            ca: false,
            path_len_constraint: None,
        }),
        key_usage: Some(KeyUsage {
            digital_signature: true,
            content_commitment: false,
            key_cert_sign: false,
            crl_sign: false,
            key_encipherment: false,
            data_encipherment: false,
            key_agreement: false,
            encipher_only: false,
            decipher_only: false,
        }),
        extended_key_usage: None,
        subject_key_identifier: Some(vec![9, 9, 9]),
        authority_key_identifier: None,
        san_dns: Vec::new(),
        san_ip: Vec::new(),
        certificate_policies: Vec::new(),
        qc_statements: QcStatements::default(),
        profile: Default::default(),
    }
}

fn status_list(encoded_list: Vec<u8>) -> StatusList {
    StatusList {
        issuer: "did:example:issuer".to_owned(),
        purpose: StatusPurpose::Revocation,
        issued_at: 1_700_000_000,
        next_update: 1_800_000_000,
        encoded_list,
        length: 8,
        list_id: None,
        signature: StatusListSignature {
            alg: StatusListAlgorithm::Ed25519,
            sig_bytes: vec![1],
        },
    }
}

#[test]
fn fallback_policy_uses_second_available_source() {
    let ocsp = StaticChecker {
        result: Err(StatusCheckError::Unavailable),
    };
    let crl = StaticChecker { result: Ok(()) };
    let checker = CompositeStatusChecker {
        policy: hybrid_fallback(instant(2)),
        ocsp: Some(&ocsp),
        crl: Some(&crl),
        statuslist: None,
    };

    checker.check(&cert(), 1_700_000_001).unwrap();
}

#[test]
fn strict_policy_stops_on_unavailable_source() {
    let ocsp = StaticChecker {
        result: Err(StatusCheckError::Unavailable),
    };
    let crl = StaticChecker { result: Ok(()) };
    let checker = CompositeStatusChecker {
        policy: eu_qtsp_x509(instant(2)),
        ocsp: Some(&ocsp),
        crl: Some(&crl),
        statuslist: None,
    };

    let err = checker.check(&cert(), 1_700_000_001).unwrap_err();

    assert_eq!(err, StatusCheckError::Unavailable);
}

#[test]
fn statuslist_checker_maps_revoked_status() {
    let list = status_list(vec![0b0000_0010]);
    let checker = StatusListChecker::new(&list, 1, &AcceptVerifier);

    let err = checker.check(&cert(), 1_700_000_001).unwrap_err();

    assert_eq!(err, StatusCheckError::Revoked);
}

#[test]
fn statuslist_checker_maps_not_yet_valid_status() {
    let list = status_list(vec![0]);
    let checker = StatusListChecker::new(&list, 1, &AcceptVerifier);

    let err = checker.check(&cert(), 1_699_999_999).unwrap_err();

    assert_eq!(err, StatusCheckError::NotYetValid);
}

#[test]
fn cache_returns_terminal_revocation() {
    let mut cache = InMemoryRevocationCache::new();
    let cert = cert();
    cache.store(
        &cert,
        RevocationEvidenceMeta {
            fetched_at_unix: 1_700_000_000,
            expires_at_unix: Some(1_800_000_000),
            source: RevocationSource::StatusList,
        },
        Err(StatusCheckError::Revoked),
    );

    let err = cache.lookup(&cert, 1_700_000_001).unwrap_err();

    assert_eq!(err, StatusCheckError::Revoked);
}

#[test]
fn cache_ignores_expired_evidence() {
    let mut cache = InMemoryRevocationCache::new();
    let cert = cert();
    cache.store(
        &cert,
        RevocationEvidenceMeta {
            fetched_at_unix: 1_700_000_000,
            expires_at_unix: Some(1_700_000_010),
            source: RevocationSource::StatusList,
        },
        Ok(()),
    );

    let cached = cache.lookup(&cert, 1_700_000_011).unwrap();

    assert_eq!(cached, None);
}

#[test]
fn cache_does_not_replay_transient_errors() {
    let mut cache = InMemoryRevocationCache::new();
    let cert = cert();
    cache.store(
        &cert,
        RevocationEvidenceMeta {
            fetched_at_unix: 1_700_000_000,
            expires_at_unix: Some(1_800_000_000),
            source: RevocationSource::StatusList,
        },
        Err(StatusCheckError::Unavailable),
    );

    let cached = cache.lookup(&cert, 1_700_000_001).unwrap();

    assert_eq!(cached, None);
}

#[test]
fn vc_statuslist_preset_is_statuslist_only() {
    let policy = vc_statuslist(instant(2));

    assert!(!policy.prefer_ocsp);
    assert!(!policy.prefer_crl);
    assert!(policy.prefer_statuslist);
}
