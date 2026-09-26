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
    eu_qtsp_x509, hybrid_fallback, vc_statuslist, CompositeRevocationPolicy,
    CompositeStatusChecker, InMemoryRevocationCache, OcspPolicy, RevocationCacheError,
    RevocationEvidenceCache, RevocationEvidenceMeta, RevocationPolicyError, RevocationSource,
    SoftFailMode, StatusCheckError, StatusChecker, StatusListChecker, DEFAULT_MAX_OCSP_AGE_SECS,
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
        subject_der: b"CN=leaf".to_vec(),
        issuer_der: b"CN=issuer".to_vec(),
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
        policy: hybrid_fallback(instant(2)).unwrap(),
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
        policy: CompositeRevocationPolicy {
            soft_fail: SoftFailMode::Strict,
            ..eu_qtsp_x509(instant(2)).unwrap()
        },
        ocsp: Some(&ocsp),
        crl: Some(&crl),
        statuslist: None,
    };

    let err = checker.check(&cert(), 1_700_000_001).unwrap_err();

    assert_eq!(err, StatusCheckError::Unavailable);
}

#[test]
fn eu_qtsp_preset_falls_back_to_crl_when_ocsp_is_unavailable() {
    let ocsp = StaticChecker {
        result: Err(StatusCheckError::Unavailable),
    };
    let crl = StaticChecker {
        result: Err(StatusCheckError::Revoked),
    };
    let checker = CompositeStatusChecker {
        policy: eu_qtsp_x509(instant(2)).unwrap(),
        ocsp: Some(&ocsp),
        crl: Some(&crl),
        statuslist: None,
    };

    assert_eq!(
        checker.check(&cert(), 1_700_000_001),
        Err(StatusCheckError::Revoked)
    );
}

#[test]
fn eu_qtsp_preset_treats_obtained_but_invalid_ocsp_evidence_as_terminal() {
    for terminal in [
        StatusCheckError::Expired,
        StatusCheckError::NotYetValid,
        StatusCheckError::InvalidSignature,
        StatusCheckError::InvalidList,
        StatusCheckError::Unknown,
    ] {
        let ocsp = StaticChecker {
            result: Err(terminal),
        };
        let crl = StaticChecker { result: Ok(()) };
        let checker = CompositeStatusChecker {
            policy: eu_qtsp_x509(instant(2)).unwrap(),
            ocsp: Some(&ocsp),
            crl: Some(&crl),
            statuslist: None,
        };

        assert_eq!(checker.check(&cert(), 1_700_000_001), Err(terminal));
    }
}

#[test]
fn eu_qtsp_preset_reports_unavailable_when_every_source_is_unavailable() {
    let unavailable = StaticChecker {
        result: Err(StatusCheckError::Unavailable),
    };
    let checker = CompositeStatusChecker {
        policy: eu_qtsp_x509(instant(2)).unwrap(),
        ocsp: Some(&unavailable),
        crl: Some(&unavailable),
        statuslist: None,
    };

    assert_eq!(
        checker.check(&cert(), 1_700_000_001),
        Err(StatusCheckError::Unavailable)
    );
}

#[test]
fn default_ocsp_policy_requires_verified_evidence_and_bounds_age() {
    let policy = OcspPolicy::default();

    assert!(policy.require_verified);
    assert_eq!(policy.max_age_secs, Some(DEFAULT_MAX_OCSP_AGE_SECS));
    assert!(hybrid_fallback(instant(2)).unwrap().ocsp.require_verified);
    assert!(vc_statuslist(instant(2)).unwrap().ocsp.require_verified);
}

#[test]
fn policy_presets_reject_pre_epoch_evaluation_times() {
    let before_epoch = time::OffsetDateTime::UNIX_EPOCH - time::Duration::seconds(1);
    assert_eq!(
        vc_statuslist(before_epoch).err(),
        Some(RevocationPolicyError::InvalidEvaluationTime)
    );
    assert_eq!(
        eu_qtsp_x509(before_epoch).err(),
        Some(RevocationPolicyError::InvalidEvaluationTime)
    );
    assert_eq!(
        hybrid_fallback(before_epoch).err(),
        Some(RevocationPolicyError::InvalidEvaluationTime)
    );
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
    cache
        .store(
            &cert,
            RevocationEvidenceMeta {
                fetched_at_unix: 1_700_000_000,
                expires_at_unix: Some(1_800_000_000),
                source: RevocationSource::StatusList,
            },
            Err(StatusCheckError::Revoked),
        )
        .unwrap();

    let err = cache.lookup(&cert, 1_700_000_001).unwrap_err();

    assert_eq!(err, StatusCheckError::Revoked);
}

#[test]
fn cache_ignores_expired_evidence() {
    let mut cache = InMemoryRevocationCache::new();
    let cert = cert();
    cache
        .store(
            &cert,
            RevocationEvidenceMeta {
                fetched_at_unix: 1_700_000_000,
                expires_at_unix: Some(1_700_000_010),
                source: RevocationSource::StatusList,
            },
            Ok(()),
        )
        .unwrap();

    let cached = cache.lookup(&cert, 1_700_000_011).unwrap();

    assert_eq!(cached, None);
}

#[test]
fn cache_does_not_replay_transient_errors() {
    let mut cache = InMemoryRevocationCache::new();
    let cert = cert();
    cache
        .store(
            &cert,
            RevocationEvidenceMeta {
                fetched_at_unix: 1_700_000_000,
                expires_at_unix: Some(1_800_000_000),
                source: RevocationSource::StatusList,
            },
            Err(StatusCheckError::Unavailable),
        )
        .unwrap();

    let cached = cache.lookup(&cert, 1_700_000_001).unwrap();

    assert_eq!(cached, None);
}

#[test]
fn vc_statuslist_preset_is_statuslist_only() {
    let policy = vc_statuslist(instant(2)).unwrap();

    assert!(!policy.prefer_ocsp);
    assert!(!policy.prefer_crl);
    assert!(policy.prefer_statuslist);
}

fn meta(expires_at_unix: Option<u64>) -> RevocationEvidenceMeta {
    RevocationEvidenceMeta {
        fetched_at_unix: 1_700_000_000,
        expires_at_unix,
        source: RevocationSource::Crl,
    }
}

#[test]
fn cache_rejects_evidence_without_expiry() {
    let mut cache = InMemoryRevocationCache::new();
    let cert = cert();

    assert_eq!(
        cache.store(&cert, meta(None), Err(StatusCheckError::Revoked)),
        Err(RevocationCacheError::MissingExpiry)
    );
    assert_eq!(cache.lookup(&cert, 1_700_000_001), Ok(None));
}

#[test]
fn cache_rejects_expiry_not_after_fetch_time() {
    let mut cache = InMemoryRevocationCache::new();
    let cert = cert();

    assert_eq!(
        cache.store(&cert, meta(Some(1_700_000_000)), Ok(())),
        Err(RevocationCacheError::InvalidExpiry)
    );
    assert_eq!(cache.lookup(&cert, 1_700_000_000), Ok(None));
}

#[test]
fn cache_does_not_collide_across_issuers_with_equal_serials() {
    let mut cache = InMemoryRevocationCache::new();
    let mut revoked_cert = cert();
    revoked_cert.issuer = "CN=issuer-a".to_owned();
    revoked_cert.authority_key_identifier = Some(vec![0xA1]);
    let mut other_issuer_same_serial = cert();
    other_issuer_same_serial.issuer = "CN=issuer-b".to_owned();
    other_issuer_same_serial.authority_key_identifier = Some(vec![0xB2]);
    let mut same_name_other_key = cert();
    same_name_other_key.issuer = "CN=issuer-a".to_owned();
    same_name_other_key.authority_key_identifier = Some(vec![0xC3]);

    cache
        .store(
            &revoked_cert,
            meta(Some(1_800_000_000)),
            Err(StatusCheckError::Revoked),
        )
        .unwrap();

    assert_eq!(
        cache.lookup(&revoked_cert, 1_700_000_001),
        Err(StatusCheckError::Revoked)
    );
    assert_eq!(
        cache.lookup(&other_issuer_same_serial, 1_700_000_001),
        Ok(None)
    );
    assert_eq!(cache.lookup(&same_name_other_key, 1_700_000_001), Ok(None));
}

#[test]
fn cache_matches_serial_with_sign_padding_for_same_issuer() {
    let mut cache = InMemoryRevocationCache::new();
    let cert = cert();
    let mut padded = cert.clone();
    padded.serial = vec![0, 1, 2, 3];

    cache
        .store(
            &cert,
            meta(Some(1_800_000_000)),
            Err(StatusCheckError::Revoked),
        )
        .unwrap();

    assert_eq!(
        cache.lookup(&padded, 1_700_000_001),
        Err(StatusCheckError::Revoked)
    );
}

#[test]
fn cache_does_not_collide_for_equal_display_names_without_aki() {
    let mut cache = InMemoryRevocationCache::new();
    let mut first = cert();
    first.authority_key_identifier = None;
    first.der = vec![1];
    first.issuer_der = vec![2];
    let mut second = first.clone();
    second.der = vec![3];
    cache
        .store(&first, meta(Some(1_800_000_000)), Ok(()))
        .unwrap();
    assert_eq!(cache.lookup(&second, 1_700_000_001), Ok(None));
    second.der = first.der.clone();
    second.issuer_der = vec![4];
    assert_eq!(cache.lookup(&second, 1_700_000_001), Ok(None));
}
