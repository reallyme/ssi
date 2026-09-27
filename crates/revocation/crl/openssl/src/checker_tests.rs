// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    normalize_serial, CrlChecker, IndexedCrl, DEFAULT_CRL_ALLOWED_SKEW_SECS,
    DEFAULT_MAX_CRL_AGE_SECS,
};
use envelopes_x509::{parse_cert_der, X509Certificate};
use identity_revocation_core::{StatusCheckError, StatusChecker};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509};
use std::collections::BTreeSet;

fn leaf() -> X509Certificate {
    parse_cert_der(include_bytes!("../tests/fixtures/leaf.der")).unwrap()
}

fn crl_for(
    leaf: &X509Certificate,
    revoked_serials: Vec<Vec<u8>>,
    this_update_unix: u64,
    next_update_unix: u64,
) -> IndexedCrl {
    IndexedCrl {
        issuer_key: leaf.authority_key_identifier.as_ref().unwrap().clone(),
        issuer_cert: X509::from_der(include_bytes!("../tests/fixtures/root.der")).unwrap(),
        revoked_serials: revoked_serials
            .iter()
            .map(|serial| normalize_serial(serial).to_vec())
            .collect::<BTreeSet<_>>(),
        suspended_serials: BTreeSet::new(),
        this_update_unix,
        next_update_unix,
    }
}

fn checker(crls: Vec<IndexedCrl>) -> CrlChecker {
    CrlChecker {
        crls,
        allowed_skew_secs: DEFAULT_CRL_ALLOWED_SKEW_SECS,
        max_age_secs: DEFAULT_MAX_CRL_AGE_SECS,
    }
}

#[test]
fn certificate_hold_is_reported_as_suspended() {
    let leaf = leaf();
    let mut crl = crl_for(&leaf, Vec::new(), 1_000, 2_000);
    crl.suspended_serials.insert(leaf.serial.clone());

    assert_eq!(
        checker(vec![crl]).check(&leaf, 1_500),
        Err(StatusCheckError::Suspended)
    );
}

#[test]
fn future_this_update_is_not_yet_valid_outside_allowed_skew() {
    let leaf = leaf();
    let checker = CrlChecker {
        crls: vec![crl_for(&leaf, Vec::new(), 1_000, 2_000)],
        allowed_skew_secs: 10,
        max_age_secs: DEFAULT_MAX_CRL_AGE_SECS,
    };

    assert_eq!(checker.check(&leaf, 990), Ok(()));
    assert_eq!(
        checker.check(&leaf, 989),
        Err(StatusCheckError::NotYetValid)
    );
}

#[test]
fn inverted_window_and_skew_overflow_are_invalid_lists() {
    let leaf = leaf();
    assert_eq!(
        checker(vec![crl_for(&leaf, Vec::new(), 2_000, 1_000)]).check(&leaf, 1_500),
        Err(StatusCheckError::InvalidList)
    );

    let overflow = CrlChecker {
        crls: vec![crl_for(&leaf, Vec::new(), 1_000, u64::MAX)],
        allowed_skew_secs: 1,
        max_age_secs: DEFAULT_MAX_CRL_AGE_SECS,
    };
    assert_eq!(
        overflow.check(&leaf, 1_500),
        Err(StatusCheckError::InvalidList)
    );
}

#[test]
fn relying_party_max_age_rejects_long_lived_crl() {
    let leaf = leaf();
    let checker = CrlChecker {
        crls: vec![crl_for(&leaf, Vec::new(), 1_000, 10_000)],
        allowed_skew_secs: 0,
        max_age_secs: 100,
    };

    assert_eq!(checker.check(&leaf, 1_099), Ok(()));
    assert_eq!(checker.check(&leaf, 1_100), Err(StatusCheckError::Expired));
}

#[test]
fn serial_comparison_ignores_asn1_sign_padding() {
    let leaf = leaf();
    let mut padded = vec![0, 0];
    padded.extend_from_slice(&leaf.serial);

    assert_eq!(
        checker(vec![crl_for(&leaf, vec![padded], 1_000, 2_000)]).check(&leaf, 1_500),
        Err(StatusCheckError::Revoked)
    );
}

#[test]
fn revocation_wins_independently_of_crl_order() {
    let leaf = leaf();
    let clean = crl_for(&leaf, Vec::new(), 1_000, 2_000);
    let revoked = crl_for(&leaf, vec![leaf.serial.clone()], 1_000, 2_000);
    let stale = crl_for(&leaf, Vec::new(), 100, 200);

    for order in [
        vec![clean.clone(), revoked.clone(), stale.clone()],
        vec![stale.clone(), revoked.clone(), clean.clone()],
        vec![revoked.clone(), clean.clone(), stale.clone()],
    ] {
        assert_eq!(
            checker(order).check(&leaf, 1_500),
            Err(StatusCheckError::Revoked)
        );
    }
}

#[test]
fn stale_revocation_does_not_override_a_fresh_clean_crl() {
    let leaf = leaf();
    let stale_revoked = crl_for(&leaf, vec![leaf.serial.clone()], 100, 200);
    let clean = crl_for(&leaf, Vec::new(), 1_000, 2_000);

    for order in [
        vec![stale_revoked.clone(), clean.clone()],
        vec![clean.clone(), stale_revoked.clone()],
    ] {
        assert_eq!(checker(order).check(&leaf, 1_500), Ok(()));
    }
}

#[test]
fn unusable_crl_error_ranking_is_deterministic() {
    let leaf = leaf();
    let expired = crl_for(&leaf, Vec::new(), 100, 200);
    let future = crl_for(&leaf, Vec::new(), 5_000, 6_000);

    for order in [
        vec![expired.clone(), future.clone()],
        vec![future.clone(), expired.clone()],
    ] {
        assert_eq!(
            checker(order).check(&leaf, 1_500),
            Err(StatusCheckError::NotYetValid)
        );
    }
}

#[test]
fn absence_of_a_matching_issuer_is_unavailable() {
    let leaf = leaf();
    let mut crl = crl_for(&leaf, Vec::new(), 1_000, 2_000);
    crl.issuer_key = vec![0xff];

    assert_eq!(
        checker(vec![crl]).check(&leaf, 1_500),
        Err(StatusCheckError::Unavailable)
    );
}

#[test]
fn matching_key_identifier_does_not_override_issuer_name_binding() {
    let leaf = leaf();
    let mut crl = crl_for(&leaf, Vec::new(), 1_000, 2_000);
    // Preserve the matching AKI index while substituting a certificate whose
    // subject name differs from the encoded leaf issuer.
    crl.issuer_cert = X509::from_der(include_bytes!("../tests/fixtures/leaf.der")).unwrap();

    assert_eq!(
        checker(vec![crl]).check(&leaf, 1_500),
        Err(StatusCheckError::Unavailable)
    );
}

#[test]
fn matching_name_and_key_identifier_do_not_override_leaf_signature_binding() {
    let leaf = leaf();
    let mut crl = crl_for(&leaf, Vec::new(), 1_000, 2_000);
    let trusted_issuer = X509::from_der(include_bytes!("../tests/fixtures/root.der")).unwrap();
    let replacement_key = PKey::from_rsa(Rsa::generate(2_048).unwrap()).unwrap();
    let mut replacement = X509Builder::new().unwrap();
    replacement.set_version(2).unwrap();
    replacement
        .set_subject_name(trusted_issuer.subject_name())
        .unwrap();
    replacement
        .set_issuer_name(trusted_issuer.subject_name())
        .unwrap();
    replacement.set_pubkey(&replacement_key).unwrap();
    replacement
        .sign(&replacement_key, MessageDigest::sha256())
        .unwrap();
    crl.issuer_cert = replacement.build();

    assert_eq!(
        checker(vec![crl]).check(&leaf, 1_500),
        Err(StatusCheckError::Unavailable)
    );
}
