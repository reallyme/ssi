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
//! Tests for OpenSSL/xmlsec-backed TSL verification.

#![cfg(all(feature = "native", feature = "xmlsec-ffi"))]

use identity_revocation_core::{StatusCheckError, StatusChecker};
use identity_trust_tsl_openssl::{
    verify_tsl_xml_openssl as verify_tsl_xml_openssl_with_status,
    verify_tsl_xml_openssl_with_community_lists as verify_tsl_xml_openssl_with_community_lists_and_status,
    verify_tsl_xml_openssl_with_external_signer as verify_tsl_xml_openssl_with_external_signer_and_status,
    TslOpenSslError, TslSignatureAlgorithm, TslSignatureProfileFailureReason,
    TslSignerAuthorizationEvidence, VerifiedTrustedList,
};

use envelopes_x509::policy::X509Policy;
use envelopes_x509::{parse_cert_pem, X509Certificate};

use time::OffsetDateTime;

// ------------------------------------------------------------
// Embedded fixtures (CORRECT WAY)
// ------------------------------------------------------------

const SIGNED_TSL_XML: &str = include_str!("fixtures/signed_tsl.xml");

const SIGNER_CERT_PEM: &[u8] = include_bytes!("fixtures/cert.pem");

struct GoodStatus;

impl StatusChecker for GoodStatus {
    fn check(&self, _cert: &X509Certificate, _now_unix: u64) -> Result<(), StatusCheckError> {
        Ok(())
    }
}

struct RevokedStatus;

impl StatusChecker for RevokedStatus {
    fn check(&self, _cert: &X509Certificate, _now_unix: u64) -> Result<(), StatusCheckError> {
        Err(StatusCheckError::Revoked)
    }
}

fn verify_tsl_xml_openssl(
    xml: &str,
    trust_roots: &[X509Certificate],
    now: OffsetDateTime,
    policy: X509Policy,
) -> Result<VerifiedTrustedList, TslOpenSslError> {
    verify_tsl_xml_openssl_with_status(xml, trust_roots, now, policy, &GoodStatus)
}

fn verify_tsl_xml_openssl_with_external_signer(
    xml: &str,
    trust_roots: &[X509Certificate],
    externally_authorized_signer: &X509Certificate,
    now: OffsetDateTime,
    policy: X509Policy,
) -> Result<VerifiedTrustedList, TslOpenSslError> {
    verify_tsl_xml_openssl_with_external_signer_and_status(
        xml,
        trust_roots,
        externally_authorized_signer,
        now,
        policy,
        &GoodStatus,
    )
}

fn verify_tsl_xml_openssl_with_community_lists(
    xml: &str,
    trust_roots: &[X509Certificate],
    community_lists: &[&VerifiedTrustedList],
    now: OffsetDateTime,
    policy: X509Policy,
) -> Result<VerifiedTrustedList, TslOpenSslError> {
    verify_tsl_xml_openssl_with_community_lists_and_status(
        xml,
        trust_roots,
        community_lists,
        now,
        policy,
        &GoodStatus,
    )
}

fn signer_cert() -> X509Certificate {
    parse_cert_pem(SIGNER_CERT_PEM).expect("invalid signer cert PEM")
}

#[test]
fn authenticated_pointer_binds_the_exact_leaf_signer() {
    let signer = signer_cert();
    let verified = verify_tsl_xml_openssl_with_community_lists(
        SIGNED_TSL_XML,
        core::slice::from_ref(&signer),
        &[],
        verification_time(),
        X509Policy::default(),
    )
    .expect("the authenticated pointer leaf must verify");

    assert_eq!(
        verified.signer_authorization(),
        TslSignerAuthorizationEvidence::ExactAuthenticatedPointerCertificate
    );
    assert_eq!(verified.signer_profile(), None);
}

fn verification_time() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("fixed test time must be valid")
}

// ------------------------------------------------------------
// Tests
// ------------------------------------------------------------

#[test]
fn verifies_signed_tsl_xml() {
    let verified = verify_tsl_xml_openssl(
        SIGNED_TSL_XML,
        &[signer_cert()],
        verification_time(),
        X509Policy::default(),
    )
    .expect("valid signed TSL must verify");

    assert!(
        verified.list().issue_date_time.unix_seconds() > 0,
        "TSL must expose a typed issue date"
    );
    assert_eq!(
        verified.signer_trust().evidence.purpose,
        reallyme_trust_core::TrustPurpose::TrustedListSigner
    );
    assert!(verified.signer_trust().evidence.source.is_some());
    assert_eq!(verified.signer_certificate_sha256().len(), 32);
    assert!(!verified.key_info_certificate_sha256().is_empty());
    assert_eq!(
        verified.signature_algorithm(),
        TslSignatureAlgorithm::RsaSha256
    );
}

#[test]
fn external_bootstrap_binds_the_exact_xml_signature_certificate() {
    let signer = signer_cert();
    let verified = verify_tsl_xml_openssl_with_external_signer(
        SIGNED_TSL_XML,
        core::slice::from_ref(&signer),
        &signer,
        verification_time(),
        X509Policy::default(),
    )
    .expect("the externally authenticated signer must verify");
    assert_eq!(
        verified.signer_authorization(),
        TslSignerAuthorizationEvidence::ExactExternalCertificate
    );
    assert_eq!(verified.signer_profile(), None);

    let mut different = signer.clone();
    different.der[0] ^= 1;
    let error = verify_tsl_xml_openssl_with_external_signer(
        SIGNED_TSL_XML,
        core::slice::from_ref(&signer),
        &different,
        verification_time(),
        X509Policy::default(),
    )
    .expect_err("a different externally supplied certificate must not authorize the signer");
    assert!(matches!(
        error,
        TslOpenSslError::ExternalSignerCertificateMismatch
    ));
}

#[test]
fn revoked_external_signer_is_rejected() {
    let signer = signer_cert();
    let error = verify_tsl_xml_openssl_with_external_signer_and_status(
        SIGNED_TSL_XML,
        core::slice::from_ref(&signer),
        &signer,
        verification_time(),
        X509Policy::default(),
        &RevokedStatus,
    )
    .expect_err("a revoked trusted-list signer must not authorize a list");

    assert!(matches!(error, TslOpenSslError::TrustFailure(_)));
}

#[test]
fn rejects_authenticated_tsl_at_its_next_update_deadline() {
    let at_next_update =
        OffsetDateTime::from_unix_timestamp(1_805_072_400).expect("fixed deadline must be valid");
    let error = verify_tsl_xml_openssl(
        SIGNED_TSL_XML,
        &[signer_cert()],
        at_next_update,
        X509Policy::default(),
    )
    .expect_err("TS 119 612 requires an expired list to be discarded");

    assert!(matches!(error, TslOpenSslError::ExpiredTrustedList));
}

#[test]
fn rejects_modified_signed_tsl() {
    let marker = "<ds:SignatureValue>";
    let start = SIGNED_TSL_XML
        .find(marker)
        .expect("fixture must contain SignatureValue")
        + marker.len();
    let mut tampered_xml = SIGNED_TSL_XML.to_owned();
    tampered_xml.replace_range(start..start + 1, "A");

    let err = verify_tsl_xml_openssl(
        tampered_xml.as_str(),
        &[signer_cert()],
        verification_time(),
        X509Policy::default(),
    )
    .unwrap_err();

    assert!(
        matches!(err, TslOpenSslError::InvalidSignature),
        "tampered XML must fail signature verification"
    );
}

#[test]
fn preserves_unrecognized_critical_extension_as_a_typed_failure() {
    let mutated = SIGNED_TSL_XML.replacen(
        "</SchemeInformation>",
        "<SchemeInformationExtensions><Extension Critical=\"true\"><FutureSemantics/></Extension></SchemeInformationExtensions></SchemeInformation>",
        1,
    );

    let error = verify_tsl_xml_openssl(
        &mutated,
        &[signer_cert()],
        verification_time(),
        X509Policy::default(),
    )
    .expect_err("unknown critical semantics must fail before signature verification");

    assert!(matches!(
        error,
        TslOpenSslError::UnsupportedCriticalExtension
    ));
}

#[test]
fn preserves_tag_and_update_window_as_typed_failures() {
    let invalid_tag = SIGNED_TSL_XML.replacen(
        "TSLTag=\"http://uri.etsi.org/19612/TSLTag\"",
        "TSLTag=\"https://example.test/not-a-tsl-tag\"",
        1,
    );
    let invalid_window = SIGNED_TSL_XML.replacen(
        "<dateTime>2027-03-15T01:00:00Z</dateTime>",
        "<dateTime>2027-03-15T02:00:00.000000001Z</dateTime>",
        1,
    );

    for (xml, expected) in [
        (invalid_tag, TslOpenSslError::InvalidTag),
        (invalid_window, TslOpenSslError::InvalidUpdateWindow),
    ] {
        let error = verify_tsl_xml_openssl(
            &xml,
            &[signer_cert()],
            verification_time(),
            X509Policy::default(),
        )
        .expect_err("invalid TSL metadata must retain its typed failure");
        assert_eq!(
            core::mem::discriminant(&error),
            core::mem::discriminant(&expected)
        );
    }
}

#[test]
fn preserves_xades_property_failures_as_typed_native_reasons() {
    let missing_signing_time = SIGNED_TSL_XML.replacen(
        "            <xades:SigningTime>2026-09-15T01:00:00Z</xades:SigningTime>\n",
        "",
        1,
    );
    let invalid_data_object_format = SIGNED_TSL_XML.replacen(
        "<xades:MimeType>application/vnd.etsi.tsl+xml</xades:MimeType>",
        "<xades:MimeType>text/plain</xades:MimeType>",
        1,
    );

    for (xml, expected) in [
        (
            missing_signing_time,
            TslSignatureProfileFailureReason::InvalidSigningTime,
        ),
        (
            invalid_data_object_format,
            TslSignatureProfileFailureReason::InvalidDataObjectFormat,
        ),
    ] {
        let error = verify_tsl_xml_openssl(
            &xml,
            &[signer_cert()],
            verification_time(),
            X509Policy::default(),
        )
        .expect_err("invalid XAdES property must retain its typed native reason");

        assert!(matches!(
            error,
            TslOpenSslError::SignatureProfile(reason) if reason == expected
        ));
    }
}

fn unrelated_root() -> X509Certificate {
    let encoded: String = include_str!("../../x509/tests/fixtures/qwac_server_auth_cert.der.b64")
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let der = openssl::base64::decode_block(&encoded).expect("fixture base64 must decode");
    envelopes_x509::parse_cert_der(&der).expect("fixture certificate must parse")
}

#[test]
fn trusts_every_configured_root_not_only_the_first() {
    // The signer is the second configured root. A backend that only loads the
    // first certificate of a concatenated bundle cannot verify this list.
    let roots = [unrelated_root(), signer_cert()];
    let verified = verify_tsl_xml_openssl(
        SIGNED_TSL_XML,
        &roots,
        verification_time(),
        X509Policy::default(),
    )
    .expect("a list signed under the second configured root must verify");
    assert_eq!(
        verified.signature_algorithm(),
        TslSignatureAlgorithm::RsaSha256
    );
}

#[test]
fn authenticated_pointer_selects_a_later_rollover_certificate_in_one_pass() {
    let roots = [unrelated_root(), signer_cert()];
    let verified = verify_tsl_xml_openssl_with_community_lists(
        SIGNED_TSL_XML,
        &roots,
        &[],
        verification_time(),
        X509Policy::default(),
    )
    .expect("the second authenticated pointer certificate must verify");
    assert_eq!(
        verified.signer_authorization(),
        TslSignerAuthorizationEvidence::ExactAuthenticatedPointerCertificate
    );

    let error = verify_tsl_xml_openssl_with_community_lists(
        SIGNED_TSL_XML,
        &[unrelated_root()],
        &[],
        verification_time(),
        X509Policy::default(),
    )
    .expect_err("a pointer that does not authenticate the signer must fail");
    assert!(matches!(
        error,
        TslOpenSslError::ExternalSignerCertificateMismatch
    ));
}

#[test]
fn rejects_a_list_issued_after_the_evaluation_time() {
    // 2026-09-15T00:50:00Z: the signer certificate is valid, but the list's
    // ListIssueDateTime (01:00:00Z) is beyond the admitted clock skew.
    let before_issue =
        OffsetDateTime::from_unix_timestamp(1_789_433_400).expect("fixed time must be valid");
    let error = verify_tsl_xml_openssl(
        SIGNED_TSL_XML,
        &[signer_cert()],
        before_issue,
        X509Policy::default(),
    )
    .expect_err("a list issued after the evaluation time must be rejected");
    assert!(matches!(
        error,
        TslOpenSslError::TrustedList(identity_trust_tsl_core::TslError::NotYetIssued)
    ));
}

#[test]
fn rejects_a_replayed_older_sequence_number() {
    let verified = verify_tsl_xml_openssl(
        SIGNED_TSL_XML,
        &[signer_cert()],
        verification_time(),
        X509Policy::default(),
    )
    .expect("valid signed TSL must verify");
    let sequence_number = verified.list().sequence_number;
    assert!(verified.validate_sequence_number(sequence_number).is_ok());
    let newer = sequence_number
        .checked_add(1)
        .expect("fixture sequence number must not be maximal");
    assert!(matches!(
        verified.validate_sequence_number(newer),
        Err(TslOpenSslError::TrustedList(
            identity_trust_tsl_core::TslError::SequenceRollback
        ))
    ));
}
