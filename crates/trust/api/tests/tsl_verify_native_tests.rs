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
//! Tests for native trusted-list verification adapters.
#![cfg(feature = "native")]

use identity_credential_trust_api::{
    ingest_eu_trusted_list as ingest_eu_trusted_list_with_status,
    verify_trust_list_xml_native as verify_trust_list_xml_native_with_status, TrustApiError,
    TrustApiResourceLimitReason, TrustedListAnchors, VerifiedTrustedList,
};
#[cfg(feature = "xmlsec-ffi")]
use identity_credential_trust_api::{
    verify_trust_list_xml_native_with_community_lists,
    verify_trust_list_xml_native_with_external_signer, TrustedListPolicyErrorReason,
    TrustedListSignatureProfileErrorReason,
};
use identity_revocation_core::{StatusCheckError, StatusChecker};
use identity_trust_tsl_openssl::{MAX_TSL_TRUST_ROOTS, MAX_TSL_TRUST_ROOT_DER_BYTES};

use envelopes_x509::policy::X509Policy;
use envelopes_x509::{parse_cert_pem, X509Certificate};

use time::OffsetDateTime;

const SIGNED_TSL_XML: &str = include_str!("../../tsl-openssl/tests/fixtures/signed_tsl.xml");
const SIGNER_CERT_PEM: &[u8] = include_bytes!("../../tsl-openssl/tests/fixtures/cert.pem");
const TRUST_ROOT_CERT_PEM: &[u8] = include_bytes!("../../tsl-openssl/tests/fixtures/root-cert.pem");

struct GoodStatus;

impl StatusChecker for GoodStatus {
    fn check(&self, _cert: &X509Certificate, _now_unix: u64) -> Result<(), StatusCheckError> {
        Ok(())
    }
}

fn verify_trust_list_xml_native(
    xml: &str,
    trust_roots: &[X509Certificate],
    now: OffsetDateTime,
    policy: X509Policy,
) -> Result<VerifiedTrustedList, TrustApiError> {
    verify_trust_list_xml_native_with_status(xml, trust_roots, 0, now, policy, &GoodStatus)
}

fn ingest_eu_trusted_list(
    xml: &[u8],
    trust_anchors: &TrustedListAnchors,
    externally_authorized_signer: &X509Certificate,
    now: OffsetDateTime,
) -> Result<VerifiedTrustedList, TrustApiError> {
    ingest_eu_trusted_list_with_status(
        xml,
        trust_anchors,
        externally_authorized_signer,
        0,
        now,
        &GoodStatus,
    )
}

fn signer_cert() -> X509Certificate {
    parse_cert_pem(SIGNER_CERT_PEM).expect("invalid signer cert PEM")
}

fn trust_root_cert() -> X509Certificate {
    parse_cert_pem(TRUST_ROOT_CERT_PEM).expect("invalid trust-root cert PEM")
}

fn verification_time() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("fixed test time must be valid")
}

#[test]
#[cfg(feature = "xmlsec-ffi")]
fn api_verifies_signed_tsl_native() {
    let tsl = verify_trust_list_xml_native(
        SIGNED_TSL_XML,
        &[trust_root_cert()],
        verification_time(),
        X509Policy::default(),
    )
    .expect("API must verify signed TSL via native backend");

    assert_eq!(tsl.list().name, "MT:Test Trusted List");
    assert!(tsl.signer_trust().evidence().source.is_some());
}

#[test]
#[cfg(feature = "xmlsec-ffi")]
fn every_public_native_verifier_rejects_sequence_rollback() {
    let signer = signer_cert();
    let trust_root = trust_root_cert();
    let parsed = identity_credential_trust_api::parse_trust_list_xml(SIGNED_TSL_XML)
        .expect("fixture XML must parse");
    let rejected_sequence = parsed
        .sequence_number
        .checked_add(1)
        .expect("fixture sequence leaves headroom");

    let errors = [
        verify_trust_list_xml_native_with_status(
            SIGNED_TSL_XML,
            core::slice::from_ref(&trust_root),
            rejected_sequence,
            verification_time(),
            X509Policy::default(),
            &GoodStatus,
        )
        .expect_err("native verifier must reject rollback"),
        verify_trust_list_xml_native_with_external_signer(
            SIGNED_TSL_XML,
            core::slice::from_ref(&trust_root),
            &signer,
            rejected_sequence,
            verification_time(),
            X509Policy::default(),
            &GoodStatus,
        )
        .expect_err("external-signer verifier must reject rollback"),
        verify_trust_list_xml_native_with_community_lists(
            SIGNED_TSL_XML,
            core::slice::from_ref(&trust_root),
            &[],
            rejected_sequence,
            verification_time(),
            X509Policy::default(),
            &GoodStatus,
        )
        .expect_err("community-list verifier must reject rollback"),
    ];

    for error in errors {
        assert!(matches!(
            error,
            TrustApiError::TrustedList(identity_trust_tsl_core::TslError::SequenceRollback)
        ));
    }
}

#[test]
#[cfg(feature = "xmlsec-ffi")]
fn api_ingests_eu_trusted_list_from_xml_bytes() {
    let signer = signer_cert();
    let anchors = TrustedListAnchors::new(vec![trust_root_cert()]).expect("valid anchors");
    let verified = ingest_eu_trusted_list(
        SIGNED_TSL_XML.as_bytes(),
        &anchors,
        &signer,
        verification_time(),
    )
    .expect("API must ingest signed TSL via native backend");

    assert_eq!(verified.list().name, "MT:Test Trusted List");
    assert!(
        verified.list().issue_date_time.unix_seconds() > 0,
        "verified list must expose issue date"
    );

    let rejected_sequence = verified
        .list()
        .sequence_number
        .checked_add(1)
        .expect("fixture sequence leaves headroom");
    let error = ingest_eu_trusted_list_with_status(
        SIGNED_TSL_XML.as_bytes(),
        &anchors,
        &signer,
        rejected_sequence,
        verification_time(),
        &GoodStatus,
    )
    .expect_err("facade ingestion must reject an authenticated older list");
    assert!(matches!(
        error,
        TrustApiError::TrustedList(identity_trust_tsl_core::TslError::SequenceRollback)
    ));
}

#[test]
#[cfg(not(feature = "xmlsec-ffi"))]
fn api_fails_closed_without_explicit_xmlsec_provider() {
    let error = verify_trust_list_xml_native(
        SIGNED_TSL_XML,
        &[trust_root_cert()],
        verification_time(),
        X509Policy::default(),
    )
    .expect_err("native without the XMLSec provider must fail closed");

    assert!(matches!(
        error,
        identity_credential_trust_api::TrustApiError::BackendFailure
    ));
}

#[test]
fn api_rejects_invalid_trusted_list_bytes_before_backend() {
    let signer = signer_cert();
    let anchors = TrustedListAnchors::new(vec![signer.clone()]).expect("valid anchors");
    let err = ingest_eu_trusted_list(&[0xff, 0xfe], &anchors, &signer, verification_time())
        .expect_err("invalid UTF-8 XML must be rejected");

    assert!(matches!(err, TrustApiError::InvalidInput));
}

#[test]
fn trusted_list_anchors_reject_empty_and_accept_the_maximum_count() {
    assert!(matches!(
        TrustedListAnchors::new(Vec::new()),
        Err(TrustApiError::InvalidInput)
    ));

    let roots = vec![signer_cert(); MAX_TSL_TRUST_ROOTS];
    let anchors = TrustedListAnchors::new(roots).expect("maximum root count must be accepted");
    assert_eq!(anchors.roots().len(), MAX_TSL_TRUST_ROOTS);
}

#[test]
fn trusted_list_anchors_reject_more_than_the_core_root_limit() {
    let roots = vec![signer_cert(); MAX_TSL_TRUST_ROOTS + 1];
    let result = TrustedListAnchors::new(roots);

    assert!(matches!(
        result,
        Err(TrustApiError::ResourceLimit(
            TrustApiResourceLimitReason::TooManyTrustRoots
        ))
    ));
}

#[test]
fn trusted_list_anchors_reject_oversized_der() {
    let mut root = signer_cert();
    root.der = vec![0_u8; MAX_TSL_TRUST_ROOT_DER_BYTES + 1];
    let result = TrustedListAnchors::new(vec![root]);

    assert!(matches!(
        result,
        Err(TrustApiError::ResourceLimit(
            TrustApiResourceLimitReason::CertificateDerTooLarge
        ))
    ));
}

#[test]
fn trusted_list_anchors_reject_aggregate_pem_budget_exhaustion() {
    let mut root = signer_cert();
    root.der = vec![0_u8; MAX_TSL_TRUST_ROOT_DER_BYTES];
    let result = TrustedListAnchors::new(vec![root; MAX_TSL_TRUST_ROOTS]);

    assert!(matches!(
        result,
        Err(TrustApiError::ResourceLimit(
            TrustApiResourceLimitReason::PemBundleTooLarge
        ))
    ));
}

#[test]
fn lower_native_entry_rejects_excessive_roots_before_xml_processing() {
    let roots = vec![signer_cert(); MAX_TSL_TRUST_ROOTS + 1];
    let result = verify_trust_list_xml_native(
        "not XML",
        &roots,
        OffsetDateTime::UNIX_EPOCH,
        X509Policy::default(),
    );

    assert!(matches!(
        result,
        Err(TrustApiError::ResourceLimit(
            TrustApiResourceLimitReason::TooManyTrustRoots
        ))
    ));
}

#[test]
#[cfg(feature = "xmlsec-ffi")]
fn external_signer_entry_rejects_excessive_roots_before_xml_processing() {
    let roots = vec![signer_cert(); MAX_TSL_TRUST_ROOTS + 1];
    let signer = signer_cert();
    let result = verify_trust_list_xml_native_with_external_signer(
        "not XML",
        &roots,
        &signer,
        0,
        OffsetDateTime::UNIX_EPOCH,
        X509Policy::default(),
        &GoodStatus,
    );

    assert!(matches!(
        result,
        Err(TrustApiError::ResourceLimit(
            TrustApiResourceLimitReason::TooManyTrustRoots
        ))
    ));
}

#[test]
#[cfg(feature = "xmlsec-ffi")]
fn community_lists_entry_rejects_excessive_roots_before_xml_processing() {
    let roots = vec![signer_cert(); MAX_TSL_TRUST_ROOTS + 1];
    let result = verify_trust_list_xml_native_with_community_lists(
        "not XML",
        &roots,
        &[],
        0,
        OffsetDateTime::UNIX_EPOCH,
        X509Policy::default(),
        &GoodStatus,
    );

    assert!(matches!(
        result,
        Err(TrustApiError::ResourceLimit(
            TrustApiResourceLimitReason::TooManyTrustRoots
        ))
    ));
}

#[test]
#[cfg(feature = "xmlsec-ffi")]
fn api_preserves_xades_property_failure_reasons() {
    let missing_signing_time = SIGNED_TSL_XML.replacen(
        "            <xades:SigningTime>2026-09-28T01:00:00Z</xades:SigningTime>\n",
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
            TrustedListSignatureProfileErrorReason::InvalidSigningTime,
        ),
        (
            invalid_data_object_format,
            TrustedListSignatureProfileErrorReason::InvalidDataObjectFormat,
        ),
    ] {
        let error = verify_trust_list_xml_native(
            &xml,
            &[trust_root_cert()],
            verification_time(),
            X509Policy::default(),
        )
        .expect_err("invalid XAdES property must retain its public typed reason");

        assert!(matches!(
            error,
            TrustApiError::TrustedListPolicy(
                TrustedListPolicyErrorReason::SignatureProfile(reason)
            ) if reason == expected
        ));
    }
}

#[test]
#[cfg(feature = "xmlsec-ffi")]
fn trusted_list_without_a_purpose_is_invalid_input() {
    let verified = verify_trust_list_xml_native(
        SIGNED_TSL_XML,
        &[trust_root_cert()],
        verification_time(),
        X509Policy::default(),
    )
    .expect("API must verify signed TSL via native backend");
    let verifier = identity_credential_trust_api::default_signature_verifier();
    let result = identity_credential_trust_api::verify_credential_trust_api(
        vec![signer_cert()],
        vec![signer_cert()],
        verifier.as_ref(),
        None,
        Some(&verified),
        None,
        verification_time(),
    );
    assert!(matches!(result, Err(TrustApiError::InvalidInput)));
}
