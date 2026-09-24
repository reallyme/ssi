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
    ingest_eu_trusted_list, verify_trust_list_xml_native, TrustApiError,
    TrustApiResourceLimitReason, TrustedListAnchors,
};
#[cfg(feature = "xmlsec-ffi")]
use identity_credential_trust_api::{
    TrustedListPolicyErrorReason, TrustedListSignatureProfileErrorReason,
};
use identity_trust_tsl_openssl::{MAX_TSL_TRUST_ROOTS, MAX_TSL_TRUST_ROOT_DER_BYTES};

use envelopes_x509::policy::X509Policy;
use envelopes_x509::{parse_cert_pem, X509Certificate};

use time::OffsetDateTime;

const SIGNED_TSL_XML: &str = include_str!("../../tsl-openssl/tests/fixtures/signed_tsl.xml");
const SIGNER_CERT_PEM: &[u8] = include_bytes!("../../tsl-openssl/tests/fixtures/cert.pem");

fn signer_cert() -> X509Certificate {
    parse_cert_pem(SIGNER_CERT_PEM).expect("invalid signer cert PEM")
}

fn verification_time() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("fixed test time must be valid")
}

#[test]
#[cfg(feature = "xmlsec-ffi")]
fn api_verifies_signed_tsl_native() {
    let tsl = verify_trust_list_xml_native(
        SIGNED_TSL_XML,
        &[signer_cert()],
        verification_time(),
        X509Policy::default(),
    )
    .expect("API must verify signed TSL via native backend");

    assert_eq!(tsl.list().name, "MT:Test Trusted List");
    assert!(tsl.signer_trust().evidence.source.is_some());
}

#[test]
#[cfg(feature = "xmlsec-ffi")]
fn api_ingests_eu_trusted_list_from_xml_bytes() {
    let signer = signer_cert();
    let anchors = TrustedListAnchors::new(vec![signer.clone()]).expect("valid anchors");
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
}

#[test]
#[cfg(not(feature = "xmlsec-ffi"))]
fn api_fails_closed_without_explicit_xmlsec_provider() {
    let error = verify_trust_list_xml_native(
        SIGNED_TSL_XML,
        &[signer_cert()],
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
fn api_preserves_xades_property_failure_reasons() {
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
            TrustedListSignatureProfileErrorReason::InvalidSigningTime,
        ),
        (
            invalid_data_object_format,
            TrustedListSignatureProfileErrorReason::InvalidDataObjectFormat,
        ),
    ] {
        let error = verify_trust_list_xml_native(
            &xml,
            &[signer_cert()],
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
