// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Provider-policy coverage for native builds without the XMLSec FFI feature.

#![cfg(all(feature = "native", not(feature = "xmlsec-ffi")))]

use envelopes_x509::parse_cert_pem;
use envelopes_x509::policy::X509Policy;
use identity_revocation_core::{StatusCheckError, StatusChecker};
use identity_trust_tsl_openssl::{
    verify_tsl_xml_openssl as verify_tsl_xml_openssl_with_status, TslOpenSslError,
    TslTrustRootErrorReason, MAX_TSL_TRUST_ROOTS, MAX_TSL_TRUST_ROOT_DER_BYTES,
};
use time::OffsetDateTime;

const SIGNED_TSL_XML: &str = include_str!("fixtures/signed_tsl.xml");
const SIGNER_CERT_PEM: &[u8] = include_bytes!("fixtures/cert.pem");

struct GoodStatus;

impl StatusChecker for GoodStatus {
    fn check(
        &self,
        _cert: &envelopes_x509::X509Certificate,
        _now_unix: u64,
    ) -> Result<(), StatusCheckError> {
        Ok(())
    }
}

fn verify_tsl_xml_openssl(
    xml: &str,
    trust_roots: &[envelopes_x509::X509Certificate],
    now: OffsetDateTime,
    policy: X509Policy,
) -> Result<identity_trust_tsl_openssl::VerifiedTrustedList, TslOpenSslError> {
    verify_tsl_xml_openssl_with_status(xml, trust_roots, now, policy, &GoodStatus)
}

fn signer_certificate() -> envelopes_x509::X509Certificate {
    parse_cert_pem(SIGNER_CERT_PEM).expect("test certificate must parse")
}

#[test]
fn native_without_explicit_xmlsec_provider_fails_closed() {
    let signer = signer_certificate();
    let result = verify_tsl_xml_openssl(
        SIGNED_TSL_XML,
        &[signer],
        OffsetDateTime::UNIX_EPOCH,
        X509Policy::default(),
    );

    assert!(matches!(result, Err(TslOpenSslError::BackendUnavailable)));
}

#[test]
fn maximum_trust_root_count_reaches_the_selected_backend() {
    let roots = vec![signer_certificate(); MAX_TSL_TRUST_ROOTS];
    let result = verify_tsl_xml_openssl(
        SIGNED_TSL_XML,
        &roots,
        OffsetDateTime::UNIX_EPOCH,
        X509Policy::default(),
    );

    assert!(matches!(result, Err(TslOpenSslError::BackendUnavailable)));
}

#[test]
fn empty_trust_roots_fail_before_xml_processing() {
    let result = verify_tsl_xml_openssl(
        "not XML",
        &[],
        OffsetDateTime::UNIX_EPOCH,
        X509Policy::default(),
    );

    assert!(matches!(
        result,
        Err(TslOpenSslError::TrustRoots(TslTrustRootErrorReason::Empty))
    ));
}

#[test]
fn excessive_trust_roots_fail_before_xml_processing() {
    let roots = vec![signer_certificate(); MAX_TSL_TRUST_ROOTS + 1];
    let result = verify_tsl_xml_openssl(
        "not XML",
        &roots,
        OffsetDateTime::UNIX_EPOCH,
        X509Policy::default(),
    );

    assert!(matches!(
        result,
        Err(TslOpenSslError::TrustRoots(
            TslTrustRootErrorReason::TooManyTrustRoots
        ))
    ));
}

#[test]
fn oversized_trust_root_der_fails_before_xml_processing() {
    let mut root = signer_certificate();
    root.der = vec![0_u8; MAX_TSL_TRUST_ROOT_DER_BYTES + 1];
    let result = verify_tsl_xml_openssl(
        "not XML",
        &[root],
        OffsetDateTime::UNIX_EPOCH,
        X509Policy::default(),
    );

    assert!(matches!(
        result,
        Err(TslOpenSslError::TrustRoots(
            TslTrustRootErrorReason::CertificateDerTooLarge
        ))
    ));
}

#[test]
fn aggregate_pem_budget_fails_before_xml_or_openssl_processing() {
    let mut root = signer_certificate();
    root.der = vec![0_u8; MAX_TSL_TRUST_ROOT_DER_BYTES];
    let roots = vec![root; MAX_TSL_TRUST_ROOTS];
    let result = verify_tsl_xml_openssl(
        "not XML",
        &roots,
        OffsetDateTime::UNIX_EPOCH,
        X509Policy::default(),
    );

    assert!(matches!(
        result,
        Err(TslOpenSslError::TrustRoots(
            TslTrustRootErrorReason::PemBundleTooLarge
        ))
    ));
}
