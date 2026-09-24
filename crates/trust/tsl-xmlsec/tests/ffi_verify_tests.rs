// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests that xmlsec FFI verifies signed TSL fixtures.
#![cfg(feature = "xmlsec-ffi")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use identity_trust_tsl_xmlsec::{
    verify_tsl_xmldsig_xmlsec, verify_tsl_xmldsig_xmlsec_with_exact_signer,
    TslXmlSignatureAlgorithm, XmlSecError, XmlSecPolicyViolationReason,
};

use std::io::Write;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;
use tempfile::NamedTempFile;

const SIGNED_TSL_XML: &str = include_str!("../../tsl-openssl/tests/fixtures/signed_tsl.xml");
const WRONG_CERTIFICATE_DIGEST_XML: &str =
    include_str!("../../tsl-openssl/tests/fixtures/signed_wrong_signing_cert_digest.xml");
const TRUST_ROOT_PEM: &[u8] = include_bytes!("../../tsl-openssl/tests/fixtures/cert.pem");

fn verification_time() -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
}

fn tampered_signature_xml() -> String {
    const START_MARKER: &str = "<ds:SignatureValue>";
    const END_MARKER: &str = "</ds:SignatureValue>";

    let marker_start = SIGNED_TSL_XML
        .find(START_MARKER)
        .expect("fixture must contain SignatureValue");
    let start = marker_start
        .checked_add(START_MARKER.len())
        .expect("fixture offset must fit usize");
    let end = SIGNED_TSL_XML[start..]
        .find(END_MARKER)
        .and_then(|offset| offset.checked_add(start))
        .expect("fixture must contain a bounded SignatureValue end");
    let replacement_end = start.checked_add(1).expect("fixture offset must fit usize");
    let first_signature_byte = SIGNED_TSL_XML
        .as_bytes()
        .get(start)
        .expect("fixture signature must not be empty");
    let replacement = if *first_signature_byte == b'A' {
        "B"
    } else {
        "A"
    };
    let mut tampered = SIGNED_TSL_XML.to_owned();
    tampered.replace_range(start..replacement_end, replacement);
    assert_eq!(tampered.len(), SIGNED_TSL_XML.len());
    assert!(end > start);
    tampered
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn resident_set_kibibytes() -> u64 {
    let process_id = std::process::id().to_string();
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", process_id.as_str()])
        .output()
        .expect("ps must be available for the native resource regression");
    assert!(output.status.success());
    let resident_set = std::str::from_utf8(&output.stdout)
        .expect("ps RSS output must be UTF-8")
        .trim();
    resident_set
        .parse::<u64>()
        .expect("ps RSS output must be an integer number of KiB")
}

#[test]
fn ffi_verifies_signed_fixture() {
    let mut pem = NamedTempFile::new().unwrap();
    pem.write_all(TRUST_ROOT_PEM).unwrap();
    pem.flush().unwrap();

    let verified = verify_tsl_xmldsig_xmlsec(
        SIGNED_TSL_XML,
        pem.path().to_str().unwrap(),
        verification_time(),
    )
    .expect("xmlsec ffi must verify signed fixture");
    assert!(!verified.signer_certificate_der().is_empty());
    assert!(verified
        .key_info_certificates_der()
        .iter()
        .any(|certificate| certificate == verified.signer_certificate_der()));
    assert_eq!(
        verified.signature_algorithm(),
        TslXmlSignatureAlgorithm::RsaSha256
    );
}

#[test]
fn exact_signer_entry_point_rejects_a_different_certificate() {
    let mut pem = NamedTempFile::new().unwrap();
    pem.write_all(TRUST_ROOT_PEM).unwrap();
    pem.flush().unwrap();

    let verified = verify_tsl_xmldsig_xmlsec(
        SIGNED_TSL_XML,
        pem.path().to_str().unwrap(),
        verification_time(),
    )
    .expect("fixture signer must be available for exact-binding regression");
    let mut different_signer = verified.signer_certificate_der().to_vec();
    let first = different_signer
        .first_mut()
        .expect("fixture signer DER must not be empty");
    *first ^= 1;

    let error = verify_tsl_xmldsig_xmlsec_with_exact_signer(
        SIGNED_TSL_XML,
        pem.path().to_str().unwrap(),
        verification_time(),
        &different_signer,
    )
    .expect_err("a different externally authenticated certificate must fail closed");
    assert!(matches!(
        error,
        XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::SignerBindingMismatch)
    ));
}

#[test]
fn ffi_uses_the_caller_selected_certificate_validation_time() {
    let mut pem = NamedTempFile::new().unwrap();
    pem.write_all(TRUST_ROOT_PEM).unwrap();
    pem.flush().unwrap();

    // The fixture certificate expires in 2031. A later evaluation must fail
    // even when the machine clock is inside the certificate validity window.
    let after_certificate_expiry =
        time::OffsetDateTime::from_unix_timestamp(2_000_000_000).unwrap();
    let error = verify_tsl_xmldsig_xmlsec(
        SIGNED_TSL_XML,
        pem.path().to_str().unwrap(),
        after_certificate_expiry,
    )
    .unwrap_err();

    assert!(matches!(error, XmlSecError::InvalidSignature));
}

#[test]
fn ffi_rejects_tampered_fixture() {
    let mut pem = NamedTempFile::new().unwrap();
    pem.write_all(TRUST_ROOT_PEM).unwrap();
    pem.flush().unwrap();

    let tampered = SIGNED_TSL_XML.replace("TrustServiceStatusList", "TrustServiceStatusListX");
    let err =
        verify_tsl_xmldsig_xmlsec(&tampered, pem.path().to_str().unwrap(), verification_time())
            .unwrap_err();

    // Exact error may vary; any error is acceptable here.
    let _ = err;
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn repeated_positive_and_tampered_verification_has_stable_resources() {
    const WARMUP_ITERATIONS: usize = 16;
    const MEASURED_ITERATIONS: usize = 128;
    // Native crypto and XML allocators may retain arenas. The historical
    // missing-manager defect grew by roughly 116 MiB in 128 iterations, so a
    // 64 MiB ceiling tolerates allocator noise while still catching that leak.
    const MAX_RESIDENT_GROWTH_KIB: u64 = 64 * 1024;

    let mut pem = NamedTempFile::new().unwrap();
    pem.write_all(TRUST_ROOT_PEM).unwrap();
    pem.flush().unwrap();
    let trusted_pem_path = pem.path().to_str().unwrap();
    let tampered = tampered_signature_xml();

    let exercise_both_paths = || {
        let verified =
            verify_tsl_xmldsig_xmlsec(SIGNED_TSL_XML, trusted_pem_path, verification_time())
                .expect("signed fixture must verify repeatedly");
        drop(verified);
        assert!(matches!(
            verify_tsl_xmldsig_xmlsec(&tampered, trusted_pem_path, verification_time()),
            Err(XmlSecError::InvalidSignature)
        ));
    };

    for _ in 0..WARMUP_ITERATIONS {
        exercise_both_paths();
    }
    let resident_before = resident_set_kibibytes();
    for _ in 0..MEASURED_ITERATIONS {
        exercise_both_paths();
    }
    let resident_after = resident_set_kibibytes();
    let growth = resident_after.saturating_sub(resident_before);
    assert!(
        growth <= MAX_RESIDENT_GROWTH_KIB,
        "native XMLSec resident-set growth exceeded the resource-stability ceiling"
    );
}

#[test]
fn ffi_rejects_valid_signature_with_substituted_signing_certificate_reference() {
    let mut pem = NamedTempFile::new().unwrap();
    pem.write_all(TRUST_ROOT_PEM).unwrap();
    pem.flush().unwrap();

    let error = verify_tsl_xmldsig_xmlsec(
        WRONG_CERTIFICATE_DIGEST_XML,
        pem.path().to_str().unwrap(),
        verification_time(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::SigningCertificateMismatch)
    ));
}

#[test]
fn ffi_rejects_document_that_violates_pinned_etsi_schema() {
    let mut pem = NamedTempFile::new().unwrap();
    pem.write_all(TRUST_ROOT_PEM).unwrap();
    pem.flush().unwrap();

    // Removing the address violates both the pinned TS 119 612 v2.4.1 schema
    // and the portable semantic projection. The native verifier must still
    // identify the earlier schema boundary deterministically.
    let start = SIGNED_TSL_XML.find("    <SchemeOperatorAddress>").unwrap();
    let end_marker = "    </SchemeOperatorAddress>\n";
    let end = SIGNED_TSL_XML.find(end_marker).unwrap() + end_marker.len();
    let mut schema_invalid = SIGNED_TSL_XML.to_owned();
    schema_invalid.replace_range(start..end, "");

    let error = verify_tsl_xmldsig_xmlsec(
        schema_invalid.as_str(),
        pem.path().to_str().unwrap(),
        verification_time(),
    )
    .unwrap_err();
    assert!(matches!(error, XmlSecError::SchemaValidationFailed));
}
