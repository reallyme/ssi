// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests that xmlsec FFI verifies signed TSL fixtures.
#![cfg(feature = "xmlsec-ffi")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use identity_trust_tsl_xmlsec::{
    verify_tsl_xmldsig_xmlsec, verify_tsl_xmldsig_xmlsec_with_exact_signers,
    TslXmlSignatureAlgorithm, XmlSecError, XmlSecPolicyViolationReason, XmlSecTrustRootErrorReason,
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;

const SIGNED_TSL_XML: &str = include_str!("../../tsl-openssl/tests/fixtures/signed_tsl.xml");
const WRONG_CERTIFICATE_DIGEST_XML: &str =
    include_str!("../../tsl-openssl/tests/fixtures/signed_wrong_signing_cert_digest.xml");
const TRUST_ROOT_PEM: &str = include_str!("../../tsl-openssl/tests/fixtures/cert.pem");
/// A valid CA certificate that did not issue the fixture signer.
const UNRELATED_ROOT_DER: &[u8] = include_bytes!("fixtures/unrelated_root.der");

fn fixture_root_der() -> Vec<u8> {
    let body: String = TRUST_ROOT_PEM
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    codec_base64::base64_to_bytes(&body).expect("fixture PEM must carry base64 DER")
}

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
    let root = fixture_root_der();

    let verified =
        verify_tsl_xmldsig_xmlsec(SIGNED_TSL_XML, &[root.as_slice()], verification_time())
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

fn fixture_signer_der() -> Vec<u8> {
    let root = fixture_root_der();
    verify_tsl_xmldsig_xmlsec(SIGNED_TSL_XML, &[root.as_slice()], verification_time())
        .expect("fixture signer must be available for exact-binding regressions")
        .signer_certificate_der()
        .to_vec()
}

fn different_certificate(certificate: &[u8]) -> Vec<u8> {
    let mut different = certificate.to_vec();
    let first = different
        .first_mut()
        .expect("fixture signer DER must not be empty");
    *first ^= 1;
    different
}

#[test]
fn exact_signers_entry_point_rejects_a_different_certificate() {
    let root = fixture_root_der();
    let different_signer = different_certificate(&fixture_signer_der());

    let error = verify_tsl_xmldsig_xmlsec_with_exact_signers(
        SIGNED_TSL_XML,
        &[root.as_slice()],
        verification_time(),
        &[different_signer.as_slice()],
    )
    .expect_err("a different externally authenticated certificate must fail closed");
    assert!(matches!(
        error,
        XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::SignerBindingMismatch)
    ));
}

#[test]
fn exact_signers_entry_point_rejects_an_empty_candidate_list() {
    let root = fixture_root_der();

    let error = verify_tsl_xmldsig_xmlsec_with_exact_signers(
        SIGNED_TSL_XML,
        &[root.as_slice()],
        verification_time(),
        &[],
    )
    .expect_err("an empty signer candidate list must fail closed");
    assert!(matches!(
        error,
        XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::SignerBindingMismatch)
    ));
}

#[test]
fn exact_signers_entry_point_accepts_any_listed_rollover_candidate() {
    let root = fixture_root_der();
    let signer = fixture_signer_der();
    let different_signer = different_certificate(&signer);

    // Rollover: the actual signer is the second candidate. A single native
    // verification must bind to whichever candidate matches.
    let verified = verify_tsl_xmldsig_xmlsec_with_exact_signers(
        SIGNED_TSL_XML,
        &[root.as_slice()],
        verification_time(),
        &[different_signer.as_slice(), signer.as_slice()],
    )
    .expect("the listed actual signer must verify");
    assert_eq!(verified.signer_certificate_der(), signer.as_slice());
}

#[test]
fn exact_signers_entry_point_does_not_require_the_signer_as_a_path_root() {
    let signer = fixture_signer_der();

    // Exact-leaf mode binds trust to the byte-identical signer rather than to
    // an XMLSec certificate path, so an unrelated anchor does not block it.
    let verified = verify_tsl_xmldsig_xmlsec_with_exact_signers(
        SIGNED_TSL_XML,
        &[UNRELATED_ROOT_DER],
        verification_time(),
        &[signer.as_slice()],
    )
    .expect("an exactly pinned signer must verify without a path root");
    assert_eq!(verified.signer_certificate_der(), signer.as_slice());
}

#[test]
fn ffi_trusts_a_signer_anchored_by_the_second_of_two_roots() {
    // Regression: roots used to be concatenated into one PEM file of which the
    // backend read only the first certificate, silently dropping later roots.
    let root = fixture_root_der();

    let verified = verify_tsl_xmldsig_xmlsec(
        SIGNED_TSL_XML,
        &[UNRELATED_ROOT_DER, root.as_slice()],
        verification_time(),
    )
    .expect("a signer anchored by the second trusted root must verify");
    assert_eq!(
        verified.signature_algorithm(),
        TslXmlSignatureAlgorithm::RsaSha256
    );
}

#[test]
fn ffi_trusts_a_signer_anchored_by_the_first_of_two_roots() {
    let root = fixture_root_der();

    verify_tsl_xmldsig_xmlsec(
        SIGNED_TSL_XML,
        &[root.as_slice(), UNRELATED_ROOT_DER],
        verification_time(),
    )
    .expect("a signer anchored by the first trusted root must verify");
}

#[test]
fn ffi_rejects_a_signer_without_a_trusted_root() {
    let error =
        verify_tsl_xmldsig_xmlsec(SIGNED_TSL_XML, &[UNRELATED_ROOT_DER], verification_time())
            .expect_err("an unanchored signer must fail closed");
    assert!(matches!(error, XmlSecError::InvalidSignature));
}

#[test]
fn ffi_rejects_malformed_trust_root_der() {
    let malformed: &[u8] = &[0x30, 0x03, 0x02, 0x01];
    let root = fixture_root_der();

    let error = verify_tsl_xmldsig_xmlsec(
        SIGNED_TSL_XML,
        &[root.as_slice(), malformed],
        verification_time(),
    )
    .expect_err("a malformed trust root must fail closed");
    assert!(matches!(
        error,
        XmlSecError::TrustRoots(XmlSecTrustRootErrorReason::InvalidCertificateDer)
    ));
}

#[test]
fn concurrent_verification_is_serialized_and_deterministic() {
    const THREADS: usize = 8;
    let root = fixture_root_der();
    let tampered = tampered_signature_xml();

    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..THREADS)
            .map(|index| {
                let root = root.as_slice();
                let tampered = tampered.as_str();
                scope.spawn(move || {
                    if index % 2 == 0 {
                        verify_tsl_xmldsig_xmlsec(SIGNED_TSL_XML, &[root], verification_time())
                            .map(|_| ())
                    } else {
                        match verify_tsl_xmldsig_xmlsec(tampered, &[root], verification_time()) {
                            Err(XmlSecError::InvalidSignature) => Ok(()),
                            Err(error) => Err(error),
                            Ok(_) => Err(XmlSecError::Internal),
                        }
                    }
                })
            })
            .collect();
        for worker in workers {
            assert!(worker.join().expect("worker must not panic").is_ok());
        }
    });
}

#[test]
fn ffi_uses_the_caller_selected_certificate_validation_time() {
    let root = fixture_root_der();

    // The fixture certificate expires in 2031. A later evaluation must fail
    // even when the machine clock is inside the certificate validity window.
    let after_certificate_expiry =
        time::OffsetDateTime::from_unix_timestamp(2_000_000_000).unwrap();
    let error =
        verify_tsl_xmldsig_xmlsec(SIGNED_TSL_XML, &[root.as_slice()], after_certificate_expiry)
            .unwrap_err();

    assert!(matches!(error, XmlSecError::InvalidSignature));
}

#[test]
fn ffi_rejects_tampered_fixture() {
    let root = fixture_root_der();

    let tampered = SIGNED_TSL_XML.replace("TrustServiceStatusList", "TrustServiceStatusListX");
    let err =
        verify_tsl_xmldsig_xmlsec(&tampered, &[root.as_slice()], verification_time()).unwrap_err();

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

    let root = fixture_root_der();
    let trusted_roots: &[&[u8]] = &[root.as_slice()];
    let tampered = tampered_signature_xml();

    let exercise_both_paths = || {
        let verified =
            verify_tsl_xmldsig_xmlsec(SIGNED_TSL_XML, trusted_roots, verification_time())
                .expect("signed fixture must verify repeatedly");
        drop(verified);
        assert!(matches!(
            verify_tsl_xmldsig_xmlsec(&tampered, trusted_roots, verification_time()),
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
    let root = fixture_root_der();

    let error = verify_tsl_xmldsig_xmlsec(
        WRONG_CERTIFICATE_DIGEST_XML,
        &[root.as_slice()],
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
    let root = fixture_root_der();

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
        &[root.as_slice()],
        verification_time(),
    )
    .unwrap_err();
    assert!(matches!(error, XmlSecError::SchemaValidationFailed));
}
