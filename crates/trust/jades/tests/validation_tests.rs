// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

//! JAdES Baseline-B validation and adversarial-boundary tests.

use envelopes_x509::{parse_cert_der, X509Certificate, X509Chain, X509Policy};
use identity_trust_jades::{
    authenticate_compact_jades, validate_compact_jades, AuthenticatedCompactJws,
    CompactJwsVerificationError, CompactJwsVerificationErrorReason, CompactJwsVerifier,
    JadesAuthenticationInput, JadesErrorReason, JadesPolicy, JadesSignatureAlgorithm,
    JadesValidationInput, JadesVerificationKey,
};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{
        extension::{BasicConstraints, KeyUsage},
        X509Builder, X509NameBuilder,
    },
};
use reallyme_codec::{
    base64::bytes_to_base64,
    base64url::{base64url_to_bytes, bytes_to_base64url},
};
use reallyme_trust_core::{
    CertificateStatusPolicy, DirectTrustEntry, SignatureVerifier, SignatureVerifyError,
    StatusRequirement, TrustConfig, TrustEvaluationContext, TrustOutcome, TrustPolicyId,
    TrustPurpose, TrustSourceEvidence,
};
use time::OffsetDateTime;
use zeroize::Zeroizing;

const SIGNING_TIME: i64 = 1_789_344_000;
const NOT_BEFORE: i64 = 1_767_225_600;
const NOT_AFTER: i64 = 1_893_456_000;

struct TestJwsVerifier {
    authenticated_header: Vec<u8>,
    failure: Option<CompactJwsVerificationErrorReason>,
}

impl CompactJwsVerifier for TestJwsVerifier {
    fn verify(
        &self,
        _compact: &str,
        algorithm: JadesSignatureAlgorithm,
        key: JadesVerificationKey<'_>,
    ) -> Result<AuthenticatedCompactJws, CompactJwsVerificationError> {
        if let Some(reason) = self.failure {
            return Err(CompactJwsVerificationError::new(reason));
        }
        assert_eq!(algorithm, JadesSignatureAlgorithm::Es256);
        assert!(matches!(key, JadesVerificationKey::P256Sec1(bytes) if !bytes.is_empty()));
        Ok(AuthenticatedCompactJws::new(
            Zeroizing::new(self.authenticated_header.clone()),
            Zeroizing::new(b"verified-payload".to_vec()),
        ))
    }
}

struct UnusedCertificateVerifier;

impl SignatureVerifier for UnusedCertificateVerifier {
    fn verify_chain(
        &self,
        _chain: &X509Chain,
        _now: OffsetDateTime,
    ) -> Result<(), SignatureVerifyError> {
        Err(SignatureVerifyError::BackendFailure)
    }
}

#[test]
fn authenticates_proof_only_against_the_exact_expected_leaf() {
    let certificate = signing_certificate();
    let encoded_certificate = bytes_to_base64(&certificate.der);
    let header =
        format!("{{\"alg\":\"ES256\",\"iat\":{SIGNING_TIME},\"x5c\":[\"{encoded_certificate}\"]}}");
    let compact = compact(&header);
    let verifier = TestJwsVerifier {
        authenticated_header: header.as_bytes().to_vec(),
        failure: None,
    };
    let evaluation_time = OffsetDateTime::from_unix_timestamp(SIGNING_TIME).unwrap();
    let policy = JadesPolicy::default();
    let authenticated = authenticate_compact_jades(
        JadesAuthenticationInput {
            compact: &compact,
            expected_signing_certificate: &certificate,
            evaluation_time,
            policy: &policy,
        },
        &verifier,
    )
    .expect("the exact expected leaf should authenticate without path trust");
    assert_eq!(authenticated.payload(), b"verified-payload");
    assert_eq!(authenticated.signing_certificate(), Some(&certificate));

    let wrong_certificate = signing_certificate();
    let error = authenticate_compact_jades(
        JadesAuthenticationInput {
            compact: &compact,
            expected_signing_certificate: &wrong_certificate,
            evaluation_time,
            policy: &policy,
        },
        &verifier,
    )
    .err()
    .expect("a substituted expected leaf must fail closed");
    assert_eq!(error.reason(), JadesErrorReason::SigningCertificateMismatch);
}

#[test]
fn validates_authenticated_header_thumbprint_time_and_direct_trust() {
    let certificate = signing_certificate();
    let thumbprint = bytes_to_base64url(reallyme_crypto::sha2::digest(&certificate.der).as_bytes());
    let header =
        format!("{{\"alg\":\"ES256\",\"iat\":{SIGNING_TIME},\"x5t#S256\":\"{thumbprint}\"}}");

    let validated = validate(
        &header,
        std::slice::from_ref(&certificate),
        optional_status(),
    )
    .expect("valid JAdES input");

    assert_eq!(validated.payload(), b"verified-payload");
    assert_eq!(validated.signing_certificate().der, certificate.der);
    assert_eq!(validated.trust_decision().outcome, TrustOutcome::Trusted);
    assert_eq!(
        validated.signature_algorithm(),
        JadesSignatureAlgorithm::Es256
    );
}

#[test]
fn reparses_supplied_der_before_using_projected_certificate_fields() {
    let certificate = signing_certificate();
    let mut altered_projection = certificate.clone();
    altered_projection.profile.subject.rdns.clear();
    altered_projection.spki_der = vec![0_u8; 1];
    let thumbprint = bytes_to_base64url(reallyme_crypto::sha2::digest(&certificate.der).as_bytes());
    let header =
        format!("{{\"alg\":\"ES256\",\"iat\":{SIGNING_TIME},\"x5t#S256\":\"{thumbprint}\"}}");
    let compact = compact(&header);
    let config = trust_config(certificate.clone(), optional_status());
    let verifier = TestJwsVerifier {
        authenticated_header: header.as_bytes().to_vec(),
        failure: None,
    };

    let validated = validate_compact_jades(
        JadesValidationInput {
            compact: &compact,
            presented_certificates: std::slice::from_ref(&altered_projection),
            trust_config: &config,
            policy: &JadesPolicy::default(),
        },
        &verifier,
        &UnusedCertificateVerifier,
        None,
    )
    .expect("DER-derived projection must be accepted");

    assert_eq!(validated.signing_certificate(), &certificate);
}

#[test]
fn validates_canonical_x5c_as_the_presented_chain() {
    let certificate = signing_certificate();
    let encoded_certificate = bytes_to_base64(&certificate.der);
    let header =
        format!("{{\"alg\":\"ES256\",\"iat\":{SIGNING_TIME},\"x5c\":[\"{encoded_certificate}\"]}}");

    let validated = validate(
        &header,
        std::slice::from_ref(&certificate),
        optional_status(),
    )
    .expect("valid embedded certificate");
    assert_eq!(validated.signing_certificate().der, certificate.der);
}

#[test]
fn rejects_missing_or_mismatched_signing_certificate_references() {
    let certificate = signing_certificate();
    let missing = format!("{{\"alg\":\"ES256\",\"iat\":{SIGNING_TIME}}}");
    assert_reason(
        &missing,
        std::slice::from_ref(&certificate),
        optional_status(),
        JadesErrorReason::MissingSigningCertificateReference,
    );

    let mismatch = format!(
        "{{\"alg\":\"ES256\",\"iat\":{SIGNING_TIME},\"x5t#S256\":\"{}\"}}",
        bytes_to_base64url(&[7_u8; 32])
    );
    assert_reason(
        &mismatch,
        std::slice::from_ref(&certificate),
        optional_status(),
        JadesErrorReason::SigningCertificateMismatch,
    );
}

#[test]
fn rejects_prohibited_sha1_x5t_parameter() {
    let certificate = signing_certificate();
    let header = format!(
        "{{\"alg\":\"ES256\",\"iat\":{SIGNING_TIME},\"x5t\":\"prohibited\",\"x5c\":[\"{}\"]}}",
        bytes_to_base64(&certificate.der)
    );
    assert_reason(
        &header,
        std::slice::from_ref(&certificate),
        optional_status(),
        JadesErrorReason::InvalidProtectedHeader,
    );
}

#[test]
fn rejects_ambiguous_and_post_transition_legacy_signing_times() {
    let certificate = signing_certificate();
    let thumbprint = bytes_to_base64url(reallyme_crypto::sha2::digest(&certificate.der).as_bytes());
    let ambiguous = format!(
        "{{\"alg\":\"ES256\",\"iat\":{SIGNING_TIME},\"sigT\":\"2024-01-01T00:00:00Z\",\"x5t#S256\":\"{thumbprint}\"}}"
    );
    assert_reason(
        &ambiguous,
        std::slice::from_ref(&certificate),
        optional_status(),
        JadesErrorReason::InvalidClaimedSigningTime,
    );

    let post_transition = format!(
        "{{\"alg\":\"ES256\",\"sigT\":\"2026-09-14T00:00:00Z\",\"x5t#S256\":\"{thumbprint}\"}}"
    );
    assert_reason(
        &post_transition,
        std::slice::from_ref(&certificate),
        optional_status(),
        JadesErrorReason::SigningTimeOutsidePolicy,
    );
}

#[test]
fn rejects_sha256_in_x5t_o_and_short_sig_x5ts() {
    let certificate = signing_certificate();
    let digest = bytes_to_base64url(reallyme_crypto::sha2::digest(&certificate.der).as_bytes());
    let x5t_o = format!(
        "{{\"alg\":\"ES256\",\"iat\":{SIGNING_TIME},\"x5t#o\":{{\"digAlg\":\"sha-256\",\"digVal\":\"{digest}\"}}}}"
    );
    assert_reason(
        &x5t_o,
        std::slice::from_ref(&certificate),
        optional_status(),
        JadesErrorReason::InvalidCertificateReference,
    );

    let sig_x5ts = format!(
        "{{\"alg\":\"ES256\",\"iat\":{SIGNING_TIME},\"sigX5ts\":[{{\"digAlg\":\"sha-256\",\"digVal\":\"{digest}\"}}]}}"
    );
    assert_reason(
        &sig_x5ts,
        std::slice::from_ref(&certificate),
        optional_status(),
        JadesErrorReason::InvalidCertificateReference,
    );
}

#[test]
fn accepts_sig_x5ts_for_a_unique_subset_of_the_certification_path() {
    let signer = signing_certificate();
    let referenced_path_certificate = signing_certificate();
    let unreferenced_path_certificate = signing_certificate();
    let signer_digest = bytes_to_base64url(reallyme_crypto::sha2::digest(&signer.der).as_bytes());
    let path_digest = bytes_to_base64url(
        reallyme_crypto::sha2::digest(&referenced_path_certificate.der).as_bytes(),
    );
    let header = format!(
        "{{\"alg\":\"ES256\",\"iat\":{SIGNING_TIME},\"sigX5ts\":[{{\"digAlg\":\"sha-256\",\"digVal\":\"{signer_digest}\"}},{{\"digAlg\":\"sha-256\",\"digVal\":\"{path_digest}\"}}]}}"
    );
    let path = [
        signer,
        referenced_path_certificate,
        unreferenced_path_certificate,
    ];

    validate(&header, &path, optional_status())
        .expect("sigX5ts may identify a strict subset of the supplied path");
}

#[test]
fn rejects_a_backend_receipt_for_different_header_bytes() {
    let certificate = signing_certificate();
    let thumbprint = bytes_to_base64url(reallyme_crypto::sha2::digest(&certificate.der).as_bytes());
    let header =
        format!("{{\"alg\":\"ES256\",\"iat\":{SIGNING_TIME},\"x5t#S256\":\"{thumbprint}\"}}");
    let compact = compact(&header);
    let config = trust_config(certificate.clone(), optional_status());
    let verifier = TestJwsVerifier {
        authenticated_header: b"{\"alg\":\"ES256\"}".to_vec(),
        failure: None,
    };
    let error = validate_compact_jades(
        JadesValidationInput {
            compact: &compact,
            presented_certificates: std::slice::from_ref(&certificate),
            trust_config: &config,
            policy: &JadesPolicy::default(),
        },
        &verifier,
        &UnusedCertificateVerifier,
        None,
    )
    .err()
    .expect("altered receipt must fail");
    assert_eq!(error.reason(), JadesErrorReason::InvalidSignature);
}

#[test]
fn rejects_a_backend_receipt_for_different_payload_bytes() {
    let certificate = signing_certificate();
    let thumbprint = bytes_to_base64url(reallyme_crypto::sha2::digest(&certificate.der).as_bytes());
    let header =
        format!("{{\"alg\":\"ES256\",\"iat\":{SIGNING_TIME},\"x5t#S256\":\"{thumbprint}\"}}");
    let compact = format!(
        "{}.{}.AA",
        bytes_to_base64url(header.as_bytes()),
        bytes_to_base64url(b"different-payload")
    );
    let config = trust_config(certificate.clone(), optional_status());
    let verifier = TestJwsVerifier {
        authenticated_header: header.as_bytes().to_vec(),
        failure: None,
    };
    let error = validate_compact_jades(
        JadesValidationInput {
            compact: &compact,
            presented_certificates: std::slice::from_ref(&certificate),
            trust_config: &config,
            policy: &JadesPolicy::default(),
        },
        &verifier,
        &UnusedCertificateVerifier,
        None,
    )
    .err()
    .expect("altered payload receipt must fail");
    assert_eq!(error.reason(), JadesErrorReason::InvalidSignature);
}

#[test]
fn preserves_indeterminate_status_as_a_distinct_failure() {
    let certificate = signing_certificate();
    let thumbprint = bytes_to_base64url(reallyme_crypto::sha2::digest(&certificate.der).as_bytes());
    let header =
        format!("{{\"alg\":\"ES256\",\"iat\":{SIGNING_TIME},\"x5t#S256\":\"{thumbprint}\"}}");
    assert_reason(
        &header,
        std::slice::from_ref(&certificate),
        required_status(),
        JadesErrorReason::CertificatePathIndeterminate,
    );
}

#[test]
fn maps_every_public_reason_to_a_canonical_protobuf_enum() {
    use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

    let mapped = IdentityCoreErrorReason::from(JadesErrorReason::SigningCertificateMismatch);
    assert_eq!(
        mapped,
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_JADES_SIGNING_CERTIFICATE_MISMATCH
    );
}

fn validate(
    header: &str,
    certificates: &[X509Certificate],
    status_policy: CertificateStatusPolicy,
) -> Result<identity_trust_jades::ValidatedJades, identity_trust_jades::JadesError> {
    let certificate = certificates
        .first()
        .cloned()
        .unwrap_or_else(signing_certificate);
    let compact = compact(header);
    let decoded_header = compact
        .split('.')
        .next()
        .and_then(|value| base64url_to_bytes(value).ok())
        .expect("test header");
    let config = trust_config(certificate, status_policy);
    let verifier = TestJwsVerifier {
        authenticated_header: decoded_header,
        failure: None,
    };
    validate_compact_jades(
        JadesValidationInput {
            compact: &compact,
            presented_certificates: certificates,
            trust_config: &config,
            policy: &JadesPolicy::default(),
        },
        &verifier,
        &UnusedCertificateVerifier,
        None,
    )
}

fn assert_reason(
    header: &str,
    certificates: &[X509Certificate],
    status_policy: CertificateStatusPolicy,
    expected: JadesErrorReason,
) {
    let error = validate(header, certificates, status_policy)
        .err()
        .expect("input must fail");
    assert_eq!(error.reason(), expected);
}

fn compact(header: &str) -> String {
    format!(
        "{}.{}.AA",
        bytes_to_base64url(header.as_bytes()),
        bytes_to_base64url(b"verified-payload")
    )
}

fn optional_status() -> CertificateStatusPolicy {
    CertificateStatusPolicy {
        leaf: StatusRequirement::Optional,
        intermediates: StatusRequirement::Exempt,
        trust_anchor: StatusRequirement::Exempt,
    }
}

fn required_status() -> CertificateStatusPolicy {
    CertificateStatusPolicy {
        leaf: StatusRequirement::Required,
        intermediates: StatusRequirement::Exempt,
        trust_anchor: StatusRequirement::Exempt,
    }
}

fn trust_config(
    certificate: X509Certificate,
    status_policy: CertificateStatusPolicy,
) -> TrustConfig {
    let source = TrustSourceEvidence {
        source_id: [11_u8; 32],
        snapshot_id: [12_u8; 32],
    };
    TrustConfig {
        trust_roots: Vec::new(),
        now: OffsetDateTime::from_unix_timestamp(SIGNING_TIME).unwrap(),
        policy: X509Policy {
            require_leaf_digital_signature: true,
            ..X509Policy::default()
        },
        link_policy: Default::default(),
        evaluation: TrustEvaluationContext {
            purpose: TrustPurpose::JadesSigner,
            policy_id: TrustPolicyId::EtsiJadesBaselineBV1,
            status_policy,
            source: Some(source),
        },
        direct_trust: vec![DirectTrustEntry {
            certificate,
            purpose: TrustPurpose::JadesSigner,
            policy_id: TrustPolicyId::EtsiJadesBaselineBV1,
            source,
        }],
    }
}

fn signing_certificate() -> X509Certificate {
    let key = p256_key();
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
    builder.set_serial_number(&serial).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COUNTRYNAME, "MT").unwrap();
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "ReallyMe Test Operator")
        .unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "JAdES Signer")
        .unwrap();
    let name = name.build();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::from_unix(NOT_BEFORE).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::from_unix(NOT_AFTER).unwrap())
        .unwrap();
    builder
        .append_extension(BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();

    parse_cert_der(&builder.build().to_der().unwrap()).unwrap()
}

fn p256_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    PKey::from_ec_key(key).unwrap()
}
