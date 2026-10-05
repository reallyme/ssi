// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used, clippy::indexing_slicing)]

use envelopes_x509::{parse_cert_der, TrustAnchorRequirement, MAX_X509_CHAIN_CERTIFICATES};
use openssl::{
    asn1::{Asn1Object, Asn1OctetString, Asn1Time},
    bn::BigNum,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509Builder, X509Extension, X509NameBuilder, X509,
    },
};
use reallyme_crypto::sha2::digest;
use reallyme_revocation::StatusCheckError;
#[cfg(feature = "openssl")]
use reallyme_trust::OpenSslSignatureVerifier;
use reallyme_trust::{
    evaluate_trust_api, evaluate_trust_configured_api, CertificateStatus, CertificateStatusPolicy,
    ChainLinkPolicy, PortableSignatureVerifier, StatusChecker, StatusRequirement, TrustAnchorKind,
    TrustApiError, TrustConfig, TrustDecisionFailure, TrustDecisionOutcome, X509Certificate,
    X509Policy,
};
use time::{Duration, OffsetDateTime};

fn make_name(cn: &str) -> openssl::x509::X509Name {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
    name.build()
}

fn set_serial(builder: &mut X509Builder, value: u32) {
    let serial = BigNum::from_u32(value).unwrap().to_asn1_integer().unwrap();
    builder.set_serial_number(&serial).unwrap();
}

fn gen_key() -> PKey<Private> {
    gen_key_with_bits(2_048)
}

fn gen_key_with_bits(bits: u32) -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(bits).unwrap()).unwrap()
}

fn build_root(cn: &str) -> (X509, PKey<Private>) {
    build_root_with_params(cn, 2_048, MessageDigest::sha256())
}

fn build_root_with_params(
    cn: &str,
    bits: u32,
    signature_digest: MessageDigest,
) -> (X509, PKey<Private>) {
    let key = gen_key_with_bits(bits);
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    set_serial(&mut builder, 1);
    let name = make_name(cn);
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    builder
        .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
    let skid = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(skid).unwrap();
    let akid = AuthorityKeyIdentifier::new()
        .keyid(true)
        .issuer(true)
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(akid).unwrap();
    builder.sign(&key, signature_digest).unwrap();

    (builder.build(), key)
}

fn build_leaf(cn: &str, issuer: &X509, issuer_key: &PKey<Private>, serial: u32) -> X509 {
    build_leaf_with_digest(cn, issuer, issuer_key, serial, MessageDigest::sha256())
}

fn build_leaf_with_digest(
    cn: &str,
    issuer: &X509,
    issuer_key: &PKey<Private>,
    serial: u32,
    signature_digest: MessageDigest,
) -> X509 {
    let key = gen_key();
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    set_serial(&mut builder, serial);
    let subject = make_name(cn);
    builder.set_subject_name(&subject).unwrap();
    builder.set_issuer_name(issuer.subject_name()).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(90).unwrap())
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
    let skid = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(Some(issuer), None))
        .unwrap();
    builder.append_extension(skid).unwrap();
    let akid = AuthorityKeyIdentifier::new()
        .keyid(true)
        .issuer(true)
        .build(&builder.x509v3_context(Some(issuer), None))
        .unwrap();
    builder.append_extension(akid).unwrap();
    builder.sign(issuer_key, signature_digest).unwrap();
    builder.build()
}

fn parsed(cert: &X509) -> X509Certificate {
    parse_cert_der(&cert.to_der().unwrap()).unwrap()
}

fn config(roots: Vec<X509Certificate>, now: OffsetDateTime) -> TrustConfig {
    TrustConfig {
        trust_roots: roots,
        now,
        policy: X509Policy {
            require_leaf_digital_signature: true,
            trust_anchor_requirement: TrustAnchorRequirement::Rfc5280Ca,
            ..Default::default()
        },
        link_policy: ChainLinkPolicy::default(),
        evaluation: Default::default(),
        direct_trust: Vec::new(),
    }
}

struct StaticStatus(Result<(), StatusCheckError>);

impl StatusChecker for StaticStatus {
    fn check(
        &self,
        _certificate: &X509Certificate,
        _now_unix: u64,
    ) -> Result<(), StatusCheckError> {
        self.0
    }
}

fn require_leaf_status(config: &mut TrustConfig) {
    config.evaluation.status_policy = CertificateStatusPolicy {
        leaf: StatusRequirement::Required,
        intermediates: StatusRequirement::Required,
        trust_anchor: StatusRequirement::Exempt,
    };
}

#[test]
fn valid_path_retains_selected_certificate_and_policy_evidence() {
    let (root, root_key) = build_root("Anchor");
    let leaf = build_leaf("Leaf", &root, &root_key, 10);
    let leaf = parsed(&leaf);
    let root = parsed(&root);
    let now = OffsetDateTime::now_utc();
    let mut cfg = config(vec![root.clone()], now);
    require_leaf_status(&mut cfg);
    let decision = evaluate_trust_configured_api(
        vec![leaf.clone()],
        cfg,
        &PortableSignatureVerifier::new(),
        Some(&StaticStatus(Ok(()))),
    )
    .unwrap();

    assert_eq!(decision.outcome(), TrustDecisionOutcome::Trusted);
    assert!(decision.is_accepted());
    assert!(decision.failures().is_empty());
    let evidence = decision.evidence();
    assert_eq!(evidence.evaluated_at_unix, now.unix_timestamp());
    assert_eq!(
        evidence.policy_id,
        reallyme_trust::TrustPolicyId::GenericX509V1
    );
    assert_eq!(
        evidence.trust_anchor.unwrap().kind,
        TrustAnchorKind::RootCertificate
    );
    assert_eq!(evidence.trust_anchor.unwrap().configured_index, 0);
    assert_eq!(
        evidence.certificate_status[0].status,
        CertificateStatus::Good
    );
    assert_eq!(
        evidence.certificate_status[1].status,
        CertificateStatus::Exempt
    );
    assert_eq!(
        evidence.selected_path_certificate_sha256,
        vec![
            digest(&leaf.der).into_bytes(),
            digest(&root.der).into_bytes(),
        ]
    );

    let wire =
        reallyme_ssi_proto::generated::proto::identity::trust::v1::TrustDecision::from(&decision);
    assert_eq!(reallyme_trust::TrustDecision::try_from(wire), Ok(decision));
}

#[test]
fn wrong_root_and_invalid_signature_have_distinct_fixed_reasons() {
    let (signing_root, signing_key) = build_root("Signing Root");
    let leaf = parsed(&build_leaf("Leaf", &signing_root, &signing_key, 11));
    let (different_root, _) = build_root("Different Root");
    let wrong_root = evaluate_trust_api(
        vec![leaf],
        vec![parsed(&different_root)],
        &PortableSignatureVerifier::new(),
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    assert_eq!(wrong_root.outcome(), TrustDecisionOutcome::Rejected);
    assert!(wrong_root
        .failures()
        .contains(&TrustDecisionFailure::NoValidPath));

    // The certificate names and key identifiers match the configured root,
    // but the signature was made with a different private key.
    let (configured_root, _) = build_root("Configured Root");
    let (_, unrelated_key) = build_root("Unrelated Root");
    let invalid_leaf = parsed(&build_leaf("Leaf", &configured_root, &unrelated_key, 12));
    let invalid = evaluate_trust_api(
        vec![invalid_leaf],
        vec![parsed(&configured_root)],
        &PortableSignatureVerifier::new(),
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    assert_eq!(invalid.outcome(), TrustDecisionOutcome::Rejected);
    assert!(invalid
        .failures()
        .contains(&TrustDecisionFailure::Signature));
}

#[test]
fn expired_path_is_rejected_by_core_policy() {
    let (root, root_key) = build_root("Anchor");
    let leaf = parsed(&build_leaf("Leaf", &root, &root_key, 13));
    let expired_at = OffsetDateTime::now_utc() + Duration::days(400);
    let decision = evaluate_trust_api(
        vec![leaf],
        vec![parsed(&root)],
        &PortableSignatureVerifier::new(),
        None,
        expired_at,
    )
    .unwrap();
    assert_eq!(decision.outcome(), TrustDecisionOutcome::Rejected);
    assert!(decision.failures().contains(&TrustDecisionFailure::Policy));
}

#[test]
fn required_status_rejects_revocation_and_fails_closed_for_unknown_or_missing_evidence() {
    let (root, root_key) = build_root("Anchor");
    let leaf = parsed(&build_leaf("Leaf", &root, &root_key, 14));
    let root = parsed(&root);
    let now = OffsetDateTime::now_utc();
    let cases = [
        (
            StatusCheckError::Revoked,
            TrustDecisionOutcome::Rejected,
            TrustDecisionFailure::StatusRevoked,
            CertificateStatus::Revoked,
        ),
        (
            StatusCheckError::Unknown,
            TrustDecisionOutcome::Indeterminate,
            TrustDecisionFailure::StatusUnknown,
            CertificateStatus::Unknown,
        ),
    ];
    for (status, outcome, reason, evidence_status) in cases {
        let mut cfg = config(vec![root.clone()], now);
        require_leaf_status(&mut cfg);
        let checker = StaticStatus(Err(status));
        let decision = evaluate_trust_configured_api(
            vec![leaf.clone()],
            cfg,
            &PortableSignatureVerifier::new(),
            Some(&checker),
        )
        .unwrap();
        assert_eq!(decision.outcome(), outcome);
        assert!(decision.failures().contains(&reason));
        assert_eq!(
            decision.evidence().certificate_status[0].status,
            evidence_status
        );
    }
    let mut cfg = config(vec![root], now);
    require_leaf_status(&mut cfg);
    let missing =
        evaluate_trust_configured_api(vec![leaf], cfg, &PortableSignatureVerifier::new(), None)
            .unwrap();
    assert_eq!(missing.outcome(), TrustDecisionOutcome::Indeterminate);
    assert!(missing
        .failures()
        .contains(&TrustDecisionFailure::StatusUnavailable));
}

const NAME_CONSTRAINTS_DER: &[u8] = &[
    0x30, 0x11, 0xa0, 0x0f, 0x30, 0x0d, 0x82, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.',
    b'c', b'o', b'm',
];

fn constrained_root() -> (X509, PKey<Private>) {
    let key = gen_key();
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    set_serial(&mut builder, 15);
    let name = make_name("Constrained Root");
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    builder
        .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
    let skid = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(skid).unwrap();
    let oid = Asn1Object::from_str("2.5.29.30").unwrap();
    let value = Asn1OctetString::new_from_bytes(NAME_CONSTRAINTS_DER).unwrap();
    builder
        .append_extension(X509Extension::new_from_der(&oid, false, &value).unwrap())
        .unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    (builder.build(), key)
}

#[test]
fn unsupported_path_constraint_is_indeterminate_without_backend_fallback() {
    let (root, root_key) = constrained_root();
    let leaf = parsed(&build_leaf("Leaf", &root, &root_key, 16));
    let decision = evaluate_trust_api(
        vec![leaf],
        vec![parsed(&root)],
        &PortableSignatureVerifier::new(),
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    assert_eq!(decision.outcome(), TrustDecisionOutcome::Indeterminate);
    assert!(decision
        .failures()
        .contains(&TrustDecisionFailure::SignatureIndeterminate));
}

#[test]
fn selected_path_cannot_be_substituted_by_a_same_name_root() {
    let (trusted_root, trusted_key) = build_root("Shared Name");
    let (substitute_root, _) = build_root("Shared Name");
    let leaf = parsed(&build_leaf("Leaf", &trusted_root, &trusted_key, 17));
    let trusted = parsed(&trusted_root);
    let substitute = parsed(&substitute_root);
    let decision = evaluate_trust_api(
        vec![leaf.clone()],
        vec![substitute.clone(), trusted.clone()],
        &PortableSignatureVerifier::new(),
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    assert_eq!(decision.outcome(), TrustDecisionOutcome::Trusted);
    assert_eq!(
        decision.evidence().trust_anchor.unwrap().configured_index,
        1
    );
    assert_eq!(
        decision.evidence().selected_path_certificate_sha256,
        vec![
            digest(&leaf.der).into_bytes(),
            digest(&trusted.der).into_bytes(),
        ]
    );
    assert_ne!(
        decision.evidence().selected_path_certificate_sha256[1],
        digest(&substitute.der).into_bytes()
    );
}

#[test]
fn portable_backend_rejects_weak_rsa_anchor_even_when_signature_is_valid() {
    let (root, root_key) = build_root_with_params("Weak Anchor", 1_024, MessageDigest::sha256());
    let leaf = parsed(&build_leaf("Leaf", &root, &root_key, 18));
    let decision = evaluate_trust_api(
        vec![leaf],
        vec![parsed(&root)],
        &PortableSignatureVerifier::new(),
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    assert_eq!(decision.outcome(), TrustDecisionOutcome::Rejected);
    assert!(decision
        .failures()
        .contains(&TrustDecisionFailure::Signature));
}

#[test]
fn mutable_certificate_projection_cannot_extend_der_validity() {
    let (root, root_key) = build_root("Anchor");
    let mut leaf = parsed(&build_leaf("Leaf", &root, &root_key, 20));
    let after_der_expiry = OffsetDateTime::now_utc() + Duration::days(120);
    leaf.not_after = after_der_expiry + Duration::days(1);
    let result = evaluate_trust_api(
        vec![leaf],
        vec![parsed(&root)],
        &PortableSignatureVerifier::new(),
        None,
        after_der_expiry,
    );
    assert!(matches!(result, Err(TrustApiError::InvalidCertificate)));
}

#[test]
fn presented_collection_limit_is_checked_before_reparsing() {
    let (root, root_key) = build_root("Anchor");
    let leaf = parsed(&build_leaf("Leaf", &root, &root_key, 21));
    let over_limit = MAX_X509_CHAIN_CERTIFICATES.checked_add(1).unwrap();
    let result = evaluate_trust_api(
        vec![leaf; over_limit],
        vec![parsed(&root)],
        &PortableSignatureVerifier::new(),
        None,
        OffsetDateTime::now_utc(),
    );
    assert!(matches!(result, Err(TrustApiError::InputLimit)));
}

#[cfg(feature = "openssl")]
#[test]
fn native_backend_retains_rsa_sha384_certificate_support() {
    let (root, root_key) = build_root_with_params("Anchor", 2_048, MessageDigest::sha384());
    let leaf = parsed(&build_leaf_with_digest(
        "Leaf",
        &root,
        &root_key,
        19,
        MessageDigest::sha384(),
    ));
    let root = parsed(&root);
    let now = OffsetDateTime::now_utc();
    let portable = evaluate_trust_api(
        vec![leaf.clone()],
        vec![root.clone()],
        &PortableSignatureVerifier::new(),
        None,
        now,
    )
    .unwrap();
    assert_eq!(portable.outcome(), TrustDecisionOutcome::Indeterminate);
    assert!(portable
        .failures()
        .contains(&TrustDecisionFailure::SignatureIndeterminate));

    let native = evaluate_trust_api(
        vec![leaf],
        vec![root],
        &OpenSslSignatureVerifier::new(),
        None,
        now,
    )
    .unwrap();
    assert_eq!(native.outcome(), TrustDecisionOutcome::Trusted);
}
