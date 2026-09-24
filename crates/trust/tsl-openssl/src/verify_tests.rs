// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::TslSignatureAlgorithm;
use crate::{
    signer_profile::{
        rsa_public_exponent_allowed, validate_tlso_signer_profile, TslSignerIssuerSource,
    },
    trust_roots::pem_encoded_upper_bound,
};
use crate::{TslOpenSslError, TslSignerProfileFailureReason, TslTrustRootErrorReason};
use envelopes_x509::{
    parse_cert_pem, BasicConstraints, NameAttributeKind, NameAttributeValue, ObjectIdentifier,
    PublicKeyProfile,
};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        extension::{
            AuthorityKeyIdentifier, BasicConstraints as OpenSslBasicConstraints, ExtendedKeyUsage,
            KeyUsage as OpenSslKeyUsage, SubjectKeyIdentifier,
        },
        X509Builder, X509NameBuilder, X509,
    },
};

fn profile_inputs() -> (
    envelopes_x509::X509Certificate,
    identity_trust_tsl_core::TrustedList,
    time::OffsetDateTime,
) {
    let certificate = parse_cert_pem(include_bytes!("../tests/fixtures/cert.pem"))
        .expect("profile fixture certificate must parse");
    let list =
        identity_trust_tsl_core::parse_tsl_xml(include_str!("../tests/fixtures/signed_tsl.xml"))
            .expect("profile fixture trusted list must parse");
    let now = time::OffsetDateTime::from_unix_timestamp(1_789_430_400)
        .expect("test timestamp must be valid");
    (certificate, list, now)
}

fn assert_profile_failure(
    certificate: &envelopes_x509::X509Certificate,
    list: &identity_trust_tsl_core::TrustedList,
    now: time::OffsetDateTime,
    expected: TslSignerProfileFailureReason,
) {
    assert!(matches!(
        validate_tlso_signer_profile(
            certificate,
            list,
            &[],
            now,
            TslSignatureAlgorithm::RsaSha256,
        ),
        Err(TslOpenSslError::SignerProfile(reason)) if reason == expected
    ));
}

#[test]
fn pem_size_arithmetic_overflow_is_a_typed_resource_failure() {
    assert!(matches!(
        pem_encoded_upper_bound(usize::MAX),
        Err(TslOpenSslError::TrustRoots(
            TslTrustRootErrorReason::PemBundleTooLarge
        ))
    ));
}

#[test]
fn enforces_the_ts_119_312_rsa_public_exponent_range() {
    let ordinary = PKey::from_rsa(Rsa::generate(2_048).expect("test key generation must succeed"))
        .expect("test key conversion must succeed");
    assert!(rsa_public_exponent_allowed(
        &ordinary
            .public_key_to_der()
            .expect("ordinary public key must encode")
    ));

    let exponent = BigNum::from_u32(3).expect("small exponent must encode");
    let weak = PKey::from_rsa(
        Rsa::generate_with_e(2_048, &exponent).expect("small-exponent test key must generate"),
    )
    .expect("small-exponent test key must convert");
    assert!(!rsa_public_exponent_allowed(
        &weak
            .public_key_to_der()
            .expect("small-exponent public key must encode")
    ));
}

#[test]
fn accepts_complete_tlso_signer_profile() {
    let (certificate, list, now) = profile_inputs();
    let evidence = validate_tlso_signer_profile(
        &certificate,
        &list,
        &[],
        now,
        TslSignatureAlgorithm::RsaSha256,
    )
    .expect("complete TLSO signer profile must pass");
    assert!(evidence.subject_country_matched);
    assert!(evidence.subject_organization_matched);
    assert!(evidence.key_usage_exclusive);
    assert!(evidence.subject_key_identifier_present);
    assert!(evidence.subject_key_identifier_valid);
    assert!(evidence.basic_constraints_ca_false);
    assert!(evidence.trusted_list_signing_eku_exclusive);
    assert!(evidence.algorithm_has_three_year_resistance);
    assert_eq!(evidence.issuer_source, TslSignerIssuerSource::SelfSigned);
}

#[test]
fn admits_only_a_cryptographically_verified_current_list_issuer() {
    let (issuer, issuer_key) = issuing_service_certificate();
    let signer = issued_tlso_certificate(&issuer, &issuer_key);
    let list = list_with_issuing_service(&issuer);
    let now = time::OffsetDateTime::from_unix_timestamp(1_789_430_400)
        .expect("test timestamp must be valid");

    let evidence =
        validate_tlso_signer_profile(&signer, &list, &[], now, TslSignatureAlgorithm::RsaSha256)
            .expect("listed issuer that signed the TLSO certificate must pass");
    assert_eq!(
        evidence.issuer_source,
        TslSignerIssuerSource::CurrentTrustedList
    );

    let (_, unrelated_list, _) = profile_inputs();
    assert_profile_failure(
        &signer,
        &unrelated_list,
        now,
        TslSignerProfileFailureReason::UnauthorizedIssuer,
    );
}

#[test]
fn rejects_each_tlso_identity_and_extension_rule() {
    let (certificate, list, now) = profile_inputs();

    let mut wrong_country = certificate.clone();
    for attribute in wrong_country
        .profile
        .subject
        .rdns
        .iter_mut()
        .flat_map(|rdn| &mut rdn.attributes)
    {
        if attribute.kind == NameAttributeKind::CountryName {
            attribute.value = NameAttributeValue::Text("US".to_owned());
        }
    }
    assert_profile_failure(
        &wrong_country,
        &list,
        now,
        TslSignerProfileFailureReason::CountryMismatch,
    );

    let mut wrong_organization = certificate.clone();
    for attribute in wrong_organization
        .profile
        .subject
        .rdns
        .iter_mut()
        .flat_map(|rdn| &mut rdn.attributes)
    {
        if attribute.kind == NameAttributeKind::OrganizationName {
            attribute.value = NameAttributeValue::Text("Other Operator".to_owned());
        }
    }
    assert_profile_failure(
        &wrong_organization,
        &list,
        now,
        TslSignerProfileFailureReason::OrganizationMismatch,
    );

    let mut missing_usage = certificate.clone();
    missing_usage.key_usage = None;
    assert_profile_failure(
        &missing_usage,
        &list,
        now,
        TslSignerProfileFailureReason::MissingKeyUsage,
    );

    let mut incompatible_usage = certificate.clone();
    incompatible_usage
        .key_usage
        .as_mut()
        .expect("fixture must contain key usage")
        .data_encipherment = true;
    assert_profile_failure(
        &incompatible_usage,
        &list,
        now,
        TslSignerProfileFailureReason::InvalidKeyUsage,
    );

    let mut missing_ski = certificate.clone();
    missing_ski.subject_key_identifier = None;
    assert_profile_failure(
        &missing_ski,
        &list,
        now,
        TslSignerProfileFailureReason::MissingSubjectKeyIdentifier,
    );

    let mut invalid_ski = certificate.clone();
    invalid_ski.subject_key_identifier = Some(vec![0_u8; 20]);
    assert_profile_failure(
        &invalid_ski,
        &list,
        now,
        TslSignerProfileFailureReason::InvalidSubjectKeyIdentifier,
    );

    let subject_public_key =
        envelopes_x509::parse_subject_public_key_info_der(certificate.spki_der.as_slice())
            .expect("fixture SPKI must parse")
            .public_key;
    let full_identifier = openssl::sha::sha1(subject_public_key.as_slice());
    let mut short_identifier = [0_u8; 8];
    short_identifier.copy_from_slice(&full_identifier[12..]);
    short_identifier[0] = (short_identifier[0] & 0x0f) | 0x40;
    let mut method_two = certificate.clone();
    method_two.subject_key_identifier = Some(short_identifier.to_vec());
    validate_tlso_signer_profile(
        &method_two,
        &list,
        &[],
        now,
        TslSignatureAlgorithm::RsaSha256,
    )
    .expect("RFC 5280 method (2) identifier must be accepted");

    let mut ca = certificate.clone();
    ca.basic_constraints = Some(BasicConstraints {
        ca: true,
        path_len_constraint: None,
    });
    assert_profile_failure(
        &ca,
        &list,
        now,
        TslSignerProfileFailureReason::InvalidBasicConstraints,
    );

    let mut wrong_eku = certificate.clone();
    wrong_eku.extended_key_usage = None;
    assert_profile_failure(
        &wrong_eku,
        &list,
        now,
        TslSignerProfileFailureReason::InvalidExtendedKeyUsage,
    );
}

#[test]
fn applies_three_year_algorithm_horizon_to_injected_time() {
    let (certificate, list, now) = profile_inputs();
    let mut legacy_rsa = certificate;
    legacy_rsa.profile.public_key = PublicKeyProfile::Rsa { bits: 2_048 };
    assert_profile_failure(
        &legacy_rsa,
        &list,
        now,
        TslSignerProfileFailureReason::AlgorithmLifetime,
    );

    let before_legacy_cutoff = time::OffsetDateTime::from_unix_timestamp(1_700_000_000)
        .expect("test timestamp must be valid");
    legacy_rsa.not_before = time::OffsetDateTime::from_unix_timestamp(1_700_000_000)
        .expect("legacy issuance timestamp must be valid");
    legacy_rsa.not_after = time::OffsetDateTime::from_unix_timestamp(1_850_000_000)
        .expect("legacy expiry timestamp must be valid");
    validate_tlso_signer_profile(
        &legacy_rsa,
        &list,
        &[],
        before_legacy_cutoff,
        TslSignatureAlgorithm::RsaSha256,
    )
    .expect("legacy RSA remains usable when the full horizon precedes its end date");

    let mut issued_at_legacy_boundary = legacy_rsa.clone();
    issued_at_legacy_boundary.not_before = time::OffsetDateTime::from_unix_timestamp(1_798_761_599)
        .expect("legacy issuance boundary must be valid");
    validate_tlso_signer_profile(
        &issued_at_legacy_boundary,
        &list,
        &[],
        before_legacy_cutoff,
        TslSignatureAlgorithm::RsaSha256,
    )
    .expect("legacy RSA certificate issued at 2026-12-31T23:59:59Z remains admitted");

    let mut issued_after_legacy_boundary = issued_at_legacy_boundary;
    issued_after_legacy_boundary.not_before =
        time::OffsetDateTime::from_unix_timestamp(1_798_761_600)
            .expect("post-boundary issuance timestamp must be valid");
    assert_profile_failure(
        &issued_after_legacy_boundary,
        &list,
        before_legacy_cutoff,
        TslSignerProfileFailureReason::AlgorithmLifetime,
    );

    let mut overlong_legacy_rsa = legacy_rsa.clone();
    overlong_legacy_rsa.not_after = time::OffsetDateTime::from_unix_timestamp(1_870_000_000)
        .expect("overlong expiry timestamp must be valid");
    assert_profile_failure(
        &overlong_legacy_rsa,
        &list,
        before_legacy_cutoff,
        TslSignerProfileFailureReason::AlgorithmLifetime,
    );

    let mut private_curve = legacy_rsa;
    private_curve.profile.public_key = PublicKeyProfile::Ec {
        bits: 256,
        curve: ObjectIdentifier::parse("1.3.6.1.4.1.55555.1"),
    };
    assert_profile_failure(
        &private_curve,
        &list,
        before_legacy_cutoff,
        TslSignerProfileFailureReason::AlgorithmLifetime,
    );

    let mut mismatched_curve_suite = private_curve;
    mismatched_curve_suite.profile.public_key = PublicKeyProfile::Ec {
        bits: 256,
        curve: ObjectIdentifier::parse("1.2.840.10045.3.1.7"),
    };
    assert!(matches!(
        validate_tlso_signer_profile(
            &mismatched_curve_suite,
            &list,
            &[],
            before_legacy_cutoff,
            TslSignatureAlgorithm::EcdsaSha512,
        ),
        Err(TslOpenSslError::SignerProfile(
            TslSignerProfileFailureReason::AlgorithmLifetime
        ))
    ));
}

fn issuing_service_certificate() -> (X509, PKey<Private>) {
    let key = PKey::from_rsa(Rsa::generate(3_072).expect("issuer key generation must succeed"))
        .expect("issuer key conversion must succeed");
    let mut name = X509NameBuilder::new().expect("issuer name builder must initialize");
    name.append_entry_by_nid(Nid::COUNTRYNAME, "MT")
        .expect("issuer country must encode");
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "Listed TSP")
        .expect("issuer organization must encode");
    name.append_entry_by_nid(Nid::COMMONNAME, "Listed Issuing Service")
        .expect("issuer common name must encode");
    let name = name.build();

    let mut builder = X509Builder::new().expect("issuer certificate builder must initialize");
    builder.set_version(2).expect("issuer version must encode");
    let serial = BigNum::from_u32(10)
        .expect("issuer serial must encode")
        .to_asn1_integer()
        .expect("issuer serial conversion must succeed");
    builder
        .set_serial_number(&serial)
        .expect("issuer serial must be accepted");
    builder
        .set_subject_name(&name)
        .expect("issuer subject must be accepted");
    builder
        .set_issuer_name(&name)
        .expect("issuer name must be accepted");
    builder
        .set_pubkey(&key)
        .expect("issuer public key must be accepted");
    builder
        .set_not_before(&Asn1Time::from_unix(1_767_225_600).expect("valid not-before"))
        .expect("issuer not-before must be accepted");
    builder
        .set_not_after(&Asn1Time::from_unix(1_893_456_000).expect("valid not-after"))
        .expect("issuer not-after must be accepted");
    builder
        .append_extension(
            OpenSslBasicConstraints::new()
                .critical()
                .ca()
                .build()
                .expect("issuer constraints must build"),
        )
        .expect("issuer constraints must append");
    builder
        .append_extension(
            OpenSslKeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .expect("issuer key usage must build"),
        )
        .expect("issuer key usage must append");
    let subject_key_identifier = {
        let context = builder.x509v3_context(None, None);
        SubjectKeyIdentifier::new()
            .build(&context)
            .expect("issuer SKI must build")
    };
    builder
        .append_extension(subject_key_identifier)
        .expect("issuer SKI must append");
    builder
        .sign(&key, MessageDigest::sha256())
        .expect("issuer certificate must sign");
    (builder.build(), key)
}

fn issued_tlso_certificate(
    issuer: &X509,
    issuer_key: &PKey<Private>,
) -> envelopes_x509::X509Certificate {
    let key = PKey::from_rsa(Rsa::generate(3_072).expect("TLSO key generation must succeed"))
        .expect("TLSO key conversion must succeed");
    let mut subject = X509NameBuilder::new().expect("TLSO subject builder must initialize");
    subject
        .append_entry_by_nid(Nid::COUNTRYNAME, "MT")
        .expect("TLSO country must encode");
    subject
        .append_entry_by_nid(Nid::ORGANIZATIONNAME, "Test Scheme Operator")
        .expect("TLSO organization must encode");
    subject
        .append_entry_by_nid(Nid::COMMONNAME, "Issued TLSO Signer")
        .expect("TLSO common name must encode");
    let subject = subject.build();

    let mut builder = X509Builder::new().expect("TLSO certificate builder must initialize");
    builder.set_version(2).expect("TLSO version must encode");
    let serial = BigNum::from_u32(11)
        .expect("TLSO serial must encode")
        .to_asn1_integer()
        .expect("TLSO serial conversion must succeed");
    builder
        .set_serial_number(&serial)
        .expect("TLSO serial must be accepted");
    builder
        .set_subject_name(&subject)
        .expect("TLSO subject must be accepted");
    builder
        .set_issuer_name(issuer.subject_name())
        .expect("TLSO issuer must be accepted");
    builder
        .set_pubkey(&key)
        .expect("TLSO public key must be accepted");
    builder
        .set_not_before(&Asn1Time::from_unix(1_767_225_600).expect("valid not-before"))
        .expect("TLSO not-before must be accepted");
    builder
        .set_not_after(&Asn1Time::from_unix(1_893_456_000).expect("valid not-after"))
        .expect("TLSO not-after must be accepted");
    builder
        .append_extension(
            OpenSslBasicConstraints::new()
                .critical()
                .build()
                .expect("TLSO constraints must build"),
        )
        .expect("TLSO constraints must append");
    builder
        .append_extension(
            OpenSslKeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .expect("TLSO key usage must build"),
        )
        .expect("TLSO key usage must append");
    let subject_key_identifier = {
        let context = builder.x509v3_context(Some(issuer), None);
        SubjectKeyIdentifier::new()
            .build(&context)
            .expect("TLSO SKI must build")
    };
    builder
        .append_extension(subject_key_identifier)
        .expect("TLSO SKI must append");
    let authority_key_identifier = {
        let context = builder.x509v3_context(Some(issuer), None);
        AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&context)
            .expect("TLSO AKI must build")
    };
    builder
        .append_extension(authority_key_identifier)
        .expect("TLSO AKI must append");
    builder
        .append_extension(
            ExtendedKeyUsage::new()
                .other(crate::TSL_SIGNING_EXTENDED_KEY_USAGE_OID)
                .build()
                .expect("TLSO EKU must build"),
        )
        .expect("TLSO EKU must append");
    builder
        .sign(issuer_key, MessageDigest::sha256())
        .expect("TLSO certificate must sign");

    envelopes_x509::parse_cert_der(
        &builder
            .build()
            .to_der()
            .expect("TLSO certificate DER must encode"),
    )
    .expect("TLSO certificate must parse")
}

fn list_with_issuing_service(issuer: &X509) -> identity_trust_tsl_core::TrustedList {
    let issuer_der = issuer.to_der().expect("issuer DER must encode");
    let issuer_base64 = openssl::base64::encode_block(&issuer_der);
    let service = format!(
        "<TrustServiceProviderList><TrustServiceProvider><TSPInformation><TSPName><Name xml:lang=\"en\">Listed TSP</Name></TSPName><TSPTradeName><Name xml:lang=\"en\">NTRMT-C12345</Name></TSPTradeName><TSPAddress><PostalAddresses><PostalAddress xml:lang=\"en\"><StreetAddress>Provider Street 1</StreetAddress><Locality>Provider City</Locality><PostalCode>1000</PostalCode><CountryName>MT</CountryName></PostalAddress></PostalAddresses><ElectronicAddress><URI xml:lang=\"en\">mailto:provider@example.test</URI><URI xml:lang=\"en\">https://example.test/provider</URI></ElectronicAddress></TSPAddress><TSPInformationURI><URI xml:lang=\"en\">https://example.test/provider/information</URI></TSPInformationURI></TSPInformation><TSPServices><TSPService><ServiceInformation><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceName><Name xml:lang=\"en\">Listed Issuing Service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>{issuer_base64}</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2026-01-01T00:00:00Z</StatusStartingTime></ServiceInformation></TSPService></TSPServices></TrustServiceProvider></TrustServiceProviderList>"
    );
    let xml = include_str!("../tests/fixtures/signed_tsl.xml").replacen(
        "  <ds:Signature Id=",
        &format!("  {service}\n  <ds:Signature Id="),
        1,
    );
    identity_trust_tsl_core::parse_tsl_xml(&xml).expect("issuer-list fixture must parse")
}
