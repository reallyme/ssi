// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
//! Test coverage for this crate.

use time::OffsetDateTime;

use reallyme_codec::base64::base64_to_bytes;
use reallyme_trust_x509::{
    model::{
        AuthorityAccessDescription, AuthorityAccessMethod, BasicConstraints, CertificateExtension,
        CertificateExtensionKind, CertificatePolicyId, DistinguishedName, ExtendedKeyUsagePurpose,
        KeyUsage, NameAttribute, NameAttributeKind, NameAttributeValue, ObjectIdentifier,
        OtherName, PublicKeyProfile, QcStatementId, QcStatements, QcType,
        RelativeDistinguishedName, RsaPssHashAlgorithm, RsaPssMaskGenerationAlgorithm,
        RsaPssParameters, SignatureAlgorithm, X509Certificate, X509Chain,
    },
    parse_cert_der,
    presets::{
        eu_policy, eudi_policy, EuPreset, EudiCertificateProfile, OID_EKU_SERVER_AUTH, OID_QCP_L,
        OID_QEVCP_W,
    },
    qcstatements::{OID_ETSI_QCS_QC_COMPLIANCE, OID_ETSI_QCS_QC_TYPE, OID_ETSI_QCT_WEB},
    screen_chain_policy_only_no_path_validation, AuthorityInformationAccessRequirement,
    LeafKeyIdentifierRequirement, QscdStatementRequirement, RevocationPointerRequirement,
    X509Error, X509Policy, X509PolicyFailure, X509ResourceLimit, MAX_X509_CHAIN_CERTIFICATES,
};

fn mk_leaf() -> X509Certificate {
    let mut profile = reallyme_trust_x509::CertificateProfile::default();
    profile.public_key = PublicKeyProfile::Rsa { bits: 2048 };
    profile.rsa_public_exponent = Some(vec![0x01, 0x00, 0x01]);
    profile.signature_algorithm = SignatureAlgorithm::RsaPkcs1Sha256;
    profile.extended_key_usage = vec![ExtendedKeyUsagePurpose::ServerAuthentication];
    profile.certificate_policies = vec![CertificatePolicyId::QevcpWeb];
    profile.qc_statement_ids = vec![QcStatementId::Compliance, QcStatementId::Type];
    profile.qc_types = vec![QcType::WebAuthentication];
    X509Certificate {
        der: vec![],
        subject: "CN=leaf".into(),
        issuer: "CN=iss".into(),
        subject_der: b"CN=leaf".to_vec(),
        issuer_der: b"CN=iss".to_vec(),
        serial: vec![1],
        not_before: OffsetDateTime::UNIX_EPOCH,
        not_after: OffsetDateTime::UNIX_EPOCH + time::Duration::days(3650),
        spki_der: vec![],
        signature_algorithm_oid: "1.2.3".into(),
        basic_constraints: Some(BasicConstraints {
            ca: false,
            path_len_constraint: None,
        }),
        key_usage: Some(KeyUsage {
            digital_signature: true,
            content_commitment: false,
            key_cert_sign: false,
            crl_sign: false,
            key_encipherment: false,
            data_encipherment: false,
            key_agreement: false,
            encipher_only: false,
            decipher_only: false,
        }),
        extended_key_usage: Some(vec![OID_EKU_SERVER_AUTH.to_string()]),
        subject_key_identifier: None,
        authority_key_identifier: None,
        san_dns: vec!["example.test".into()],
        san_ip: vec![],

        certificate_policies: vec![OID_QEVCP_W.to_string()],
        qc_statements: QcStatements {
            statement_ids: vec![
                OID_ETSI_QCS_QC_COMPLIANCE.to_string(),
                OID_ETSI_QCS_QC_TYPE.to_string(),
            ],
            qc_types: vec![OID_ETSI_QCT_WEB.to_string()],
        },
        profile,
    }
}

fn name(attributes: &[(NameAttributeKind, &str)]) -> DistinguishedName {
    DistinguishedName {
        rdns: attributes
            .iter()
            .map(|(kind, value)| RelativeDistinguishedName {
                attributes: vec![NameAttribute {
                    kind: kind.clone(),
                    value: NameAttributeValue::Text((*value).to_owned()),
                }],
            })
            .collect(),
    }
}

fn natural_person_name() -> DistinguishedName {
    name(&[
        (NameAttributeKind::CountryName, "MT"),
        (NameAttributeKind::GivenName, "A"),
        (NameAttributeKind::Surname, "B"),
        (NameAttributeKind::CommonName, "A B"),
    ])
}

fn legal_person_name() -> DistinguishedName {
    name(&[
        (NameAttributeKind::CountryName, "MT"),
        (NameAttributeKind::OrganizationName, "Example"),
        (NameAttributeKind::OrganizationIdentifier, "VATMT-1"),
        (NameAttributeKind::CommonName, "Example"),
    ])
}

fn issuing_authority_name() -> DistinguishedName {
    name(&[
        (NameAttributeKind::CountryName, "MT"),
        (NameAttributeKind::OrganizationName, "Issuer"),
        (NameAttributeKind::CommonName, "Issuer CA"),
    ])
}

fn extension(kind: CertificateExtensionKind, critical: bool) -> CertificateExtension {
    CertificateExtension { kind, critical }
}

fn pid_or_wallet_leaf(qc_type: QcType) -> X509Certificate {
    let mut leaf = mk_leaf();
    leaf.profile.subject = natural_person_name();
    leaf.profile.issuer = issuing_authority_name();
    leaf.profile.extensions = vec![
        extension(CertificateExtensionKind::KeyUsage, true),
        extension(CertificateExtensionKind::SubjectKeyIdentifier, false),
        extension(CertificateExtensionKind::AuthorityKeyIdentifier, false),
        extension(CertificateExtensionKind::CertificatePolicies, false),
        extension(CertificateExtensionKind::QcStatements, false),
        extension(CertificateExtensionKind::AuthorityInformationAccess, false),
    ];
    leaf.profile.qc_statement_ids = vec![QcStatementId::Type];
    leaf.profile.qc_types = vec![qc_type];
    leaf.profile
        .authority_information_access
        .push(AuthorityAccessDescription {
            method: AuthorityAccessMethod::CaIssuers,
            uri: "https://issuer.example/ca.der".to_owned(),
        });
    leaf.subject_key_identifier = Some(vec![1]);
    leaf.authority_key_identifier = Some(vec![2]);
    leaf
}

fn wrpac_leaf(policy: CertificatePolicyId) -> X509Certificate {
    let mut leaf = mk_leaf();
    leaf.key_usage.as_mut().unwrap().content_commitment = true;
    leaf.profile.subject = match policy {
        CertificatePolicyId::WrpacNcpNatural | CertificatePolicyId::WrpacQcpNatural => {
            natural_person_name()
        }
        _ => legal_person_name(),
    };
    leaf.profile.issuer = issuing_authority_name();
    leaf.profile.extensions = vec![
        extension(CertificateExtensionKind::KeyUsage, true),
        extension(CertificateExtensionKind::AuthorityKeyIdentifier, false),
        extension(CertificateExtensionKind::CertificatePolicies, false),
        extension(CertificateExtensionKind::SubjectAlternativeName, false),
        extension(CertificateExtensionKind::AuthorityInformationAccess, false),
        extension(CertificateExtensionKind::CrlDistributionPoints, false),
    ];
    leaf.profile.certificate_policies = vec![policy.clone()];
    leaf.profile.certificate_policy_cps_uris = vec!["https://issuer.example/cps".to_owned()];
    leaf.profile.subject_alternative_names.uris =
        vec!["https://relying-party.example/contact".to_owned()];
    leaf.profile
        .authority_information_access
        .push(AuthorityAccessDescription {
            method: AuthorityAccessMethod::CaIssuers,
            uri: "https://issuer.example/ca.der".to_owned(),
        });
    leaf.profile.crl_distribution_point_uris = vec!["https://issuer.example/issuer.crl".to_owned()];
    leaf.authority_key_identifier = Some(vec![2]);
    if matches!(
        policy,
        CertificatePolicyId::WrpacQcpNatural | CertificatePolicyId::WrpacQcpLegal
    ) {
        leaf.profile.qc_statement_ids = vec![QcStatementId::Compliance, QcStatementId::Type];
        leaf.profile.qc_types = vec![if policy == CertificatePolicyId::WrpacQcpNatural {
            QcType::ElectronicSignature
        } else {
            QcType::ElectronicSeal
        }];
    }
    leaf
}

fn provider_anchor() -> X509Certificate {
    let mut anchor = mk_intermediate();
    anchor.profile.certificate_policies = vec![CertificatePolicyId::Other(
        ObjectIdentifier::parse("1.3.6.1.4.1.55555.1").unwrap(),
    )];
    anchor
}

fn rsa_pss_parameters(
    hash_algorithm: RsaPssHashAlgorithm,
    mask_hash_algorithm: RsaPssHashAlgorithm,
) -> RsaPssParameters {
    RsaPssParameters {
        hash_algorithm,
        mask_generation_algorithm: RsaPssMaskGenerationAlgorithm::Mgf1(mask_hash_algorithm),
        salt_length: 32,
        trailer_field: 1,
    }
}

fn mk_intermediate() -> X509Certificate {
    let mut profile = reallyme_trust_x509::CertificateProfile::default();
    profile.public_key = PublicKeyProfile::Rsa { bits: 2048 };
    profile.rsa_public_exponent = Some(vec![0x01, 0x00, 0x01]);
    X509Certificate {
        der: vec![],
        subject: "CN=iss".into(),
        issuer: "CN=root".into(),
        subject_der: b"CN=iss".to_vec(),
        issuer_der: b"CN=root".to_vec(),
        serial: vec![2],
        not_before: OffsetDateTime::UNIX_EPOCH,
        not_after: OffsetDateTime::UNIX_EPOCH + time::Duration::days(3650),
        spki_der: vec![],
        signature_algorithm_oid: "1.2.3".into(),

        basic_constraints: Some(BasicConstraints {
            ca: true,
            path_len_constraint: Some(0),
        }),
        key_usage: Some(KeyUsage {
            digital_signature: false,
            content_commitment: false,
            key_cert_sign: true,
            crl_sign: true,
            key_encipherment: false,
            data_encipherment: false,
            key_agreement: false,
            encipher_only: false,
            decipher_only: false,
        }),
        extended_key_usage: None,

        subject_key_identifier: None,
        authority_key_identifier: None,
        san_dns: vec![],
        san_ip: vec![],

        certificate_policies: vec![],
        qc_statements: QcStatements::default(),
        profile,
    }
}

#[test]
fn qwac_policy_accepts_valid_shape() {
    let chain = X509Chain {
        certs: vec![mk_leaf(), mk_intermediate()],
    };
    let pol = eu_policy(EuPreset::Qwac);
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);

    screen_chain_policy_only_no_path_validation(&chain, now, &pol).unwrap();
}

#[test]
fn policy_rejects_certificate_chain_over_limit() {
    let chain = X509Chain {
        certs: vec![mk_intermediate(); MAX_X509_CHAIN_CERTIFICATES + 1],
    };
    let pol = eu_policy(EuPreset::Qwac);
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);

    let err = screen_chain_policy_only_no_path_validation(&chain, now, &pol).unwrap_err();

    assert_eq!(
        err,
        X509Error::ResourceLimitExceeded(X509ResourceLimit::CertificateChainTooLong)
    );
}

#[test]
fn typed_conditional_profile_rules_enforce_key_ids_aia_and_qscd() {
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);
    let mut leaf = mk_leaf();
    let mut policy = X509Policy {
        leaf_key_identifier_requirement: LeafKeyIdentifierRequirement::SubjectAndAuthority,
        ..X509Policy::default()
    };

    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![leaf.clone()],
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::LeafKeyIdentifierRequirement
        ))
    );

    leaf.subject_key_identifier = Some(vec![1]);
    leaf.authority_key_identifier = Some(vec![2]);
    policy.leaf_key_identifier_requirement = LeafKeyIdentifierRequirement::None;
    policy.authority_information_access_requirement =
        AuthorityInformationAccessRequirement::OcspAndCaIssuers;
    leaf.profile
        .authority_information_access
        .push(AuthorityAccessDescription {
            method: AuthorityAccessMethod::Ocsp,
            uri: "https://status.example/ocsp".to_owned(),
        });
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![leaf.clone()],
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::LeafAuthorityInformationAccessRequirement
        ))
    );

    leaf.profile
        .authority_information_access
        .push(AuthorityAccessDescription {
            method: AuthorityAccessMethod::CaIssuers,
            uri: "https://issuer.example/ca.der".to_owned(),
        });
    policy.authority_information_access_requirement = AuthorityInformationAccessRequirement::None;
    policy.qscd_statement_requirement = QscdStatementRequirement::WhenQscdPolicy;
    leaf.profile.certificate_policies = vec![CertificatePolicyId::QcpLegalPersonQscd];
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![leaf.clone()],
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::LeafMissingQscdStatement
        ))
    );

    leaf.profile.qc_statement_ids.push(QcStatementId::QcSscd);
    assert_eq!(
        screen_chain_policy_only_no_path_validation(&X509Chain { certs: vec![leaf] }, now, &policy,),
        Ok(())
    );
}

#[test]
fn ca_issuers_aia_alone_does_not_satisfy_revocation_pointer_policy() {
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);
    let mut leaf = mk_leaf();
    leaf.profile
        .authority_information_access
        .push(AuthorityAccessDescription {
            method: AuthorityAccessMethod::CaIssuers,
            uri: "https://issuer.example/ca.der".to_owned(),
        });
    let policy = X509Policy {
        revocation_pointer_requirement: RevocationPointerRequirement::OcspOrCrl,
        ..X509Policy::default()
    };

    assert_eq!(
        screen_chain_policy_only_no_path_validation(&X509Chain { certs: vec![leaf] }, now, &policy,),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::RevocationPointerMissing
        ))
    );
}

#[test]
fn qwac_policy_rejects_real_der_without_required_dns_or_ip_name() {
    let der =
        base64_to_bytes(include_str!("fixtures/qwac_server_auth_cert.der.b64").trim()).unwrap();
    let leaf = parse_cert_der(&der).unwrap();

    assert!(leaf
        .extended_key_usage
        .as_ref()
        .unwrap()
        .contains(&OID_EKU_SERVER_AUTH.to_string()));

    let now = leaf.not_before + time::Duration::days(1);
    let chain = X509Chain { certs: vec![leaf] };
    let pol = eu_policy(EuPreset::Qwac);

    assert_eq!(
        screen_chain_policy_only_no_path_validation(&chain, now, &pol).unwrap_err(),
        X509Error::PolicyFailed(X509PolicyFailure::LeafNameRequirement)
    );
}

#[test]
fn qwac_policy_rejects_missing_qctype() {
    let mut leaf = mk_leaf();
    leaf.qc_statements.qc_types.clear();
    leaf.profile.qc_types.clear();

    let chain = X509Chain {
        certs: vec![leaf, mk_intermediate()],
    };
    let pol = eu_policy(EuPreset::Qwac);
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);

    assert!(screen_chain_policy_only_no_path_validation(&chain, now, &pol).is_err());
}

#[test]
fn qwac_policy_rejects_wrong_qctype() {
    let mut leaf = mk_leaf();
    leaf.qc_statements.qc_types = vec![reallyme_trust_x509::OID_ETSI_QCT_ESIGN.to_string()];
    leaf.profile.qc_types = vec![QcType::ElectronicSignature];

    let chain = X509Chain {
        certs: vec![leaf, mk_intermediate()],
    };
    let pol = eu_policy(EuPreset::Qwac);
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);

    let err = screen_chain_policy_only_no_path_validation(&chain, now, &pol).unwrap_err();

    assert_eq!(
        err,
        X509Error::PolicyFailed(X509PolicyFailure::LeafQcTypeMismatch)
    );
}

#[test]
fn qwac_policy_rejects_missing_qc_compliance_statement() {
    let mut leaf = mk_leaf();
    leaf.qc_statements
        .statement_ids
        .retain(|id| id != OID_ETSI_QCS_QC_COMPLIANCE);
    leaf.profile
        .qc_statement_ids
        .retain(|id| id != &QcStatementId::Compliance);

    let chain = X509Chain {
        certs: vec![leaf, mk_intermediate()],
    };
    let pol = eu_policy(EuPreset::Qwac);
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);

    let err = screen_chain_policy_only_no_path_validation(&chain, now, &pol).unwrap_err();

    assert_eq!(
        err,
        X509Error::PolicyFailed(X509PolicyFailure::LeafMissingRequiredQcStatement)
    );
}

#[test]
fn qwac_policy_rejects_wrong_certificate_policy_oid() {
    let mut leaf = mk_leaf();
    leaf.certificate_policies = vec![OID_QCP_L.to_string()];
    leaf.profile.certificate_policies = vec![CertificatePolicyId::QcpLegalPerson];

    let chain = X509Chain {
        certs: vec![leaf, mk_intermediate()],
    };
    let pol = eu_policy(EuPreset::Qwac);
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);

    let err = screen_chain_policy_only_no_path_validation(&chain, now, &pol).unwrap_err();

    assert_eq!(
        err,
        X509Error::PolicyFailed(X509PolicyFailure::LeafCertificatePolicyMismatch)
    );
}

#[test]
fn pid_and_wallet_presets_accept_both_subject_profiles_and_exact_qc_types() {
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);
    let pid_policy = eudi_policy(EudiCertificateProfile::PidProviderSignerV1);
    let pid_leaf = pid_or_wallet_leaf(QcType::PidProvider);
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![pid_leaf]
            },
            now,
            &pid_policy,
        ),
        Ok(())
    );

    let wallet_policy = eudi_policy(EudiCertificateProfile::WalletProviderSignerV1);
    let mut wallet_leaf = pid_or_wallet_leaf(QcType::WalletProvider);
    wallet_leaf.profile.subject = legal_person_name();
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![wallet_leaf]
            },
            now,
            &wallet_policy,
        ),
        Ok(())
    );
}

#[test]
fn pid_preset_rejects_wrong_qc_type_key_usage_and_extension_criticality() {
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);
    let policy = eudi_policy(EudiCertificateProfile::PidProviderSignerV1);

    let wrong_qc_type = pid_or_wallet_leaf(QcType::WalletProvider);
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![wrong_qc_type]
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::LeafQcTypeMismatch
        ))
    );

    let mut invalid_key_usage = pid_or_wallet_leaf(QcType::PidProvider);
    invalid_key_usage.key_usage.as_mut().unwrap().key_cert_sign = true;
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![invalid_key_usage]
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::LeafKeyUsageProfile
        ))
    );

    let mut critical_ski = pid_or_wallet_leaf(QcType::PidProvider);
    critical_ski
        .profile
        .extensions
        .iter_mut()
        .find(|extension| extension.kind == CertificateExtensionKind::SubjectKeyIdentifier)
        .unwrap()
        .critical = true;
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![critical_ski]
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::ExtensionCriticality
        ))
    );
}

#[test]
fn eudi_presets_reject_unapproved_rsa_exponents_and_private_ec_curves() {
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);
    let policy = eudi_policy(EudiCertificateProfile::PidProviderSignerV1);

    let mut weak_exponent = pid_or_wallet_leaf(QcType::PidProvider);
    weak_exponent.profile.rsa_public_exponent = Some(vec![0x03]);
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![weak_exponent]
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::AlgorithmParametersNotAllowed
        ))
    );

    let mut private_curve = pid_or_wallet_leaf(QcType::PidProvider);
    private_curve.profile.public_key = PublicKeyProfile::Ec {
        bits: 256,
        curve: Some(ObjectIdentifier::parse("1.3.6.1.4.1.55555.9").unwrap()),
    };
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![private_curve]
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::AlgorithmParametersNotAllowed
        ))
    );
}

#[test]
fn eudi_presets_enforce_rsa_pss_parameter_suites() {
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);
    let policy = eudi_policy(EudiCertificateProfile::PidProviderSignerV1);

    let mut allowed = pid_or_wallet_leaf(QcType::PidProvider);
    allowed.profile.signature_algorithm = SignatureAlgorithm::RsaPss;
    allowed.profile.rsa_pss_parameters = Some(rsa_pss_parameters(
        RsaPssHashAlgorithm::Sha256,
        RsaPssHashAlgorithm::Sha512,
    ));
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![allowed]
            },
            now,
            &policy,
        ),
        Ok(())
    );

    for invalid_parameters in [
        None,
        Some(rsa_pss_parameters(
            RsaPssHashAlgorithm::Sha1,
            RsaPssHashAlgorithm::Sha1,
        )),
        Some(rsa_pss_parameters(
            RsaPssHashAlgorithm::Sha256,
            RsaPssHashAlgorithm::Sha3_256,
        )),
        Some(RsaPssParameters {
            hash_algorithm: RsaPssHashAlgorithm::Sha256,
            mask_generation_algorithm: RsaPssMaskGenerationAlgorithm::Mgf1(
                RsaPssHashAlgorithm::Sha256,
            ),
            salt_length: 32,
            trailer_field: 2,
        }),
    ] {
        let mut rejected = pid_or_wallet_leaf(QcType::PidProvider);
        rejected.profile.signature_algorithm = SignatureAlgorithm::RsaPss;
        rejected.profile.rsa_pss_parameters = invalid_parameters;
        assert_eq!(
            screen_chain_policy_only_no_path_validation(
                &X509Chain {
                    certs: vec![rejected]
                },
                now,
                &policy,
            ),
            Err(X509Error::PolicyFailed(
                X509PolicyFailure::AlgorithmParametersNotAllowed
            ))
        );
    }
}

#[test]
fn pid_preset_accepts_self_issued_subject_but_requires_aia_for_ca_issuance() {
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);
    let policy = eudi_policy(EudiCertificateProfile::PidProviderSignerV1);

    let mut self_issued = pid_or_wallet_leaf(QcType::PidProvider);
    self_issued.profile.issuer = self_issued.profile.subject.clone();
    self_issued.profile.authority_information_access.clear();
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![self_issued]
            },
            now,
            &policy,
        ),
        Ok(())
    );

    let mut ca_issued = pid_or_wallet_leaf(QcType::PidProvider);
    ca_issued.profile.authority_information_access.clear();
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![ca_issued]
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::LeafAuthorityInformationAccessRequirement
        ))
    );
}

#[test]
fn wrpac_preset_binds_natural_and_legal_policy_families_to_subject_and_qc() {
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);
    let policy = eudi_policy(EudiCertificateProfile::WrpacLeafV1);
    for certificate_policy in [
        CertificatePolicyId::WrpacNcpNatural,
        CertificatePolicyId::WrpacNcpLegal,
        CertificatePolicyId::WrpacQcpNatural,
        CertificatePolicyId::WrpacQcpLegal,
    ] {
        assert_eq!(
            screen_chain_policy_only_no_path_validation(
                &X509Chain {
                    certs: vec![wrpac_leaf(certificate_policy), provider_anchor()]
                },
                now,
                &policy,
            ),
            Ok(())
        );
    }
}

#[test]
fn wrpac_preset_rejects_ambiguous_policy_subject_qc_and_no_rev_avail() {
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);
    let policy = eudi_policy(EudiCertificateProfile::WrpacLeafV1);

    let mut ambiguous = wrpac_leaf(CertificatePolicyId::WrpacNcpNatural);
    ambiguous
        .profile
        .certificate_policies
        .push(CertificatePolicyId::WrpacNcpLegal);
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![ambiguous, provider_anchor()]
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::WrpacPolicyAmbiguous
        ))
    );

    let mut wrong_subject = wrpac_leaf(CertificatePolicyId::WrpacNcpNatural);
    wrong_subject.profile.subject = legal_person_name();
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![wrong_subject, provider_anchor()]
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::LeafSubjectNameProfile
        ))
    );

    let mut wrong_qc = wrpac_leaf(CertificatePolicyId::WrpacQcpLegal);
    wrong_qc.profile.qc_types = vec![QcType::ElectronicSignature];
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![wrong_qc, provider_anchor()]
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::WrpacQcStatements
        ))
    );

    let mut no_rev_avail = wrpac_leaf(CertificatePolicyId::WrpacNcpLegal);
    no_rev_avail.profile.no_rev_avail = true;
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![no_rev_avail, provider_anchor()]
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::LeafForbiddenNoRevAvail
        ))
    );
}

include!("policy_eval/anchor_tests.rs");
include!("policy_eval/algorithm_tests.rs");
