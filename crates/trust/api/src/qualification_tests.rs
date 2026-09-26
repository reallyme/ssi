// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use envelopes_x509::{
    CertificatePolicyId, CertificateProfile, DistinguishedName, KeyUsage, NameAttribute,
    NameAttributeKind, NameAttributeValue, RelativeDistinguishedName, X509Certificate,
};
use identity_trust_tsl_core::{
    QualificationAssertion, QualificationCriteria, QualificationCriterion, QualificationKeyUsage,
    QualificationKeyUsageBit, ServiceQualification, ServiceQualifier, ServiceQualifierKind,
    TslObjectIdentifier,
};
use time::OffsetDateTime;

use super::{matching_service_qualifiers, qualification_criteria_matches};

#[test]
fn evaluates_all_supported_certificate_criteria() {
    let certificate = certificate();
    let criteria = QualificationCriteria {
        assertion: QualificationAssertion::All,
        criteria: vec![
            QualificationCriterion::KeyUsage(vec![QualificationKeyUsage {
                bit: QualificationKeyUsageBit::DigitalSignature,
                expected: true,
            }]),
            QualificationCriterion::CertificatePolicies(vec![oid("1.2.3.4")]),
            QualificationCriterion::ExtendedKeyUsage(vec![oid("1.3.6.1.5.5.7.3.3")]),
            QualificationCriterion::SubjectDistinguishedNameAttributes(vec![oid("2.5.4.10")]),
        ],
        description: None,
    };

    assert!(qualification_criteria_matches(&certificate, &criteria));
}

#[test]
fn evaluates_nested_assertion_modes_without_weakening_missing_extensions() {
    let certificate = certificate();
    let missing_policy = QualificationCriterion::CertificatePolicies(vec![oid("1.2.3.999")]);
    let matching_usage = QualificationCriterion::KeyUsage(vec![QualificationKeyUsage {
        bit: QualificationKeyUsageBit::DigitalSignature,
        expected: true,
    }]);

    let at_least_one = QualificationCriteria {
        assertion: QualificationAssertion::AtLeastOne,
        criteria: vec![missing_policy.clone(), matching_usage.clone()],
        description: None,
    };
    let none = QualificationCriteria {
        assertion: QualificationAssertion::None,
        criteria: vec![missing_policy],
        description: None,
    };
    let nested = QualificationCriteria {
        assertion: QualificationAssertion::All,
        criteria: vec![QualificationCriterion::Nested(at_least_one), matching_usage],
        description: None,
    };

    assert!(qualification_criteria_matches(&certificate, &none));
    assert!(qualification_criteria_matches(&certificate, &nested));
}

#[test]
fn returns_qualifiers_only_from_matching_elements() {
    let certificate = certificate();
    let qualifications = vec![
        qualification(
            "1.2.3.4",
            ServiceQualifierKind::QualifiedCertificateWithQscd,
        ),
        qualification("1.2.3.5", ServiceQualifierKind::NotQualified),
    ];

    let applied = matching_service_qualifiers(&certificate, &qualifications).collect::<Vec<_>>();

    assert_eq!(applied.len(), 1);
    assert_eq!(
        applied[0].kind,
        ServiceQualifierKind::QualifiedCertificateWithQscd
    );
}

fn qualification(policy: &str, kind: ServiceQualifierKind) -> ServiceQualification {
    ServiceQualification {
        qualifiers: vec![ServiceQualifier { kind }],
        criteria: QualificationCriteria {
            assertion: QualificationAssertion::All,
            criteria: vec![QualificationCriterion::CertificatePolicies(vec![oid(
                policy,
            )])],
            description: None,
        },
    }
}

fn oid(value: &str) -> TslObjectIdentifier {
    TslObjectIdentifier::parse(value).expect("test OID must be valid")
}

fn certificate() -> X509Certificate {
    let mut profile = CertificateProfile::default();
    profile.subject = DistinguishedName {
        rdns: vec![RelativeDistinguishedName {
            attributes: vec![NameAttribute {
                kind: NameAttributeKind::OrganizationName,
                value: NameAttributeValue::Text("Example".to_owned()),
            }],
        }],
    };
    profile.certificate_policies = vec![CertificatePolicyId::QcpLegalPerson];

    X509Certificate {
        der: Vec::new(),
        subject: "O=Example".to_owned(),
        issuer: "O=Example".to_owned(),
        subject_der: b"O=Example".to_vec(),
        issuer_der: b"O=Example".to_vec(),
        serial: vec![1],
        not_before: OffsetDateTime::UNIX_EPOCH,
        not_after: OffsetDateTime::UNIX_EPOCH,
        spki_der: Vec::new(),
        signature_algorithm_oid: "1.2.840.113549.1.1.11".to_owned(),
        basic_constraints: None,
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
        extended_key_usage: Some(vec!["1.3.6.1.5.5.7.3.3".to_owned()]),
        subject_key_identifier: None,
        authority_key_identifier: None,
        san_dns: Vec::new(),
        san_ip: Vec::new(),
        certificate_policies: vec!["1.2.3.4".to_owned()],
        qc_statements: Default::default(),
        profile,
    }
}
