// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use envelopes_x509::{NameAttributeKind, X509Certificate};
use identity_trust_tsl_core::{
    QualificationAssertion, QualificationCriteria, QualificationCriterion,
    QualificationKeyUsageBit, ServiceQualification, ServiceQualifier, TslObjectIdentifier,
};

/// Return the qualifiers whose complete certificate criteria match.
///
/// ETSI TS 119 612 v2.4.1 clauses 5.5.9.2 and 5.5.9.2.2 require every
/// qualification element to be evaluated independently and all qualifiers of
/// each matching element to apply. The parser bounds both recursion and item
/// counts before this iterator can be constructed.
pub fn matching_service_qualifiers<'a>(
    certificate: &'a X509Certificate,
    qualifications: &'a [ServiceQualification],
) -> impl Iterator<Item = &'a ServiceQualifier> + 'a {
    qualifications
        .iter()
        .filter(move |qualification| {
            qualification_criteria_matches(certificate, &qualification.criteria)
        })
        .flat_map(|qualification| qualification.qualifiers.iter())
}

/// Evaluate one recursively composed TS 119 612 `CriteriaList`.
pub fn qualification_criteria_matches(
    certificate: &X509Certificate,
    criteria: &QualificationCriteria,
) -> bool {
    let mut results = criteria
        .criteria
        .iter()
        .map(|criterion| criterion_matches(certificate, criterion));

    match criteria.assertion {
        QualificationAssertion::All => results.all(|matched| matched),
        QualificationAssertion::AtLeastOne => results.any(|matched| matched),
        QualificationAssertion::None => results.all(|matched| !matched),
    }
}

fn criterion_matches(certificate: &X509Certificate, criterion: &QualificationCriterion) -> bool {
    match criterion {
        // TS 119 612 clause 5.5.9.2.2.1: the extension must exist and every
        // asserted bit value must match, including explicitly asserted false.
        QualificationCriterion::KeyUsage(assertions) => {
            certificate.key_usage.as_ref().is_some_and(|usage| {
                assertions
                    .iter()
                    .all(|assertion| key_usage_bit(usage, assertion.bit) == assertion.expected)
            })
        }
        // TS 119 612 clause 5.5.9.2.2.2: every listed policy must occur.
        QualificationCriterion::CertificatePolicies(required) => {
            !certificate.certificate_policies.is_empty()
                && all_oids_present(required, &certificate.certificate_policies)
        }
        // TS 119 612 clause 5.5.9.2.2.3: every key purpose must occur.
        QualificationCriterion::ExtendedKeyUsage(required) => certificate
            .extended_key_usage
            .as_ref()
            .is_some_and(|present| all_oids_present(required, present)),
        // TS 119 612 clause 5.5.9.2.2.3: every named attribute type must be
        // present. Attribute values are deliberately irrelevant to this test.
        QualificationCriterion::SubjectDistinguishedNameAttributes(required) => required
            .iter()
            .all(|oid| subject_contains_attribute(certificate, oid)),
        QualificationCriterion::Nested(nested) => {
            qualification_criteria_matches(certificate, nested)
        }
    }
}

fn all_oids_present(required: &[TslObjectIdentifier], present: &[String]) -> bool {
    required
        .iter()
        .all(|required_oid| present.iter().any(|oid| oid == required_oid.as_str()))
}

fn subject_contains_attribute(
    certificate: &X509Certificate,
    required: &TslObjectIdentifier,
) -> bool {
    certificate
        .profile
        .subject
        .rdns
        .iter()
        .flat_map(|rdn| rdn.attributes.iter())
        .any(|attribute| name_attribute_oid(&attribute.kind) == required.as_str())
}

fn name_attribute_oid(kind: &NameAttributeKind) -> &str {
    match kind {
        NameAttributeKind::CommonName => "2.5.4.3",
        NameAttributeKind::CountryName => "2.5.4.6",
        NameAttributeKind::GivenName => "2.5.4.42",
        NameAttributeKind::Surname => "2.5.4.4",
        NameAttributeKind::Pseudonym => "2.5.4.65",
        NameAttributeKind::OrganizationName => "2.5.4.10",
        NameAttributeKind::OrganizationalUnitName => "2.5.4.11",
        NameAttributeKind::LocalityName => "2.5.4.7",
        NameAttributeKind::StateOrProvinceName => "2.5.4.8",
        NameAttributeKind::SerialNumber => "2.5.4.5",
        NameAttributeKind::StreetAddress => "2.5.4.9",
        NameAttributeKind::PostalCode => "2.5.4.17",
        NameAttributeKind::DomainComponent => "0.9.2342.19200300.100.1.25",
        NameAttributeKind::EmailAddress => "1.2.840.113549.1.9.1",
        NameAttributeKind::OrganizationIdentifier => "2.5.4.97",
        NameAttributeKind::TelephoneNumber => "2.5.4.20",
        NameAttributeKind::Other(oid) => oid.as_str(),
    }
}

fn key_usage_bit(usage: &envelopes_x509::KeyUsage, bit: QualificationKeyUsageBit) -> bool {
    match bit {
        QualificationKeyUsageBit::DigitalSignature => usage.digital_signature,
        QualificationKeyUsageBit::NonRepudiation => usage.content_commitment,
        QualificationKeyUsageBit::KeyEncipherment => usage.key_encipherment,
        QualificationKeyUsageBit::DataEncipherment => usage.data_encipherment,
        QualificationKeyUsageBit::KeyAgreement => usage.key_agreement,
        QualificationKeyUsageBit::KeyCertSign => usage.key_cert_sign,
        QualificationKeyUsageBit::CrlSign => usage.crl_sign,
        QualificationKeyUsageBit::EncipherOnly => usage.encipher_only,
        QualificationKeyUsageBit::DecipherOnly => usage.decipher_only,
    }
}

#[cfg(test)]
#[path = "qualification_tests.rs"]
mod tests;
