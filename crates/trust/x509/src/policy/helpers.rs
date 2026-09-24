// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn absolute_uri_syntax(value: &str) -> bool {
    let Some((scheme, remainder)) = value.split_once(':') else {
        return false;
    };
    !scheme.is_empty()
        && scheme.bytes().enumerate().all(|(index, byte)| match index {
            0 => byte.is_ascii_alphabetic(),
            _ => byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'),
        })
        && !remainder.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii() && !byte.is_ascii_whitespace())
}

fn telephone_other_name_is_valid(other_name: &crate::OtherName) -> bool {
    const OID_TELEPHONE_NUMBER: &str = "2.5.4.20";
    const MAX_TELEPHONE_NUMBER_CHARACTERS: usize = 32;

    if other_name.type_id.as_str() != OID_TELEPHONE_NUMBER {
        return false;
    }
    let Ok((outer_remaining, explicit_value)) = Any::from_der(&other_name.value_der) else {
        return false;
    };
    if !outer_remaining.is_empty()
        || explicit_value.class() != Class::ContextSpecific
        || explicit_value.tag() != Tag(0)
        || !explicit_value.header.is_constructed()
    {
        return false;
    }
    let Ok((inner_remaining, telephone_number)) =
        PrintableString::from_der(explicit_value.data)
    else {
        return false;
    };
    let value = telephone_number.as_ref();
    inner_remaining.is_empty()
        && !value.is_empty()
        && value.len() <= MAX_TELEPHONE_NUMBER_CHARACTERS
}

fn public_key_meets_minimums(certificate: &crate::X509Certificate, policy: &X509Policy) -> bool {
    match &certificate.profile.public_key {
        PublicKeyProfile::Rsa { bits } => policy
            .minimum_rsa_bits
            .is_none_or(|minimum| *bits >= minimum),
        PublicKeyProfile::Ec { bits, .. } => policy
            .minimum_ec_bits
            .is_none_or(|minimum| *bits >= minimum),
        _ => true,
    }
}

fn known_extension_matches(
    actual: &CertificateExtensionKind,
    required: KnownCertificateExtension,
) -> bool {
    matches!(
        (actual, required),
        (
            CertificateExtensionKind::BasicConstraints,
            KnownCertificateExtension::BasicConstraints
        ) | (
            CertificateExtensionKind::KeyUsage,
            KnownCertificateExtension::KeyUsage
        ) | (
            CertificateExtensionKind::ExtendedKeyUsage,
            KnownCertificateExtension::ExtendedKeyUsage
        ) | (
            CertificateExtensionKind::SubjectKeyIdentifier,
            KnownCertificateExtension::SubjectKeyIdentifier
        ) | (
            CertificateExtensionKind::AuthorityKeyIdentifier,
            KnownCertificateExtension::AuthorityKeyIdentifier
        ) | (
            CertificateExtensionKind::SubjectAlternativeName,
            KnownCertificateExtension::SubjectAlternativeName
        ) | (
            CertificateExtensionKind::CertificatePolicies,
            KnownCertificateExtension::CertificatePolicies
        ) | (
            CertificateExtensionKind::AuthorityInformationAccess,
            KnownCertificateExtension::AuthorityInformationAccess
        ) | (
            CertificateExtensionKind::CrlDistributionPoints,
            KnownCertificateExtension::CrlDistributionPoints
        ) | (
            CertificateExtensionKind::QcStatements,
            KnownCertificateExtension::QcStatements
        ) | (
            CertificateExtensionKind::NoRevAvail,
            KnownCertificateExtension::NoRevAvail
        )
    )
}

fn leaf_key_usage_matches(
    key_usage: Option<&KeyUsage>,
    requirement: LeafKeyUsageRequirement,
) -> bool {
    if requirement == LeafKeyUsageRequirement::None {
        return true;
    }
    let Some(key_usage) = key_usage else {
        return false;
    };
    if key_usage.key_cert_sign
        || key_usage.crl_sign
        || key_usage.data_encipherment
        || key_usage.encipher_only
        || key_usage.decipher_only
    {
        return false;
    }
    let no_key_transport = !key_usage.key_encipherment && !key_usage.key_agreement;
    let one_key_transport = key_usage.key_encipherment != key_usage.key_agreement;
    let type_a = key_usage.content_commitment && !key_usage.digital_signature && no_key_transport;
    let type_b = key_usage.content_commitment && key_usage.digital_signature && no_key_transport;
    let type_c = !key_usage.content_commitment && key_usage.digital_signature && no_key_transport;
    let type_f = key_usage.content_commitment && key_usage.digital_signature && one_key_transport;
    match requirement {
        LeafKeyUsageRequirement::None => true,
        LeafKeyUsageRequirement::PidOrWalletTypeAbcf => type_a || type_b || type_c || type_f,
        LeafKeyUsageRequirement::WrpacTypeAbf => type_a || type_b || type_f,
    }
}

fn distinguished_name_matches(
    name: &DistinguishedName,
    requirement: DistinguishedNameRequirement,
) -> bool {
    match requirement {
        DistinguishedNameRequirement::None => true,
        DistinguishedNameRequirement::NaturalPerson => natural_person_name_matches(name, false),
        DistinguishedNameRequirement::LegalPerson => legal_person_name_matches(name),
        DistinguishedNameRequirement::NaturalOrLegalPerson => {
            natural_person_name_matches(name, false) || legal_person_name_matches(name)
        }
        DistinguishedNameRequirement::IssuingAuthority => {
            legal_person_issuer_name_matches(name) || natural_person_name_matches(name, true)
        }
        DistinguishedNameRequirement::IssuingAuthorityOrSelfIssued => {
            legal_person_issuer_name_matches(name) || natural_person_name_matches(name, true)
        }
    }
}

fn attribute_count(name: &DistinguishedName, kind: NameAttributeKind) -> usize {
    name.rdns
        .iter()
        .flat_map(|rdn| &rdn.attributes)
        .filter(|attribute| {
            attribute.kind == kind
                && matches!(&attribute.value, NameAttributeValue::Text(value) if !value.is_empty())
        })
        .count()
}

fn natural_person_name_matches(name: &DistinguishedName, issuer: bool) -> bool {
    let country = attribute_count(name, NameAttributeKind::CountryName);
    let common_name = attribute_count(name, NameAttributeKind::CommonName);
    let given_name = attribute_count(name, NameAttributeKind::GivenName);
    let surname = attribute_count(name, NameAttributeKind::Surname);
    let pseudonym = attribute_count(name, NameAttributeKind::Pseudonym);
    let serial_number = attribute_count(name, NameAttributeKind::SerialNumber);
    let formal_name = given_name
        .checked_add(surname)
        .is_some_and(|count| count > 0);
    let identity_choice = (formal_name && pseudonym == 0) || (!formal_name && pseudonym == 1);
    country == 1
        && common_name == 1
        && given_name <= 1
        && surname <= 1
        && identity_choice
        && (!issuer || (serial_number == 1 && pseudonym == 0))
}

fn legal_person_name_matches(name: &DistinguishedName) -> bool {
    attribute_count(name, NameAttributeKind::CountryName) == 1
        && attribute_count(name, NameAttributeKind::OrganizationName) == 1
        && attribute_count(name, NameAttributeKind::OrganizationIdentifier) == 1
        && attribute_count(name, NameAttributeKind::CommonName) == 1
}

fn legal_person_issuer_name_matches(name: &DistinguishedName) -> bool {
    attribute_count(name, NameAttributeKind::CountryName) == 1
        && attribute_count(name, NameAttributeKind::OrganizationName) == 1
        && attribute_count(name, NameAttributeKind::CommonName) == 1
        && attribute_count(name, NameAttributeKind::OrganizationIdentifier) <= 1
}

fn validate_wrpac_profile(leaf: &crate::X509Certificate) -> Result<(), X509Error> {
    let wrpac_policies = leaf
        .profile
        .certificate_policies
        .iter()
        .filter(|policy| {
            matches!(
                policy,
                CertificatePolicyId::WrpacNcpNatural
                    | CertificatePolicyId::WrpacNcpLegal
                    | CertificatePolicyId::WrpacQcpNatural
                    | CertificatePolicyId::WrpacQcpLegal
            )
        })
        .collect::<Vec<_>>();
    let [wrpac_policy] = wrpac_policies.as_slice() else {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::WrpacPolicyAmbiguous,
        ));
    };

    let subject_matches = match wrpac_policy {
        CertificatePolicyId::WrpacNcpNatural | CertificatePolicyId::WrpacQcpNatural => {
            natural_person_name_matches(&leaf.profile.subject, false)
        }
        CertificatePolicyId::WrpacNcpLegal | CertificatePolicyId::WrpacQcpLegal => {
            legal_person_name_matches(&leaf.profile.subject)
        }
        _ => false,
    };
    if !subject_matches {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::LeafSubjectNameProfile,
        ));
    }

    let qc_matches = match wrpac_policy {
        CertificatePolicyId::WrpacNcpNatural | CertificatePolicyId::WrpacNcpLegal => true,
        CertificatePolicyId::WrpacQcpNatural => {
            leaf.profile
                .qc_statement_ids
                .contains(&QcStatementId::Compliance)
                && leaf.profile.qc_statement_ids.contains(&QcStatementId::Type)
                && leaf.profile.qc_types.contains(&QcType::ElectronicSignature)
        }
        CertificatePolicyId::WrpacQcpLegal => {
            leaf.profile
                .qc_statement_ids
                .contains(&QcStatementId::Compliance)
                && leaf.profile.qc_statement_ids.contains(&QcStatementId::Type)
                && leaf.profile.qc_types.contains(&QcType::ElectronicSeal)
        }
        _ => false,
    };
    if !qc_matches {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::WrpacQcStatements,
        ));
    }
    Ok(())
}

fn etsi_ts_119_312_v2_1_1_key_allowed(
    certificate: &crate::X509Certificate,
    now: OffsetDateTime,
) -> bool {
    const MINIMUM_RECOMMENDED_RSA_BITS: u16 = 3_000;
    const MINIMUM_LEGACY_RSA_BITS: u16 = 1_900;
    const MINIMUM_EC_BITS: u16 = 256;
    const LEGACY_RSA_ISSUANCE_END_UNIX_SECONDS: i64 = 1_798_761_599;
    const LEGACY_RSA_USABILITY_END_UNIX_SECONDS: i64 = 1_861_919_999;

    match &certificate.profile.public_key {
        PublicKeyProfile::Rsa { bits } => {
            let strength_allowed = *bits >= MINIMUM_RECOMMENDED_RSA_BITS
                || (*bits >= MINIMUM_LEGACY_RSA_BITS
                    && certificate.not_before.unix_timestamp()
                        <= LEGACY_RSA_ISSUANCE_END_UNIX_SECONDS
                    && certificate.not_after.unix_timestamp()
                        <= LEGACY_RSA_USABILITY_END_UNIX_SECONDS
                    && now.unix_timestamp() <= LEGACY_RSA_USABILITY_END_UNIX_SECONDS);
            strength_allowed
                && certificate
                    .profile
                    .rsa_public_exponent
                    .as_deref()
                    .is_some_and(rsa_public_exponent_allowed)
        }
        PublicKeyProfile::Ec { bits, curve } => {
            *bits >= MINIMUM_EC_BITS
                && curve.as_ref().is_some_and(|curve| {
                    matches!(
                        curve.as_str(),
                        "1.2.250.1.223.101.256.1"
                            | "1.3.36.3.3.2.8.1.1.7"
                            | "1.3.36.3.3.2.8.1.1.11"
                            | "1.3.36.3.3.2.8.1.1.13"
                            | "1.2.840.10045.3.1.7"
                            | "1.3.132.0.34"
                            | "1.3.132.0.35"
                    )
                })
        }
        PublicKeyProfile::Ed25519 | PublicKeyProfile::Ed448 => true,
        PublicKeyProfile::Dsa { .. } | PublicKeyProfile::Other { .. } => false,
    }
}

fn etsi_ts_119_312_v2_1_1_signature_parameters_allowed(
    certificate: &crate::X509Certificate,
) -> bool {
    if certificate.profile.signature_algorithm != SignatureAlgorithm::RsaPss {
        return certificate.profile.rsa_pss_parameters.is_none();
    }

    let Some(parameters) = certificate.profile.rsa_pss_parameters.as_ref() else {
        return false;
    };
    if parameters.trailer_field != 1 {
        return false;
    }

    let hash_family = match &parameters.hash_algorithm {
        RsaPssHashAlgorithm::Sha256
        | RsaPssHashAlgorithm::Sha384
        | RsaPssHashAlgorithm::Sha512 => 2_u8,
        RsaPssHashAlgorithm::Sha3_256
        | RsaPssHashAlgorithm::Sha3_384
        | RsaPssHashAlgorithm::Sha3_512 => 3_u8,
        RsaPssHashAlgorithm::Sha1 | RsaPssHashAlgorithm::Other(_) => return false,
    };
    let mask_hash_family = match &parameters.mask_generation_algorithm {
        RsaPssMaskGenerationAlgorithm::Mgf1(
            RsaPssHashAlgorithm::Sha256
            | RsaPssHashAlgorithm::Sha384
            | RsaPssHashAlgorithm::Sha512,
        ) => 2_u8,
        RsaPssMaskGenerationAlgorithm::Mgf1(
            RsaPssHashAlgorithm::Sha3_256
            | RsaPssHashAlgorithm::Sha3_384
            | RsaPssHashAlgorithm::Sha3_512,
        ) => 3_u8,
        RsaPssMaskGenerationAlgorithm::Mgf1(
            RsaPssHashAlgorithm::Sha1 | RsaPssHashAlgorithm::Other(_),
        )
        | RsaPssMaskGenerationAlgorithm::Other(_) => return false,
    };
    hash_family == mask_hash_family
}

fn rsa_public_exponent_allowed(exponent: &[u8]) -> bool {
    // RFC 8017 Section 3.1 defines the RSA public exponent. ETSI TS 119 312
    // V2.1.1 Section 6.2.2.1 narrows it to an odd value in (2^16, 2^256).
    let first_non_zero = exponent.iter().position(|byte| *byte != 0);
    let Some(first_non_zero) = first_non_zero else {
        return false;
    };
    let normalized = &exponent[first_non_zero..];
    if normalized.len() > 32 || normalized.last().is_none_or(|byte| byte & 1 == 0) {
        return false;
    }
    normalized.len() > 3 || (normalized.len() == 3 && normalized > [0x01_u8, 0x00, 0x00].as_slice())
}
