// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ETSI TS 119 612 TLSO signing-certificate policy.

#[cfg(feature = "native")]
use envelopes_x509::{
    parse_subject_public_key_info_der, NameAttributeKind, NameAttributeValue, PublicKeyProfile,
    SignatureAlgorithm, X509Certificate,
};
#[cfg(feature = "native")]
use identity_trust_tsl_core::TrustedList;

#[cfg(feature = "native")]
use crate::error::{TslOpenSslError, TslSignerProfileFailureReason};

/// TS 119 612 registered trusted-list-signing KeyPurposeId.
pub const TSL_SIGNING_EXTENDED_KEY_USAGE_OID: &str = "0.4.0.2231.3.0";

/// Authenticated XML signature suite applied to a trusted list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, zeroize::Zeroize)]
pub enum TslSignatureAlgorithm {
    /// RSA PKCS#1 v1.5 with SHA-256.
    RsaSha256,
    /// RSA PKCS#1 v1.5 with SHA-384.
    RsaSha384,
    /// RSA PKCS#1 v1.5 with SHA-512.
    RsaSha512,
    /// RSASSA-PSS with SHA-256 and MGF1-SHA-256.
    RsaPssSha256,
    /// RSASSA-PSS with SHA-384 and MGF1-SHA-384.
    RsaPssSha384,
    /// RSASSA-PSS with SHA-512 and MGF1-SHA-512.
    RsaPssSha512,
    /// ECDSA with SHA-256.
    EcdsaSha256,
    /// ECDSA with SHA-384.
    EcdsaSha384,
    /// ECDSA with SHA-512.
    EcdsaSha512,
}

#[cfg(feature = "native")]
const MINIMUM_RECOMMENDED_RSA_BITS: u16 = 3_000;
#[cfg(feature = "native")]
const MINIMUM_LEGACY_RSA_BITS: u16 = 1_900;
#[cfg(feature = "native")]
const MINIMUM_EC_BITS: u16 = 256;
#[cfg(feature = "native")]
const THREE_YEAR_RESISTANCE_DAYS: i64 = 1_095;
#[cfg(feature = "native")]
// TS 119 312 v2.1.1 table 6 includes the complete named UTC dates.
const LEGACY_RSA_ISSUANCE_END_UNIX_SECONDS: i64 = 1_798_761_599; // 2026-12-31T23:59:59Z
#[cfg(feature = "native")]
const LEGACY_RSA_USABILITY_END_UNIX_SECONDS: i64 = 1_861_919_999; // 2028-12-31T23:59:59Z
#[cfg(feature = "native")]
const SHA1_IDENTIFIER_BYTES: usize = 20;
#[cfg(feature = "native")]
const SHORT_IDENTIFIER_BYTES: usize = 8;
#[cfg(feature = "native")]
const SHORT_IDENTIFIER_SOURCE_OFFSET: usize = SHA1_IDENTIFIER_BYTES - SHORT_IDENTIFIER_BYTES;
#[cfg(feature = "native")]
const SHORT_IDENTIFIER_TYPE_FIELD: u8 = 0x40;
#[cfg(feature = "native")]
const FRP256V1_OID: &str = "1.2.250.1.223.101.256.1";
#[cfg(feature = "native")]
const BRAINPOOL_P256R1_OID: &str = "1.3.36.3.3.2.8.1.1.7";
#[cfg(feature = "native")]
const BRAINPOOL_P384R1_OID: &str = "1.3.36.3.3.2.8.1.1.11";
#[cfg(feature = "native")]
const BRAINPOOL_P512R1_OID: &str = "1.3.36.3.3.2.8.1.1.13";
#[cfg(feature = "native")]
const NIST_P256_OID: &str = "1.2.840.10045.3.1.7";
#[cfg(feature = "native")]
const NIST_P384_OID: &str = "1.3.132.0.34";
#[cfg(feature = "native")]
const NIST_P521_OID: &str = "1.3.132.0.35";

/// Maximum prior verified lists considered for same-community issuer policy.
pub const MAX_TSL_SIGNER_COMMUNITY_LISTS: usize = 32;

/// Authenticated origin of the certificate that issued the TLSO signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TslSignerIssuerSource {
    /// The TLSO signing certificate is cryptographically self-signed.
    SelfSigned,
    /// Its issuer certificate identifies a TSP service in the signed TL.
    CurrentTrustedList,
    /// Its issuer certificate identifies a TSP service in a previously
    /// verified TL sharing at least one scheme-community URI.
    SameCommunityTrustedList,
}

/// Non-secret evidence produced only after every TLSO certificate rule passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TslSignerProfileEvidence {
    /// Authenticated source satisfying the TS 119 612 issuer restriction.
    pub issuer_source: TslSignerIssuerSource,
    /// Subject country matched the scheme territory.
    pub subject_country_matched: bool,
    /// A Subject organization matched a scheme operator name.
    pub subject_organization_matched: bool,
    /// Only signature/content-commitment key usages were asserted.
    pub key_usage_exclusive: bool,
    /// SubjectKeyIdentifier was present and non-empty.
    pub subject_key_identifier_present: bool,
    /// SubjectKeyIdentifier matched RFC 5280 section 4.2.1.2 method (1) or (2).
    pub subject_key_identifier_valid: bool,
    /// BasicConstraints explicitly asserted CA=false.
    pub basic_constraints_ca_false: bool,
    /// ExtendedKeyUsage contained only the trusted-list-signing purpose.
    pub trusted_list_signing_eku_exclusive: bool,
    /// The key and signature suite met the injected three-year horizon.
    pub algorithm_has_three_year_resistance: bool,
}

#[cfg(feature = "native")]
pub(crate) fn validate_tlso_signer_profile(
    signer: &X509Certificate,
    tsl: &TrustedList,
    community_lists: &[&crate::verify::VerifiedTrustedList],
    now: time::OffsetDateTime,
    signature_algorithm: TslSignatureAlgorithm,
) -> Result<TslSignerProfileEvidence, TslOpenSslError> {
    if community_lists.len() > MAX_TSL_SIGNER_COMMUNITY_LISTS {
        return Err(TslOpenSslError::SignerProfile(
            TslSignerProfileFailureReason::CommunityListLimit,
        ));
    }
    let territory = tsl
        .scheme_territory
        .as_deref()
        .ok_or(TslOpenSslError::SignerProfile(
            TslSignerProfileFailureReason::CountryMismatch,
        ))?;
    let countries: Vec<&str> = signer
        .profile
        .subject
        .rdns
        .iter()
        .flat_map(|rdn| &rdn.attributes)
        .filter_map(|attribute| match (&attribute.kind, &attribute.value) {
            (NameAttributeKind::CountryName, NameAttributeValue::Text(value)) => {
                Some(value.as_str())
            }
            _ => None,
        })
        .collect();
    if countries.len() != 1 || countries[0] != territory {
        return Err(TslOpenSslError::SignerProfile(
            TslSignerProfileFailureReason::CountryMismatch,
        ));
    }

    let organization_matches = signer
        .profile
        .subject
        .rdns
        .iter()
        .flat_map(|rdn| &rdn.attributes)
        .filter_map(|attribute| match (&attribute.kind, &attribute.value) {
            (NameAttributeKind::OrganizationName, NameAttributeValue::Text(value)) => {
                Some(value.as_str())
            }
            _ => None,
        })
        .any(|organization| {
            tsl.scheme_operator_names
                .iter()
                .any(|name| name.value == organization)
        });
    if !organization_matches {
        return Err(TslOpenSslError::SignerProfile(
            TslSignerProfileFailureReason::OrganizationMismatch,
        ));
    }

    // RFC 5280 section 4.2.1.3 defines the complete KeyUsage bit set. TS
    // 119 612 clause 5.7.1 permits only digitalSignature and/or
    // contentCommitment for a TLSO signer, so every other projected bit is
    // checked explicitly instead of assuming an abbreviated model.
    let key_usage = signer
        .key_usage
        .as_ref()
        .ok_or(TslOpenSslError::SignerProfile(
            TslSignerProfileFailureReason::MissingKeyUsage,
        ))?;
    if !(key_usage.digital_signature || key_usage.content_commitment)
        || key_usage.key_cert_sign
        || key_usage.crl_sign
        || key_usage.key_encipherment
        || key_usage.data_encipherment
        || key_usage.key_agreement
        || key_usage.encipher_only
        || key_usage.decipher_only
    {
        return Err(TslOpenSslError::SignerProfile(
            TslSignerProfileFailureReason::InvalidKeyUsage,
        ));
    }

    validate_subject_key_identifier(signer)?;
    if signer
        .basic_constraints
        .as_ref()
        .is_none_or(|constraints| constraints.ca)
    {
        return Err(TslOpenSslError::SignerProfile(
            TslSignerProfileFailureReason::InvalidBasicConstraints,
        ));
    }
    let extended_key_usage =
        signer
            .extended_key_usage
            .as_deref()
            .ok_or(TslOpenSslError::SignerProfile(
                TslSignerProfileFailureReason::InvalidExtendedKeyUsage,
            ))?;
    if extended_key_usage.len() != 1 || extended_key_usage[0] != TSL_SIGNING_EXTENDED_KEY_USAGE_OID
    {
        return Err(TslOpenSslError::SignerProfile(
            TslSignerProfileFailureReason::InvalidExtendedKeyUsage,
        ));
    }

    let resistance_horizon = now
        .checked_add(time::Duration::days(THREE_YEAR_RESISTANCE_DAYS))
        .ok_or(TslOpenSslError::SignerProfile(
            TslSignerProfileFailureReason::AlgorithmLifetime,
        ))?;
    let public_key_allowed = match &signer.profile.public_key {
        PublicKeyProfile::Rsa { bits } if *bits >= MINIMUM_RECOMMENDED_RSA_BITS => true,
        PublicKeyProfile::Rsa { bits } if *bits >= MINIMUM_LEGACY_RSA_BITS => {
            signer.not_before.unix_timestamp() <= LEGACY_RSA_ISSUANCE_END_UNIX_SECONDS
                && signer.not_after.unix_timestamp() <= LEGACY_RSA_USABILITY_END_UNIX_SECONDS
                && resistance_horizon.unix_timestamp() <= LEGACY_RSA_USABILITY_END_UNIX_SECONDS
        }
        PublicKeyProfile::Ec { bits, curve } => {
            *bits >= MINIMUM_EC_BITS && curve.as_ref().is_some_and(is_recommended_ec_curve)
        }
        PublicKeyProfile::Ed25519 | PublicKeyProfile::Ed448 => true,
        PublicKeyProfile::Dsa { .. }
        | PublicKeyProfile::Other { .. }
        | PublicKeyProfile::Rsa { .. } => false,
    };
    let certificate_signature_allowed = matches!(
        signer.profile.signature_algorithm,
        SignatureAlgorithm::RsaPkcs1Sha256
            | SignatureAlgorithm::RsaPkcs1Sha384
            | SignatureAlgorithm::RsaPkcs1Sha512
            | SignatureAlgorithm::RsaPss
            | SignatureAlgorithm::EcdsaSha256
            | SignatureAlgorithm::EcdsaSha384
            | SignatureAlgorithm::EcdsaSha512
            | SignatureAlgorithm::Ed25519
            | SignatureAlgorithm::Ed448
    );
    let certified_key_parameters_allowed = match signer.profile.public_key {
        PublicKeyProfile::Rsa { .. } => rsa_public_exponent_allowed(signer.spki_der.as_slice()),
        _ => true,
    };
    if !public_key_allowed
        || !certificate_signature_allowed
        || !certified_key_parameters_allowed
        || !signature_suite_matches_certified_key(&signer.profile.public_key, signature_algorithm)
    {
        return Err(TslOpenSslError::SignerProfile(
            TslSignerProfileFailureReason::AlgorithmLifetime,
        ));
    }

    let issuer_source = validate_issuer(signer, tsl, community_lists)?;

    Ok(TslSignerProfileEvidence {
        issuer_source,
        subject_country_matched: true,
        subject_organization_matched: true,
        key_usage_exclusive: true,
        subject_key_identifier_present: true,
        subject_key_identifier_valid: true,
        basic_constraints_ca_false: true,
        trusted_list_signing_eku_exclusive: true,
        algorithm_has_three_year_resistance: true,
    })
}

#[cfg(feature = "native")]
pub(crate) fn rsa_public_exponent_allowed(subject_public_key_info_der: &[u8]) -> bool {
    // ETSI TS 119 312 v2.1.1 clause 6.2.2.1 requires an odd exponent strictly
    // greater than 2^16 and strictly less than 2^256. The SPKI is reparsed so
    // a caller-mutated high-level key projection cannot bypass this parameter
    // rule. An odd 17-bit value is necessarily at least 65,537.
    let Ok(key) = openssl::pkey::PKey::public_key_from_der(subject_public_key_info_der) else {
        return false;
    };
    let Ok(rsa) = key.rsa() else {
        return false;
    };
    let exponent = rsa.e();
    exponent.is_bit_set(0) && exponent.num_bits() > 16 && exponent.num_bits() <= 256
}

#[cfg(feature = "native")]
fn signature_suite_matches_certified_key(
    public_key: &PublicKeyProfile,
    signature_algorithm: TslSignatureAlgorithm,
) -> bool {
    // ETSI TS 119 612 v2.4.1 clause 5.7.1 binds both the authenticated
    // SignatureMethod and certified signing key to TS 119 312. Table 4 limits
    // ECDSA suites to the digest matching the curve size; preserving the
    // method in the XMLSec receipt prevents a valid but non-profile suite from
    // being accepted after the cryptographic check.
    match (public_key, signature_algorithm) {
        (
            PublicKeyProfile::Rsa { .. },
            TslSignatureAlgorithm::RsaSha256
            | TslSignatureAlgorithm::RsaSha384
            | TslSignatureAlgorithm::RsaSha512
            | TslSignatureAlgorithm::RsaPssSha256
            | TslSignatureAlgorithm::RsaPssSha384
            | TslSignatureAlgorithm::RsaPssSha512,
        ) => true,
        (
            PublicKeyProfile::Ec {
                curve: Some(curve), ..
            },
            algorithm,
        ) => matches!(
            (curve.as_str(), algorithm),
            (
                FRP256V1_OID | BRAINPOOL_P256R1_OID | NIST_P256_OID,
                TslSignatureAlgorithm::EcdsaSha256
            ) | (
                BRAINPOOL_P384R1_OID | NIST_P384_OID,
                TslSignatureAlgorithm::EcdsaSha384
            ) | (
                BRAINPOOL_P512R1_OID | NIST_P521_OID,
                TslSignatureAlgorithm::EcdsaSha512
            )
        ),
        _ => false,
    }
}

#[cfg(feature = "native")]
fn is_recommended_ec_curve(curve: &envelopes_x509::ObjectIdentifier) -> bool {
    // ETSI TS 119 312 v2.1.1 clause 6.2.2.3 and table 3 make the
    // named-curve list normative. A nominal bit length alone cannot establish
    // that an explicit or private curve is an admitted ECDSA parameter set.
    matches!(
        curve.as_str(),
        FRP256V1_OID
            | BRAINPOOL_P256R1_OID
            | BRAINPOOL_P384R1_OID
            | BRAINPOOL_P512R1_OID
            | NIST_P256_OID
            | NIST_P384_OID
            | NIST_P521_OID
    )
}

#[cfg(feature = "native")]
fn validate_issuer(
    signer: &X509Certificate,
    tsl: &TrustedList,
    community_lists: &[&crate::verify::VerifiedTrustedList],
) -> Result<TslSignerIssuerSource, TslOpenSslError> {
    // ETSI TS 119 612 v2.4.1 clause 5.7.1 admits a cryptographically
    // self-signed TLSO certificate, or an issuer that is a TSP trust service
    // in this TL or a TL in the same community. Configured PKIX roots alone do
    // not prove that semantic relationship.
    if signer.profile.subject == signer.profile.issuer
        && verifies_certificate_signature(signer, signer)
    {
        return Ok(TslSignerIssuerSource::SelfSigned);
    }

    if list_contains_issuer(tsl, signer) {
        return Ok(TslSignerIssuerSource::CurrentTrustedList);
    }
    if community_lists.iter().any(|verified| {
        shares_scheme_community(tsl, verified.list())
            && list_contains_issuer(verified.list(), signer)
    }) {
        return Ok(TslSignerIssuerSource::SameCommunityTrustedList);
    }

    Err(TslOpenSslError::SignerProfile(
        TslSignerProfileFailureReason::UnauthorizedIssuer,
    ))
}

#[cfg(feature = "native")]
fn shares_scheme_community(left: &TrustedList, right: &TrustedList) -> bool {
    left.scheme_type_community_rules.iter().any(|left_rule| {
        right
            .scheme_type_community_rules
            .iter()
            .any(|right_rule| left_rule.uri == right_rule.uri)
    })
}

#[cfg(feature = "native")]
fn list_contains_issuer(list: &TrustedList, signer: &X509Certificate) -> bool {
    // TS 119 612 clause 5.5.3 requires every certificate representation of a
    // service identity to carry the same subject name and public key, and the
    // parser enforces that. One representation per service therefore decides
    // the subject/signature test exactly. RFC 5280 clause 4.2.1.9 only lets a
    // CA key verify certificate signatures, so non-CA service identities are
    // excluded before any certificate is parsed.
    list.services()
        .filter_map(|service| match &service.digital_identity {
            identity_trust_tsl_core::ServiceDigitalIdentity::Pki(identity)
                if identity.is_certificate_authority() =>
            {
                identity.certificates_der.first()
            }
            _ => None,
        })
        .filter_map(|der| envelopes_x509::parse_cert_der(der).ok())
        .any(|candidate| {
            candidate.profile.subject == signer.profile.issuer
                && verifies_certificate_signature(signer, &candidate)
        })
}

#[cfg(feature = "native")]
fn verifies_certificate_signature(certificate: &X509Certificate, issuer: &X509Certificate) -> bool {
    let Ok(certificate) = openssl::x509::X509::from_der(certificate.der.as_slice()) else {
        return false;
    };
    let Ok(issuer) = openssl::x509::X509::from_der(issuer.der.as_slice()) else {
        return false;
    };
    let Ok(public_key) = issuer.public_key() else {
        return false;
    };
    matches!(certificate.verify(&public_key), Ok(true))
}

#[cfg(feature = "native")]
fn validate_subject_key_identifier(signer: &X509Certificate) -> Result<(), TslOpenSslError> {
    let identifier = signer
        .subject_key_identifier
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or(TslOpenSslError::SignerProfile(
            TslSignerProfileFailureReason::MissingSubjectKeyIdentifier,
        ))?;
    let subject_public_key = parse_subject_public_key_info_der(signer.spki_der.as_slice())
        .map_err(|_| {
            TslOpenSslError::SignerProfile(
                TslSignerProfileFailureReason::InvalidSubjectKeyIdentifier,
            )
        })?
        .public_key;

    // RFC 5280 section 4.2.1.2 method (1) hashes the subjectPublicKey BIT
    // STRING contents, excluding its tag, length, and unused-bit count. Method
    // (2) uses the least-significant 60 bits and prefixes the 0100 type field.
    // SHA-1 is used only for this standards-defined non-security identifier;
    // signature and certificate security policy never admits SHA-1.
    let full_identifier = openssl::sha::sha1(subject_public_key.as_slice());
    let mut short_identifier = [0_u8; SHORT_IDENTIFIER_BYTES];
    short_identifier.copy_from_slice(&full_identifier[SHORT_IDENTIFIER_SOURCE_OFFSET..]);
    short_identifier[0] = (short_identifier[0] & 0x0f) | SHORT_IDENTIFIER_TYPE_FIELD;

    if identifier != full_identifier && identifier != short_identifier {
        return Err(TslOpenSslError::SignerProfile(
            TslSignerProfileFailureReason::InvalidSubjectKeyIdentifier,
        ));
    }
    Ok(())
}
