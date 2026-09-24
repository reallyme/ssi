// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    model::{
        AuthorityAccessDescription, AuthorityAccessMethod, BasicConstraints, CertificateExtension,
        CertificateExtensionKind, CertificatePolicyId, CertificateProfile, CertificateVersion,
        DistinguishedName, ExtendedKeyUsagePurpose, KeyUsage, NameAttribute, NameAttributeKind,
        NameAttributeValue, ObjectIdentifier, OtherName, PublicKeyProfile, QcStatementId,
        QcStatements, QcType, RelativeDistinguishedName, RsaPssHashAlgorithm,
        RsaPssMaskGenerationAlgorithm, RsaPssParameters, SignatureAlgorithm,
        SubjectAlternativeNames, X509Certificate, MAX_X509_CERTIFICATE_DER_BYTES,
        MAX_X509_CERTIFICATE_PEM_BYTES, MAX_X509_CHAIN_CERTIFICATES, MAX_X509_CHAIN_PEM_BYTES,
        MAX_X509_EXTENSIONS, MAX_X509_SERIAL_BYTES,
    },
    qcstatements::{
        parse_qc_statements, OID_ETSI_QCS_QC_COMPLIANCE, OID_ETSI_QCS_QC_SSCD,
        OID_ETSI_QCS_QC_TYPE, OID_ETSI_QCT_ESEAL, OID_ETSI_QCT_ESIGN, OID_ETSI_QCT_WEB,
        OID_QC_STATEMENTS_EXT,
    },
    X509Error, X509ResourceLimit,
};

use ::pem::{parse, parse_many};
use ::time::OffsetDateTime;
use asn1_rs::{FromDer, Ia5String};
use std::collections::BTreeSet;
use x509_parser::{
    certificate::X509Certificate as ParsedCert,
    extensions::{
        DistributionPointName, ExtendedKeyUsage as XExtendedKeyUsage, GeneralName,
        KeyUsage as XKeyUsage, ParsedExtension,
    },
    nom::Parser,
    prelude::X509CertificateParser,
    public_key::PublicKey,
    signature_algorithm::RsaSsaPssParams,
    x509::{AlgorithmIdentifier, X509Name},
};

const OID_EKU_ANY: &str = "2.5.29.37.0";
const OID_EKU_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
const OID_EKU_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
const OID_EKU_CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";
const OID_EKU_EMAIL_PROTECTION: &str = "1.3.6.1.5.5.7.3.4";
const OID_EKU_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
const OID_EKU_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";
const OID_AIA_OCSP: &str = "1.3.6.1.5.5.7.48.1";
const OID_AIA_CA_ISSUERS: &str = "1.3.6.1.5.5.7.48.2";
const OID_CERTIFICATE_POLICY_CPS: &str = "1.3.6.1.5.5.7.2.1";
// RFC 9608 §4 assigns id-ce-noRevAvail and requires relying parties to
// distinguish it from ordinary revocation pointers.
const OID_NO_REV_AVAIL: &str = "2.5.29.56";
const MAX_NAME_ATTRIBUTES: usize = 128;

pub fn parse_cert_der(der: &[u8]) -> Result<X509Certificate, X509Error> {
    if der.len() > MAX_X509_CERTIFICATE_DER_BYTES {
        return Err(X509Error::ResourceLimitExceeded(
            X509ResourceLimit::CertificateDerTooLarge,
        ));
    }
    if der.is_empty() {
        return Err(X509Error::InvalidDer);
    }
    let (remaining, cert) = X509CertificateParser::new()
        .parse(der)
        .map_err(|_| X509Error::InvalidDer)?;
    if !remaining.is_empty() {
        return Err(X509Error::InvalidDer);
    }

    project_cert(der.to_vec(), &cert)
}

pub fn parse_cert_pem(pem_bytes: &[u8]) -> Result<X509Certificate, X509Error> {
    if pem_bytes.len() > MAX_X509_CERTIFICATE_PEM_BYTES {
        return Err(X509Error::ResourceLimitExceeded(
            X509ResourceLimit::CertificatePemTooLarge,
        ));
    }
    let p = parse(pem_bytes).map_err(|_| X509Error::InvalidPem)?;
    if p.tag() != "CERTIFICATE" {
        return Err(X509Error::UnsupportedPemLabel);
    }
    parse_cert_der(p.contents())
}

pub fn parse_chain_pem(bundle: &[u8]) -> Result<Vec<X509Certificate>, X509Error> {
    if bundle.len() > MAX_X509_CHAIN_PEM_BYTES {
        return Err(X509Error::ResourceLimitExceeded(
            X509ResourceLimit::CertificatePemBundleTooLarge,
        ));
    }
    let pems = parse_many(bundle).map_err(|_| X509Error::InvalidPem)?;
    let mut out = Vec::new();

    for p in pems {
        if p.tag() == "CERTIFICATE" {
            if out.len() >= MAX_X509_CHAIN_CERTIFICATES {
                return Err(X509Error::ResourceLimitExceeded(
                    X509ResourceLimit::CertificateChainTooLong,
                ));
            }
            out.push(parse_cert_der(p.contents())?);
        }
    }

    if out.is_empty() {
        return Err(X509Error::InvalidPem);
    }

    Ok(out)
}

fn project_cert(der: Vec<u8>, cert: &ParsedCert<'_>) -> Result<X509Certificate, X509Error> {
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let encoded_serial = cert.raw_serial();
    let Some(first) = encoded_serial.first().copied() else {
        return Err(X509Error::InvalidSerialNumber);
    };
    // DER prefixes a positive INTEGER whose magnitude begins with a high bit
    // with one zero sign octet. Retain the canonical unsigned magnitude in the
    // model so RFC 5280's 20-octet limit is applied to the serial value rather
    // than its encoding overhead. A high bit without that prefix is negative.
    let serial = if first == 0 && encoded_serial.len() > 1 {
        encoded_serial[1..].to_vec()
    } else {
        if first & 0x80 != 0 {
            return Err(X509Error::InvalidSerialNumber);
        }
        encoded_serial.to_vec()
    };
    // Zero-valued serials violate the CA issuance profile in RFC 5280, but
    // occur in authenticated legacy EU trusted-list anchors. Retain the value
    // only as an identifier; signature, key, and purpose-specific profile
    // policy still govern whether the certificate may authorize a chain.
    if serial.len() > MAX_X509_SERIAL_BYTES {
        return Err(X509Error::InvalidSerialNumber);
    }

    let not_before: OffsetDateTime = cert.validity().not_before.to_datetime();
    let not_after: OffsetDateTime = cert.validity().not_after.to_datetime();

    let spki_der = cert.public_key().raw.to_vec();
    let signature_algorithm_oid = cert.signature_algorithm.algorithm.to_id_string();
    let rsa_public_exponent = match cert.public_key().parsed() {
        Ok(PublicKey::RSA(public_key)) => Some(public_key.exponent.to_vec()),
        _ => None,
    };

    let mut basic_constraints = None;
    let mut key_usage = None;
    let mut extended_key_usage = None;
    let mut ski = None;
    let mut aki = None;
    let mut san_dns = Vec::new();
    let mut san_ip = Vec::new();
    let mut certificate_policies = Vec::new();
    let mut certificate_policy_cps_uris = Vec::new();
    let mut qc_statements = QcStatements::default();
    let mut extension_oids = BTreeSet::new();
    let mut extensions = Vec::new();
    let mut subject_alternative_names = SubjectAlternativeNames::default();
    let mut authority_information_access = Vec::new();
    let mut crl_distribution_point_uris = Vec::new();
    let mut no_rev_avail = false;

    if cert.extensions().len() > MAX_X509_EXTENSIONS {
        return Err(X509Error::ResourceLimitExceeded(
            X509ResourceLimit::TooManyExtensions,
        ));
    }

    for ext in cert.extensions() {
        let oid = ext.oid.to_id_string();
        if !extension_oids.insert(oid.clone()) {
            return Err(X509Error::DuplicateExtension);
        }
        extensions.push(CertificateExtension {
            kind: extension_kind(&oid)?,
            critical: ext.critical,
        });
        match ext.parsed_extension() {
            ParsedExtension::BasicConstraints(bc) => {
                basic_constraints = Some(BasicConstraints {
                    ca: bc.ca,
                    path_len_constraint: bc.path_len_constraint,
                });
            }

            ParsedExtension::KeyUsage(XKeyUsage { flags }) => {
                // KeyUsage is a BIT STRING. Bits are defined in RFC 5280:
                // 0 digitalSignature, 1 contentCommitment, 2 keyEncipherment,
                // 4 keyAgreement, 5 keyCertSign, 6 cRLSign, ...
                key_usage = Some(KeyUsage {
                    digital_signature: flags & (1 << 0) != 0,
                    content_commitment: flags & (1 << 1) != 0,
                    key_encipherment: flags & (1 << 2) != 0,
                    data_encipherment: flags & (1 << 3) != 0,
                    key_agreement: flags & (1 << 4) != 0,
                    key_cert_sign: flags & (1 << 5) != 0,
                    crl_sign: flags & (1 << 6) != 0,
                    encipher_only: flags & (1 << 7) != 0,
                    decipher_only: flags & (1 << 8) != 0,
                });
            }

            ParsedExtension::ExtendedKeyUsage(eku) => {
                extended_key_usage = Some(project_extended_key_usage(eku));
            }

            ParsedExtension::SubjectKeyIdentifier(k) => {
                ski = Some(k.0.to_vec());
            }

            ParsedExtension::AuthorityKeyIdentifier(k) => {
                if let Some(id) = &k.key_identifier {
                    aki = Some(id.0.to_vec());
                }
            }

            ParsedExtension::SubjectAlternativeName(san) => {
                for gn in &san.general_names {
                    match gn {
                        // RFC 8399 updated RFC 5280's internationalized-name
                        // rules and was subsequently obsoleted by RFC 9549.
                        // Preserve the certificate's IA5String source form;
                        // relying-party matching applies the current RFC 9549
                        // profile instead of lossy display normalization here.
                        GeneralName::DNSName(d) => san_dns.push(d.to_string()),
                        GeneralName::IPAddress(b) => san_ip.push(b.to_vec()),
                        GeneralName::URI(uri) => {
                            subject_alternative_names.uris.push((*uri).to_owned())
                        }
                        GeneralName::RFC822Name(email) => subject_alternative_names
                            .email_addresses
                            .push((*email).to_owned()),
                        GeneralName::OtherName(type_id, value_der) => {
                            subject_alternative_names.other_names.push(OtherName {
                                type_id: bounded_oid(type_id.to_id_string())?,
                                value_der: value_der.to_vec(),
                            });
                        }
                        _ => {}
                    }
                }
            }

            ParsedExtension::CertificatePolicies(pols) => {
                for p in pols {
                    certificate_policies.push(p.policy_id.to_id_string());
                    if let Some(qualifiers) = &p.policy_qualifiers {
                        for qualifier in qualifiers {
                            if qualifier.policy_qualifier_id.to_id_string()
                                == OID_CERTIFICATE_POLICY_CPS
                            {
                                let (remaining, cps_uri) = Ia5String::from_der(qualifier.qualifier)
                                    .map_err(|_| X509Error::ParseError)?;
                                if !remaining.is_empty() {
                                    return Err(X509Error::ParseError);
                                }
                                certificate_policy_cps_uris.push(cps_uri.as_ref().to_owned());
                            }
                        }
                    }
                }
            }

            ParsedExtension::AuthorityInfoAccess(access) => {
                for descriptor in &access.accessdescs {
                    if let GeneralName::URI(uri) = &descriptor.access_location {
                        authority_information_access.push(AuthorityAccessDescription {
                            method: authority_access_method(
                                &descriptor.access_method.to_id_string(),
                            )?,
                            uri: (*uri).to_owned(),
                        });
                    }
                }
            }

            ParsedExtension::CRLDistributionPoints(points) => {
                for point in &points.points {
                    if let Some(DistributionPointName::FullName(names)) = &point.distribution_point
                    {
                        for name in names {
                            if let GeneralName::URI(uri) = name {
                                crl_distribution_point_uris.push((*uri).to_owned());
                            }
                        }
                    }
                }
            }

            ParsedExtension::ParseError { .. } => {
                // A malformed critical extension cannot be interpreted safely.
                // Non-critical legacy extensions contribute no policy claim and
                // may be retained as typed extension metadata without blocking
                // publication of an independently authenticated TSL anchor.
                if ext.critical {
                    return Err(X509Error::ParseError);
                }
                continue;
            }

            _ => {}
        }

        if oid == OID_QC_STATEMENTS_EXT {
            match parse_qc_statements(ext.value) {
                Ok(statements) => qc_statements = statements,
                Err(_) if ext.critical => return Err(X509Error::ParseError),
                Err(_) => continue,
            }
        }
        if oid == OID_NO_REV_AVAIL {
            no_rev_avail = true;
        }
    }

    certificate_policies.sort();
    certificate_policies.dedup();
    let typed_signature_algorithm = signature_algorithm(&signature_algorithm_oid)?;
    let typed_rsa_pss_parameters = rsa_pss_parameters(&cert.signature_algorithm)?;
    let typed_certificate_policies = certificate_policies
        .iter()
        .map(|oid| certificate_policy(oid))
        .collect::<Result<Vec<_>, _>>()?;
    let typed_extended_key_usage = extended_key_usage
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|oid| extended_key_usage_purpose(oid))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(X509Certificate {
        der,
        subject,
        issuer,
        serial,
        not_before,
        not_after,
        spki_der,
        signature_algorithm_oid,
        basic_constraints,
        key_usage,
        extended_key_usage,
        subject_key_identifier: ski,
        authority_key_identifier: aki,
        san_dns,
        san_ip,
        certificate_policies,
        profile: CertificateProfile {
            version: certificate_version(cert.version().0)?,
            subject: project_name(cert.subject())?,
            issuer: project_name(cert.issuer())?,
            extensions,
            subject_alternative_names,
            authority_information_access,
            crl_distribution_point_uris,
            no_rev_avail,
            public_key: public_key_profile(cert)?,
            rsa_public_exponent,
            signature_algorithm: typed_signature_algorithm,
            rsa_pss_parameters: typed_rsa_pss_parameters,
            extended_key_usage: typed_extended_key_usage,
            certificate_policies: typed_certificate_policies,
            certificate_policy_cps_uris,
            qc_statement_ids: qc_statements
                .statement_ids
                .iter()
                .map(|oid| qc_statement_id(oid))
                .collect::<Result<Vec<_>, _>>()?,
            qc_types: qc_statements
                .qc_types
                .iter()
                .map(|oid| qc_type(oid))
                .collect::<Result<Vec<_>, _>>()?,
        },
        qc_statements,
    })
}

fn bounded_oid(value: String) -> Result<ObjectIdentifier, X509Error> {
    ObjectIdentifier::parse(&value).ok_or(X509Error::ResourceLimitExceeded(
        X509ResourceLimit::ObjectIdentifierTooLong,
    ))
}

fn certificate_version(version: u32) -> Result<CertificateVersion, X509Error> {
    match version {
        0 => Ok(CertificateVersion::V1),
        1 => Ok(CertificateVersion::V2),
        2 => Ok(CertificateVersion::V3),
        _ => Err(X509Error::InvalidDer),
    }
}

fn extension_kind(oid: &str) -> Result<CertificateExtensionKind, X509Error> {
    let kind = match oid {
        "2.5.29.19" => CertificateExtensionKind::BasicConstraints,
        "2.5.29.15" => CertificateExtensionKind::KeyUsage,
        "2.5.29.37" => CertificateExtensionKind::ExtendedKeyUsage,
        "2.5.29.14" => CertificateExtensionKind::SubjectKeyIdentifier,
        "2.5.29.35" => CertificateExtensionKind::AuthorityKeyIdentifier,
        "2.5.29.17" => CertificateExtensionKind::SubjectAlternativeName,
        "2.5.29.32" => CertificateExtensionKind::CertificatePolicies,
        "1.3.6.1.5.5.7.1.1" => CertificateExtensionKind::AuthorityInformationAccess,
        "2.5.29.31" => CertificateExtensionKind::CrlDistributionPoints,
        OID_QC_STATEMENTS_EXT => CertificateExtensionKind::QcStatements,
        OID_NO_REV_AVAIL => CertificateExtensionKind::NoRevAvail,
        _ => CertificateExtensionKind::Other(bounded_oid(oid.to_owned())?),
    };
    Ok(kind)
}

fn project_name(name: &X509Name<'_>) -> Result<DistinguishedName, X509Error> {
    let mut attribute_count = 0_usize;
    let mut rdns = Vec::new();
    for rdn in name.iter_rdn() {
        let mut attributes = Vec::new();
        for attribute in rdn.iter() {
            attribute_count =
                attribute_count
                    .checked_add(1)
                    .ok_or(X509Error::ResourceLimitExceeded(
                        X509ResourceLimit::TooManyNameAttributes,
                    ))?;
            if attribute_count > MAX_NAME_ATTRIBUTES {
                return Err(X509Error::ResourceLimitExceeded(
                    X509ResourceLimit::TooManyNameAttributes,
                ));
            }
            let oid = attribute.attr_type().to_id_string();
            let value = match attribute.as_str() {
                Ok(text) => NameAttributeValue::Text(text.to_owned()),
                Err(_) => NameAttributeValue::Binary(attribute.as_slice().to_vec()),
            };
            attributes.push(NameAttribute {
                kind: name_attribute_kind(&oid)?,
                value,
            });
        }
        rdns.push(RelativeDistinguishedName { attributes });
    }
    Ok(DistinguishedName { rdns })
}

include!("parse/project_fields.rs");

#[cfg(test)]
#[path = "parse/project_fields_tests.rs"]
mod project_fields_tests;
