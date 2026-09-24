// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn name_attribute_kind(oid: &str) -> Result<NameAttributeKind, X509Error> {
    let kind = match oid {
        "2.5.4.3" => NameAttributeKind::CommonName,
        "2.5.4.6" => NameAttributeKind::CountryName,
        "2.5.4.42" => NameAttributeKind::GivenName,
        "2.5.4.4" => NameAttributeKind::Surname,
        "2.5.4.65" => NameAttributeKind::Pseudonym,
        "2.5.4.10" => NameAttributeKind::OrganizationName,
        "2.5.4.11" => NameAttributeKind::OrganizationalUnitName,
        "2.5.4.7" => NameAttributeKind::LocalityName,
        "2.5.4.8" => NameAttributeKind::StateOrProvinceName,
        "2.5.4.5" => NameAttributeKind::SerialNumber,
        "2.5.4.9" => NameAttributeKind::StreetAddress,
        "2.5.4.17" => NameAttributeKind::PostalCode,
        "0.9.2342.19200300.100.1.25" => NameAttributeKind::DomainComponent,
        "1.2.840.113549.1.9.1" => NameAttributeKind::EmailAddress,
        "2.5.4.97" => NameAttributeKind::OrganizationIdentifier,
        "2.5.4.20" => NameAttributeKind::TelephoneNumber,
        _ => NameAttributeKind::Other(bounded_oid(oid.to_owned())?),
    };
    Ok(kind)
}

fn authority_access_method(oid: &str) -> Result<AuthorityAccessMethod, X509Error> {
    match oid {
        OID_AIA_OCSP => Ok(AuthorityAccessMethod::Ocsp),
        OID_AIA_CA_ISSUERS => Ok(AuthorityAccessMethod::CaIssuers),
        _ => Ok(AuthorityAccessMethod::Other(bounded_oid(oid.to_owned())?)),
    }
}

fn public_key_profile(cert: &ParsedCert<'_>) -> Result<PublicKeyProfile, X509Error> {
    let algorithm = cert.public_key().algorithm.algorithm.to_id_string();
    let parsed = match cert.public_key().parsed() {
        Ok(parsed) => parsed,
        Err(_) => {
            let bits = cert
                .public_key()
                .subject_public_key
                .data
                .len()
                .checked_mul(8)
                .and_then(|bits| u16::try_from(bits).ok())
                .ok_or(X509Error::ParseError)?;
            // Preserve a structurally valid but unprojectable legacy key as an
            // unknown family. Algorithm allow-lists and strength floors then
            // reject it during evaluation instead of treating it as a parsed
            // RSA/EC key with guessed security properties.
            return Ok(PublicKeyProfile::Other {
                algorithm: bounded_oid(algorithm)?,
                bits,
            });
        }
    };
    let bits = u16::try_from(parsed.key_size()).map_err(|_| X509Error::ParseError)?;
    match algorithm.as_str() {
        "1.2.840.113549.1.1.1" => Ok(PublicKeyProfile::Rsa { bits }),
        "1.2.840.10045.2.1" => Ok(PublicKeyProfile::Ec {
            bits,
            curve: cert
                .public_key()
                .algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| asn1_rs::Oid::try_from(parameters.clone()).ok())
                .map(|oid| bounded_oid(oid.to_id_string()))
                .transpose()?,
        }),
        "1.3.101.112" => Ok(PublicKeyProfile::Ed25519),
        "1.3.101.113" => Ok(PublicKeyProfile::Ed448),
        "1.2.840.10040.4.1" => Ok(PublicKeyProfile::Dsa { bits }),
        _ => {
            let measured_bits = match parsed {
                PublicKey::Unknown(bytes) => {
                    u16::try_from(bytes.len().checked_mul(8).ok_or(X509Error::ParseError)?)
                        .map_err(|_| X509Error::ParseError)?
                }
                _ => bits,
            };
            Ok(PublicKeyProfile::Other {
                algorithm: bounded_oid(algorithm)?,
                bits: measured_bits,
            })
        }
    }
}

fn signature_algorithm(oid: &str) -> Result<SignatureAlgorithm, X509Error> {
    let algorithm = match oid {
        "1.2.840.113549.1.1.11" => SignatureAlgorithm::RsaPkcs1Sha256,
        "1.2.840.113549.1.1.12" => SignatureAlgorithm::RsaPkcs1Sha384,
        "1.2.840.113549.1.1.13" => SignatureAlgorithm::RsaPkcs1Sha512,
        "1.2.840.113549.1.1.10" => SignatureAlgorithm::RsaPss,
        "1.2.840.10045.4.3.2" => SignatureAlgorithm::EcdsaSha256,
        "1.2.840.10045.4.3.3" => SignatureAlgorithm::EcdsaSha384,
        "1.2.840.10045.4.3.4" => SignatureAlgorithm::EcdsaSha512,
        "1.3.101.112" => SignatureAlgorithm::Ed25519,
        "1.3.101.113" => SignatureAlgorithm::Ed448,
        _ => SignatureAlgorithm::Other(bounded_oid(oid.to_owned())?),
    };
    Ok(algorithm)
}

fn rsa_pss_parameters(
    algorithm: &AlgorithmIdentifier<'_>,
) -> Result<Option<RsaPssParameters>, X509Error> {
    const OID_RSA_PSS: &str = "1.2.840.113549.1.1.10";
    const OID_MGF1: &str = "1.2.840.113549.1.1.8";

    if algorithm.algorithm.to_id_string() != OID_RSA_PSS {
        return Ok(None);
    }

    // RFC 4055 requires RSASSA-PSS signature AlgorithmIdentifiers to carry
    // parameters. Applying ASN.1 defaults when fields inside that sequence are
    // absent is valid; accepting a missing sequence itself is not.
    let encoded = algorithm
        .parameters
        .as_ref()
        .ok_or(X509Error::ParseError)?;
    let parameters = RsaSsaPssParams::try_from(encoded).map_err(|_| X509Error::ParseError)?;
    let mask_generation = parameters
        .mask_gen_algorithm()
        .map_err(|_| X509Error::ParseError)?;
    let mask_generation_algorithm = if mask_generation.mgf.to_id_string() == OID_MGF1 {
        RsaPssMaskGenerationAlgorithm::Mgf1(rsa_pss_hash_algorithm(
            &mask_generation.hash.to_id_string(),
        )?)
    } else {
        RsaPssMaskGenerationAlgorithm::Other(bounded_oid(
            mask_generation.mgf.to_id_string(),
        )?)
    };

    Ok(Some(RsaPssParameters {
        hash_algorithm: rsa_pss_hash_algorithm(&parameters.hash_algorithm_oid().to_id_string())?,
        mask_generation_algorithm,
        salt_length: parameters.salt_length(),
        trailer_field: parameters.trailer_field(),
    }))
}

fn rsa_pss_hash_algorithm(oid: &str) -> Result<RsaPssHashAlgorithm, X509Error> {
    let algorithm = match oid {
        "1.3.14.3.2.26" => RsaPssHashAlgorithm::Sha1,
        "2.16.840.1.101.3.4.2.1" => RsaPssHashAlgorithm::Sha256,
        "2.16.840.1.101.3.4.2.2" => RsaPssHashAlgorithm::Sha384,
        "2.16.840.1.101.3.4.2.3" => RsaPssHashAlgorithm::Sha512,
        "2.16.840.1.101.3.4.2.8" => RsaPssHashAlgorithm::Sha3_256,
        "2.16.840.1.101.3.4.2.9" => RsaPssHashAlgorithm::Sha3_384,
        "2.16.840.1.101.3.4.2.10" => RsaPssHashAlgorithm::Sha3_512,
        _ => RsaPssHashAlgorithm::Other(bounded_oid(oid.to_owned())?),
    };
    Ok(algorithm)
}

fn certificate_policy(oid: &str) -> Result<CertificatePolicyId, X509Error> {
    let policy = match oid {
        "0.4.0.194112.1.0" => CertificatePolicyId::QcpNaturalPerson,
        "0.4.0.194112.1.1" => CertificatePolicyId::QcpLegalPerson,
        "0.4.0.194112.1.2" => CertificatePolicyId::QcpNaturalPersonQscd,
        "0.4.0.194112.1.3" => CertificatePolicyId::QcpLegalPersonQscd,
        "0.4.0.194112.1.4" => CertificatePolicyId::QevcpWeb,
        "0.4.0.194112.1.5" => CertificatePolicyId::QncpWeb,
        "0.4.0.194112.1.6" => CertificatePolicyId::QncpWebGeneric,
        "0.4.0.194118.1.1" => CertificatePolicyId::WrpacNcpNatural,
        "0.4.0.194118.1.2" => CertificatePolicyId::WrpacNcpLegal,
        "0.4.0.194118.1.3" => CertificatePolicyId::WrpacQcpNatural,
        "0.4.0.194118.1.4" => CertificatePolicyId::WrpacQcpLegal,
        _ => CertificatePolicyId::Other(bounded_oid(oid.to_owned())?),
    };
    Ok(policy)
}

fn extended_key_usage_purpose(oid: &str) -> Result<ExtendedKeyUsagePurpose, X509Error> {
    let purpose = match oid {
        OID_EKU_ANY => ExtendedKeyUsagePurpose::Any,
        OID_EKU_SERVER_AUTH => ExtendedKeyUsagePurpose::ServerAuthentication,
        OID_EKU_CLIENT_AUTH => ExtendedKeyUsagePurpose::ClientAuthentication,
        OID_EKU_CODE_SIGNING => ExtendedKeyUsagePurpose::CodeSigning,
        OID_EKU_EMAIL_PROTECTION => ExtendedKeyUsagePurpose::EmailProtection,
        OID_EKU_TIME_STAMPING => ExtendedKeyUsagePurpose::TimeStamping,
        OID_EKU_OCSP_SIGNING => ExtendedKeyUsagePurpose::OcspSigning,
        _ => ExtendedKeyUsagePurpose::Other(bounded_oid(oid.to_owned())?),
    };
    Ok(purpose)
}

fn qc_statement_id(oid: &str) -> Result<QcStatementId, X509Error> {
    let statement = match oid {
        OID_ETSI_QCS_QC_COMPLIANCE => QcStatementId::Compliance,
        "0.4.0.1862.1.2" => QcStatementId::LimitValue,
        "0.4.0.1862.1.3" => QcStatementId::RetentionPeriod,
        OID_ETSI_QCS_QC_SSCD => QcStatementId::QcSscd,
        "0.4.0.1862.1.5" => QcStatementId::Pds,
        OID_ETSI_QCS_QC_TYPE => QcStatementId::Type,
        _ => QcStatementId::Other(bounded_oid(oid.to_owned())?),
    };
    Ok(statement)
}

fn qc_type(oid: &str) -> Result<QcType, X509Error> {
    let value = match oid {
        OID_ETSI_QCT_ESIGN => QcType::ElectronicSignature,
        OID_ETSI_QCT_ESEAL => QcType::ElectronicSeal,
        OID_ETSI_QCT_WEB => QcType::WebAuthentication,
        "0.4.0.194126.1.1" => QcType::PidProvider,
        "0.4.0.194126.1.2" => QcType::WalletProvider,
        _ => QcType::Other(bounded_oid(oid.to_owned())?),
    };
    Ok(value)
}

fn project_extended_key_usage(eku: &XExtendedKeyUsage<'_>) -> Vec<String> {
    let mut out = Vec::new();

    if eku.any {
        out.push(OID_EKU_ANY.to_string());
    }
    if eku.server_auth {
        out.push(OID_EKU_SERVER_AUTH.to_string());
    }
    if eku.client_auth {
        out.push(OID_EKU_CLIENT_AUTH.to_string());
    }
    if eku.code_signing {
        out.push(OID_EKU_CODE_SIGNING.to_string());
    }
    if eku.email_protection {
        out.push(OID_EKU_EMAIL_PROTECTION.to_string());
    }
    if eku.time_stamping {
        out.push(OID_EKU_TIME_STAMPING.to_string());
    }
    if eku.ocsp_signing {
        out.push(OID_EKU_OCSP_SIGNING.to_string());
    }

    out.extend(eku.other.iter().map(|o| o.to_id_string()));
    out.sort();
    out.dedup();
    out
}
