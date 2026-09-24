// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn finish_certificate(profile: &mut SignatureProfile) -> Result<(), XmlSecError> {
    let text = profile
        .certificate_text
        .take()
        .ok_or_else(profile_violation)?;
    let compact: String = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if compact.is_empty() || compact.len() > MAX_CERTIFICATE_BASE64_BYTES {
        return Err(profile_violation());
    }
    let certificate = base64_to_bytes(&compact).map_err(|_| profile_violation())?;
    if certificate.is_empty() || certificate.len() > MAX_SIGNER_DER_BYTES {
        return Err(profile_violation());
    }
    profile.key_info_certificates_der.push(certificate);
    Ok(())
}

fn finish_certificate_digest(profile: &mut SignatureProfile) -> Result<(), XmlSecError> {
    let text = profile
        .certificate_digest_text
        .take()
        .ok_or_else(profile_violation)?;
    let compact: String = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let digest = base64_to_bytes(&compact).map_err(|_| profile_violation())?;
    let expected_length = match profile.certificate_digest_algorithm {
        Some(DigestAlgorithm::Sha256) => 32,
        Some(DigestAlgorithm::Sha384) => 48,
        Some(DigestAlgorithm::Sha512) => 64,
        None => return Err(profile_violation()),
    };
    if digest.len() != expected_length {
        return Err(profile_violation());
    }
    profile.certificate_digest = Some(digest);
    Ok(())
}

fn finish_signing_time(profile: &mut SignatureProfile) -> Result<(), XmlSecError> {
    let text = profile
        .signing_time_text
        .take()
        .ok_or(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::InvalidSigningTime,
        ))?;
    let parsed = OffsetDateTime::parse(&text, &Rfc3339).map_err(|_| {
        XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::InvalidSigningTime)
    })?;
    // ETSI EN 319 132-1 v1.3.1 clauses 5.2.1 and 6.3 (table 2,
    // requirement h) make one signed claimed UTC time mandatory for XAdES-B-B.
    if parsed.offset() != UtcOffset::UTC {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::InvalidSigningTime,
        ));
    }
    profile.signing_time_validated = true;
    Ok(())
}

fn finish_mime_type(profile: &mut SignatureProfile) -> Result<(), XmlSecError> {
    let text = profile
        .mime_type_text
        .take()
        .ok_or(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::InvalidDataObjectFormat,
        ))?;
    if text.is_empty() || text.chars().any(char::is_control) {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::InvalidDataObjectFormat,
        ));
    }
    let index = profile
        .current_data_object_format
        .ok_or(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::InvalidDataObjectFormat,
        ))?;
    let format = profile
        .data_object_formats
        .get_mut(index)
        .ok_or(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::InvalidDataObjectFormat,
        ))?;
    format.mime_type = Some(text);
    Ok(())
}

fn current_reference_mut(
    profile: &mut SignatureProfile,
) -> Result<&mut ReferenceProfile, XmlSecError> {
    let index = profile.current_reference.ok_or_else(profile_violation)?;
    profile
        .references
        .get_mut(index)
        .ok_or_else(profile_violation)
}

fn parse_digest_algorithm(value: &str) -> Result<DigestAlgorithm, XmlSecError> {
    match value.as_bytes() {
        DIGEST_SHA256 => Ok(DigestAlgorithm::Sha256),
        DIGEST_SHA384 => Ok(DigestAlgorithm::Sha384),
        DIGEST_SHA512 => Ok(DigestAlgorithm::Sha512),
        _ => Err(unsupported_algorithm()),
    }
}

fn parse_signature_algorithm(value: &str) -> Result<TslXmlSignatureAlgorithm, XmlSecError> {
    match value.as_bytes() {
        SIGNATURE_RSA_SHA256 => Ok(TslXmlSignatureAlgorithm::RsaSha256),
        SIGNATURE_RSA_SHA384 => Ok(TslXmlSignatureAlgorithm::RsaSha384),
        SIGNATURE_RSA_SHA512 => Ok(TslXmlSignatureAlgorithm::RsaSha512),
        SIGNATURE_RSA_PSS_SHA256 => Ok(TslXmlSignatureAlgorithm::RsaPssSha256),
        SIGNATURE_RSA_PSS_SHA384 => Ok(TslXmlSignatureAlgorithm::RsaPssSha384),
        SIGNATURE_RSA_PSS_SHA512 => Ok(TslXmlSignatureAlgorithm::RsaPssSha512),
        SIGNATURE_ECDSA_SHA256 => Ok(TslXmlSignatureAlgorithm::EcdsaSha256),
        SIGNATURE_ECDSA_SHA384 => Ok(TslXmlSignatureAlgorithm::EcdsaSha384),
        SIGNATURE_ECDSA_SHA512 => Ok(TslXmlSignatureAlgorithm::EcdsaSha512),
        _ => Err(unsupported_algorithm()),
    }
}

fn is_xades_name(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    expected_local_name: &str,
) -> bool {
    is_expanded_name(
        reader,
        element,
        XADES_132_NAMESPACE,
        expected_local_name,
    )
}

fn is_misnamespaced_xades_core_element(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
) -> bool {
    // EN 319 132-1 defines the baseline containers and basic qualifying
    // properties in the v1.3.2 namespace. The v1.4.1 namespace is reserved
    // for specific later properties and is not an alias for the core grammar.
    const CORE_NAMES: &[&str] = &[
        "QualifyingProperties",
        "SignedProperties",
        "SignedSignatureProperties",
        "SigningTime",
        "SigningCertificateV2",
        "Cert",
        "CertDigest",
        "SignedDataObjectProperties",
        "DataObjectFormat",
        "MimeType",
    ];
    CORE_NAMES.iter().any(|name| {
        is_expanded_name(reader, element, XADES_141_NAMESPACE, name)
    })
}
