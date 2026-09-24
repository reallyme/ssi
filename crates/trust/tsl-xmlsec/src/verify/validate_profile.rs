// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn validate_complete_profile(
    root_seen: bool,
    profile: &SignatureProfile,
) -> Result<(), XmlSecError> {
    if !root_seen {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::MissingRootElement,
        ));
    }
    if profile.signature_count != 1
        || profile.signed_info_count != 1
        || !profile.canonicalization_method_seen
        || profile.signature_algorithm.is_none()
        || profile.key_info_count != 1
        || profile.x509_data_count != 1
        || profile.qualifying_properties_count != 1
        || profile.signed_signature_properties_count != 1
        || profile.certificate_text.is_some()
    {
        return Err(profile_violation());
    }

    if profile.signing_time_count != 1
        || !profile.signing_time_validated
        || profile.signing_time_text.is_some()
    {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::InvalidSigningTime,
        ));
    }

    if profile.key_info_certificates_der.len() != 1 {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::KeyInfoCertificateCount,
        ));
    }

    let expected_root_uri = profile
        .root_id
        .as_deref()
        .map(same_document_uri)
        .transpose()?;
    let root_references: Vec<&ReferenceProfile> = profile
        .references
        .iter()
        .filter(|reference| {
            // XML Signature 1.1 section 4.4.3 permits an empty URI to identify
            // the same XML document. TS 119 612 v2.4.1 Annex B.1 requires the
            // reference to cover the enveloping TrustServiceStatusList but
            // does not require ID-based addressing. The unique document root,
            // signature, and transform checks below retain the wrapping guard.
            reference.reference_type.is_none()
                && (reference.uri.is_empty()
                    || expected_root_uri
                        .as_deref()
                        .is_some_and(|expected| reference.uri == expected))
        })
        .collect();
    if root_references.len() != 1 {
        return Err(profile_violation());
    }
    let root_reference = root_references[0];
    if root_reference.transforms_count != 1
        || root_reference.transforms.len() != 2
        || root_reference.transforms[0].as_bytes() != TRANSFORM_ENVELOPED_SIGNATURE
        || root_reference.transforms[1].as_bytes() != C14N_EXCLUSIVE
        || !root_reference.digest_method_seen
    {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::RootTransformProfile,
        ));
    }

    let signed_properties_id = profile.signed_properties_id.as_deref().ok_or(
        XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::InvalidSignedProperties),
    )?;
    let expected_signed_properties_uri = same_document_uri(signed_properties_id)?;
    let signed_properties_references: Vec<&ReferenceProfile> = profile
        .references
        .iter()
        .filter(|reference| reference.reference_type.as_deref() == Some(SIGNED_PROPERTIES_TYPE))
        .collect();
    if profile.signed_properties_count != 1
        || signed_properties_references.len() != 1
        || signed_properties_references[0].uri != expected_signed_properties_uri
        || signed_properties_references[0].transforms_count > 1
        || signed_properties_references[0].transforms.len() > 1
        || signed_properties_references[0]
            .transforms
            .first()
            .is_some_and(|value| value.as_bytes() != C14N_EXCLUSIVE)
        || !signed_properties_references[0].digest_method_seen
    {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::InvalidSignedProperties,
        ));
    }

    let signed_data_references: Vec<&ReferenceProfile> = profile
        .references
        .iter()
        .filter(|reference| reference.reference_type.as_deref() != Some(SIGNED_PROPERTIES_TYPE))
        .collect();
    if profile.signed_data_object_properties_count != 1
        || profile.data_object_formats.len() != signed_data_references.len()
        || profile.mime_type_text.is_some()
    {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::InvalidDataObjectFormat,
        ));
    }

    // ETSI EN 319 132-1 v1.3.1 clause 6.3 (table 2, requirements k and l)
    // requires one DataObjectFormat with a MIME type for every signed data
    // object other than SignedProperties. Requiring a bijection prevents a
    // duplicate format from masking an unclassified signed object.
    for reference in &signed_data_references {
        let reference_id = reference.id.as_deref().ok_or(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::InvalidDataObjectFormat,
        ))?;
        let expected_reference = same_document_uri(reference_id)?;
        let matching_formats: Vec<&DataObjectFormatProfile> = profile
            .data_object_formats
            .iter()
            .filter(|format| format.object_reference == expected_reference)
            .collect();
        if matching_formats.len() != 1 || matching_formats[0].mime_type.is_none() {
            return Err(XmlSecError::PolicyViolation(
                XmlSecPolicyViolationReason::InvalidDataObjectFormat,
            ));
        }
    }
    let root_reference_id = root_reference.id.as_deref().ok_or(
        XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::InvalidDataObjectFormat),
    )?;
    let root_object_reference = same_document_uri(root_reference_id)?;
    if !profile.data_object_formats.iter().any(|format| {
        format.object_reference == root_object_reference
            && format
                .mime_type
                .as_deref()
                .is_some_and(is_xml_data_object_mime_type)
    }) {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::InvalidDataObjectFormat,
        ));
    }

    for reference in &profile.references {
        if !reference.uri.is_empty()
            && !profile
                .ids
                .iter()
                .any(|id| reference.uri.strip_prefix('#') == Some(id.as_str()))
        {
            return Err(profile_violation());
        }
        if !reference.digest_method_seen {
            return Err(profile_violation());
        }
    }

    if profile.signing_certificate_v2_count != 1
        || profile.signing_certificate_cert_count != 1
        || profile.certificate_digest_algorithm.is_none()
        || profile.certificate_digest.is_none()
        || profile.certificate_digest_text.is_some()
    {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::InvalidSigningCertificate,
        ));
    }
    Ok(())
}

fn is_xml_data_object_mime_type(value: &str) -> bool {
    // EN 319 132-1 v1.3.1 clause 6.3 requires a MIME declaration for the
    // signed data object; it does not import TS 119 612 clause 6.2.1.1's HTTP
    // transport Content-Type into XAdES. RFC 7303 registers application/xml
    // and text/xml, while application/vnd.etsi.tsl+xml is the TS-specific XML
    // media type. Current EU LOTL and national TL signatures use text/xml.
    matches!(
        value,
        TSL_MIME_TYPE | APPLICATION_XML_MIME_TYPE | TEXT_XML_MIME_TYPE
    )
}

fn same_document_uri(id: &str) -> Result<String, XmlSecError> {
    let capacity = id.len().checked_add(1).ok_or_else(profile_violation)?;
    let mut uri = String::new();
    uri.try_reserve_exact(capacity)
        .map_err(|_| profile_violation())?;
    uri.push('#');
    uri.push_str(id);
    Ok(uri)
}

fn is_expanded_name(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    expected_namespace: &str,
    expected_local_name: &str,
) -> bool {
    let (namespace, local_name) = reader.resolver().resolve_element(element.name());
    local_name.as_ref() == expected_local_name
        && matches!(namespace, ResolveResult::Bound(value) if value.as_ref() == expected_namespace)
}

fn required_attribute(element: &BytesStart<'_>, name: &str) -> Result<String, XmlSecError> {
    let mut found: Option<String> = None;
    for attribute in element.attributes().with_checks(true) {
        let attribute = attribute.map_err(|_| XmlSecError::Internal)?;
        if attribute.key.as_ref() == name {
            if found.is_some() {
                return Err(profile_violation());
            }
            let value = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(|_| XmlSecError::Internal)?;
            found = Some(value.as_ref().to_owned());
        }
    }
    found.ok_or_else(profile_violation)
}

fn optional_attribute(element: &BytesStart<'_>, name: &str) -> Result<Option<String>, XmlSecError> {
    let mut found: Option<String> = None;
    for attribute in element.attributes().with_checks(true) {
        let attribute = attribute.map_err(|_| XmlSecError::Internal)?;
        if attribute.key.as_ref() == name {
            if found.is_some() {
                return Err(profile_violation());
            }
            let value = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(|_| XmlSecError::Internal)?;
            found = Some(value.as_ref().to_owned());
        }
    }
    Ok(found)
}

fn matches_allowed(value: &str, allowed: &[&[u8]]) -> bool {
    allowed.contains(&value.as_bytes())
}

fn profile_violation() -> XmlSecError {
    XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::InvalidSignatureProfile)
}

fn unsupported_algorithm() -> XmlSecError {
    XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::UnsupportedAlgorithm)
}

#[cfg(feature = "xmlsec-ffi")]
pub(super) fn verify_xmlsec_backend(
    xml: &str,
    trusted_pem_path: &str,
    verification_time_unix: i64,
    allow_trusted_leaf: bool,
) -> Result<Vec<u8>, XmlSecError> {
    use std::ffi::CString;
    use std::sync::{Mutex, OnceLock};

    static XMLSEC_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = XMLSEC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| XmlSecError::Internal)?;

    let xml_c = CString::new(xml).map_err(|_| XmlSecError::Internal)?;
    let pem_c = CString::new(trusted_pem_path).map_err(|_| XmlSecError::Internal)?;
    let mut signer_der = vec![0_u8; MAX_SIGNER_DER_BYTES];
    let mut signer_der_len = 0_usize;

    // SAFETY: every pointer is valid for the duration of the serialized call.
    // The input lengths describe their originating allocations; the output
    // pointer has exactly `MAX_SIGNER_DER_BYTES` writable bytes; the C shim
    // checks capacity before encoding and retains no pointer.
    #[allow(unsafe_code)]
    let rc = unsafe {
        identity_trust_tsl_xmlsec_sys::meid_xmlsec_verify_tsl(
            xml_c.as_ptr(),
            xml_c.as_bytes().len(),
            pem_c.as_ptr(),
            verification_time_unix,
            i32::from(allow_trusted_leaf),
            signer_der.as_mut_ptr(),
            signer_der.len(),
            &mut signer_der_len,
        )
    };

    let backend_error = match rc {
        0 => None,
        -12 => Some(XmlSecError::SchemaValidationFailed),
        -5 | -10 => Some(XmlSecError::InvalidSignature),
        _ => Some(XmlSecError::Internal),
    };
    if let Some(error) = backend_error {
        signer_der.zeroize();
        return Err(error);
    }
    if signer_der_len == 0 || signer_der_len > signer_der.len() {
        signer_der.zeroize();
        return Err(XmlSecError::Internal);
    }
    signer_der[signer_der_len..].zeroize();
    signer_der.truncate(signer_der_len);
    Ok(signer_der)
}

#[cfg(not(feature = "xmlsec-ffi"))]
pub(super) fn verify_xmlsec_backend(
    _xml: &str,
    _trusted_pem_path: &str,
    _verification_time_unix: i64,
    _allow_trusted_leaf: bool,
) -> Result<Vec<u8>, XmlSecError> {
    Err(XmlSecError::BackendUnavailable)
}
