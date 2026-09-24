// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn inspect_element(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    depth: usize,
    empty: bool,
    profile: &mut SignatureProfile,
    root_seen: &mut bool,
) -> Result<(), XmlSecError> {
    if element.attributes().count() > MAX_ATTRIBUTES_PER_ELEMENT {
        return Err(profile_violation());
    }
    if profile
        .signing_time_depth
        .is_some_and(|parent| depth > parent)
    {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::InvalidSigningTime,
        ));
    }
    if profile
        .mime_type_depth
        .is_some_and(|parent| depth > parent)
    {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::InvalidDataObjectFormat,
        ));
    }
    if is_misnamespaced_xades_core_element(reader, element) {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::InvalidSignedProperties,
        ));
    }

    let is_root = depth == 1;
    if is_root {
        if *root_seen || !is_expanded_name(reader, element, TSL_NAMESPACE, "TrustServiceStatusList")
        {
            return Err(XmlSecError::PolicyViolation(
                XmlSecPolicyViolationReason::InvalidRootElement,
            ));
        }
        *root_seen = true;
    }

    collect_ids(element, is_root, profile)?;

    if is_expanded_name(reader, element, XMLDSIG_NAMESPACE, "RetrievalMethod") {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::RetrievalMethodNotAllowed,
        ));
    }
    if element.local_name().as_ref() == "KeyInfoReference" {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::KeyInfoReferenceNotAllowed,
        ));
    }
    if is_xades_name(reader, element, "QualifyingPropertiesReference")
        || is_xades_name(reader, element, "SigningCertificate")
        || is_xades_name(reader, element, "SignerRole")
        || is_xades_name(reader, element, "SignatureProductionPlace")
    {
        // ETSI EN 319 132-1 v1.3.1 clause 6.3 requires direct incorporation
        // and prohibits these superseded properties at every baseline level.
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::InvalidSignedProperties,
        ));
    }

    if is_expanded_name(reader, element, XMLDSIG_NAMESPACE, "Signature") {
        profile.signature_count = profile
            .signature_count
            .checked_add(1)
            .ok_or_else(profile_violation)?;
        if depth != 2 || profile.signature_count != 1 {
            return Err(profile_violation());
        }
        profile.signature_depth = Some(depth);
        profile.signature_id = Some(required_attribute(element, "Id")?);
        return Ok(());
    }

    let signature_depth = match profile.signature_depth {
        Some(signature_depth) if depth > signature_depth => signature_depth,
        _ => return Ok(()),
    };

    if is_expanded_name(reader, element, XMLDSIG_NAMESPACE, "SignedInfo") {
        profile.signed_info_count = profile
            .signed_info_count
            .checked_add(1)
            .ok_or_else(profile_violation)?;
        if depth != signature_depth + 1 || profile.signed_info_count != 1 {
            return Err(profile_violation());
        }
        profile.signed_info_depth = Some(depth);
    } else if is_expanded_name(reader, element, XMLDSIG_NAMESPACE, "CanonicalizationMethod") {
        if profile.signed_info_depth.is_none_or(|parent| depth != parent + 1)
            || profile.canonicalization_method_seen
        {
            return Err(profile_violation());
        }
        let algorithm = required_attribute(element, "Algorithm")?;
        // TS 119 612 Annex B.1 requires exclusive canonicalization exactly;
        // accepting C14N 1.1 here changes the signed octet stream profile.
        if algorithm.as_bytes() != C14N_EXCLUSIVE {
            return Err(unsupported_algorithm());
        }
        profile.canonicalization_method_seen = true;
    } else if is_expanded_name(reader, element, XMLDSIG_NAMESPACE, "SignatureMethod") {
        if profile.signed_info_depth.is_none_or(|parent| depth != parent + 1)
            || profile.signature_algorithm.is_some()
        {
            return Err(profile_violation());
        }
        let algorithm = required_attribute(element, "Algorithm")?;
        profile.signature_algorithm = Some(parse_signature_algorithm(&algorithm)?);
    } else if is_expanded_name(reader, element, XMLDSIG_NAMESPACE, "Reference") {
        if profile.signed_info_depth.is_none_or(|parent| depth != parent + 1)
            || profile.current_reference.is_some()
            || profile.references.len() >= MAX_REFERENCES
        {
            return Err(profile_violation());
        }
        let uri = required_attribute(element, "URI")?;
        if !uri.is_empty() && !uri.starts_with('#') {
            return Err(XmlSecError::PolicyViolation(
                XmlSecPolicyViolationReason::NonSameDocumentReference,
            ));
        }
        let reference_type = optional_attribute(element, "Type")?;
        let id = optional_attribute(element, "Id")?;
        profile.references.push(ReferenceProfile {
            id,
            uri,
            reference_type,
            transforms_count: 0,
            transforms: Vec::new(),
            digest_method_seen: false,
        });
        profile.current_reference = profile.references.len().checked_sub(1);
        profile.current_reference_depth = Some(depth);
    } else if is_expanded_name(reader, element, XMLDSIG_NAMESPACE, "Transforms") {
        if profile
            .current_reference_depth
            .is_none_or(|parent| depth != parent + 1)
            || profile.transforms_depth.is_some()
        {
            return Err(profile_violation());
        }
        let reference = current_reference_mut(profile)?;
        reference.transforms_count = reference
            .transforms_count
            .checked_add(1)
            .ok_or_else(profile_violation)?;
        profile.transforms_depth = Some(depth);
    } else if is_expanded_name(reader, element, XMLDSIG_NAMESPACE, "Transform") {
        if profile.transforms_depth.is_none_or(|parent| depth != parent + 1) {
            return Err(profile_violation());
        }
        let reference = current_reference_mut(profile)?;
        if reference.transforms.len() >= 2 {
            return Err(profile_violation());
        }
        let algorithm = required_attribute(element, "Algorithm")?;
        if !matches_allowed(&algorithm, &[TRANSFORM_ENVELOPED_SIGNATURE, C14N_EXCLUSIVE]) {
            return Err(unsupported_algorithm());
        }
        reference.transforms.push(algorithm);
    } else if is_expanded_name(reader, element, XMLDSIG_NAMESPACE, "DigestMethod") {
        let algorithm = required_attribute(element, "Algorithm")?;
        if !matches_allowed(&algorithm, &[DIGEST_SHA256, DIGEST_SHA384, DIGEST_SHA512]) {
            return Err(unsupported_algorithm());
        }
        if profile.certificate_digest_depth.is_some() {
            if profile
                .certificate_digest_depth
                .is_none_or(|parent| depth != parent + 1)
                || profile.certificate_digest_algorithm.is_some()
            {
                return Err(profile_violation());
            }
            profile.certificate_digest_algorithm = Some(parse_digest_algorithm(&algorithm)?);
        } else {
            if profile
                .current_reference_depth
                .is_none_or(|parent| depth != parent + 1)
            {
                return Err(profile_violation());
            }
            let reference = current_reference_mut(profile)?;
            if reference.digest_method_seen {
                return Err(profile_violation());
            }
            reference.digest_method_seen = true;
        }
    } else if is_expanded_name(reader, element, XMLDSIG_NAMESPACE, "KeyInfo") {
        profile.key_info_count = profile
            .key_info_count
            .checked_add(1)
            .ok_or_else(profile_violation)?;
        if depth != signature_depth + 1 || profile.key_info_count != 1 {
            return Err(profile_violation());
        }
        profile.key_info_depth = Some(depth);
    } else if is_expanded_name(reader, element, XMLDSIG_NAMESPACE, "X509Data") {
        profile.x509_data_count = profile
            .x509_data_count
            .checked_add(1)
            .ok_or_else(profile_violation)?;
        if profile.key_info_depth.is_none_or(|parent| depth != parent + 1)
            || profile.x509_data_count != 1
        {
            return Err(profile_violation());
        }
        profile.x509_data_depth = Some(depth);
    } else if is_expanded_name(reader, element, XMLDSIG_NAMESPACE, "X509Certificate") {
        if empty
            || profile
                .x509_data_depth
                .is_none_or(|parent| depth != parent + 1)
            || profile.certificate_text.is_some()
            || profile.key_info_certificates_der.len() >= MAX_KEY_INFO_CERTIFICATES
        {
            return Err(profile_violation());
        }
        profile.certificate_text = Some(String::new());
        profile.x509_certificate_depth = Some(depth);
    } else if is_expanded_name(reader, element, XMLDSIG_NAMESPACE, "KeyValue")
        || is_expanded_name(reader, element, XMLDSIG_NAMESPACE, "KeyName")
    {
        return Err(profile_violation());
    } else if is_expanded_name(reader, element, XMLDSIG_NAMESPACE, "Object") {
        if depth != signature_depth + 1 || profile.object_depth.is_some() {
            return Err(profile_violation());
        }
        profile.object_depth = Some(depth);
    } else if is_xades_name(reader, element, "QualifyingProperties") {
        profile.qualifying_properties_count = profile
            .qualifying_properties_count
            .checked_add(1)
            .ok_or_else(profile_violation)?;
        if profile.object_depth.is_none_or(|parent| depth != parent + 1)
            || profile.qualifying_properties_count != 1
        {
            return Err(XmlSecError::PolicyViolation(
                XmlSecPolicyViolationReason::InvalidSignedProperties,
            ));
        }
        let signature_id = profile.signature_id.as_deref().ok_or_else(profile_violation)?;
        if required_attribute(element, "Target")? != same_document_uri(signature_id)? {
            return Err(XmlSecError::PolicyViolation(
                XmlSecPolicyViolationReason::InvalidSignedProperties,
            ));
        }
        profile.qualifying_properties_depth = Some(depth);
    } else if is_xades_name(reader, element, "SignedProperties") {
        profile.signed_properties_count = profile
            .signed_properties_count
            .checked_add(1)
            .ok_or_else(profile_violation)?;
        if profile
            .qualifying_properties_depth
            .is_none_or(|parent| depth != parent + 1)
            || profile.signed_properties_count != 1
        {
            return Err(XmlSecError::PolicyViolation(
                XmlSecPolicyViolationReason::InvalidSignedProperties,
            ));
        }
        profile.signed_properties_id = Some(required_attribute(element, "Id")?);
        profile.signed_properties_depth = Some(depth);
    } else if is_xades_name(reader, element, "SignedSignatureProperties") {
        profile.signed_signature_properties_count = profile
            .signed_signature_properties_count
            .checked_add(1)
            .ok_or_else(profile_violation)?;
        if profile
            .signed_properties_depth
            .is_none_or(|parent| depth != parent + 1)
            || profile.signed_signature_properties_count != 1
        {
            return Err(XmlSecError::PolicyViolation(
                XmlSecPolicyViolationReason::InvalidSignedProperties,
            ));
        }
        profile.signed_signature_properties_depth = Some(depth);
    } else if is_xades_name(reader, element, "SigningTime") {
        profile.signing_time_count = profile
            .signing_time_count
            .checked_add(1)
            .ok_or_else(profile_violation)?;
        if empty
            || profile
                .signed_signature_properties_depth
                .is_none_or(|parent| depth != parent + 1)
            || profile.signing_time_count != 1
            || profile.signing_time_text.is_some()
            || profile.signing_time_validated
        {
            return Err(XmlSecError::PolicyViolation(
                XmlSecPolicyViolationReason::InvalidSigningTime,
            ));
        }
        profile.signing_time_text = Some(String::new());
        profile.signing_time_depth = Some(depth);
    } else if is_xades_name(reader, element, "SigningCertificateV2") {
        profile.signing_certificate_v2_count = profile
            .signing_certificate_v2_count
            .checked_add(1)
            .ok_or_else(profile_violation)?;
        if profile
            .signed_signature_properties_depth
            .is_none_or(|parent| depth != parent + 1)
            || profile.signing_certificate_v2_count != 1
        {
            return Err(XmlSecError::PolicyViolation(
                XmlSecPolicyViolationReason::InvalidSigningCertificate,
            ));
        }
        profile.signing_certificate_v2_depth = Some(depth);
    } else if is_xades_name(reader, element, "Cert") {
        profile.signing_certificate_cert_count = profile
            .signing_certificate_cert_count
            .checked_add(1)
            .ok_or_else(profile_violation)?;
        if profile
            .signing_certificate_v2_depth
            .is_none_or(|parent| depth != parent + 1)
            || profile.signing_certificate_cert_count != 1
        {
            return Err(XmlSecError::PolicyViolation(
                XmlSecPolicyViolationReason::InvalidSigningCertificate,
            ));
        }
        // EN 319 132-1 clause 6.3 additional requirement i prohibits the
        // optional Cert/@URI indirection in baseline signatures. The digest
        // must identify the certificate embedded in this signature directly.
        if optional_attribute(element, "URI")?.is_some() {
            return Err(XmlSecError::PolicyViolation(
                XmlSecPolicyViolationReason::InvalidSigningCertificate,
            ));
        }
        profile.signing_certificate_cert_depth = Some(depth);
    } else if is_xades_name(reader, element, "CertDigest") {
        if profile
            .signing_certificate_cert_depth
            .is_none_or(|parent| depth != parent + 1)
            || profile.certificate_digest_depth.is_some()
        {
            return Err(profile_violation());
        }
        profile.certificate_digest_depth = Some(depth);
    } else if is_expanded_name(reader, element, XMLDSIG_NAMESPACE, "DigestValue")
        && profile.certificate_digest_depth.is_some()
    {
        if profile
            .certificate_digest_depth
            .is_none_or(|parent| depth != parent + 1)
            || empty
            || profile.certificate_digest_text.is_some()
            || profile.certificate_digest.is_some()
        {
            return Err(profile_violation());
        }
        profile.certificate_digest_text = Some(String::new());
        profile.certificate_digest_value_depth = Some(depth);
    } else if is_xades_name(reader, element, "SignedDataObjectProperties") {
        profile.signed_data_object_properties_count = profile
            .signed_data_object_properties_count
            .checked_add(1)
            .ok_or_else(profile_violation)?;
        if profile
            .signed_properties_depth
            .is_none_or(|parent| depth != parent + 1)
            || profile.signed_data_object_properties_count != 1
        {
            return Err(XmlSecError::PolicyViolation(
                XmlSecPolicyViolationReason::InvalidDataObjectFormat,
            ));
        }
        profile.signed_data_object_properties_depth = Some(depth);
    } else if is_xades_name(reader, element, "DataObjectFormat") {
        if empty
            || profile
                .signed_data_object_properties_depth
                .is_none_or(|parent| depth != parent + 1)
            || profile.current_data_object_format.is_some()
            || profile.data_object_formats.len() >= MAX_REFERENCES
        {
            return Err(XmlSecError::PolicyViolation(
                XmlSecPolicyViolationReason::InvalidDataObjectFormat,
            ));
        }
        let object_reference = required_attribute(element, "ObjectReference")?;
        if !object_reference.starts_with('#') || object_reference.len() == 1 {
            return Err(XmlSecError::PolicyViolation(
                XmlSecPolicyViolationReason::InvalidDataObjectFormat,
            ));
        }
        profile.data_object_formats.push(DataObjectFormatProfile {
            object_reference,
            mime_type: None,
        });
        profile.current_data_object_format = profile.data_object_formats.len().checked_sub(1);
        profile.current_data_object_format_depth = Some(depth);
    } else if is_xades_name(reader, element, "MimeType") {
        if empty
            || profile
                .current_data_object_format_depth
                .is_none_or(|parent| depth != parent + 1)
            || profile.mime_type_text.is_some()
            || profile
                .current_data_object_format
                .and_then(|index| profile.data_object_formats.get(index))
                .is_none_or(|format| format.mime_type.is_some())
        {
            return Err(XmlSecError::PolicyViolation(
                XmlSecPolicyViolationReason::InvalidDataObjectFormat,
            ));
        }
        profile.mime_type_text = Some(String::new());
        profile.mime_type_depth = Some(depth);
    }

    Ok(())
}
