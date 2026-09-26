// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn enforce_xml_limits_and_namespace(xml: &str) -> Result<(), TslError> {
    if xml.is_empty() || xml.len() > MAX_TSL_XML_BYTES {
        return Err(TslError::ResourceLimit(TslResourceLimit::XmlBytes));
    }
    let mut reader = NsReader::from_str(xml);
    let mut depth = 0_usize;
    let mut element_count = 0_usize;
    let mut text_bytes = 0_usize;
    let mut root_seen = false;
    let mut signature_depth = None;
    let mut extension_depth = None;
    let mut qualification_depth = None;
    let mut digital_id_depth = None;
    let mut other_digital_id_depth = None;
    let mut other_qualifier_depth = None;
    let mut key_value_depth = None;
    let mut critical_extension_depth = None;
    let mut critical_extension_supported = false;
    let mut qualification_path: Vec<QualificationNode> = Vec::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                depth = depth
                    .checked_add(1)
                    .ok_or(TslError::ResourceLimit(TslResourceLimit::XmlDepth))?;
                element_count = element_count
                    .checked_add(1)
                    .ok_or(TslError::ResourceLimit(TslResourceLimit::XmlElements))?;
                if depth > MAX_XML_DEPTH {
                    return Err(TslError::ResourceLimit(TslResourceLimit::XmlDepth));
                }
                if element_count > MAX_XML_ELEMENTS {
                    return Err(TslError::ResourceLimit(TslResourceLimit::XmlElements));
                }
                if element.attributes().count() > MAX_ATTRIBUTES_PER_ELEMENT {
                    return Err(TslError::ResourceLimit(TslResourceLimit::XmlElements));
                }
                let (namespace, local_name) = reader.resolver().resolve_element(element.name());
                if depth == 1 {
                    if root_seen
                        || local_name.as_ref() != "TrustServiceStatusList"
                        || !matches!(namespace, ResolveResult::Bound(value) if value.as_ref() == TSL_NAMESPACE)
                    {
                        return Err(TslError::Xml(TslXmlFailure::Root));
                    }
                    root_seen = true;
                } else {
                    validate_element_namespace(
                        &namespace,
                        local_name.as_ref(),
                        ElementNamespaceContext {
                            depth,
                            signature_depth: &mut signature_depth,
                            extension_depth,
                            qualification_depth,
                            digital_id_depth,
                            other_digital_id_depth,
                            other_qualifier_depth,
                            key_value_depth,
                            critical_extension_depth,
                        },
                    )?;
                }
                let extension_criticality = validate_critical_attribute(
                    &namespace,
                    local_name.as_ref(),
                    &element,
                )?;
                if let Some(critical) = extension_criticality {
                    if extension_depth.is_some() || critical_extension_depth.is_some() {
                        return Err(TslError::Xml(TslXmlFailure::ExtensionNesting));
                    }
                    extension_depth = Some(depth);
                    if critical {
                        critical_extension_depth = Some(depth);
                        critical_extension_supported = false;
                    }
                } else if critical_extension_depth
                    .and_then(|extension_depth| extension_depth.checked_add(1))
                    == Some(depth)
                {
                    if !is_supported_critical_extension_root(&namespace, local_name.as_ref()) {
                        return Err(TslError::UnsupportedCriticalExtension);
                    }
                    critical_extension_supported = true;
                }
                if qualification_depth.is_some_and(|qualification| depth > qualification) {
                    let node = classify_qualification_child(
                        qualification_path.last().copied(),
                        &namespace,
                        local_name.as_ref(),
                        critical_extension_depth.is_some(),
                    )?;
                    qualification_path.push(node);
                } else if is_qualification_root(&namespace, local_name.as_ref()) {
                    qualification_depth = Some(depth);
                    qualification_path.clear();
                    qualification_path.push(QualificationNode::Qualifications);
                }
                if is_tsl_element(&namespace, local_name.as_ref(), "DigitalId") {
                    digital_id_depth = Some(depth);
                }
                if is_tsl_element(&namespace, local_name.as_ref(), "Other")
                    && digital_id_depth.is_some_and(|digital_id| depth > digital_id)
                {
                    other_digital_id_depth = Some(depth);
                }
                if local_name.as_ref() == "OtherQualifier"
                    && matches!(namespace, ResolveResult::Bound(value) if value.as_ref() == TSL_ADDITIONAL_TYPES_NAMESPACE)
                    && critical_extension_depth.is_some()
                {
                    other_qualifier_depth = Some(depth);
                }
                if local_name.as_ref() == "KeyValue"
                    && matches!(namespace, ResolveResult::Bound(value) if value.as_ref() == XMLDSIG_NAMESPACE)
                    && digital_id_depth.is_some_and(|digital_id| depth > digital_id)
                {
                    key_value_depth = Some(depth);
                }
            }
            Ok(Event::Empty(element)) => {
                depth = depth
                    .checked_add(1)
                    .ok_or(TslError::ResourceLimit(TslResourceLimit::XmlDepth))?;
                element_count = element_count
                    .checked_add(1)
                    .ok_or(TslError::ResourceLimit(TslResourceLimit::XmlElements))?;
                if depth > MAX_XML_DEPTH || element_count > MAX_XML_ELEMENTS {
                    return Err(TslError::ResourceLimit(TslResourceLimit::XmlElements));
                }
                if element.attributes().count() > MAX_ATTRIBUTES_PER_ELEMENT {
                    return Err(TslError::ResourceLimit(TslResourceLimit::XmlElements));
                }
                let (namespace, local_name) = reader.resolver().resolve_element(element.name());
                if depth == 1 {
                    if root_seen
                        || local_name.as_ref() != "TrustServiceStatusList"
                        || !matches!(namespace, ResolveResult::Bound(value) if value.as_ref() == TSL_NAMESPACE)
                    {
                        return Err(TslError::Xml(TslXmlFailure::Root));
                    }
                    root_seen = true;
                } else {
                    validate_element_namespace(
                        &namespace,
                        local_name.as_ref(),
                        ElementNamespaceContext {
                            depth,
                            signature_depth: &mut signature_depth,
                            extension_depth,
                            qualification_depth,
                            digital_id_depth,
                            other_digital_id_depth,
                            other_qualifier_depth,
                            key_value_depth,
                            critical_extension_depth,
                        },
                    )?;
                }
                let extension_criticality = validate_critical_attribute(
                    &namespace,
                    local_name.as_ref(),
                    &element,
                )?;
                if extension_criticality == Some(true) {
                    return Err(TslError::UnsupportedCriticalExtension);
                }
                if critical_extension_depth
                    .and_then(|extension_depth| extension_depth.checked_add(1))
                    == Some(depth)
                {
                    if !is_supported_critical_extension_root(&namespace, local_name.as_ref()) {
                        return Err(TslError::UnsupportedCriticalExtension);
                    }
                    critical_extension_supported = true;
                }
                if qualification_depth.is_some_and(|qualification| depth > qualification) {
                    classify_qualification_child(
                        qualification_path.last().copied(),
                        &namespace,
                        local_name.as_ref(),
                        critical_extension_depth.is_some(),
                    )?;
                }
                if signature_depth == Some(depth) {
                    signature_depth = None;
                }
                depth = depth
                    .checked_sub(1)
                    .ok_or(TslError::Xml(TslXmlFailure::Unbalanced))?;
            }
            Ok(Event::End(_)) => {
                if qualification_depth.is_some_and(|qualification| depth > qualification) {
                    qualification_path.pop();
                }
                if qualification_depth == Some(depth) {
                    qualification_depth = None;
                    qualification_path.clear();
                }
                if digital_id_depth == Some(depth) {
                    digital_id_depth = None;
                }
                if other_digital_id_depth == Some(depth) {
                    other_digital_id_depth = None;
                }
                if other_qualifier_depth == Some(depth) {
                    other_qualifier_depth = None;
                }
                if key_value_depth == Some(depth) {
                    key_value_depth = None;
                }
                if critical_extension_depth == Some(depth) {
                    if !critical_extension_supported {
                        return Err(TslError::UnsupportedCriticalExtension);
                    }
                    critical_extension_depth = None;
                    critical_extension_supported = false;
                }
                if extension_depth == Some(depth) {
                    extension_depth = None;
                }
                if signature_depth == Some(depth) {
                    signature_depth = None;
                }
                depth = depth
                    .checked_sub(1)
                    .ok_or(TslError::Xml(TslXmlFailure::Unbalanced))?;
            }
            Ok(Event::Text(text)) => {
                text_bytes = text_bytes
                    .checked_add(text.len())
                    .ok_or(TslError::ResourceLimit(TslResourceLimit::XmlText))?;
                if text_bytes > MAX_XML_TEXT_BYTES {
                    return Err(TslError::ResourceLimit(TslResourceLimit::XmlText));
                }
            }
            Ok(Event::CData(text)) => {
                text_bytes = text_bytes
                    .checked_add(text.len())
                    .ok_or(TslError::ResourceLimit(TslResourceLimit::XmlText))?;
                if text_bytes > MAX_XML_TEXT_BYTES {
                    return Err(TslError::ResourceLimit(TslResourceLimit::XmlText));
                }
            }
            Ok(Event::DocType(_)) => return Err(TslError::Xml(TslXmlFailure::DocumentType)),
            Ok(Event::Eof) => break,
            Err(_) => return Err(TslError::Xml(TslXmlFailure::Syntax)),
            _ => {}
        }
    }
    if !root_seen || depth != 0 {
        return Err(TslError::Xml(TslXmlFailure::Unbalanced));
    }
    Ok(())
}

fn validate_critical_attribute(
    namespace: &ResolveResult<'_>,
    local_name: &str,
    element: &BytesStart<'_>,
) -> Result<Option<bool>, TslError> {
    // ETSI TS 119 612 V2.4.1 clauses 5.3.17 and B.0 adopt RFC 5280's
    // fail-closed critical-extension semantics. This streaming pass validates
    // the lexical boolean. Semantic recognition is performed after bounded
    // deserialization, where the complete extension child is available.
    let is_extension = local_name == "Extension"
        && matches!(namespace, ResolveResult::Bound(value) if value.as_ref() == TSL_NAMESPACE);
    if is_extension {
        return is_critical_extension(element).map(Some);
    }
    Ok(None)
}

fn is_tsl_element(namespace: &ResolveResult<'_>, local_name: &str, expected: &str) -> bool {
    local_name == expected
        && matches!(namespace, ResolveResult::Bound(value) if value.as_ref() == TSL_NAMESPACE)
}

fn is_qualification_root(namespace: &ResolveResult<'_>, local_name: &str) -> bool {
    local_name == "Qualifications"
        && matches!(
            namespace,
            ResolveResult::Bound(value) if value.as_ref() == TSL_QUALIFICATIONS_NAMESPACE
        )
}

fn is_supported_critical_extension_root(
    namespace: &ResolveResult<'_>,
    local_name: &str,
) -> bool {
    matches!(
        namespace,
        ResolveResult::Bound(value)
            if (value.as_ref() == TSL_NAMESPACE
                && local_name == "AdditionalServiceInformation")
                || (value.as_ref() == TSL_ADDITIONAL_TYPES_NAMESPACE
                    && local_name == "TakenOverBy")
                || (value.as_ref() == TSL_QUALIFICATIONS_NAMESPACE
                    && local_name == "Qualifications")
    )
}

fn is_critical_extension(element: &BytesStart<'_>) -> Result<bool, TslError> {
    let mut critical = None;
    for attribute in element.attributes().with_checks(true) {
        let attribute =
            attribute.map_err(|_| TslError::Xml(TslXmlFailure::CriticalAttribute))?;
        if attribute.key.as_ref() != "Critical" {
            continue;
        }
        if critical.is_some() {
            return Err(TslError::Xml(TslXmlFailure::CriticalAttribute));
        }
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|_| TslError::Xml(TslXmlFailure::CriticalAttribute))?;
        critical = Some(match value.as_ref() {
            "true" | "1" => true,
            "false" | "0" => false,
            _ => return Err(TslError::Xml(TslXmlFailure::CriticalAttribute)),
        });
    }
    Ok(critical.unwrap_or(false))
}

struct ElementNamespaceContext<'a> {
    depth: usize,
    signature_depth: &'a mut Option<usize>,
    extension_depth: Option<usize>,
    qualification_depth: Option<usize>,
    digital_id_depth: Option<usize>,
    other_digital_id_depth: Option<usize>,
    other_qualifier_depth: Option<usize>,
    key_value_depth: Option<usize>,
    critical_extension_depth: Option<usize>,
}

fn validate_element_namespace(
    namespace: &ResolveResult<'_>,
    local_name: &str,
    context: ElementNamespaceContext<'_>,
) -> Result<(), TslError> {
    let ElementNamespaceContext {
        depth,
        signature_depth,
        extension_depth,
        qualification_depth,
        digital_id_depth,
        other_digital_id_depth,
        other_qualifier_depth,
        key_value_depth,
        critical_extension_depth,
    } = context;
    let ResolveResult::Bound(namespace) = namespace else {
        return Err(TslError::Xml(TslXmlFailure::ElementNamespace));
    };
    if other_digital_id_depth.is_some_and(|other| depth > other)
        || other_qualifier_depth.is_some_and(|other| depth > other)
    {
        // `Other` is xsd:anyType. Its subtree is ignored only when a PKI
        // representation independently identifies the service; the typed
        // projection still rejects a structured `Other` used by itself.
        return Ok(());
    }
    if extension_depth.is_some() && critical_extension_depth.is_none() {
        // TS 119 612 v2.4.1 clause B.0 permits applications to ignore an
        // unrecognized non-critical extension. Namespace enforcement must
        // therefore accept its bounded XML subtree; the typed projection
        // still ignores it, while critical extensions remain fail-closed.
        return Ok(());
    }
    match namespace.as_ref() {
        value if value == TSL_NAMESPACE && signature_depth.is_none() => {
            if critical_extension_depth
                .and_then(|extension| extension.checked_add(1))
                .is_some_and(|extension_child_depth| depth > extension_child_depth)
                && !matches!(
                    local_name,
                    "URI"
                        | "InformationValue"
                        | "OtherInformation"
                        | "SchemeOperatorName"
                        | "Name"
                        | "SchemeTerritory"
                )
            {
                return Err(TslError::UnsupportedCriticalExtension);
            }
            Ok(())
        }
        value if value == XMLDSIG_NAMESPACE => {
            if signature_depth.is_none() {
                if is_xml_dsig_key_value_element(local_name)
                    && digital_id_depth.is_some_and(|digital_id| depth > digital_id)
                {
                    return Ok(());
                }
                if local_name != "Signature" {
                    return Err(TslError::Xml(TslXmlFailure::ElementNamespace));
                }
                *signature_depth = Some(depth);
            }
            Ok(())
        }
        value
            if signature_depth.is_none()
                && value == XMLDSIG11_NAMESPACE
                && key_value_depth.is_some_and(|key_value| depth > key_value)
                && matches!(local_name, "ECKeyValue" | "NamedCurve" | "PublicKey") =>
        {
            // XML Signature 1.1 section 4.5.2 places ECKeyValue in the
            // xmldsig11 namespace even though it is selected from ds:KeyValue.
            Ok(())
        }
        value
            if signature_depth.is_some()
                && matches!(value, XADES_132_NAMESPACE | XADES_141_NAMESPACE) =>
        {
            Ok(())
        }
        value
            if signature_depth.is_none()
                && value == TSL_ADDITIONAL_TYPES_NAMESPACE
                && (local_name == "MimeType"
                    || (critical_extension_depth.is_some()
                        && matches!(
                            local_name,
                            "TakenOverBy" | "URI" | "TSPName" | "OtherQualifier"
                        ))) =>
        {
            Ok(())
        }
        value
            if signature_depth.is_none()
                && qualification_depth.is_some()
                && value == TSL_ADDITIONAL_TYPES_NAMESPACE
                && matches!(
                    local_name,
                    "ExtendedKeyUsage"
                        | "KeyPurposeId"
                        | "CertSubjectDNAttribute"
                        | "AttributeOID"
                ) =>
        {
            Ok(())
        }
        value
            if signature_depth.is_none()
                && value == TSL_QUALIFICATIONS_NAMESPACE
                && (qualification_depth.is_some()
                    || (local_name == "Qualifications"
                        && extension_depth
                            .and_then(|extension| extension.checked_add(1))
                            == Some(depth))) =>
        {
            if qualification_depth.is_some()
                && !is_supported_qualification_element(local_name)
            {
                return if critical_extension_depth.is_some() {
                    Err(TslError::UnsupportedCriticalExtension)
                } else {
                    Err(TslError::Qualification(
                        TslQualificationFailure::UnsupportedSemantics,
                    ))
                };
            }
            Ok(())
        }
        value
            if signature_depth.is_none()
                && qualification_depth.is_some()
                && value == XADES_132_NAMESPACE
                && matches!(
                    local_name,
                    "Identifier"
                        | "Description"
                        | "DocumentationReferences"
                        | "DocumentationReference"
                ) =>
        {
            Ok(())
        }
        _ if digital_id_depth.is_some() => Err(TslError::DigitalIdentity(
            TslDigitalIdentityFailure::UnsupportedOtherRepresentation,
        )),
        _ => Err(TslError::Xml(TslXmlFailure::ElementNamespace)),
    }
}

include!("boundary/elements.rs");
include!("boundary/qualification_structure.rs");
