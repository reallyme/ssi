// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
