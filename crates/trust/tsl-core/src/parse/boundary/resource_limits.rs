// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Validate only bounded XML structure before signature authentication.
///
/// Semantic namespace, extension, and qualification checks intentionally run
/// after XMLDSig authentication. This pass limits parser work and rejects an
/// invalid document envelope without exposing unauthenticated semantics.
pub fn validate_tsl_xml_boundary(xml: &str) -> Result<(), TslError> {
    if xml.is_empty() || xml.len() > MAX_TSL_XML_BYTES {
        return Err(TslError::ResourceLimit(TslResourceLimit::XmlBytes));
    }

    let mut reader = NsReader::from_str(xml);
    let mut depth = 0_usize;
    let mut element_count = 0_usize;
    let mut text_bytes = 0_usize;
    let mut root_seen = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => register_boundary_element(
                &reader,
                &element,
                &mut depth,
                &mut element_count,
                &mut root_seen,
            )?,
            Ok(Event::Empty(element)) => {
                register_boundary_element(
                    &reader,
                    &element,
                    &mut depth,
                    &mut element_count,
                    &mut root_seen,
                )?;
                depth = depth
                    .checked_sub(1)
                    .ok_or(TslError::Xml(TslXmlFailure::Unbalanced))?;
            }
            Ok(Event::End(_)) => {
                depth = depth
                    .checked_sub(1)
                    .ok_or(TslError::Xml(TslXmlFailure::Unbalanced))?;
            }
            Ok(Event::Text(text)) => {
                if depth == 0 && !text.as_ref().bytes().all(|byte| byte.is_ascii_whitespace()) {
                    return Err(TslError::Xml(TslXmlFailure::Root));
                }
                text_bytes = text_bytes
                    .checked_add(text.len())
                    .ok_or(TslError::ResourceLimit(TslResourceLimit::XmlText))?;
                if text_bytes > MAX_XML_TEXT_BYTES {
                    return Err(TslError::ResourceLimit(TslResourceLimit::XmlText));
                }
            }
            Ok(Event::CData(text)) => {
                if depth == 0 {
                    return Err(TslError::Xml(TslXmlFailure::Root));
                }
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

fn register_boundary_element(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    depth: &mut usize,
    element_count: &mut usize,
    root_seen: &mut bool,
) -> Result<(), TslError> {
    *depth = depth
        .checked_add(1)
        .ok_or(TslError::ResourceLimit(TslResourceLimit::XmlDepth))?;
    *element_count = element_count
        .checked_add(1)
        .ok_or(TslError::ResourceLimit(TslResourceLimit::XmlElements))?;
    if *depth > MAX_XML_DEPTH {
        return Err(TslError::ResourceLimit(TslResourceLimit::XmlDepth));
    }
    if *element_count > MAX_XML_ELEMENTS
        || element.attributes().count() > MAX_ATTRIBUTES_PER_ELEMENT
    {
        return Err(TslError::ResourceLimit(TslResourceLimit::XmlElements));
    }
    if *depth == 1 {
        let (namespace, local_name) = reader.resolver().resolve_element(element.name());
        if *root_seen
            || local_name.as_ref() != "TrustServiceStatusList"
            || !matches!(namespace, ResolveResult::Bound(value) if value.as_ref() == TSL_NAMESPACE)
        {
            return Err(TslError::Xml(TslXmlFailure::Root));
        }
        *root_seen = true;
    }
    Ok(())
}
