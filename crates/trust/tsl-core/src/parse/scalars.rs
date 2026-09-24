// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn parse_names(raw: RawInternationalNames) -> Result<Vec<LocalizedText>, TslError> {
    if raw.names.is_empty() || raw.names.len() > MAX_NAMES_PER_FIELD {
        return Err(TslError::InvalidStructure(
            TslStructureFailure::MultilingualName,
        ));
    }
    raw.names
        .into_iter()
        .map(|name| {
            let language = parse_language_tag(name.language.ok_or(TslError::InvalidStructure(
                TslStructureFailure::MultilingualName,
            ))?)
            .map_err(|_| TslError::InvalidStructure(TslStructureFailure::MultilingualName))?;
            let value = bounded_multilingual_text(name.value.ok_or(TslError::InvalidStructure(
                TslStructureFailure::MultilingualName,
            ))?)
            .map_err(|_| TslError::InvalidStructure(TslStructureFailure::MultilingualName))?;
            Ok(LocalizedText { language, value })
        })
        .collect()
}

fn parse_language_tag(value: String) -> Result<String, TslError> {
    const MAX_LANGUAGE_TAG_BYTES: usize = 35;
    if value.is_empty()
        || value.len() > MAX_LANGUAGE_TAG_BYTES
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
        || !language_tag_has_valid_shape(&value)
    {
        return Err(TslError::InvalidStructure(TslStructureFailure::Text));
    }
    Ok(value)
}

fn parse_pointer_language_tag(value: String) -> Result<String, TslError> {
    const MAX_LANGUAGE_TAG_BYTES: usize = 35;
    if value.is_empty() || value.len() > MAX_LANGUAGE_TAG_BYTES || !value.is_ascii() {
        return Err(TslError::InvalidStructure(TslStructureFailure::Text));
    }
    // RFC 5646 tags are case-insensitive. Clause 5.1.4 adds a lower-case
    // constraint for multilingual character strings, but deliberately omits
    // it for multilingual pointers. Normalize pointer tags so downstream
    // equality remains deterministic without rejecting valid source casing.
    let normalized = value.to_ascii_lowercase();
    if !language_tag_has_valid_shape(&normalized) {
        return Err(TslError::InvalidStructure(TslStructureFailure::Text));
    }
    Ok(normalized)
}

fn language_tag_has_valid_shape(value: &str) -> bool {
    let subtags: Vec<&str> = value.split('-').collect();
    if subtags.iter().any(|subtag| subtag.is_empty()) {
        return false;
    }
    let mut index = 0_usize;
    if subtags.first() == Some(&"x") {
        return subtags.len() > 1 && subtags[1..].iter().all(|subtag| valid_alphanumeric(subtag, 1, 8));
    }
    let Some(primary) = subtags.first() else {
        return false;
    };
    if !(2..=8).contains(&primary.len()) || !primary.bytes().all(|byte| byte.is_ascii_lowercase()) {
        return false;
    }
    index += 1;

    let mut extlang_count = 0_usize;
    while primary.len() <= 3
        && extlang_count < 3
        && subtags.get(index).is_some_and(|subtag| {
            subtag.len() == 3 && subtag.bytes().all(|byte| byte.is_ascii_lowercase())
        })
    {
        index += 1;
        extlang_count += 1;
    }
    if subtags.get(index).is_some_and(|subtag| {
        subtag.len() == 4 && subtag.bytes().all(|byte| byte.is_ascii_lowercase())
    }) {
        index += 1;
    }
    if subtags.get(index).is_some_and(|subtag| {
        (subtag.len() == 2 && subtag.bytes().all(|byte| byte.is_ascii_lowercase()))
            || (subtag.len() == 3 && subtag.bytes().all(|byte| byte.is_ascii_digit()))
    }) {
        index += 1;
    }
    while subtags.get(index).is_some_and(|subtag| {
        valid_alphanumeric(subtag, 5, 8)
            || (subtag.len() == 4
                && subtag.as_bytes().first().is_some_and(u8::is_ascii_digit)
                && subtag.bytes().all(|byte| byte.is_ascii_alphanumeric()))
    }) {
        index += 1;
    }
    while subtags.get(index).is_some_and(|subtag| {
        subtag.len() == 1
            && subtag != &"x"
            && subtag.bytes().all(|byte| byte.is_ascii_alphanumeric())
    }) {
        index += 1;
        let extension_start = index;
        while subtags
            .get(index)
            .is_some_and(|subtag| valid_alphanumeric(subtag, 2, 8))
        {
            index += 1;
        }
        if index == extension_start {
            return false;
        }
    }
    if subtags.get(index) == Some(&"x") {
        index += 1;
        let private_use_start = index;
        while subtags
            .get(index)
            .is_some_and(|subtag| valid_alphanumeric(subtag, 1, 8))
        {
            index += 1;
        }
        if index == private_use_start {
            return false;
        }
    }
    index == subtags.len()
}

fn valid_alphanumeric(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn parse_timestamp(value: String) -> Result<TslTimestamp, TslError> {
    parse_utc_timestamp(&value).map(tsl_timestamp)
}

fn parse_utc_timestamp(value: &str) -> Result<OffsetDateTime, TslError> {
    if value.is_empty() || value.len() > 64 {
        return Err(TslError::InvalidTimestamp);
    }
    let timestamp =
        OffsetDateTime::parse(value, &Rfc3339).map_err(|_| TslError::InvalidTimestamp)?;
    if timestamp.offset() != UtcOffset::UTC {
        return Err(TslError::InvalidTimestamp);
    }
    Ok(timestamp)
}

fn tsl_timestamp(timestamp: OffsetDateTime) -> TslTimestamp {
    TslTimestamp::new(
        timestamp.unix_timestamp(),
        timestamp.nanosecond(),
    )
}

fn parse_uri(value: String) -> Result<TslUri, TslError> {
    if value.is_empty()
        || value.len() > MAX_TSL_URI_BYTES
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err(TslError::InvalidUri);
    }
    if url::Url::parse(&value).is_err() {
        return Err(TslError::InvalidUri);
    }
    Ok(TslUri::new(value))
}

fn parse_service_type(value: String) -> Result<TrustServiceType, TslError> {
    let uri = parse_uri(value)?;
    let typed = match uri.as_str() {
        "http://uri.etsi.org/TrstSvc/Svctype/CA/QC" => TrustServiceType::CaQualifiedCertificates,
        "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC" => {
            TrustServiceType::OcspQualifiedCertificates
        }
        "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST" => TrustServiceType::QualifiedTimestamp,
        "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q" => {
            TrustServiceType::QualifiedElectronicAttestation
        }
        _ => TrustServiceType::Other(uri),
    };
    Ok(typed)
}

fn parse_service_status(value: String) -> Result<TrustServiceStatus, TslError> {
    let uri = parse_uri(value)?;
    let typed = match uri.as_str() {
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted" => TrustServiceStatus::Granted,
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/expired" => TrustServiceStatus::Expired,
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn" => {
            TrustServiceStatus::Withdrawn
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel" => {
            TrustServiceStatus::DeprecatedAtNationalLevel
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel" => {
            TrustServiceStatus::RecognisedAtNationalLevel
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision" => {
            TrustServiceStatus::UnderSupervision
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionceased" => {
            TrustServiceStatus::SupervisionCeased
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionrevoked" => {
            TrustServiceStatus::SupervisionRevoked
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited" => {
            TrustServiceStatus::Accredited
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationceased" => {
            TrustServiceStatus::AccreditationCeased
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked" => {
            TrustServiceStatus::AccreditationRevoked
        }
        _ => TrustServiceStatus::Other(uri),
    };
    Ok(typed)
}

fn bounded_text(value: String) -> Result<String, TslError> {
    let value = bounded_xml_string(value)?;
    // XML Schema Part 2 defines normalizedString with the whiteSpace facet
    // fixed to "replace". ETSI TS 119 612 uses normalizedString-derived
    // types for names and identifiers, so the portable parser must apply the
    // same tab/CR/LF replacement as an XSD-validating processor. Rejecting
    // those code points would incorrectly reject schema-valid trusted lists.
    let mut bytes = value.into_bytes();
    for byte in &mut bytes {
        if matches!(*byte, b'\t' | b'\n' | b'\r') {
            *byte = b' ';
        }
    }
    String::from_utf8(bytes)
        .map_err(|_| TslError::InvalidStructure(TslStructureFailure::Text))
}

fn bounded_multilingual_text(value: String) -> Result<String, TslError> {
    let value = bounded_xml_string(value)?;
    if value.chars().any(is_prohibited_multilingual_character) {
        return Err(TslError::InvalidStructure(TslStructureFailure::Text));
    }
    Ok(value)
}

fn bounded_multilingual_legal_notice_text(value: String) -> Result<String, TslError> {
    // Annex E.2 prohibits control characters in multilingual strings. The
    // signed Commission LOTL nevertheless serializes paragraph boundaries in
    // TSLLegalNotice as TAB/CR/LF. Treat those three layout characters as
    // spaces before applying the Annex E.2 character restrictions. Keeping
    // this compatibility rule specific to legal notices prevents a deployed
    // LOTL quirk from weakening names, addresses, or other identity fields.
    let value = bounded_text(value)?;
    if value.chars().any(is_prohibited_multilingual_character) {
        return Err(TslError::InvalidStructure(TslStructureFailure::Text));
    }
    Ok(value)
}

fn is_prohibited_multilingual_character(character: char) -> bool {
    matches!(character, '\t' | '\n' | '\r')
        || matches!(
            u32::from(character),
            0xE000..=0xF8FF
                | 0xE0000..=0xE007F
                | 0xF0000..=0xFFFFD
                | 0x100000..=0x10FFFD
        )
}

fn bounded_xml_string(value: String) -> Result<String, TslError> {
    if value.is_empty()
        || value.len() > MAX_TEXT_FIELD_BYTES
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\t' | '\n' | '\r'))
    {
        return Err(TslError::InvalidStructure(TslStructureFailure::Text));
    }
    Ok(value)
}

fn bounded_optional_xml_string(value: String) -> Result<Option<String>, TslError> {
    if value.is_empty() {
        return Ok(None);
    }
    bounded_xml_string(value).map(Some)
}

fn required<T>(value: Option<T>, field: TslRequiredField) -> Result<T, TslError> {
    value.ok_or(TslError::MissingField(field))
}
