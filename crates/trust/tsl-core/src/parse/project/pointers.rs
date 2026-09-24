// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn parse_pointers(raw: Option<RawPointers>) -> Result<Vec<TslPointer>, TslError> {
    let raw = raw.map(|value| value.pointers).unwrap_or_default();
    if raw.len() > MAX_POINTERS {
        return Err(TslError::ResourceLimit(TslResourceLimit::Pointers));
    }
    raw.into_iter()
        .map(|pointer| {
            let url = parse_uri(required(pointer.url, TslRequiredField::PointerLocation)?)?;
            let raw_identities = pointer
                .identities
                .map(|identities| identities.identities)
                .unwrap_or_default();
            if raw_identities.len() > MAX_POINTER_IDENTITIES {
                return Err(TslError::ResourceLimit(
                    TslResourceLimit::PointerIdentities,
                ));
            }
            let digital_identities = raw_identities
                .into_iter()
                .map(parse_current_digital_identity)
                .collect::<Result<Vec<_>, TslError>>()?;
            if !digital_identities
                .iter()
                .any(|identity| !identity.certificates_der().is_empty())
            {
                return Err(TslError::PointerQualifier(
                    TslPointerQualifierFailure::MissingIssuerIdentity,
                ));
            }
            let qualifiers = parse_pointer_qualifiers(pointer.additional_information)?;
            Ok(TslPointer {
                digital_identities,
                url,
                tsl_type: qualifiers.tsl_type,
                scheme_operator_names: qualifiers.scheme_operator_names,
                scheme_type_community_rules: qualifiers.scheme_type_community_rules,
                territory: qualifiers.territory,
                media_type: qualifiers.media_type,
            })
        })
        .collect()
}
struct ParsedPointerQualifiers {
    tsl_type: TslUri,
    scheme_operator_names: Vec<LocalizedText>,
    scheme_type_community_rules: Vec<LocalizedUri>,
    territory: String,
    media_type: TslMediaType,
}

fn parse_pointer_qualifiers(
    raw: Option<RawPointerAdditionalInformation>,
) -> Result<ParsedPointerQualifiers, TslError> {
    let values = raw
        .ok_or(TslError::PointerQualifier(TslPointerQualifierFailure::Missing))?
        .values;
    if values.len() > MAX_POINTER_QUALIFIERS {
        return Err(TslError::ResourceLimit(TslResourceLimit::Pointers));
    }

    let mut tsl_type = None;
    let mut names = None;
    let mut rules = None;
    let mut territory = None;
    let mut media_type = None;

    for value in values {
        let field_count = usize::from(value.tsl_type.is_some())
            .checked_add(usize::from(value.scheme_operator_name.is_some()))
            .and_then(|count| {
                count.checked_add(usize::from(value.scheme_type_community_rules.is_some()))
            })
            .and_then(|count| count.checked_add(usize::from(value.territory.is_some())))
            .and_then(|count| count.checked_add(usize::from(value.mime_type.is_some())))
            .ok_or(TslError::PointerQualifier(
                TslPointerQualifierFailure::Malformed,
            ))?;
        if field_count != 1 {
            return Err(TslError::PointerQualifier(
                TslPointerQualifierFailure::Malformed,
            ));
        }
        if let Some(raw_value) = value.tsl_type {
            merge_pointer_qualifier(&mut tsl_type, parse_uri(raw_value)?)?;
        }
        if let Some(raw_value) = value.scheme_operator_name {
            merge_pointer_qualifier(&mut names, parse_names(raw_value)?)?;
        }
        if let Some(raw_value) = value.scheme_type_community_rules {
            merge_pointer_qualifier(
                &mut rules,
                parse_localized_uris(
                    raw_value,
                    TslError::PointerQualifier(TslPointerQualifierFailure::Malformed),
                )?,
            )?;
        }
        if let Some(raw_value) = value.territory {
            merge_pointer_qualifier(&mut territory, bounded_text(raw_value)?)?;
        }
        if let Some(raw_value) = value.mime_type {
            let parsed = TslMediaType::parse(&raw_value);
            // TS 119 612 clause 5.3.13 carries the authenticated media type.
            // The EU LOTL profile publishes both its machine-processable XML
            // authorization and a human-readable PDF authorization; retaining
            // both is necessary so the app can select XML before traversal.
            // Generic response Content-Types do not become authenticated
            // pointer types merely because an HTTP server sends them.
            if !matches!(
                parsed,
                TslMediaType::EtsiTrustedListXml | TslMediaType::Pdf
            ) {
                return Err(TslError::PointerQualifier(
                    TslPointerQualifierFailure::NonNormativeMimeType,
                ));
            }
            merge_pointer_qualifier(&mut media_type, parsed)?;
        }
    }

    Ok(ParsedPointerQualifiers {
        tsl_type: required_pointer_qualifier(tsl_type)?,
        scheme_operator_names: required_pointer_qualifier(names)?,
        scheme_type_community_rules: required_pointer_qualifier(rules)?,
        territory: required_pointer_qualifier(territory)?,
        media_type: required_pointer_qualifier(media_type)?,
    })
}

fn merge_pointer_qualifier<T: PartialEq>(slot: &mut Option<T>, value: T) -> Result<(), TslError> {
    if let Some(existing) = slot {
        let reason = if existing == &value {
            TslPointerQualifierFailure::Duplicate
        } else {
            TslPointerQualifierFailure::Contradictory
        };
        return Err(TslError::PointerQualifier(reason));
    }
    *slot = Some(value);
    Ok(())
}

fn required_pointer_qualifier<T>(value: Option<T>) -> Result<T, TslError> {
    value.ok_or(TslError::PointerQualifier(TslPointerQualifierFailure::Missing))
}
