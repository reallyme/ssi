// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn parse_localized_uris(
    raw: RawInternationalUris,
    invalid_error: TslError,
) -> Result<Vec<LocalizedUri>, TslError> {
    if raw.uris.is_empty() || raw.uris.len() > MAX_NAMES_PER_FIELD {
        return Err(invalid_error);
    }
    raw.uris
        .into_iter()
        .map(|value| {
            Ok(LocalizedUri {
                language: parse_pointer_language_tag(value.language.ok_or(invalid_error)?)
                    .map_err(|_| invalid_error)?,
                uri: parse_uri(value.value.ok_or(invalid_error)?).map_err(|_| invalid_error)?,
            })
        })
        .collect()
}

fn parse_provider_information_uris(
    raw: RawInternationalUris,
) -> Result<Vec<LocalizedUri>, TslError> {
    let invalid_error = TslError::InvalidField(TslRequiredField::ProviderInformationUri);
    if raw.uris.is_empty() || raw.uris.len() > MAX_NAMES_PER_FIELD {
        return Err(invalid_error);
    }
    raw.uris
        .into_iter()
        .map(|value| {
            let language = parse_pointer_language_tag(value.language.ok_or(invalid_error)?)
                .map_err(|_| invalid_error)?;
            let source = value.value.ok_or(invalid_error)?;
            let host_candidate = source.split('/').next().unwrap_or_default();
            let is_bare_dns_name = !source.contains(':')
                && host_candidate.contains('.')
                && host_candidate
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'));
            let normalized = if is_bare_dns_name {
                let mut normalized = String::with_capacity(source.len().checked_add(8).ok_or(
                    TslError::ResourceLimit(TslResourceLimit::XmlText),
                )?);
                // Provider information is descriptive metadata, not a fetch
                // authorization. Deployed TLs omit the scheme for DNS names;
                // normalize only that unambiguous host-shaped form to HTTPS.
                normalized.push_str("https://");
                normalized.push_str(&source);
                normalized
            } else {
                source
            };
            let uri = parse_uri(normalized).map_err(|_| invalid_error)?;
            Ok(LocalizedUri { language, uri })
        })
        .collect()
}

fn parse_address(
    address: RawAddress,
    required_field: TslRequiredField,
    context: TslAddressContext,
    supplemental_website: bool,
) -> Result<TslAddress, TslError> {
    let postal_addresses = required(address.postal_addresses, required_field)?.addresses;
    if postal_addresses.is_empty() || postal_addresses.len() > MAX_NAMES_PER_FIELD {
        return Err(TslError::Address(
            context,
            TslAddressFailure::PostalAddressCount,
        ));
    }
    let parsed_postal_addresses = postal_addresses
        .into_iter()
        .map(|postal_address| {
            let language = postal_address
                .language
                .ok_or(TslError::Address(
                    context,
                    TslAddressFailure::PostalLanguage,
                ))
                .and_then(|value| {
                    parse_language_tag(value).map_err(|_| {
                        TslError::Address(context, TslAddressFailure::PostalLanguage)
                    })
                })?;
            let street_address = bounded_multilingual_text(
                postal_address
                    .street_address
                    .ok_or(TslError::Address(
                        context,
                        TslAddressFailure::PostalStreet,
                    ))?,
            )
            .map_err(|_| TslError::Address(context, TslAddressFailure::PostalStreet))?;
            let locality = bounded_multilingual_text(postal_address.locality.ok_or(
                TslError::Address(context, TslAddressFailure::PostalLocality),
            )?)
            .map_err(|_| TslError::Address(context, TslAddressFailure::PostalLocality))?;
            let state_or_province = postal_address
                .state_or_province
                .map(bounded_multilingual_text)
                .transpose()
                .map_err(|_| {
                    TslError::Address(context, TslAddressFailure::PostalStateOrProvince)
                })?;
            let postal_code = postal_address
                .postal_code
                .map(bounded_multilingual_text)
                .transpose()
                .map_err(|_| TslError::Address(context, TslAddressFailure::PostalCode))?;
            let country_code = bounded_text(
                postal_address
                    .country_name
                    .ok_or(TslError::Address(
                        context,
                        TslAddressFailure::PostalCountryCode,
                    ))?,
            )
            .map_err(|_| TslError::Address(context, TslAddressFailure::PostalCountryCode))?;
            if country_code.len() != 2
                || !country_code.bytes().all(|value| value.is_ascii_uppercase())
            {
                return Err(TslError::Address(
                    context,
                    TslAddressFailure::PostalCountryCode,
                ));
            }
            Ok(TslPostalAddress {
                language,
                street_address,
                locality,
                state_or_province,
                postal_code,
                country_code,
            })
        })
        .collect::<Result<Vec<_>, TslError>>()?;

    let electronic_address = required(address.electronic_address, required_field)?;
    if electronic_address.uris.is_empty() || electronic_address.uris.len() > MAX_NAMES_PER_FIELD {
        return Err(TslError::Address(
            context,
            TslAddressFailure::ElectronicAddressCount,
        ));
    }
    let mut electronic_addresses = electronic_address
        .uris
        .into_iter()
        .map(|value| {
            let language = value
                .language
                .ok_or(TslError::Address(
                    context,
                    TslAddressFailure::ElectronicLanguage,
                ))
                .and_then(|language| {
                    parse_language_tag(language).map_err(|_| {
                        TslError::Address(context, TslAddressFailure::ElectronicLanguage)
                    })
                })?;
            let uri = value
                .value
                .ok_or(TslError::Address(
                    context,
                    TslAddressFailure::ElectronicUri,
                ))
                .and_then(|uri| {
                    parse_uri(uri).map_err(|_| {
                        TslError::Address(context, TslAddressFailure::ElectronicUri)
                    })
                })?;
            Ok(LocalizedUri { language, uri })
        })
        .collect::<Result<Vec<_>, TslError>>()?;
    let had_malformed_mailbox = electronic_addresses.iter().any(|address| {
        uri_scheme_is(&address.uri, "mailto") && !has_valid_mailbox(&address.uri)
    });
    electronic_addresses.retain(|address| {
        !uri_scheme_is(&address.uri, "mailto") || has_valid_mailbox(&address.uri)
    });
    if had_malformed_mailbox
        && !electronic_addresses
            .iter()
            .any(|address| uri_scheme_is(&address.uri, "mailto"))
    {
        return Err(TslError::Address(
            context,
            TslAddressFailure::ElectronicUri,
        ));
    }
    validate_electronic_address_roles(&electronic_addresses, context, supplemental_website)?;
    Ok(TslAddress {
        postal_addresses: parsed_postal_addresses,
        electronic_addresses,
    })
}

fn validate_electronic_address_roles(
    addresses: &[LocalizedUri],
    context: TslAddressContext,
    supplemental_website: bool,
) -> Result<(), TslError> {
    let mut has_email = false;
    let mut has_website = false;
    for address in addresses {
        let parsed = url::Url::parse(address.uri.as_str())
            .map_err(|_| TslError::Address(context, TslAddressFailure::ElectronicUri))?;
        if uri_scheme_is(&address.uri, "mailto") {
            if !has_valid_mailbox(&address.uri) {
                return Err(TslError::Address(
                    context,
                    TslAddressFailure::ElectronicUri,
                ));
            }
            has_email = true;
        } else if uri_scheme_is(&address.uri, "http") || uri_scheme_is(&address.uri, "https") {
            if parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
            {
                return Err(TslError::Address(
                    context,
                    TslAddressFailure::ElectronicUri,
                ));
            }
            has_website = true;
        } else if uri_scheme_is(&address.uri, "tel") {
            // Telephone contact is optional. The XML schema represents every
            // electronic address as the same repeatable multilingual URI
            // type, so no positional inference is safe here.
            if parsed.path().is_empty() {
                return Err(TslError::Address(
                    context,
                    TslAddressFailure::ElectronicUri,
                ));
            }
        } else {
            return Err(TslError::Address(
                context,
                TslAddressFailure::ElectronicScheme,
            ));
        }
    }
    if !has_email {
        return Err(TslError::Address(
            context,
            TslAddressFailure::MissingEmail,
        ));
    }
    if !has_website && !supplemental_website {
        return Err(TslError::Address(
            context,
            TslAddressFailure::MissingWebsite,
        ));
    }
    Ok(())
}

fn has_valid_mailbox(uri: &TslUri) -> bool {
    url::Url::parse(uri.as_str()).is_ok_and(|parsed| {
        parsed
            .path()
            .rsplit_once('@')
            .is_some_and(|(local_part, domain)| !local_part.is_empty() && !domain.is_empty())
    })
}

fn uri_scheme_is(uri: &TslUri, expected: &str) -> bool {
    uri.as_str()
        .split(':')
        .next()
        .is_some_and(|value| value.eq_ignore_ascii_case(expected))
}
