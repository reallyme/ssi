// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0


include!("project/pointers.rs");
include!("project/address.rs");

fn validate_policy_or_legal_notice(policy: RawPolicyOrLegalNotice) -> Result<(), TslError> {
    if !policy.policies.is_empty() && !policy.legal_notices.is_empty() {
        return Err(TslError::InvalidStructure(
            TslStructureFailure::PolicyOrLegalNotice,
        ));
    }
    let item_count = policy
        .policies
        .len()
        .checked_add(policy.legal_notices.len())
        .ok_or(TslError::ResourceLimit(TslResourceLimit::XmlElements))?;
    if item_count == 0 || item_count > MAX_NAMES_PER_FIELD {
        return Err(TslError::InvalidStructure(
            TslStructureFailure::PolicyOrLegalNotice,
        ));
    }

    for value in policy.policies {
        parse_language_tag(value.language.ok_or(TslError::InvalidStructure(
            TslStructureFailure::PolicyOrLegalNotice,
        ))?)
        .map_err(|_| {
            TslError::InvalidStructure(TslStructureFailure::PolicyOrLegalNotice)
        })?;
        parse_uri(value.value.ok_or(TslError::InvalidStructure(
            TslStructureFailure::PolicyOrLegalNotice,
        ))?)
        .map_err(|_| {
            TslError::InvalidStructure(TslStructureFailure::PolicyOrLegalNotice)
        })?;
    }
    for value in policy.legal_notices {
        parse_language_tag(value.language.ok_or(TslError::InvalidStructure(
            TslStructureFailure::PolicyOrLegalNotice,
        ))?)
        .map_err(|_| {
            TslError::InvalidStructure(TslStructureFailure::PolicyOrLegalNotice)
        })?;
        bounded_multilingual_legal_notice_text(value.value.ok_or(
            TslError::InvalidStructure(TslStructureFailure::PolicyOrLegalNotice),
        )?)
        .map_err(|_| {
            TslError::InvalidStructure(TslStructureFailure::PolicyOrLegalNotice)
        })?;
    }
    Ok(())
}

fn parse_registration_identifier(
    trade_names: &[LocalizedText],
) -> Result<Vec<TspRegistrationIdentifier>, TslError> {
    let mut registration_identifiers = Vec::new();
    for trade_name in trade_names {
        if let Some(parsed) = parse_registration_identifier_value(&trade_name.value)? {
            if !registration_identifiers.contains(&parsed) {
                registration_identifiers.push(parsed);
            }
        }
    }
    Ok(registration_identifiers)
}

fn parse_registration_identifier_value(
    value: &str,
) -> Result<Option<TspRegistrationIdentifier>, TslError> {
        if value.len() < 7 {
            return Ok(None);
        }
        let (kind, remainder) = match value.get(..3) {
            Some("VAT") => (TspRegistrationIdentifierKind::ValueAddedTax, &value[3..]),
            Some("NTR") => (
                TspRegistrationIdentifierKind::NationalTradeRegister,
                &value[3..],
            ),
            Some("PAS") => (TspRegistrationIdentifierKind::Passport, &value[3..]),
            Some("IDC") => (TspRegistrationIdentifierKind::IdentityCard, &value[3..]),
            Some("PNO") => (TspRegistrationIdentifierKind::PersonalNumber, &value[3..]),
            Some("TIN") => (
                TspRegistrationIdentifierKind::TaxIdentificationNumber,
                &value[3..],
            ),
            _ => return Ok(None),
        };
        let remainder = remainder.trim_matches(' ');
        let Some(country_code) = remainder.get(..2) else {
            return Err(TslError::Provider(
                TslProviderFailure::MalformedRegistrationIdentifier,
            ));
        };
        let separator_and_identifier = remainder.get(2..).ok_or(TslError::Provider(
            TslProviderFailure::MalformedRegistrationIdentifier,
        ))?;
        let identifier = separator_and_identifier
            .trim_start_matches(' ')
            .strip_prefix('-')
            .map(str::trim)
            .ok_or(TslError::Provider(
                TslProviderFailure::MalformedRegistrationIdentifier,
            ))?;
        if country_code.len() != 2
            || !country_code.bytes().all(|value| value.is_ascii_uppercase())
        {
            return Err(TslError::Provider(
                TslProviderFailure::MalformedRegistrationIdentifier,
            ));
        }
        if identifier.is_empty() {
            return Err(TslError::Provider(
                TslProviderFailure::MalformedRegistrationIdentifier,
            ));
        }
        Ok(Some(TspRegistrationIdentifier {
            kind,
            country_code: country_code.to_owned(),
            value: bounded_text(identifier.to_owned())?,
        }))
}

fn complete_registration_identifiers_from_service_certificates(
    registration_identifiers: &mut Vec<TspRegistrationIdentifier>,
    services: &[TrustService],
    provider_names: &[LocalizedText],
    address: &TslAddress,
) -> Result<(), TslError> {
    if !registration_identifiers.is_empty() {
        return Ok(());
    }
    for certificate_der in services
        .iter()
        .flat_map(TrustService::certificates_der)
    {
        let facts = parse_certificate_identity_facts(certificate_der)?;
        for value in &facts.organization_identifiers {
            if let Some(parsed) = parse_registration_identifier_value(value)? {
                if !registration_identifiers.contains(&parsed) {
                    registration_identifiers.push(parsed);
                }
            }
        }
    }
    if registration_identifiers.is_empty() {
        let provider_name = provider_names.first().ok_or(TslError::Provider(
            TslProviderFailure::MissingRegistrationIdentifier,
        ))?;
        let country_code = address
            .postal_addresses
            .first()
            .map(|postal| postal.country_code.clone())
            .ok_or(TslError::Provider(
                TslProviderFailure::MissingRegistrationIdentifier,
            ))?;
        // Clause 5.4.2 requires the TLSO to allocate an NTR identifier when no
        // official registration exists. A legacy archived list can omit that
        // allocation. Preserve graph reachability with the authenticated legal
        // name and country as the scheme-scoped NTR material; downstream code
        // hashes it with the list territory and never presents it as an
        // official registry number.
        registration_identifiers.push(TspRegistrationIdentifier {
            kind: TspRegistrationIdentifierKind::NationalTradeRegister,
            country_code,
            value: provider_name.value.clone(),
        });
    }
    Ok(())
}

fn parse_providers(raw: Option<RawTspList>) -> Result<Vec<TrustServiceProvider>, TslError> {
    let providers = raw.map(|value| value.providers).unwrap_or_default();
    if providers.len() > MAX_PROVIDERS {
        return Err(TslError::ResourceLimit(TslResourceLimit::Providers));
    }
    let mut output = Vec::new();
    let mut total_services = 0_usize;
    for provider in providers {
        let information = required(
            provider.information,
            TslRequiredField::ProviderInformation,
        )?;
        let names = parse_names(required(
            information.names,
            TslRequiredField::ProviderName,
        )?)?;
        let trade_names = information
            .trade_names
            .map(parse_names)
            .transpose()?
            .unwrap_or_else(|| names.clone());
        let information_uris = parse_provider_information_uris(required(
            information.information_uris,
            TslRequiredField::ProviderInformationUri,
        )?)?;
        let information_uri_supplies_website = information_uris.iter().any(|value| {
            uri_scheme_is(&value.uri, "http") || uri_scheme_is(&value.uri, "https")
        });
        let address = parse_address(
            required(information.address, TslRequiredField::ProviderAddress)?,
            TslRequiredField::ProviderAddress,
            TslAddressContext::Provider,
            information_uri_supplies_website,
        )?;
        let services = required(provider.services, TslRequiredField::ProviderServices)?.services;
        if services.is_empty() {
            return Err(TslError::MissingField(TslRequiredField::ProviderServices));
        }
        let new_length = total_services
            .checked_add(services.len())
            .ok_or(TslError::ResourceLimit(TslResourceLimit::Services))?;
        if new_length > MAX_SERVICES {
            return Err(TslError::ResourceLimit(TslResourceLimit::Services));
        }
        total_services = new_length;
        let services = services
            .into_iter()
            .map(parse_service)
            .collect::<Result<Vec<_>, TslError>>()?;
        let services = coalesce_duplicate_current_services(services)?;
        let mut registration_identifiers = parse_registration_identifier(&trade_names)?;
        // Deployed lists occasionally omit the clause 5.4.2 identifier from
        // TSPTradeName while publishing the same official identifier in the
        // service certificate's organizationIdentifier. The certificate is
        // authenticated by the TSL and provides a stronger fallback than a
        // synthesized name-derived identifier.
        complete_registration_identifiers_from_service_certificates(
            &mut registration_identifiers,
            &services,
            &names,
            &address,
        )?;
        output.push(TrustServiceProvider {
            names,
            trade_names,
            registration_identifiers,
            address,
            information_uris,
            services,
        });
    }
    coalesce_duplicate_providers(output)
}

include!("project/coalesce.rs");

fn normalize_service_history(
    current_type: &TrustServiceType,
    current_start: TslTimestamp,
    history: &mut Vec<TrustServiceHistoryEntry>,
) {
    history.sort_by(|left, right| {
        (
            right.status_starting_time.unix_seconds(),
            right.status_starting_time.nanosecond(),
        )
            .cmp(&(
                left.status_starting_time.unix_seconds(),
                left.status_starting_time.nanosecond(),
            ))
    });
    let mut upper_bound = (current_start.unix_seconds(), current_start.nanosecond());
    history.retain(|entry| {
        let effective = (
            entry.status_starting_time.unix_seconds(),
            entry.status_starting_time.nanosecond(),
        );
        let retain = &entry.service_type == current_type && effective < upper_bound;
        if retain {
            upper_bound = effective;
        }
        retain
    });
}

fn merge_current_certificates(
    current: &mut ServiceDigitalIdentity,
    candidate: &ServiceDigitalIdentity,
) -> Result<(), TslError> {
    match (current, candidate) {
        (ServiceDigitalIdentity::Pki(current), ServiceDigitalIdentity::Pki(candidate)) => {
            for certificate in &candidate.certificates_der {
                if !current.certificates_der.contains(certificate) {
                    if current.certificates_der.len() >= MAX_CERTIFICATES_PER_IDENTITY {
                        return Err(TslError::ResourceLimit(TslResourceLimit::Certificates));
                    }
                    current.certificates_der.push(certificate.clone());
                }
            }
            Ok(())
        }
        (ServiceDigitalIdentity::NonPki(current), ServiceDigitalIdentity::NonPki(candidate))
            if current == candidate =>
        {
            Ok(())
        }
        _ => Err(TslError::DigitalIdentity(
            TslDigitalIdentityFailure::DuplicateServiceKey,
        )),
    }
}

fn historical_identity_from_current(
    identity: &ServiceDigitalIdentity,
) -> Result<ServiceDigitalIdentity, TslError> {
    let ServiceDigitalIdentity::Pki(identity) = identity else {
        return Ok(identity.clone());
    };
    let subject_key_identifier = if let Some(identifier) = &identity.subject_key_identifier {
        Some(identifier.clone())
    } else {
        let certificate = identity.certificates_der.first().ok_or(
            TslError::DigitalIdentity(TslDigitalIdentityFailure::MissingCertificate),
        )?;
        let facts = parse_certificate_identity_facts(certificate)?;
        Some(
            facts
                .subject_key_identifier
                .clone()
                .unwrap_or_else(|| facts.derived_subject_key_identifier.to_vec()),
        )
    };
    let subject_key_identifier = subject_key_identifier.ok_or(TslError::DigitalIdentity(
        TslDigitalIdentityFailure::MissingHistoricalSubjectKeyIdentifier,
    ))?;
    Ok(ServiceDigitalIdentity::Pki(Box::new(
        PkiServiceDigitalIdentity {
            certificates_der: Vec::new(),
            subject_name: identity.subject_name.clone(),
            key_value: identity.key_value.clone(),
            subject_key_identifier: Some(subject_key_identifier),
            subject_public_key_info_der: Vec::new(),
            certificate_authority: false,
        },
    )))
}

fn merge_unique<T: PartialEq>(target: &mut Vec<T>, values: Vec<T>) {
    for value in values {
        if !target.contains(&value) {
            target.push(value);
        }
    }
}

fn parse_service(raw: RawService) -> Result<TrustService, TslError> {
    let information = required(raw.information, TslRequiredField::ServiceInformation)?;
    let service_names = parse_names(required(
        information.service_names,
        TslRequiredField::ServiceName,
    )?)?;
    let service_type = parse_service_type(required(
        information.service_type,
        TslRequiredField::ServiceType,
    )?)?;
    let status = parse_service_status(required(
        information.status,
        TslRequiredField::ServiceStatus,
    )?)?;
    let status_starting_time = parse_timestamp(required(
        information.status_time,
        TslRequiredField::ServiceStatusStartingTime,
    )?)?;
    let supply_points = parse_supply_points(information.supply_points)?;
    let digital_identity = parse_current_digital_identity(required(
        information.identity,
        TslRequiredField::ServiceDigitalIdentity,
    )?)?;
    let (qualifications, additional_service_information) =
        parse_extensions(information.extensions, &service_type)?;
    let mut history = parse_history(raw.history)?;
    normalize_service_history(&service_type, status_starting_time, &mut history);
    Ok(TrustService {
        service_names,
        service_type,
        status,
        status_starting_time,
        supply_points,
        digital_identity,
        qualifications,
        additional_service_information,
        history,
    })
}

fn parse_history(
    raw: Option<RawServiceHistory>,
) -> Result<Vec<TrustServiceHistoryEntry>, TslError> {
    let entries = raw.map(|value| value.entries).unwrap_or_default();
    if entries.len() > MAX_HISTORY_PER_SERVICE {
        return Err(TslError::ResourceLimit(TslResourceLimit::History));
    }
    let mut history = Vec::new();
    for entry in entries {
        let service_type =
            parse_service_type(required(entry.service_type, TslRequiredField::ServiceType)?)?;
        let status =
            parse_service_status(required(entry.status, TslRequiredField::ServiceStatus)?)?;
        let status_starting_time = parse_timestamp(required(
            entry.status_time,
            TslRequiredField::ServiceStatusStartingTime,
        )?)?;
        let service_names = parse_names(required(
            entry.service_names,
            TslRequiredField::ServiceName,
        )?)?;
        let digital_identity = parse_historical_digital_identity(required(
            entry.identity,
            TslRequiredField::ServiceDigitalIdentity,
        )?)?;
        let (qualifications, additional_service_information) =
            parse_extensions(entry.extensions, &service_type)?;
        let Some(digital_identity) = digital_identity else {
            continue;
        };
        history.push(TrustServiceHistoryEntry {
            service_type,
            service_names,
            status,
            status_starting_time,
            digital_identity,
            qualifications,
            additional_service_information,
        });
    }
    Ok(history)
}

fn parse_supply_points(raw: Option<RawSupplyPoints>) -> Result<Vec<TslUri>, TslError> {
    let points = raw.map(|value| value.points).unwrap_or_default();
    if points.len() > MAX_SUPPLY_POINTS_PER_SERVICE {
        return Err(TslError::ResourceLimit(TslResourceLimit::SupplyPoints));
    }
    points.into_iter().map(parse_uri).collect()
}

include!("project/digital_identity.rs");
include!("project/extensions.rs");

include!("scalars.rs");
