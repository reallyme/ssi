// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Parse a schema-shaped TSL/LOTL XML document into a bounded typed model.
///
/// Native ingestion additionally performs XSD and XMLDSig verification before
/// returning this projection. The portable parser independently enforces the
/// namespace, supported version, typed timestamps, and allocation limits so it
/// cannot be used as a permissive alternate parser.
pub fn parse_tsl_xml(xml: &str) -> Result<TrustedList, TslError> {
    enforce_xml_limits_and_namespace(xml)?;
    let envelope: RawEnvelope = from_str(xml).map_err(|_| {
        TslError::InvalidStructure(TslStructureFailure::Deserialization)
    })?;
    let tsl_tag = required(envelope.tsl_tag, TslRequiredField::Tag)?;
    // ETSI TS 119 612 v2.4.1 clauses 5.2.1 and D.1 fix this value exactly.
    // Treating it as an arbitrary URI defeats the tag's protocol discriminator.
    if tsl_tag != REQUIRED_TSL_TAG {
        return Err(TslError::InvalidTag);
    }
    let scheme = required(
        envelope.scheme_information,
        TslRequiredField::SchemeInformation,
    )?;

    // ETSI TS 119 612 v2.4.1 clause 5.3.1 fixes the trusted-list format
    // version at 6. Older parsers admitted version 5 for compatibility, but
    // doing so here would let a legacy document bypass current mandatory
    // fields and semantics through the portable verification lane.
    let version = match required(scheme.version, TslRequiredField::Version)? {
        6 => TslVersion::V6,
        _ => return Err(TslError::UnsupportedVersion),
    };
    let sequence_number = required(scheme.sequence_number, TslRequiredField::SequenceNumber)?;
    if sequence_number == 0 {
        return Err(TslError::InvalidStructure(
            TslStructureFailure::SequenceNumber,
        ));
    }
    let tsl_type = parse_uri(required(scheme.tsl_type, TslRequiredField::ListType)?)
        .map_err(|_| TslError::InvalidField(TslRequiredField::ListType))?;
    let scheme_operator_names = parse_names(required(
        scheme.scheme_operator_name,
        TslRequiredField::SchemeOperatorName,
    )?)?;
    let scheme_operator_address = parse_address(
        required(
            scheme.scheme_operator_address,
            TslRequiredField::SchemeOperatorAddress,
        )?,
        TslRequiredField::SchemeOperatorAddress,
        TslAddressContext::SchemeOperator,
        false,
    )?;
    let scheme_names = parse_names(required(scheme.scheme_name, TslRequiredField::SchemeName)?)?;
    let scheme_information_uris = parse_localized_uris(
        required(
            scheme.scheme_information_uri,
            TslRequiredField::SchemeInformationUri,
        )?,
        TslError::InvalidField(TslRequiredField::SchemeInformationUri),
    )?;
    let status_determination_approach = parse_uri(required(
        scheme.status_determination_approach,
        TslRequiredField::StatusDeterminationApproach,
    )?)
    .map_err(|_| TslError::InvalidField(TslRequiredField::StatusDeterminationApproach))?;
    let scheme_type_community_rules = parse_localized_uris(
        required(
            scheme.scheme_type_community_rules,
            TslRequiredField::SchemeTypeCommunityRules,
        )?,
        TslError::InvalidField(TslRequiredField::SchemeTypeCommunityRules),
    )?;
    let scheme_territory = bounded_text(required(
        scheme.territory,
        TslRequiredField::SchemeTerritory,
    )?)?;
    validate_policy_or_legal_notice(required(
        scheme.policy_or_legal_notice,
        TslRequiredField::PolicyOrLegalNotice,
    )?)?;
    let historical_information_period_days = required(
        scheme.historical_information_period,
        TslRequiredField::HistoricalInformationPeriod,
    )?;
    // ETSI TS 119 612 v2.4.1 clauses 5.3.9 through 5.3.15 deliberately
    // impose requirements that are stricter than the legacy XML schema.
    // Enforcing the prose here prevents portable parsing from becoming a
    // permissive bypass around native XSD validation.
    if historical_information_period_days != REQUIRED_HISTORICAL_INFORMATION_PERIOD_DAYS {
        return Err(TslError::InvalidStructure(
            TslStructureFailure::HistoricalInformationPeriod,
        ));
    }
    let name = scheme_names
        .first()
        .map(|entry| entry.value.clone())
        .ok_or(TslError::MissingField(TslRequiredField::SchemeName))?;
    let issue_date_time_source = required(scheme.issue, TslRequiredField::IssueDateTime)?;
    let issue_date_time_value = parse_utc_timestamp(&issue_date_time_source)?;
    let next_update_value = required(scheme.next_update, TslRequiredField::NextUpdate)?
        .date_time
        .map(|value| parse_utc_timestamp(&value))
        .transpose()?;
    validate_update_window(issue_date_time_value, next_update_value)?;
    let issue_date_time = tsl_timestamp(issue_date_time_value);
    let next_update = next_update_value.map(tsl_timestamp);

    let pointers = parse_pointers(scheme.pointers)?;
    if matches!(
        tsl_type.as_str(),
        EU_GENERIC_TSL_TYPE | EU_LIST_OF_TRUSTED_LISTS_TYPE
    ) && pointers.is_empty()
    {
        return Err(TslError::MissingField(TslRequiredField::PointersToOtherTsl));
    }
    let providers = parse_providers(envelope.tsp_list)?;
    validate_closed_list_services(next_update, &providers)?;

    Ok(TrustedList {
        name,
        version,
        sequence_number,
        tsl_type,
        scheme_operator_names,
        scheme_operator_address,
        scheme_names,
        scheme_information_uris,
        status_determination_approach,
        scheme_type_community_rules,
        scheme_territory: Some(scheme_territory),
        historical_information_period_days,
        issue_date_time,
        next_update,
        pointers,
        providers,
    })
}

fn validate_closed_list_services(
    next_update: Option<TslTimestamp>,
    providers: &[TrustServiceProvider],
) -> Result<(), TslError> {
    if next_update.is_none()
        && providers
            .iter()
            .flat_map(|provider| provider.services.iter())
            .any(|service| !closed_list_status_is_non_authorizing(&service.status))
    {
        // Clause 5.3.15 requires "expired". The Commission's authenticated
        // archival UK list also uses legacy terminal national-status values.
        // Admit only statuses that cannot authorize a currently supervised or
        // accredited service; a live or unknown status still cannot disable
        // freshness by omitting its next deadline.
        return Err(TslError::ClosedListNonExpiredService);
    }
    Ok(())
}

fn closed_list_status_is_non_authorizing(status: &TrustServiceStatus) -> bool {
    matches!(
        status,
        TrustServiceStatus::Expired
            | TrustServiceStatus::Withdrawn
            | TrustServiceStatus::DeprecatedAtNationalLevel
            | TrustServiceStatus::RecognisedAtNationalLevel
            | TrustServiceStatus::SupervisionCeased
            | TrustServiceStatus::SupervisionRevoked
            | TrustServiceStatus::AccreditationCeased
            | TrustServiceStatus::AccreditationRevoked
    )
}

/// Reject an authenticated trusted list whose mandatory re-issuance deadline
/// has elapsed.
///
/// ETSI TS 119 612 v2.4.1 clause 5.3.15 requires applications to discard an
/// expired list. A null `NextUpdate` denotes a final closed list and therefore
/// has no freshness deadline.
pub fn validate_tsl_freshness(list: &TrustedList, now: OffsetDateTime) -> Result<(), TslError> {
    let Some(next_update) = list.next_update else {
        return Ok(());
    };
    if (next_update.unix_seconds(), next_update.nanosecond())
        <= (now.unix_timestamp(), now.nanosecond())
    {
        return Err(TslError::Expired);
    }
    Ok(())
}

fn validate_update_window(
    issue_date_time: OffsetDateTime,
    next_update: Option<OffsetDateTime>,
) -> Result<(), TslError> {
    let Some(next_update) = next_update else {
        return Ok(());
    };
    let deadline = add_calendar_months(issue_date_time, MAX_UPDATE_INTERVAL_MONTHS)?;
    let interoperability_deadline = deadline
        .checked_add(Duration::seconds(MAX_UPDATE_DST_SHIFT_SECONDS))
        .ok_or(TslError::InvalidUpdateWindow)?;
    // TS 119 612 v2.4.1 clause 5.3.15 caps the interval at six calendar
    // months. Current EU LOTL and Member-State TL publications preserve local
    // wall-clock time across daylight-saving transitions, which can move the
    // UTC encoding forward by exactly one hour. The narrow bound admits that
    // deployed interpretation without becoming stale-list grace. A
    // non-forward interval cannot represent a future re-issuance deadline.
    if next_update <= issue_date_time || next_update > interoperability_deadline {
        return Err(TslError::InvalidUpdateWindow);
    }
    Ok(())
}

fn add_calendar_months(value: OffsetDateTime, months: u16) -> Result<OffsetDateTime, TslError> {
    let month = u16::from(u8::from(value.month()));
    let zero_based_month = month.checked_sub(1).ok_or(TslError::InvalidUpdateWindow)?;
    let advanced_month = zero_based_month
        .checked_add(months)
        .ok_or(TslError::InvalidUpdateWindow)?;
    let year_delta = i32::from(advanced_month / 12);
    let target_year = value
        .year()
        .checked_add(year_delta)
        .ok_or(TslError::InvalidUpdateWindow)?;
    let target_month_number =
        u8::try_from((advanced_month % 12) + 1).map_err(|_| TslError::InvalidUpdateWindow)?;
    let target_month =
        Month::try_from(target_month_number).map_err(|_| TslError::InvalidUpdateWindow)?;
    let target_day = value.day().min(target_month.length(target_year));
    let target_date = Date::from_calendar_date(target_year, target_month, target_day)
        .map_err(|_| TslError::InvalidUpdateWindow)?;
    Ok(value.replace_date(target_date))
}
