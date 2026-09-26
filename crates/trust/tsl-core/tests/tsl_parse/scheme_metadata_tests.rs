// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn rejects_missing_normative_scheme_metadata() {
    let cases = [
        (
            "<SchemeOperatorAddress>",
            "</SchemeOperatorAddress>",
            TslRequiredField::SchemeOperatorAddress,
        ),
        (
            "<SchemeInformationURI>",
            "</SchemeInformationURI>",
            TslRequiredField::SchemeInformationUri,
        ),
        (
            "<StatusDeterminationApproach>",
            "</StatusDeterminationApproach>",
            TslRequiredField::StatusDeterminationApproach,
        ),
        (
            "<SchemeTypeCommunityRules>",
            "</SchemeTypeCommunityRules>",
            TslRequiredField::SchemeTypeCommunityRules,
        ),
        (
            "<SchemeTerritory>",
            "</SchemeTerritory>",
            TslRequiredField::SchemeTerritory,
        ),
        (
            "<PolicyOrLegalNotice>",
            "</PolicyOrLegalNotice>",
            TslRequiredField::PolicyOrLegalNotice,
        ),
        (
            "<HistoricalInformationPeriod>",
            "</HistoricalInformationPeriod>",
            TslRequiredField::HistoricalInformationPeriod,
        ),
        (
            "<NextUpdate>",
            "</NextUpdate>",
            TslRequiredField::NextUpdate,
        ),
    ];

    for (start, end, required_field) in cases {
        let source = document("");
        let start_index = source.find(start).unwrap();
        let end_index = source.find(end).unwrap() + end.len();
        let mut malformed = source;
        malformed.replace_range(start_index..end_index, "");
        assert_eq!(
            parse_tsl_xml(&malformed).unwrap_err(),
            TslError::MissingField(required_field)
        );
    }
}

#[test]
fn rejects_non_normative_history_period_and_missing_eu_pointer() {
    let wrong_history = document("").replace(
        "<HistoricalInformationPeriod>65535</HistoricalInformationPeriod>",
        "<HistoricalInformationPeriod>3653</HistoricalInformationPeriod>",
    );
    assert_eq!(
        parse_tsl_xml(&wrong_history).unwrap_err(),
        TslError::InvalidStructure(TslStructureFailure::HistoricalInformationPeriod)
    );

    let eu_list = document("").replace(
        "https://example.test/type",
        "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric",
    );
    assert_eq!(
        parse_tsl_xml(&eu_list).unwrap_err(),
        TslError::MissingField(TslRequiredField::PointersToOtherTsl)
    );
}

#[test]
fn rejects_malformed_scheme_address_and_policy_shapes() {
    let missing_email =
        document("").replace("<URI xml:lang=\"en\">mailto:trust@example.test</URI>", "");
    assert_eq!(
        parse_tsl_xml(&missing_email).unwrap_err(),
        TslError::Address(
            TslAddressContext::SchemeOperator,
            TslAddressFailure::MissingEmail
        )
    );

    let invalid_postal_country = document("").replace(
        "<CountryName>EU</CountryName>",
        "<CountryName>eu</CountryName>",
    );
    assert_eq!(
        parse_tsl_xml(&invalid_postal_country).unwrap_err(),
        TslError::Address(
            TslAddressContext::SchemeOperator,
            TslAddressFailure::PostalCountryCode
        )
    );

    let mixed_policy_choice = document("").replace(
        "</PolicyOrLegalNotice>",
        "<TSLLegalNotice xml:lang=\"en\">Notice</TSLLegalNotice></PolicyOrLegalNotice>",
    );
    assert_eq!(
        parse_tsl_xml(&mixed_policy_choice).unwrap_err(),
        TslError::InvalidStructure(TslStructureFailure::PolicyOrLegalNotice)
    );
}

#[test]
fn permits_present_next_update_with_null_date_for_closed_list() {
    let closed = document("").replace(
        "<NextUpdate><dateTime>2026-02-01T00:00:00Z</dateTime></NextUpdate>",
        "<NextUpdate/>",
    );
    assert!(parse_tsl_xml(&closed).unwrap().next_update.is_none());
}

#[test]
fn rejects_null_next_update_when_a_current_service_is_not_expired() {
    let live_service = document_with_service_extension("").replace(
        "<NextUpdate><dateTime>2026-02-01T00:00:00Z</dateTime></NextUpdate>",
        "<NextUpdate/>",
    );

    assert_eq!(
        parse_tsl_xml(&live_service).unwrap_err(),
        TslError::ClosedListNonExpiredService
    );
}

#[test]
fn permits_null_next_update_when_every_current_service_is_expired() {
    let closed = document_with_service_extension("")
        .replace(
            "<NextUpdate><dateTime>2026-02-01T00:00:00Z</dateTime></NextUpdate>",
            "<NextUpdate/>",
        )
        .replace(
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/expired",
        );

    assert!(parse_tsl_xml(&closed).unwrap().next_update.is_none());
}
