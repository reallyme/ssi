// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    pid_claims::{valid_calendar_date, valid_pid_text, validate_pid_claims},
    validate_attestation, AttestationCategory, AttestationFormat, CommonAttestationFacts,
    ConformanceError, FormatFacts, NaturalPersonPidClaims, Result, EU_PID_MDOC_TYPE,
    EU_PID_SD_JWT_VCT,
};

const MANDATORY_FAMILY_NAME: u8 = 1 << 0;
const MANDATORY_GIVEN_NAME: u8 = 1 << 1;
const MANDATORY_BIRTH_DATE: u8 = 1 << 2;
const MANDATORY_BIRTH_PLACE: u8 = 1 << 3;
const MANDATORY_NATIONALITY: u8 = 1 << 4;
const MANDATORY_PORTRAIT: u8 = 1 << 5;
const ALL_MANDATORY_NATURAL_PID: u8 = MANDATORY_FAMILY_NAME
    | MANDATORY_GIVEN_NAME
    | MANDATORY_BIRTH_DATE
    | MANDATORY_BIRTH_PLACE
    | MANDATORY_NATIONALITY
    | MANDATORY_PORTRAIT;

/// Optional natural-person PID: full residence address.
pub const OPTIONAL_RESIDENT_ADDRESS: u16 = 1 << 0;
/// Optional natural-person PID: residence country.
pub const OPTIONAL_RESIDENT_COUNTRY: u16 = 1 << 1;
/// Optional natural-person PID: residence state/region.
pub const OPTIONAL_RESIDENT_STATE: u16 = 1 << 2;
/// Optional natural-person PID: residence city/locality.
pub const OPTIONAL_RESIDENT_CITY: u16 = 1 << 3;
/// Optional natural-person PID: residence postal code.
pub const OPTIONAL_RESIDENT_POSTAL_CODE: u16 = 1 << 4;
/// Optional natural-person PID: residence street.
pub const OPTIONAL_RESIDENT_STREET: u16 = 1 << 5;
/// Optional natural-person PID: personal administrative number.
pub const OPTIONAL_PERSONAL_ADMINISTRATIVE_NUMBER: u16 = 1 << 6;
/// Optional natural-person PID: family name at birth.
pub const OPTIONAL_FAMILY_NAME_BIRTH: u16 = 1 << 7;
/// Optional natural-person PID: given name at birth.
pub const OPTIONAL_GIVEN_NAME_BIRTH: u16 = 1 << 8;
/// Optional natural-person PID: sex.
pub const OPTIONAL_SEX: u16 = 1 << 9;
/// Optional natural-person PID: email address.
pub const OPTIONAL_EMAIL: u16 = 1 << 10;
/// Optional natural-person PID: mobile telephone number.
pub const OPTIONAL_MOBILE_PHONE_NUMBER: u16 = 1 << 11;
pub(crate) const ALL_OPTIONAL_NATURAL_PID: u16 = OPTIONAL_RESIDENT_ADDRESS
    | OPTIONAL_RESIDENT_COUNTRY
    | OPTIONAL_RESIDENT_STATE
    | OPTIONAL_RESIDENT_CITY
    | OPTIONAL_RESIDENT_POSTAL_CODE
    | OPTIONAL_RESIDENT_STREET
    | OPTIONAL_PERSONAL_ADMINISTRATIVE_NUMBER
    | OPTIONAL_FAMILY_NAME_BIRTH
    | OPTIONAL_GIVEN_NAME_BIRTH
    | OPTIONAL_SEX
    | OPTIONAL_EMAIL
    | OPTIONAL_MOBILE_PHONE_NUMBER;

/// Encoding-independent calendar date used by PID provider metadata.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CalendarDate {
    /// Four-digit Gregorian year.
    pub year: u16,
    /// Gregorian month in the range 1 through 12.
    pub month: u8,
    /// Gregorian day valid for the selected year and month.
    pub day: u8,
}

/// PID provider metadata common to natural and legal persons.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PidProviderMetadata<'a> {
    /// Name of the issuing authority.
    pub issuing_authority: &'a str,
    /// ISO 3166-1 alpha-2 issuing country code.
    pub issuing_country: &'a str,
    /// Optional PID expiry date.
    pub expiry_date: Option<CalendarDate>,
    /// Optional document number.
    pub document_number: Option<&'a str>,
    /// Optional issuing jurisdiction.
    pub issuing_jurisdiction: Option<&'a str>,
    /// Optional PID issuance date.
    pub issuance_date: Option<CalendarDate>,
}

/// Natural-person PID claims and independently established disclosure evidence.
///
/// Claim values are borrowed and validated directly. The only remaining masks
/// describe the envelope's selective-disclosure capabilities, which cannot be
/// inferred from decoded values alone.
pub struct NaturalPersonPidFacts<'a> {
    /// Actual mandatory and optional PID values.
    pub claims: NaturalPersonPidClaims<'a>,
    /// Claims in the mandatory set that are independently selectively disclosable.
    pub mandatory_disclosable: u8,
    /// Present optional claims that are independently selectively disclosable.
    pub optional_disclosable: u16,
    /// The empty portrait value is authorized by the issuing Member State.
    pub portrait_opt_out_authorized: bool,
    /// PID provider metadata.
    pub provider_metadata: PidProviderMetadata<'a>,
}

impl NaturalPersonPidFacts<'_> {
    /// Presence mask representing all mandatory natural-person PID claims.
    #[must_use]
    pub const fn all_mandatory_mask() -> u8 {
        ALL_MANDATORY_NATURAL_PID
    }
}

/// Legal-person PID values from Annex section 2.
///
/// The regulation does not define a common wire mapping for these values. The
/// caller therefore supplies the decoded values while this crate enforces
/// presence, bounded text, and identifier shape without inventing an encoding.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct LegalPersonPidClaims<'a> {
    /// Current legal name.
    pub current_legal_name: &'a str,
    /// Member-State cross-border identifier, constructed to be as persistent as possible.
    pub cross_border_identifier: &'a str,
    /// Current address.
    pub current_address: Option<&'a str>,
    /// VAT registration number.
    pub vat_registration_number: Option<&'a str>,
    /// Tax reference number.
    pub tax_reference_number: Option<&'a str>,
    /// European unique identifier under Directive (EU) 2017/1132.
    pub european_unique_identifier: Option<&'a str>,
    /// Legal Entity Identifier under Implementing Regulation (EU) 2022/1860.
    pub legal_entity_identifier: Option<&'a str>,
    /// Economic Operator Registration and Identification number.
    pub eori: Option<&'a str>,
    /// Excise number under Regulation (EU) No 389/2012.
    pub excise_number: Option<&'a str>,
}

/// Legal-person PID claim and provider facts from Annex section 2.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct LegalPersonPidFacts<'a> {
    /// Actual mandatory and optional legal-person PID values.
    pub claims: LegalPersonPidClaims<'a>,
    /// PID provider metadata.
    pub provider_metadata: PidProviderMetadata<'a>,
}

/// Validate the legal-person PID set defined by Annex section 2.
///
/// No common wire mapping is imposed because the regulation does not define
/// one for the legal-person set.
pub fn validate_legal_person_pid(pid: &LegalPersonPidFacts<'_>) -> Result<()> {
    if !valid_pid_text(pid.claims.current_legal_name)
        || !valid_legal_identifier(pid.claims.cross_border_identifier)
    {
        return Err(ConformanceError::MissingMandatoryPidClaim);
    }
    if pid
        .claims
        .current_address
        .is_some_and(|value| !valid_pid_text(value))
        || [
            pid.claims.vat_registration_number,
            pid.claims.tax_reference_number,
            pid.claims.european_unique_identifier,
            pid.claims.legal_entity_identifier,
            pid.claims.eori,
            pid.claims.excise_number,
        ]
        .into_iter()
        .flatten()
        .any(|value| !valid_legal_identifier(value))
    {
        return Err(ConformanceError::InvalidPidClaimEncoding);
    }
    validate_provider_metadata(&pid.provider_metadata)
}

fn valid_legal_identifier(value: &str) -> bool {
    const MAX_LEGAL_IDENTIFIER_BYTES: usize = 128;
    !value.is_empty()
        && value.len() <= MAX_LEGAL_IDENTIFIER_BYTES
        && value.trim() == value
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '.' | '-' | '_' | '/' | ':' | '+' | ' ')
        })
}

/// Validate natural-person PID content and its ETSI envelope realization.
pub fn validate_natural_person_pid(
    common: &CommonAttestationFacts<'_>,
    format: &FormatFacts<'_>,
    pid: &NaturalPersonPidFacts<'_>,
) -> Result<()> {
    if !matches!(common.category, AttestationCategory::NaturalPersonPid) {
        return Err(ConformanceError::InvalidAttestationType);
    }

    validate_attestation(common, format)?;
    validate_pid_type(common, format)?;

    let optional_present =
        validate_pid_claims(common.format, &pid.claims, pid.portrait_opt_out_authorized)?;
    validate_provider_metadata(&pid.provider_metadata)?;
    if pid.mandatory_disclosable & ALL_MANDATORY_NATURAL_PID != ALL_MANDATORY_NATURAL_PID
        || pid.mandatory_disclosable & !ALL_MANDATORY_NATURAL_PID != 0
        || optional_present & !pid.optional_disclosable != 0
        || pid.optional_disclosable & !ALL_OPTIONAL_NATURAL_PID != 0
    {
        return Err(ConformanceError::InvalidPidSelectiveDisclosure);
    }

    Ok(())
}

fn validate_provider_metadata(metadata: &PidProviderMetadata<'_>) -> Result<()> {
    if !valid_pid_text(metadata.issuing_authority)
        || !crate::country::is_iso_3166_alpha_2(metadata.issuing_country)
        || metadata
            .document_number
            .is_some_and(|value| !valid_pid_text(value))
        || metadata
            .issuing_jurisdiction
            .is_some_and(|value| !valid_issuing_jurisdiction(value, metadata.issuing_country))
        || metadata
            .expiry_date
            .is_some_and(|date| !valid_calendar_date(date))
        || metadata
            .issuance_date
            .is_some_and(|date| !valid_calendar_date(date))
        || matches!(
            (metadata.issuance_date, metadata.expiry_date),
            (Some(issued), Some(expires)) if issued > expires
        )
    {
        Err(ConformanceError::InvalidPidMetadata)
    } else {
        Ok(())
    }
}

fn valid_issuing_jurisdiction(value: &str, issuing_country: &str) -> bool {
    let Some((country, subdivision)) = value.split_once('-') else {
        return false;
    };
    country == issuing_country
        && !subdivision.is_empty()
        && subdivision.len() <= 3
        && subdivision
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn validate_pid_type(common: &CommonAttestationFacts<'_>, format: &FormatFacts<'_>) -> Result<()> {
    match (common.format, format) {
        (AttestationFormat::SdJwtVc, FormatFacts::SdJwt(facts))
            if common.type_identifier == EU_PID_SD_JWT_VCT && facts.vct == EU_PID_SD_JWT_VCT =>
        {
            Ok(())
        }
        (AttestationFormat::IsoMdoc, FormatFacts::Mdoc(facts))
            if common.type_identifier == EU_PID_MDOC_TYPE
                && facts.doc_type == EU_PID_MDOC_TYPE
                && facts.namespace == EU_PID_MDOC_TYPE =>
        {
            Ok(())
        }
        _ => Err(ConformanceError::InvalidAttestationType),
    }
}
