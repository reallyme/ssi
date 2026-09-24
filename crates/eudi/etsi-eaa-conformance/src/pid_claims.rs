// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use email_address::EmailAddress;

use crate::{
    country::is_iso_3166_alpha_2, AttestationFormat, CalendarDate, ConformanceError, Result,
    OPTIONAL_EMAIL, OPTIONAL_FAMILY_NAME_BIRTH, OPTIONAL_GIVEN_NAME_BIRTH,
    OPTIONAL_MOBILE_PHONE_NUMBER, OPTIONAL_PERSONAL_ADMINISTRATIVE_NUMBER,
    OPTIONAL_RESIDENT_ADDRESS, OPTIONAL_RESIDENT_CITY, OPTIONAL_RESIDENT_COUNTRY,
    OPTIONAL_RESIDENT_POSTAL_CODE, OPTIONAL_RESIDENT_STATE, OPTIONAL_RESIDENT_STREET, OPTIONAL_SEX,
};

const MAX_PID_TEXT_CHARACTERS: usize = 150;
const MAX_NATIONALITIES: usize = 32;
const MAX_PORTRAIT_BYTES: usize = 10 * 1024 * 1024;
const MAX_PORTRAIT_BASE64_BYTES: usize = 13_981_016;
const JPEG_START: [u8; 2] = [0xff, 0xd8];
const JPEG_END: [u8; 2] = [0xff, 0xd9];
const SD_JWT_JPEG_DATA_URL_PREFIX: &str = "data:image/jpeg;base64,";
const PORTRAIT_APPLICABILITY_DATE: CalendarDate = CalendarDate {
    year: 2028,
    month: 8,
    day: 11,
};

/// Structured PID place of birth.
///
/// The borrowed fields are validated in place and are never retained by the
/// validator. The type intentionally does not implement `Debug` or `Clone` so
/// PID values cannot be copied or logged accidentally through this API.
pub struct BirthPlace<'a> {
    /// ISO 3166-1 alpha-2 country, when supplied.
    pub country: Option<&'a str>,
    /// Region, state, or province, when supplied.
    pub region: Option<&'a str>,
    /// City or locality, when supplied.
    pub locality: Option<&'a str>,
}

/// Sex values permitted by the natural-person PID Annex.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Sex {
    /// Not known.
    NotKnown = 0,
    /// Male.
    Male = 1,
    /// Female.
    Female = 2,
    /// Other.
    Other = 3,
    /// Inter.
    Inter = 4,
    /// Diverse.
    Diverse = 5,
    /// Open value.
    Open = 6,
    /// Not applicable.
    NotApplicable = 9,
}

/// Biometric image-quality assessment associated with a non-empty portrait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortraitQualityProfile {
    /// Quality is not assessed because the 2028 requirement is not yet applicable.
    NotAssessedBefore2028,
    /// Assessed against the full-frontal image requirements in ISO/IEC 39794-5.
    Iso39794_5,
    /// Assessed under the permitted ISO/IEC 19794-5 backward-compatibility clauses.
    LegacyIso19794_5,
}

/// Portrait representation carried by the selected PID credential format.
///
/// Portrait bytes are borrowed and never allocated, copied, or retained.
pub enum Portrait<'a> {
    /// JPEG bytes decoded from an ISO/IEC mdoc `bstr`.
    MdocJpeg {
        /// Borrowed JPEG data.
        bytes: &'a [u8],
        /// Biometric quality assessment.
        quality: PortraitQualityProfile,
    },
    /// Canonical base64 JPEG data URL carried by the SD-JWT `picture` claim.
    SdJwtJpegDataUrl {
        /// Borrowed data URL.
        value: &'a str,
        /// Biometric quality assessment.
        quality: PortraitQualityProfile,
    },
    /// Empty portrait value authorized by a Member State opt-out policy.
    OptedOutEmpty,
}

/// Optional natural-person PID claims from CIR (EU) 2024/2977.
///
/// Values are borrowed for validation only. This type deliberately has no
/// logging or copying traits because its fields contain PII.
pub struct OptionalNaturalPersonPidClaims<'a> {
    /// Full residence address.
    pub resident_address: Option<&'a str>,
    /// ISO 3166-1 alpha-2 residence country.
    pub resident_country: Option<&'a str>,
    /// Residence state or region.
    pub resident_state: Option<&'a str>,
    /// Residence city or locality.
    pub resident_city: Option<&'a str>,
    /// Residence postal code.
    pub resident_postal_code: Option<&'a str>,
    /// Residence street.
    pub resident_street: Option<&'a str>,
    /// Personal administrative number.
    pub personal_administrative_number: Option<&'a str>,
    /// Family name at birth.
    pub family_name_birth: Option<&'a str>,
    /// Given name at birth.
    pub given_name_birth: Option<&'a str>,
    /// Closed Annex sex value.
    pub sex: Option<Sex>,
    /// RFC 5322 email address.
    pub email: Option<&'a str>,
    /// International mobile number beginning with `+` and digits only.
    pub mobile_phone_number: Option<&'a str>,
}

impl OptionalNaturalPersonPidClaims<'_> {
    /// Construct an optional claim set with every claim absent.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            resident_address: None,
            resident_country: None,
            resident_state: None,
            resident_city: None,
            resident_postal_code: None,
            resident_street: None,
            personal_administrative_number: None,
            family_name_birth: None,
            given_name_birth: None,
            sex: None,
            email: None,
            mobile_phone_number: None,
        }
    }

    pub(crate) fn presence_mask(&self) -> u16 {
        let mut mask = 0_u16;
        set_when_present(&mut mask, OPTIONAL_RESIDENT_ADDRESS, self.resident_address);
        set_when_present(&mut mask, OPTIONAL_RESIDENT_COUNTRY, self.resident_country);
        set_when_present(&mut mask, OPTIONAL_RESIDENT_STATE, self.resident_state);
        set_when_present(&mut mask, OPTIONAL_RESIDENT_CITY, self.resident_city);
        set_when_present(
            &mut mask,
            OPTIONAL_RESIDENT_POSTAL_CODE,
            self.resident_postal_code,
        );
        set_when_present(&mut mask, OPTIONAL_RESIDENT_STREET, self.resident_street);
        set_when_present(
            &mut mask,
            OPTIONAL_PERSONAL_ADMINISTRATIVE_NUMBER,
            self.personal_administrative_number,
        );
        set_when_present(
            &mut mask,
            OPTIONAL_FAMILY_NAME_BIRTH,
            self.family_name_birth,
        );
        set_when_present(&mut mask, OPTIONAL_GIVEN_NAME_BIRTH, self.given_name_birth);
        if self.sex.is_some() {
            mask |= OPTIONAL_SEX;
        }
        set_when_present(&mut mask, OPTIONAL_EMAIL, self.email);
        set_when_present(
            &mut mask,
            OPTIONAL_MOBILE_PHONE_NUMBER,
            self.mobile_phone_number,
        );
        mask
    }
}

/// Actual natural-person PID values validated by this crate.
///
/// The fields model the mandatory Annex set directly, making omission a type
/// error at the call site. Empty or malformed values are rejected at runtime.
pub struct NaturalPersonPidClaims<'a> {
    /// Current family name.
    pub family_name: &'a str,
    /// Current given name.
    pub given_name: &'a str,
    /// Gregorian date of birth.
    pub birth_date: CalendarDate,
    /// Structured place of birth with at least one component.
    pub birth_place: BirthPlace<'a>,
    /// Non-empty nationality list using assigned ISO codes, `QU`, or `QS`.
    pub nationalities: &'a [&'a str],
    /// Format-specific portrait value.
    pub portrait: Portrait<'a>,
    /// Date used to determine whether biometric quality assessment is mandatory.
    pub assessment_date: CalendarDate,
    /// Optional Annex values.
    pub optional: OptionalNaturalPersonPidClaims<'a>,
}

pub(crate) fn validate_pid_claims(
    format: AttestationFormat,
    claims: &NaturalPersonPidClaims<'_>,
    portrait_opt_out_authorized: bool,
) -> Result<u16> {
    if !valid_pid_text(claims.family_name) || !valid_pid_text(claims.given_name) {
        return Err(ConformanceError::MissingMandatoryPidClaim);
    }
    if !valid_calendar_date(claims.birth_date) {
        return Err(ConformanceError::InvalidPidClaimEncoding);
    }
    validate_birth_place(&claims.birth_place)?;
    validate_nationalities(claims.nationalities)?;
    validate_portrait(
        format,
        &claims.portrait,
        claims.assessment_date,
        portrait_opt_out_authorized,
    )?;
    validate_optional_claims(&claims.optional)?;
    Ok(claims.optional.presence_mask())
}

pub(crate) fn valid_pid_text(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value.chars().count() <= MAX_PID_TEXT_CHARACTERS
        && !value.chars().any(char::is_control)
}

pub(crate) fn valid_calendar_date(date: CalendarDate) -> bool {
    let leap_year = date.year.is_multiple_of(4)
        && (!date.year.is_multiple_of(100) || date.year.is_multiple_of(400));
    let maximum_day = match date.month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return false,
    };
    date.year != 0 && date.day != 0 && date.day <= maximum_day
}

fn validate_birth_place(place: &BirthPlace<'_>) -> Result<()> {
    if place.country.is_none() && place.region.is_none() && place.locality.is_none() {
        return Err(ConformanceError::InvalidPidClaimEncoding);
    }
    if place
        .country
        .is_some_and(|country| !is_iso_3166_alpha_2(country))
        || place.region.is_some_and(|value| !valid_pid_text(value))
        || place.locality.is_some_and(|value| !valid_pid_text(value))
    {
        return Err(ConformanceError::InvalidPidClaimEncoding);
    }
    Ok(())
}

fn validate_nationalities(nationalities: &[&str]) -> Result<()> {
    if nationalities.is_empty() || nationalities.len() > MAX_NATIONALITIES {
        return Err(ConformanceError::InvalidPidClaimEncoding);
    }
    for (index, nationality) in nationalities.iter().enumerate() {
        let valid_code = is_iso_3166_alpha_2(nationality) || matches!(*nationality, "QU" | "QS");
        let duplicated = nationalities[..index]
            .iter()
            .any(|existing| existing == nationality);
        if !valid_code || duplicated {
            return Err(ConformanceError::InvalidPidClaimEncoding);
        }
    }
    Ok(())
}

fn validate_optional_claims(claims: &OptionalNaturalPersonPidClaims<'_>) -> Result<()> {
    let text_values = [
        claims.resident_address,
        claims.resident_state,
        claims.resident_city,
        claims.resident_postal_code,
        claims.resident_street,
        claims.personal_administrative_number,
        claims.family_name_birth,
        claims.given_name_birth,
    ];
    if text_values
        .into_iter()
        .flatten()
        .any(|value| !valid_pid_text(value))
        || claims
            .resident_country
            .is_some_and(|country| !is_iso_3166_alpha_2(country))
        || claims
            .email
            .is_some_and(|email| !valid_pid_text(email) || !EmailAddress::is_valid(email))
        || claims
            .mobile_phone_number
            .is_some_and(|number| !valid_mobile_number(number))
    {
        return Err(ConformanceError::InvalidPidClaimEncoding);
    }
    Ok(())
}

fn valid_mobile_number(value: &str) -> bool {
    let Some(digits) = value.strip_prefix('+') else {
        return false;
    };
    !digits.is_empty()
        && value.len() <= MAX_PID_TEXT_CHARACTERS
        && digits.bytes().all(|byte| byte.is_ascii_digit())
}

fn validate_portrait(
    format: AttestationFormat,
    portrait: &Portrait<'_>,
    assessment_date: CalendarDate,
    portrait_opt_out_authorized: bool,
) -> Result<()> {
    if !valid_calendar_date(assessment_date) {
        return Err(ConformanceError::InvalidPidPortrait);
    }
    match (format, portrait) {
        (AttestationFormat::IsoMdoc, Portrait::MdocJpeg { bytes, quality })
            if valid_jpeg_bytes(bytes) && valid_portrait_quality(*quality, assessment_date) =>
        {
            Ok(())
        }
        (AttestationFormat::SdJwtVc, Portrait::SdJwtJpegDataUrl { value, quality })
            if valid_jpeg_data_url(value) && valid_portrait_quality(*quality, assessment_date) =>
        {
            Ok(())
        }
        (_, Portrait::OptedOutEmpty) if portrait_opt_out_authorized => Ok(()),
        _ => Err(ConformanceError::InvalidPidPortrait),
    }
}

fn valid_portrait_quality(profile: PortraitQualityProfile, assessment_date: CalendarDate) -> bool {
    assessment_date < PORTRAIT_APPLICABILITY_DATE
        || matches!(
            profile,
            PortraitQualityProfile::Iso39794_5 | PortraitQualityProfile::LegacyIso19794_5
        )
}

fn valid_jpeg_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && bytes.len() <= MAX_PORTRAIT_BYTES
        && bytes.starts_with(&JPEG_START)
        && bytes.ends_with(&JPEG_END)
}

fn valid_jpeg_data_url(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix(SD_JWT_JPEG_DATA_URL_PREFIX) else {
        return false;
    };
    let Some(decoded) = inspect_canonical_base64(encoded) else {
        return false;
    };
    decoded.length >= 4 && decoded.first == JPEG_START && decoded.last == JPEG_END
}

struct DecodedBase64Edges {
    length: usize,
    first: [u8; 2],
    last: [u8; 2],
}

fn inspect_canonical_base64(encoded: &str) -> Option<DecodedBase64Edges> {
    if encoded.is_empty()
        || encoded.len() > MAX_PORTRAIT_BASE64_BYTES
        || !encoded.len().is_multiple_of(4)
    {
        return None;
    }

    let mut decoded_length = 0_usize;
    let mut first = [0_u8; 2];
    let mut first_length = 0_usize;
    let mut last = [0_u8; 2];
    let chunk_count = encoded.len() / 4;

    for (index, chunk) in encoded.as_bytes().as_chunks::<4>().0.iter().enumerate() {
        let final_chunk = index.checked_add(1)? == chunk_count;
        let padding = match (chunk[2], chunk[3]) {
            (b'=', b'=') => 2,
            (_, b'=') => 1,
            (b'=', _) => return None,
            _ => 0,
        };
        if padding != 0 && !final_chunk {
            return None;
        }

        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let c = if padding == 2 {
            0
        } else {
            base64_value(chunk[2])?
        };
        let d = if padding == 0 {
            base64_value(chunk[3])?
        } else {
            0
        };
        if (padding == 2 && b & 0x0f != 0) || (padding == 1 && c & 0x03 != 0) {
            return None;
        }

        let bytes = [(a << 2) | (b >> 4), (b << 4) | (c >> 2), (c << 6) | d];
        let byte_count = 3_usize.checked_sub(padding)?;
        decoded_length = decoded_length.checked_add(byte_count)?;
        if decoded_length > MAX_PORTRAIT_BYTES {
            return None;
        }
        for byte in bytes.iter().take(byte_count).copied() {
            if first_length < first.len() {
                first[first_length] = byte;
                first_length = first_length.checked_add(1)?;
            }
            last[0] = last[1];
            last[1] = byte;
        }
    }

    Some(DecodedBase64Edges {
        length: decoded_length,
        first,
        last,
    })
}

const fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn set_when_present(mask: &mut u16, bit: u16, value: Option<&str>) {
    if value.is_some() {
        *mask |= bit;
    }
}
