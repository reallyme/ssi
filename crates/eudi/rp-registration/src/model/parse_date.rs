// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use time::format_description::well_known::{Iso8601, Rfc3339};
use time::{Date, OffsetDateTime};

use crate::{RegistrationError, RegistrationErrorReason};

const REGISTRATION_DATE_BYTES: usize = 10;
const MONTH_SEPARATOR_OFFSET: usize = 4;
const DAY_SEPARATOR_OFFSET: usize = 7;

/// TS5 v1.6 validity dates are calendar dates, interpreted at the UTC day boundary.
/// Keeping this parser shared prevents query evaluation from ignoring a date that
/// the document validator accepted under a different timestamp grammar.
pub(crate) fn parse_iso_calendar_date(value: &str) -> Result<Date, RegistrationError> {
    if value.len() != REGISTRATION_DATE_BYTES
        || value.as_bytes().get(MONTH_SEPARATOR_OFFSET) != Some(&b'-')
        || value.as_bytes().get(DAY_SEPARATOR_OFFSET) != Some(&b'-')
    {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidValidityInterval,
        ));
    }
    Date::parse(value, &Iso8601::DATE).map_err(|_error| {
        RegistrationError::from_reason(RegistrationErrorReason::InvalidValidityInterval)
    })
}

/// Accepts the normative calendar date and the date-time form declared by the
/// accompanying v1.6 JSON Schema. Both become UTC instants for safe ordering.
pub(crate) fn parse_registration_date(value: &str) -> Result<OffsetDateTime, RegistrationError> {
    if let Ok(date) = parse_iso_calendar_date(value) {
        return Ok(date.midnight().assume_utc());
    }
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_error| {
        RegistrationError::from_reason(RegistrationErrorReason::InvalidValidityInterval)
    })
}
