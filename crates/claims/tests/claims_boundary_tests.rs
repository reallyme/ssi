// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use reallyme_credential_claims::{
    ClaimDate, ClaimDateTime, ClaimDecimal, ClaimsError, ClaimsInvalidReason,
};

#[test]
fn property_claim_dates_and_decimals_reject_invalid_boundaries() {
    for value in [
        "", "-", ".1", "1.", "01", "-0", "1.10", "1.0", "1e9", "NaN", "Infinity",
    ] {
        assert_eq!(
            ClaimDecimal::new(value),
            Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::InvalidDecimal
            ))
        );
    }

    for value in ["1900-02-29", "2026-02-29", "2026-13-01", "2026-00-01"] {
        assert_eq!(
            ClaimDate::new(value),
            Err(ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidDate))
        );
    }

    for value in [
        "2026-07-13",
        "2026-07-13T10:15:30",
        "2026-07-13T25:15:30Z",
        "2026-02-29T10:15:30Z",
    ] {
        assert_eq!(
            ClaimDateTime::new(value),
            Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::InvalidDateTime
            ))
        );
    }
}
