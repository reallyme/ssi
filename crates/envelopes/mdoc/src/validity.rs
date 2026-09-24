// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{MdocEnvelopeError, MdocInvalidInputReason, ValidityInfo};

/// Validate the ordering required for an authenticated MSO validity window.
///
/// This predicate is shared by issuance and verification so an externally
/// produced issuerAuth cannot bypass the constraints applied to locally issued
/// documents. Current-time checks are separate because they are caller policy,
/// while the signed ordering is an intrinsic property of the MSO.
pub(crate) fn validate_validity_window(validity: &ValidityInfo) -> Result<(), MdocEnvelopeError> {
    if validity.signed == 0
        || validity.valid_from == 0
        || validity.valid_until == 0
        || validity.signed > validity.valid_from
        || validity.valid_from >= validity.valid_until
    {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::InvalidValidityWindow,
        ));
    }

    Ok(())
}
