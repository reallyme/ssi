// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::update::error::UpdateError;

/// Validate the update policy bounds before an update is accepted.
pub fn validate_update_policy(
    allowed: &[String],
    threshold: Option<u64>,
) -> Result<(), UpdateError> {
    if allowed.is_empty() {
        return Err(UpdateError::PolicyViolation);
    }

    if let Some(value) = threshold {
        let Ok(value_usize) = usize::try_from(value) else {
            return Err(UpdateError::PolicyViolation);
        };

        if value_usize == 0 || value_usize > allowed.len() {
            return Err(UpdateError::PolicyViolation);
        }
    }

    Ok(())
}
