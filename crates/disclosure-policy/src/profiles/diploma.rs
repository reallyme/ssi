// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::VpPolicy;

/// EU education credential policy for diplomas and degrees.
pub fn eu_diploma_policy() -> VpPolicy {
    VpPolicy {
        require_qeaa: false,
        require_status: true,
        max_status_age_seconds: Some(30 * 86_400),
        // Only credentials of this claimset satisfy this profile.
        allowed_claimsets: Some(vec!["eu.diploma.v1".into()]),
        ..VpPolicy::default()
    }
}
