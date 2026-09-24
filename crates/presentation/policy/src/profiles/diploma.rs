// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::VpPolicy;

/// Education credentials (diplomas, degrees).
///
/// QEAA is RECOMMENDED but not strictly mandatory.
pub fn eu_diploma_policy() -> VpPolicy {
    VpPolicy {
        require_qeaa: false,

        require_status: true,
        max_status_age_seconds: Some(30 * 86_400), // 30 days

        ..VpPolicy::default()
    }
}
