// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::VpPolicy;

/// EU PID baseline policy without QEAA requirement.
pub fn eu_pid_baseline_policy() -> VpPolicy {
    VpPolicy {
        require_qeaa: false,
        require_status: true,
        max_status_age_seconds: Some(86_400),
        // Only credentials of this claimset satisfy this profile.
        allowed_claimsets: Some(vec!["eu.pid.baseline.v1".into()]),
        ..VpPolicy::default()
    }
}
