// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::VpPolicy;

/// EU PID without QEAA (e.g. test, sandbox, private sector).
pub fn eu_pid_baseline_policy() -> VpPolicy {
    VpPolicy {
        require_qeaa: false,
        require_status: true,
        max_status_age_seconds: Some(86_400),

        ..VpPolicy::default()
    }
}
