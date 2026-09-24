// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::VpPolicy;

/// EU Personal Identification (PID) – QEAA required.
pub fn eu_pid_policy() -> VpPolicy {
    VpPolicy {
        require_qeaa: true,

        // ETSI QEAA profile
        min_qeaa_profile: Some("QEAA-ETSI-1.0".into()),

        // HIGH identity proofing
        min_identity_proofing_level: Some(3),

        // Status list mandatory
        require_status: true,
        max_status_age_seconds: Some(86_400), // 24h

        ..VpPolicy::default()
    }
}
