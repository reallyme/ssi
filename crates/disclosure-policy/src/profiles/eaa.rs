// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::VpPolicy;

/// EU Electronic Attestation policy.
pub fn eu_eaa_policy() -> VpPolicy {
    VpPolicy {
        require_qeaa: true,
        min_qeaa_profile: Some("QEAA-ETSI-1.0".into()),
        min_identity_proofing_level: Some(2),
        require_status: true,
        max_status_age_seconds: Some(86_400),
        ..VpPolicy::default()
    }
}
