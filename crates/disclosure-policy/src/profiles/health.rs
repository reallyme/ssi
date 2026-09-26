// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::VpPolicy;
use identity_core_primitives::Algorithm;

/// EU health credential policy.
pub fn eu_health_policy() -> VpPolicy {
    VpPolicy {
        require_status: true,
        max_status_age_seconds: Some(24 * 3_600),
        require_qeaa: false,
        min_qeaa_profile: None,
        min_identity_proofing_level: None,
        allowed_issuer_algorithms: vec![Algorithm::P256],
        allowed_holder_algorithms: vec![Algorithm::P256],
        allow_sd_jwt: true,
        allow_zk: false,
        // Only credentials of this claimset satisfy this profile.
        allowed_claimsets: Some(vec!["eu.health.v1".into()]),
        ..VpPolicy::default()
    }
}
