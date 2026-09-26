// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::VpPolicy;
use identity_core_primitives::Algorithm;

/// EU age or pseudonymous age policy.
pub fn eu_age_policy() -> VpPolicy {
    VpPolicy {
        require_status: false,
        require_qeaa: false,
        min_qeaa_profile: None,
        min_identity_proofing_level: None,
        allowed_issuer_algorithms: vec![Algorithm::P256, Algorithm::Ed25519],
        allowed_holder_algorithms: vec![Algorithm::P256, Algorithm::Ed25519],
        allow_sd_jwt: true,
        allow_zk: true,
        // Only credentials of this claimset satisfy this profile.
        allowed_claimsets: Some(vec!["eu.age.v1".into()]),
        ..VpPolicy::default()
    }
}
