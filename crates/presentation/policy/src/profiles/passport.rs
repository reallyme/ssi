// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// passport.rs
use crate::VpPolicy;
use identity_core_primitives::Algorithm;

/// Build the verifier policy for a passport credential presentation.
pub fn eu_passport_policy() -> VpPolicy {
    VpPolicy {
        require_status: true,
        max_status_age_seconds: Some(3600),

        require_qeaa: true,
        min_qeaa_profile: Some("QEAA-ETSI-1.0".into()),
        min_identity_proofing_level: Some(3), // HIGH

        allowed_issuer_algorithms: vec![Algorithm::P256],
        allowed_holder_algorithms: vec![Algorithm::P256],

        allow_sd_jwt: false,
        allow_zk: true,

        ..VpPolicy::default()
    }
}
