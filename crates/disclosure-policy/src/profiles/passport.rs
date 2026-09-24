// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::VpPolicy;
use identity_core_primitives::Algorithm;

/// EU passport or travel document policy.
pub fn eu_passport_policy() -> VpPolicy {
    VpPolicy {
        require_status: true,
        max_status_age_seconds: Some(3_600),
        require_qeaa: true,
        min_qeaa_profile: Some("QEAA-ETSI-1.0".into()),
        min_identity_proofing_level: Some(3),
        allowed_issuer_algorithms: vec![Algorithm::P256],
        allowed_holder_algorithms: vec![Algorithm::P256],
        allow_sd_jwt: false,
        allow_zk: true,
        ..VpPolicy::default()
    }
}
