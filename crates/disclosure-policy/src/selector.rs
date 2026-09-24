// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::profiles;
use crate::VpPolicy;

/// Select a built-in verifier policy based on credential claimset id.
pub fn policy_for_claimset(claimset_id: &str) -> Option<VpPolicy> {
    match claimset_id {
        "eu.pid.v1" => Some(profiles::eu_pid_policy()),
        "eu.pid.baseline.v1" => Some(profiles::eu_pid_baseline_policy()),
        "eu.eaa.v1" => Some(profiles::eu_eaa_policy()),
        "eu.address.v1" => Some(profiles::eu_address_policy()),
        "eu.age.v1" => Some(profiles::eu_age_policy()),
        "eu.diploma.v1" => Some(profiles::eu_diploma_policy()),
        "eu.driving_license.v1" => Some(profiles::eu_driving_license_policy()),
        "eu.professional_license.v1" => Some(profiles::eu_professional_license_policy()),
        "eu.passport.v1" => Some(profiles::eu_passport_policy()),
        "eu.health.v1" => Some(profiles::eu_health_policy()),
        "eu.kyc.v1" => Some(profiles::eu_kyc_policy()),
        "eu.company.v1" => Some(profiles::eu_company_policy()),
        "eu.tax.v1" => Some(profiles::eu_tax_policy()),
        "eu.eidas-vid.v1" => Some(profiles::eu_eidas_vid_policy()),
        _ => None,
    }
}
