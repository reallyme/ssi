// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::profiles;
use crate::VpPolicy;

/// Select a verifier policy based on credential `claimset_id`.
///
/// This function is:
/// - deterministic
/// - side-effect free
/// - auditable
///
/// Unknown claimsets MUST be rejected by the caller.
pub fn policy_for_claimset(claimset_id: &str) -> Option<VpPolicy> {
    match claimset_id {
        // -----------------------------------------------------------------
        // EU PID
        // -----------------------------------------------------------------
        "eu.pid.v1" => Some(profiles::eu_pid_policy()),
        "eu.pid.baseline.v1" => Some(profiles::eu_pid_baseline_policy()),

        // -----------------------------------------------------------------
        // Electronic Attestations (EAA)
        // -----------------------------------------------------------------
        "eu.eaa.v1" => Some(profiles::eu_eaa_policy()),

        // -----------------------------------------------------------------
        // Address / residence
        // -----------------------------------------------------------------
        "eu.address.v1" => Some(profiles::eu_address_policy()),

        // -----------------------------------------------------------------
        // Age / pseudonymous age
        // -----------------------------------------------------------------
        "eu.age.v1" => Some(profiles::eu_age_policy()),

        // -----------------------------------------------------------------
        // Education / diplomas
        // -----------------------------------------------------------------
        "eu.diploma.v1" => Some(profiles::eu_diploma_policy()),

        // -----------------------------------------------------------------
        // Driving licence
        // -----------------------------------------------------------------
        "eu.driving_license.v1" => Some(profiles::eu_driving_license_policy()),

        // -----------------------------------------------------------------
        // Professional licence
        // -----------------------------------------------------------------
        "eu.professional_license.v1" => Some(profiles::eu_professional_license_policy()),

        // -----------------------------------------------------------------
        // Travel documents / passport
        // -----------------------------------------------------------------
        "eu.passport.v1" => Some(profiles::eu_passport_policy()),

        // -----------------------------------------------------------------
        // Health credentials
        // -----------------------------------------------------------------
        "eu.health.v1" => Some(profiles::eu_health_policy()),

        // -----------------------------------------------------------------
        // KYC / AML
        // -----------------------------------------------------------------
        "eu.kyc.v1" => Some(profiles::eu_kyc_policy()),

        // -----------------------------------------------------------------
        // Company registry
        // -----------------------------------------------------------------
        "eu.company.v1" => Some(profiles::eu_company_policy()),

        // -----------------------------------------------------------------
        // Tax residency
        // -----------------------------------------------------------------
        "eu.tax.v1" => Some(profiles::eu_tax_policy()),

        // -----------------------------------------------------------------
        // eIDAS natural person VID
        // -----------------------------------------------------------------
        "eu.eidas-vid.v1" => Some(profiles::eu_eidas_vid_policy()),

        // -----------------------------------------------------------------
        // Unknown
        // -----------------------------------------------------------------
        _ => None,
    }
}
