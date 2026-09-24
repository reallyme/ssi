// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn registry_for_predefined_claimset(
    claimset_id: &str,
) -> Option<reallyme_credential_claims::ClaimsRegistry> {
    match claimset_id {
        "eu.pid.v1" => Some(eu_pid_v1()),
        "eu.eaa.v1" => Some(eu_eaa_v1()),
        "eu.age.v1" => Some(eu_age_v1()),
        "eu.address.v1" => Some(eu_address_v1()),
        "eu.diploma.v1" => Some(eu_diploma_v1()),
        "eu.driving_license.v1" => Some(eu_driving_license_v1()),
        "eu.professional_license.v1" => Some(eu_professional_license_v1()),
        "eu.health.v1" => Some(eu_health_v1()),
        "eu.company.v1" => Some(eu_company_v1()),
        "eu.tax.v1" => Some(eu_tax_v1()),
        "eu.eidas-vid.v1" => Some(eu_eidas_vid_v1()),
        "eu.passport.v1" => Some(eu_passport_v1()),
        "icao.passport.v1" => Some(icao_passport_v1()),
        _ => None,
    }
}
