// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Built-in credential claim registries.

mod common;

/// EU address claim registry.
pub mod address;
/// EU age claim registry.
pub mod age;
/// EU company claim registry.
pub mod company;
/// EU diploma claim registry.
pub mod diploma;
/// EU driving licence claim registry.
pub mod driving_license;
/// Generic EU EAA claim registry.
pub mod eaa;
/// eIDAS VID claim registry.
pub mod eidas_vid;
/// EU health claim registry.
pub mod health;
/// ICAO passport claim registry.
pub mod passport;
/// EU PID claim registry.
pub mod pid;
/// EU professional licence claim registry.
pub mod professional_license;
/// EU tax claim registry.
pub mod tax;

pub use address::{eu_address_v1, EU_ADDRESS_V1_CLAIM_IDS};
pub use age::{eu_age_v1, EU_AGE_V1_CLAIM_IDS};
pub use company::{eu_company_v1, EU_COMPANY_V1_CLAIM_IDS};
pub use diploma::{eu_diploma_v1, EU_DIPLOMA_V1_CLAIM_IDS};
pub use driving_license::{eu_driving_license_v1, EU_DRIVING_LICENSE_V1_CLAIM_IDS};
pub use eaa::{eu_eaa_v1, EU_EAA_V1_CLAIM_IDS};
pub use eidas_vid::{eu_eidas_vid_v1, EU_EIDAS_VID_V1_CLAIM_IDS};
pub use health::{eu_health_v1, EU_HEALTH_V1_CLAIM_IDS};
pub use passport::{
    eu_passport_v1, icao_passport_v1, EU_PASSPORT_V1_CLAIM_IDS, ICAO_PASSPORT_V1_CLAIM_IDS,
};
pub use pid::{eu_pid_v1, EU_PID_V1_CLAIM_IDS};
pub use professional_license::{eu_professional_license_v1, EU_PROFESSIONAL_LICENSE_V1_CLAIM_IDS};
pub use tax::{eu_tax_v1, EU_TAX_V1_CLAIM_IDS};
