// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Built-in verifier policy profiles.
//!
//! These profiles express trust and acceptance requirements such as QEAA,
//! identity proofing rank, status freshness, accepted algorithms, and accepted
//! presentation formats. Claim schemas remain separate from these profiles.

/// EU address policy.
pub mod address;
/// EU age policy.
pub mod age;
/// EU company policy.
pub mod company;
/// EU diploma policy.
pub mod diploma;
/// EU driving licence policy.
pub mod driving_license;
/// EU electronic attestation policy.
pub mod eaa;
/// eIDAS VID policy.
pub mod eidas_vid;
/// EU health credential policy.
pub mod health;
/// EU KYC policy.
pub mod kyc;
/// EU passport policy.
pub mod passport;
/// EU PID policy.
pub mod pid;
/// EU PID baseline policy.
pub mod pid_baseline;
/// EU professional licence policy.
pub mod professional_license;
/// EU tax policy.
pub mod tax;

pub use address::eu_address_policy;
pub use age::eu_age_policy;
pub use company::eu_company_policy;
pub use diploma::eu_diploma_policy;
pub use driving_license::eu_driving_license_policy;
pub use eaa::eu_eaa_policy;
pub use eidas_vid::eu_eidas_vid_policy;
pub use health::eu_health_policy;
pub use kyc::eu_kyc_policy;
pub use passport::eu_passport_policy;
pub use pid::eu_pid_policy;
pub use pid_baseline::eu_pid_baseline_policy;
pub use professional_license::eu_professional_license_policy;
pub use tax::eu_tax_policy;
