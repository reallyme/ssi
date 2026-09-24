// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verifier policy profiles.
//!
//! These profiles express **trust and acceptance requirements**
//! (QEAA, LOIP, status checking, etc.), not claim schemas.
//!
//! They are intended to be paired with claim registries
//! (e.g. `identity-credential-claims-core::profiles`).

// ---------------------------------------------------------------------
// Core EU identity profiles
// ---------------------------------------------------------------------

/// Electronic attestation of attributes policy profile.
pub mod eaa;
/// EU PID policy profile.
pub mod pid;
/// Baseline EU PID policy profile.
pub mod pid_baseline;

// ---------------------------------------------------------------------
// Sector-specific EU profiles
// ---------------------------------------------------------------------

/// Address credential policy profile.
pub mod address;
/// Age credential policy profile.
pub mod age;
/// Company credential policy profile.
pub mod company;
/// Diploma credential policy profile.
pub mod diploma;
/// Driving-license credential policy profile.
pub mod driving_license;
/// eIDAS VID credential policy profile.
pub mod eidas_vid;
/// Health credential policy profile.
pub mod health;
/// KYC credential policy profile.
pub mod kyc;
/// Passport credential policy profile.
pub mod passport;
/// Professional-license credential policy profile.
pub mod professional_license;
/// Tax credential policy profile.
pub mod tax;

// ---------------------------------------------------------------------
// Re-exports (explicit and auditable)
// ---------------------------------------------------------------------

pub use eaa::eu_eaa_policy;
pub use pid::eu_pid_policy;
pub use pid_baseline::eu_pid_baseline_policy;

pub use address::eu_address_policy;
pub use age::eu_age_policy;
pub use company::eu_company_policy;
pub use diploma::eu_diploma_policy;
pub use driving_license::eu_driving_license_policy;
pub use eidas_vid::eu_eidas_vid_policy;
pub use health::eu_health_policy;
pub use kyc::eu_kyc_policy;
pub use passport::eu_passport_policy;
pub use professional_license::eu_professional_license_policy;
pub use tax::eu_tax_policy;
