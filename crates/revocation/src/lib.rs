// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protocol-neutral credential revocation and suspension policy.
//!
//! This crate composes already-resolved status evidence. It does not fetch OCSP,
//! CRL, or StatusList resources and does not define HTTP protocol behavior.

mod cache;
mod composite;
mod error;
mod model;
mod presets;
mod statuslist;

pub use cache::{InMemoryRevocationCache, RevocationEvidenceCache};
pub use composite::CompositeStatusChecker;
pub use error::{RevocationPolicyError, StatusCheckError};
pub use model::{
    CompositeRevocationPolicy, OcspPolicy, RevocationEvidenceMeta, RevocationSource, SoftFailMode,
    StatusChecker,
};
pub use presets::{eu_qtsp_x509, hybrid_fallback, vc_statuslist};
pub use reallyme_trust_x509::X509Certificate;
pub use statuslist::StatusListChecker;
