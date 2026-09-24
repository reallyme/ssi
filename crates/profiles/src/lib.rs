// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cross-protocol interoperability profile identity.
//!
//! HAIP and EUDI are interoperability profiles that constrain *both* credential
//! issuance (OpenID4VCI) and presentation (OpenID4VP). This crate owns only the
//! shared identity of those profiles — their canonical names, versions, and
//! eIDAS relevance — so the issuance and presentation layers reference one
//! definition instead of each re-declaring the profile enum. The protocol-
//! specific policy (which algorithms, formats, and attestations a profile
//! requires for a given flow) stays in each protocol's own crates.

mod profile;

pub use profile::{
    Profile, EUDI_PID_PROFILE_NAME, HAIP_PROFILE_NAME, HAIP_SHORT_NAME, HAIP_VERSION,
};
