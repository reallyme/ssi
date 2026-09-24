// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `es256-jws-cid-2025` Data Integrity cryptosuite.

/// Custom cryptosuite identifier.
pub const ES256_JWS_CID_2025_CRYPTOSUITE: &str = "es256-jws-cid-2025";

/// Compile-time status for the staged cryptosuite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Es256JwsCid2025Status {
    /// Typed DID document integration is compiled into this crate.
    Active,
}

/// Current status of this suite in `reallyme/ssi`.
pub const ES256_JWS_CID_2025_STATUS: Es256JwsCid2025Status = Es256JwsCid2025Status::Active;

#[path = "es256_jws_cid_2025/source/mod.rs"]
mod source;

pub use source::{sign_es256_jws_cid_2025, verify_es256_jws_cid_2025, Es256JwsCid2025Error};
