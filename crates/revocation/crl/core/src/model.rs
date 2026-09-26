// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Portable, backend-agnostic representation of a parsed and verified CRL.
///
/// This type:
/// - contains NO OpenSSL or native crypto handles
/// - is safe for wasm / swift / kotlin bindings
/// - is suitable for revocation checking logic
///
/// Backends must only produce this model for a complete (non-delta), unscoped,
/// direct CRL whose signature has been verified and whose `nextUpdate` is
/// present (RFC 5280 Section 5.1.2.5 requires conforming issuers to include it).
#[derive(Debug, Clone)]
pub struct ParsedCrl {
    /// Issuer key identifier (AKI / SKI hash or canonical bytes)
    pub issuer_key: Vec<u8>,

    /// Serial numbers of revoked certificates
    pub revoked_serials: Vec<Vec<u8>>,

    /// Serial numbers temporarily suspended with `certificateHold`.
    pub suspended_serials: Vec<Vec<u8>>,

    /// thisUpdate (unix seconds)
    pub this_update_unix: u64,

    /// nextUpdate (unix seconds)
    pub next_update_unix: u64,
}
