// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
/// Portable, backend-agnostic representation of a parsed CRL.
///
/// This type:
/// - contains NO OpenSSL or native crypto handles
/// - is safe for wasm / swift / kotlin bindings
/// - is suitable for revocation checking logic
#[derive(Debug, Clone)]
pub struct ParsedCrl {
    /// Issuer key identifier (AKI / SKI hash or canonical bytes)
    pub issuer_key: Vec<u8>,

    /// Serial numbers of revoked certificates
    pub revoked_serials: Vec<Vec<u8>>,

    /// thisUpdate (unix seconds)
    pub this_update_unix: Option<u64>,

    /// nextUpdate (unix seconds)
    pub next_update_unix: Option<u64>,
}
