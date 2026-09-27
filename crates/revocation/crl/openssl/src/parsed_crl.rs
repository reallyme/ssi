// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use openssl::x509::{X509Crl, X509};

/// OpenSSL-backed parsed CRL.
///
/// Internal type used only during:
/// - CRL parsing
/// - signature verification
/// - issuer validation
pub struct ParsedOpenSslCrl {
    /// Issuer key identifier used to match certificates to this CRL.
    pub(crate) issuer_key: Vec<u8>,
    /// OpenSSL CRL handle retained during native validation.
    pub(crate) _crl: X509Crl,
    /// Revoked certificate serial numbers.
    pub(crate) revoked_serials: Vec<Vec<u8>>,
    /// Serial numbers carrying the temporary `certificateHold` reason.
    pub(crate) suspended_serials: Vec<Vec<u8>>,
    /// `thisUpdate` as Unix seconds.
    pub(crate) this_update_unix: u64,
    /// `nextUpdate` as Unix seconds.
    pub(crate) next_update_unix: u64,
    /// Issuer certificate used to verify the CRL signature.
    pub(crate) _issuer_cert: X509,
}

impl ParsedOpenSslCrl {
    /// Revoked serial numbers extracted from the verified CRL.
    pub fn revoked_serials(&self) -> &[Vec<u8>] {
        &self.revoked_serials
    }

    /// Suspended serial numbers extracted from `certificateHold` entries.
    pub fn suspended_serials(&self) -> &[Vec<u8>] {
        &self.suspended_serials
    }

    /// CRL `thisUpdate` as Unix seconds.
    pub const fn this_update_unix(&self) -> u64 {
        self.this_update_unix
    }

    /// CRL `nextUpdate` as Unix seconds.
    pub const fn next_update_unix(&self) -> u64 {
        self.next_update_unix
    }
}

impl core::fmt::Debug for ParsedOpenSslCrl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ParsedOpenSslCrl")
            .field("issuer_key", &self.issuer_key)
            .field("revoked_serials", &self.revoked_serials)
            .field("suspended_serials", &self.suspended_serials)
            .field("this_update_unix", &self.this_update_unix)
            .field("next_update_unix", &self.next_update_unix)
            .finish()
    }
}
