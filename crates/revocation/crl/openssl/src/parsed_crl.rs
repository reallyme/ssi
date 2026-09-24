// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use identity_revocation_crl_core::ParsedCrl;
use openssl::x509::{X509Crl, X509};

/// OpenSSL-backed parsed CRL.
///
/// Internal type used only during:
/// - CRL parsing
/// - signature verification
/// - issuer validation
pub struct ParsedOpenSslCrl {
    /// Issuer key identifier used to match certificates to this CRL.
    pub issuer_key: Vec<u8>,
    /// OpenSSL CRL handle retained during native validation.
    pub crl: X509Crl,
    /// Revoked certificate serial numbers.
    pub revoked_serials: Vec<Vec<u8>>,
    /// `thisUpdate` as Unix seconds.
    pub this_update_unix: Option<u64>,
    /// `nextUpdate` as Unix seconds.
    pub next_update_unix: Option<u64>,
    /// Issuer certificate used to verify the CRL signature.
    pub issuer_cert: X509,
}

impl core::fmt::Debug for ParsedOpenSslCrl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ParsedOpenSslCrl")
            .field("issuer_key", &self.issuer_key)
            .field("revoked_serials", &self.revoked_serials)
            .field("this_update_unix", &self.this_update_unix)
            .field("next_update_unix", &self.next_update_unix)
            .finish()
    }
}

impl From<ParsedOpenSslCrl> for ParsedCrl {
    fn from(crl: ParsedOpenSslCrl) -> Self {
        ParsedCrl {
            issuer_key: crl.issuer_key,
            revoked_serials: crl.revoked_serials,
            this_update_unix: crl.this_update_unix,
            next_update_unix: crl.next_update_unix,
        }
    }
}
