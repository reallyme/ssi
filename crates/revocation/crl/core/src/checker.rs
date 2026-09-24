// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::ParsedCrl;

use envelopes_x509::X509Certificate;
use identity_revocation_core::{StatusCheckError, StatusChecker};

/// CRL-based status checker (portable)
pub struct CrlChecker {
    crls: Vec<ParsedCrl>,
}

impl CrlChecker {
    /// Create a CRL status checker from already parsed and verified CRLs.
    pub fn new(crls: Vec<ParsedCrl>) -> Self {
        Self { crls }
    }
}

// CRL serial numbers may include ASN.1 sign padding; comparison uses the
// canonical unsigned serial bytes.
fn normalize_serial(s: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < s.len() && s[i] == 0 {
        i += 1;
    }
    &s[i..]
}

impl StatusChecker for CrlChecker {
    fn check(&self, cert: &X509Certificate, now_unix: u64) -> Result<(), StatusCheckError> {
        // ------------------------------------------------------------
        // 1) Match CRL by issuer key identifier
        // ------------------------------------------------------------
        let issuer_key = cert
            .authority_key_identifier
            .as_ref()
            .ok_or(StatusCheckError::Unavailable)?;

        let crl = self
            .crls
            .iter()
            .find(|c| &c.issuer_key == issuer_key)
            .ok_or(StatusCheckError::Unavailable)?;

        // ------------------------------------------------------------
        // 2) Freshness check
        // ------------------------------------------------------------
        if let Some(next) = crl.next_update_unix {
            if now_unix > next {
                return Err(StatusCheckError::Unavailable);
            }
        }

        // ------------------------------------------------------------
        // 3) Revocation check
        // ------------------------------------------------------------
        let needle = normalize_serial(&cert.serial);

        if crl
            .revoked_serials
            .iter()
            .any(|s| normalize_serial(s) == needle)
        {
            return Err(StatusCheckError::Revoked);
        }

        Ok(())
    }
}
