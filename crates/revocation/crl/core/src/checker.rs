// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;

use crate::ParsedCrl;

use envelopes_x509::X509Certificate;
use identity_revocation_core::{StatusCheckError, StatusChecker};

/// Default clock-skew allowance applied to CRL `thisUpdate`/`nextUpdate`.
pub const DEFAULT_CRL_ALLOWED_SKEW_SECS: u64 = 300;

/// CRL-based status checker (portable)
pub struct CrlChecker {
    crls: Vec<IndexedCrl>,
    allowed_skew_secs: u64,
}

/// A CRL with its revoked serials normalized into an ordered set so lookups
/// are logarithmic and independent of the input encoding of each serial.
struct IndexedCrl {
    issuer_key: Vec<u8>,
    revoked_serials: BTreeSet<Vec<u8>>,
    suspended_serials: BTreeSet<Vec<u8>>,
    this_update_unix: u64,
    next_update_unix: u64,
}

/// Outcome of evaluating one matching CRL.
enum CrlVerdict {
    Revoked,
    Suspended,
    NotRevoked,
    Rejected(StatusCheckError),
}

impl CrlChecker {
    /// Create a CRL status checker from already parsed and verified CRLs.
    pub fn new(crls: Vec<ParsedCrl>) -> Self {
        let crls = crls
            .into_iter()
            .map(|crl| IndexedCrl {
                revoked_serials: crl
                    .revoked_serials
                    .iter()
                    .map(|serial| normalize_serial(serial).to_vec())
                    .collect(),
                suspended_serials: crl
                    .suspended_serials
                    .iter()
                    .map(|serial| normalize_serial(serial).to_vec())
                    .collect(),
                issuer_key: crl.issuer_key,
                this_update_unix: crl.this_update_unix,
                next_update_unix: crl.next_update_unix,
            })
            .collect();
        Self {
            crls,
            allowed_skew_secs: DEFAULT_CRL_ALLOWED_SKEW_SECS,
        }
    }

    /// Override the clock-skew allowance applied to CRL freshness checks.
    pub fn with_allowed_skew_secs(mut self, allowed_skew_secs: u64) -> Self {
        self.allowed_skew_secs = allowed_skew_secs;
        self
    }
}

// CRL serial numbers may include ASN.1 sign padding; comparison uses the
// canonical unsigned serial bytes.
fn normalize_serial(serial: &[u8]) -> &[u8] {
    let start = serial
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(serial.len());
    serial.get(start..).unwrap_or_default()
}

impl IndexedCrl {
    fn evaluate(&self, serial: &[u8], now_unix: u64, skew: u64) -> CrlVerdict {
        // RFC 5280 Section 5.1.2.4/5.1.2.5: a CRL is only usable between
        // thisUpdate and nextUpdate. Skew widens the window in the accepting
        // direction and every addition is checked so extreme values cannot
        // wrap into a fresh window.
        if self.next_update_unix < self.this_update_unix {
            return CrlVerdict::Rejected(StatusCheckError::InvalidList);
        }
        let Some(latest_acceptable_this_update) = now_unix.checked_add(skew) else {
            return CrlVerdict::Rejected(StatusCheckError::InvalidList);
        };
        if self.this_update_unix > latest_acceptable_this_update {
            return CrlVerdict::Rejected(StatusCheckError::NotYetValid);
        }
        let Some(expires_at) = self.next_update_unix.checked_add(skew) else {
            return CrlVerdict::Rejected(StatusCheckError::InvalidList);
        };
        if now_unix > expires_at {
            return CrlVerdict::Rejected(StatusCheckError::Expired);
        }

        if self.revoked_serials.contains(serial) {
            CrlVerdict::Revoked
        } else if self.suspended_serials.contains(serial) {
            CrlVerdict::Suspended
        } else {
            CrlVerdict::NotRevoked
        }
    }
}

/// Deterministic severity used to report one error when every matching CRL is
/// unusable, independent of the order in which CRLs were supplied.
const fn rejection_rank(error: StatusCheckError) -> u8 {
    match error {
        StatusCheckError::InvalidList => 3,
        StatusCheckError::NotYetValid => 2,
        StatusCheckError::Expired => 1,
        _ => 0,
    }
}

impl StatusChecker for CrlChecker {
    fn check(&self, cert: &X509Certificate, now_unix: u64) -> Result<(), StatusCheckError> {
        let issuer_key = cert
            .authority_key_identifier
            .as_ref()
            .ok_or(StatusCheckError::Unavailable)?;
        let serial = normalize_serial(&cert.serial);

        // Every CRL from this issuer is evaluated so the outcome does not
        // depend on input order: any fresh CRL listing the serial wins, then
        // any fresh CRL that does not list it.
        let mut saw_fresh_not_revoked = false;
        let mut saw_suspended = false;
        let mut rejection: Option<StatusCheckError> = None;
        for crl in self.crls.iter().filter(|c| &c.issuer_key == issuer_key) {
            match crl.evaluate(serial, now_unix, self.allowed_skew_secs) {
                CrlVerdict::Revoked => return Err(StatusCheckError::Revoked),
                CrlVerdict::Suspended => saw_suspended = true,
                CrlVerdict::NotRevoked => saw_fresh_not_revoked = true,
                CrlVerdict::Rejected(error) => {
                    let replace = rejection
                        .map(|current| rejection_rank(error) > rejection_rank(current))
                        .unwrap_or(true);
                    if replace {
                        rejection = Some(error);
                    }
                }
            }
        }

        if saw_suspended {
            return Err(StatusCheckError::Suspended);
        }

        if saw_fresh_not_revoked {
            return Ok(());
        }
        Err(rejection.unwrap_or(StatusCheckError::Unavailable))
    }
}
