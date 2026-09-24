// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{OcspCertStatus, OcspPolicy, ParsedOcspResponse};
use envelopes_x509::model::X509Certificate;
use identity_revocation_core::{StatusCheckError, StatusChecker};

/// OCSP-based status checker (core logic, no networking).
pub struct OcspChecker {
    policy: OcspPolicy,
    responses: Vec<ParsedOcspResponse>,
}

impl OcspChecker {
    /// Create an OCSP status checker from already parsed responses.
    pub fn new(responses: Vec<ParsedOcspResponse>) -> Self {
        Self {
            policy: OcspPolicy::default(),
            responses,
        }
    }

    /// Override OCSP freshness and responder-verification policy.
    pub fn with_policy(mut self, policy: OcspPolicy) -> Self {
        self.policy = policy;
        self
    }
}

/// Normalize ASN.1 serial numbers (strip leading zero padding).
fn normalize_serial(mut serial: &[u8]) -> &[u8] {
    while let Some((0, remainder)) = serial.split_first() {
        if remainder.is_empty() {
            break;
        }
        serial = remainder;
    }
    serial
}

impl StatusChecker for OcspChecker {
    fn check(&self, cert: &X509Certificate, now_unix: u64) -> Result<(), StatusCheckError> {
        let issuer_key = cert
            .authority_key_identifier
            .as_ref()
            .ok_or(StatusCheckError::Unavailable)?;

        let serial = normalize_serial(&cert.serial);

        // Find matching OCSP response entry
        let resp = self
            .responses
            .iter()
            .find(|response| {
                response.issuer_key == *issuer_key && normalize_serial(&response.serial) == serial
            })
            .ok_or(StatusCheckError::Unavailable)?;

        // --------------------------------------------------
        // Verification checks (policy-driven)
        // --------------------------------------------------
        if self.policy.require_verified {
            if resp.signature_valid != Some(true) {
                return Err(StatusCheckError::InvalidSignature);
            }
            if resp.responder_authorized != Some(true) {
                return Err(StatusCheckError::InvalidSignature);
            }
            if resp.responder_eku_ocsp_signing != Some(true) {
                return Err(StatusCheckError::InvalidSignature);
            }
        }

        // --------------------------------------------------
        // Freshness checks (policy-driven)
        // --------------------------------------------------
        let skew = self.policy.allowed_skew_secs;

        // RFC 6960 §4.2.2.1 defines thisUpdate/nextUpdate semantics. Skew is
        // applied in the accepting direction and every addition is checked so
        // an extreme timestamp cannot wrap into a fresh response.
        if resp.this_update == 0 {
            return Err(StatusCheckError::InvalidList);
        }
        let latest_acceptable_this_update = now_unix
            .checked_add(skew)
            .ok_or(StatusCheckError::InvalidList)?;
        if resp.this_update > latest_acceptable_this_update {
            return Err(StatusCheckError::InvalidList);
        }

        if let Some(max_age) = self.policy.max_age_secs {
            let expires_at = resp
                .this_update
                .checked_add(max_age)
                .and_then(|value| value.checked_add(skew))
                .ok_or(StatusCheckError::InvalidList)?;
            if now_unix > expires_at {
                return Err(StatusCheckError::Expired);
            }
        }

        if let Some(next) = resp.next_update {
            let expires_at = next
                .checked_add(skew)
                .ok_or(StatusCheckError::InvalidList)?;
            if now_unix > expires_at {
                return Err(StatusCheckError::Expired);
            }
        } else if self.policy.require_next_update {
            return Err(StatusCheckError::InvalidList);
        }

        // RFC 6960 §2.2 defines good, revoked, and unknown as distinct
        // protocol states. In particular, unknown is not evidence of revocation.
        match resp.status {
            OcspCertStatus::Good => Ok(()),
            OcspCertStatus::Revoked => Err(StatusCheckError::Revoked),
            OcspCertStatus::Unknown => Err(StatusCheckError::Unknown),
        }
    }
}
