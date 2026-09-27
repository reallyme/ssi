// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_revocation_ocsp_core::{OcspCertStatus, OcspPolicy};

use crate::ParsedOcspResponse;
use envelopes_x509::{model::X509Certificate, parse_cert_der};
use identity_revocation_core::{
    CompositeRevocationPolicy, OcspStatusChecker, StatusCheckError, StatusChecker,
};

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

    /// Create an OCSP status checker governed by the OCSP section of a
    /// composite revocation policy.
    pub fn from_composite_policy(
        responses: Vec<ParsedOcspResponse>,
        policy: &CompositeRevocationPolicy,
    ) -> Self {
        Self::new(responses).with_policy(policy.ocsp)
    }

    /// Override OCSP freshness and responder-verification policy.
    pub fn with_policy(mut self, policy: OcspPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Validate one matching response against verification and freshness
    /// policy, returning the reported status only when the response is usable.
    fn evaluate(
        &self,
        resp: &ParsedOcspResponse,
        now_unix: u64,
        policy: OcspPolicy,
    ) -> Result<OcspCertStatus, StatusCheckError> {
        let skew = policy.allowed_skew_secs;

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

        if let Some(max_age) = policy.max_age_secs {
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
            if next < resp.this_update {
                return Err(StatusCheckError::InvalidList);
            }
            let expires_at = next
                .checked_add(skew)
                .ok_or(StatusCheckError::InvalidList)?;
            if now_unix > expires_at {
                return Err(StatusCheckError::Expired);
            }
        } else if policy.require_next_update {
            return Err(StatusCheckError::InvalidList);
        }

        Ok(resp.status)
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

/// Deterministic severity used to report one error when every matching
/// response is unusable, independent of response order.
const fn rejection_rank(error: StatusCheckError) -> u8 {
    match error {
        StatusCheckError::InvalidSignature => 3,
        StatusCheckError::InvalidList => 2,
        StatusCheckError::Expired => 1,
        _ => 0,
    }
}

impl StatusChecker for OcspChecker {
    fn check(&self, cert: &X509Certificate, now_unix: u64) -> Result<(), StatusCheckError> {
        self.check_with_policy_value(cert, now_unix, self.policy)
    }
}

impl OcspStatusChecker for OcspChecker {
    fn check_with_policy(
        &self,
        cert: &X509Certificate,
        now_unix: u64,
        policy: OcspPolicy,
    ) -> Result<(), StatusCheckError> {
        self.check_with_policy_value(cert, now_unix, policy)
    }
}

impl OcspChecker {
    fn check_with_policy_value(
        &self,
        cert: &X509Certificate,
        now_unix: u64,
        policy: OcspPolicy,
    ) -> Result<(), StatusCheckError> {
        let parsed_cert =
            parse_cert_der(cert.der.as_slice()).map_err(|_| StatusCheckError::InvalidList)?;
        let serial = normalize_serial(&parsed_cert.serial);
        let certificate_sha256 = reallyme_crypto::sha2::digest(cert.der.as_slice());

        // Every matching response is evaluated so the outcome does not depend
        // on input order: any usable Revoked wins, then any usable Good, then
        // any usable Unknown. RFC 6960 §2.2 defines good, revoked, and unknown
        // as distinct states; unknown is not evidence of revocation.
        let mut saw_good = false;
        let mut saw_unknown = false;
        let mut rejection: Option<StatusCheckError> = None;
        for resp in self.responses.iter().filter(|response| {
            response.certificate_sha256 == *certificate_sha256.as_bytes()
                && normalize_serial(&response.serial) == serial
        }) {
            match self.evaluate(resp, now_unix, policy) {
                Ok(OcspCertStatus::Revoked) => return Err(StatusCheckError::Revoked),
                Ok(OcspCertStatus::Good) => saw_good = true,
                Ok(OcspCertStatus::Unknown) => saw_unknown = true,
                Err(error) => {
                    let replace = rejection
                        .map(|current| rejection_rank(error) > rejection_rank(current))
                        .unwrap_or(true);
                    if replace {
                        rejection = Some(error);
                    }
                }
            }
        }

        if saw_good {
            return Ok(());
        }
        if saw_unknown {
            return Err(StatusCheckError::Unknown);
        }
        Err(rejection.unwrap_or(StatusCheckError::Unavailable))
    }
}
