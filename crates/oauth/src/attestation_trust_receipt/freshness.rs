// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::attestation_client_auth::MAX_ATTESTATION_TRUST_EVIDENCE_AGE_SECONDS;
use crate::error::{OauthError, OauthResult, Reason};

use super::WalletAttestationTrustEvidence;

impl WalletAttestationTrustEvidence {
    /// Validates and narrows this receipt to its effective trust-evidence
    /// lifetime at a trusted request time.
    ///
    /// RFC 5280 §4.1.2.5 supplies the certificate deadline, but it does not
    /// make a past status or trust-list decision current. The caller-supplied
    /// bounded age therefore independently limits reuse of that decision; the
    /// narrower deadline is retained in the protobuf audit receipt.
    pub fn validate_freshness_at(
        &mut self,
        current_time: i64,
        max_age_seconds: i64,
    ) -> OauthResult<()> {
        if current_time <= 0
            || max_age_seconds <= 0
            || max_age_seconds > MAX_ATTESTATION_TRUST_EVIDENCE_AGE_SECONDS
        {
            return Err(OauthError::new(Reason::InvalidClientAttestation));
        }
        let evaluated_at = self.evidence.evaluated_at.unix_timestamp();
        if evaluated_at > current_time {
            return Err(OauthError::new(
                Reason::AttestationTrustEvidenceFutureIssued,
            ));
        }
        let evidence_deadline = evaluated_at
            .checked_add(max_age_seconds)
            .ok_or(OauthError::new(Reason::InvalidAttestationReceipt))?;
        let effective_deadline = self.valid_until_unix.min(evidence_deadline);
        if effective_deadline < current_time {
            return Err(OauthError::new(Reason::AttestationTrustEvidenceStale));
        }
        self.valid_until_unix = effective_deadline;
        Ok(())
    }
}
