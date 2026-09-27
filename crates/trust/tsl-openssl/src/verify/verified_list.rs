// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_trust_tsl_core::TrustedList;

use super::{
    TslOpenSslError, TslSignatureAlgorithm, TslSignerAuthorizationEvidence,
    TslSignerProfileEvidence, VerifiedTrustedList,
};

impl VerifiedTrustedList {
    /// Borrows the authenticated normalized trusted list.
    #[must_use]
    pub const fn list(&self) -> &TrustedList {
        &self.list
    }

    /// Borrows the signer path and status decision.
    #[must_use]
    pub const fn signer_trust(&self) -> &reallyme_trust_core::TrustDecision {
        &self.signer_trust
    }

    /// Returns the SHA-256 identity of the certificate that verified the XML signature.
    #[must_use]
    pub const fn signer_certificate_sha256(&self) -> [u8; 32] {
        self.signer_certificate_sha256
    }

    /// Borrows SHA-256 identities of certificates in the signature's KeyInfo.
    #[must_use]
    pub fn key_info_certificate_sha256(&self) -> &[[u8; 32]] {
        &self.key_info_certificate_sha256
    }

    /// Returns the signer-authorization policy evidence.
    #[must_use]
    pub const fn signer_authorization(&self) -> TslSignerAuthorizationEvidence {
        self.signer_authorization
    }

    /// Returns the TLSO profile evidence when TS 119 612 clause 5.7.1 was selected.
    #[must_use]
    pub const fn signer_profile(&self) -> Option<TslSignerProfileEvidence> {
        match self.signer_authorization {
            TslSignerAuthorizationEvidence::TrustedListOperatorProfile(evidence) => Some(evidence),
            TslSignerAuthorizationEvidence::AuthenticatedPointerCertificate(evidence) => {
                Some(evidence)
            }
            TslSignerAuthorizationEvidence::ExactExternalCertificate => None,
        }
    }

    /// Returns the authenticated XML signature suite admitted by policy.
    #[must_use]
    pub const fn signature_algorithm(&self) -> TslSignatureAlgorithm {
        self.signature_algorithm
    }

    /// Rejects a list older than the last accepted list for the same location.
    pub fn validate_sequence_number(
        &self,
        last_accepted_sequence_number: u64,
    ) -> Result<(), TslOpenSslError> {
        identity_trust_tsl_core::validate_tsl_sequence_number(
            &self.list,
            last_accepted_sequence_number,
        )
        .map_err(TslOpenSslError::TrustedList)
    }
}

impl core::fmt::Debug for VerifiedTrustedList {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedTrustedList([REDACTED])")
    }
}
