// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_credential_status::{
    verify_status, CredentialStatusError, StatusList, StatusListVerifier,
};
use reallyme_trust_x509::X509Certificate;

use crate::{StatusCheckError, StatusChecker};

/// StatusList-backed revocation checker.
pub struct StatusListChecker<'a> {
    /// Status list to check.
    pub list: &'a StatusList,

    /// Credential index within the list.
    pub index: u64,

    /// Signature verifier for the status list.
    pub verifier: &'a dyn StatusListVerifier,
}

impl<'a> StatusListChecker<'a> {
    /// Create a new status-list checker.
    pub const fn new(
        list: &'a StatusList,
        index: u64,
        verifier: &'a dyn StatusListVerifier,
    ) -> Self {
        Self {
            list,
            index,
            verifier,
        }
    }
}

impl StatusChecker for StatusListChecker<'_> {
    fn check(&self, _cert: &X509Certificate, now_unix: u64) -> Result<(), StatusCheckError> {
        verify_status(self.list, self.index, now_unix, self.verifier).map_err(map_status_error)
    }
}

fn map_status_error(error: CredentialStatusError) -> StatusCheckError {
    match error {
        CredentialStatusError::Revoked => StatusCheckError::Revoked,
        CredentialStatusError::Suspended => StatusCheckError::Suspended,
        CredentialStatusError::Expired => StatusCheckError::Expired,
        CredentialStatusError::NotYetValid => StatusCheckError::NotYetValid,
        CredentialStatusError::InvalidSignature => StatusCheckError::InvalidSignature,
        CredentialStatusError::InvalidInput(reason) => match reason {
            reallyme_credential_status::CredentialStatusInvalidReason::InvalidIndex => {
                StatusCheckError::InvalidIndex
            }
            reallyme_credential_status::CredentialStatusInvalidReason::InvalidEncodedList
            | reallyme_credential_status::CredentialStatusInvalidReason::InvalidLength
            | reallyme_credential_status::CredentialStatusInvalidReason::TooLarge
            | reallyme_credential_status::CredentialStatusInvalidReason::InvalidTimeWindow
            | reallyme_credential_status::CredentialStatusInvalidReason::EmptyIssuer
            | reallyme_credential_status::CredentialStatusInvalidReason::UnsupportedPurpose
            | reallyme_credential_status::CredentialStatusInvalidReason::PayloadEncoding => {
                StatusCheckError::InvalidList
            }
            reallyme_credential_status::CredentialStatusInvalidReason::InvalidSignatureMetadata => {
                StatusCheckError::InvalidSignature
            }
        },
    }
}
