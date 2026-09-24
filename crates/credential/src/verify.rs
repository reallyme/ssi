// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    validate_credential_envelope, verify_credential_issuer_signature, CredentialEnvelope,
    CredentialError, CredentialIssuerVerifier, CredentialStatusReason,
};
use reallyme_credential_status::{
    verify_status, CredentialStatusError, CredentialStatusInvalidReason, StatusList,
    StatusListVerifier,
};
use reallyme_revocation::{
    CompositeRevocationPolicy, CompositeStatusChecker, StatusCheckError, StatusChecker,
    StatusListChecker, X509Certificate,
};

/// Inputs for complete local credential verification.
pub struct CredentialVerificationInput<'a> {
    /// Credential envelope to verify.
    pub envelope: &'a CredentialEnvelope,

    /// Issuer signature verifier with already-resolved issuer key material.
    pub issuer_verifier: &'a dyn CredentialIssuerVerifier,

    /// Status list referenced by the credential envelope.
    pub status_list: &'a StatusList,

    /// Status-list signature verifier with already-resolved status-list issuer key material.
    pub status_verifier: &'a dyn StatusListVerifier,

    /// Verification time as Unix seconds.
    pub now_unix: u64,
}

/// Inputs for complete credential verification through a composed revocation policy.
pub struct CredentialRevocationVerificationInput<'a> {
    /// Credential envelope to verify.
    pub envelope: &'a CredentialEnvelope,

    /// Issuer signature verifier with already-resolved issuer key material.
    pub issuer_verifier: &'a dyn CredentialIssuerVerifier,

    /// Already-composed revocation checker.
    pub status_checker: &'a dyn StatusChecker,

    /// Certificate or trust context required by the configured checker.
    pub certificate: &'a X509Certificate,

    /// Verification time as Unix seconds.
    pub now_unix: u64,
}

/// Inputs for credential verification with a status-list source inside a revocation policy.
pub struct CredentialStatusListPolicyInput<'a> {
    /// Credential envelope to verify.
    pub envelope: &'a CredentialEnvelope,

    /// Issuer signature verifier with already-resolved issuer key material.
    pub issuer_verifier: &'a dyn CredentialIssuerVerifier,

    /// Composite revocation evaluation policy.
    pub policy: CompositeRevocationPolicy,

    /// Optional OCSP checker participating in the composite policy.
    pub ocsp_checker: Option<&'a dyn StatusChecker>,

    /// Optional CRL checker participating in the composite policy.
    pub crl_checker: Option<&'a dyn StatusChecker>,

    /// Status list referenced by the credential envelope.
    pub status_list: &'a StatusList,

    /// Status-list signature verifier with already-resolved status-list issuer key material.
    pub status_verifier: &'a dyn StatusListVerifier,

    /// Certificate or trust context required by the configured checker.
    pub certificate: &'a X509Certificate,
}

/// Inputs for status-only verification with a status-list source inside a revocation policy.
pub struct CredentialStatusListPolicyStatusInput<'a> {
    /// Credential envelope whose status pointer is being checked.
    pub envelope: &'a CredentialEnvelope,

    /// Composite revocation evaluation policy.
    pub policy: CompositeRevocationPolicy,

    /// Optional OCSP checker participating in the composite policy.
    pub ocsp_checker: Option<&'a dyn StatusChecker>,

    /// Optional CRL checker participating in the composite policy.
    pub crl_checker: Option<&'a dyn StatusChecker>,

    /// Status list referenced by the credential envelope.
    pub status_list: &'a StatusList,

    /// Status-list signature verifier with already-resolved status-list issuer key material.
    pub status_verifier: &'a dyn StatusListVerifier,

    /// Certificate or trust context required by the configured checker.
    pub certificate: &'a X509Certificate,
}

/// Verify issuer signature and status-list evidence for one credential.
pub fn verify_credential(input: &CredentialVerificationInput<'_>) -> Result<(), CredentialError> {
    verify_credential_issuer_signature(input.envelope, input.issuer_verifier)?;
    verify_credential_status(
        input.envelope,
        input.status_list,
        input.now_unix,
        input.status_verifier,
    )
}

/// Verify issuer signature and composed revocation evidence for one credential.
pub fn verify_credential_with_revocation(
    input: &CredentialRevocationVerificationInput<'_>,
) -> Result<(), CredentialError> {
    verify_credential_issuer_signature(input.envelope, input.issuer_verifier)?;
    verify_credential_revocation_status(
        input.envelope,
        input.status_checker,
        input.certificate,
        input.now_unix,
    )
}

/// Verify issuer signature and a status-list source inside a composite revocation policy.
pub fn verify_credential_with_statuslist_policy(
    input: &CredentialStatusListPolicyInput<'_>,
) -> Result<(), CredentialError> {
    verify_credential_issuer_signature(input.envelope, input.issuer_verifier)?;
    verify_credential_status_with_policy(&CredentialStatusListPolicyStatusInput {
        envelope: input.envelope,
        policy: input.policy.clone(),
        ocsp_checker: input.ocsp_checker,
        crl_checker: input.crl_checker,
        status_list: input.status_list,
        status_verifier: input.status_verifier,
        certificate: input.certificate,
    })
}

/// Verify the credential's status pointer against a supplied signed status list.
pub fn verify_credential_status(
    envelope: &CredentialEnvelope,
    status_list: &StatusList,
    now_unix: u64,
    verifier: &dyn StatusListVerifier,
) -> Result<(), CredentialError> {
    validate_credential_envelope(envelope)?;
    validate_status_pointer(envelope, status_list)?;
    verify_status(
        status_list,
        envelope.status.status_list_index,
        now_unix,
        verifier,
    )
    .map_err(map_status_error)
}

/// Verify credential revocation state through an already-composed status checker.
///
/// The checker owns source selection and evidence policy. Callers that include
/// status-list evidence should use [`verify_credential_status_with_policy`] so
/// the credential's status-list pointer is checked before composition.
pub fn verify_credential_revocation_status(
    envelope: &CredentialEnvelope,
    checker: &dyn StatusChecker,
    certificate: &X509Certificate,
    now_unix: u64,
) -> Result<(), CredentialError> {
    validate_credential_envelope(envelope)?;
    checker
        .check(certificate, now_unix)
        .map_err(map_revocation_status_error)
}

/// Verify a credential status-list source through the shared revocation policy engine.
pub fn verify_credential_status_with_policy(
    input: &CredentialStatusListPolicyStatusInput<'_>,
) -> Result<(), CredentialError> {
    validate_credential_envelope(input.envelope)?;
    validate_status_pointer(input.envelope, input.status_list)?;
    let statuslist_checker = StatusListChecker::new(
        input.status_list,
        input.envelope.status.status_list_index,
        input.status_verifier,
    );
    let checker = CompositeStatusChecker {
        policy: input.policy.clone(),
        ocsp: input.ocsp_checker,
        crl: input.crl_checker,
        statuslist: Some(&statuslist_checker),
    };
    checker
        .check(input.certificate, checker.policy.now_unix)
        .map_err(map_revocation_status_error)
}

fn validate_status_pointer(
    envelope: &CredentialEnvelope,
    status_list: &StatusList,
) -> Result<(), CredentialError> {
    let issuer = match &envelope.issuer_reference {
        crate::PartyReference::Did(value)
        | crate::PartyReference::Uri(value)
        | crate::PartyReference::FederationEntityId(value)
        | crate::PartyReference::OpaqueIdentifier(value) => value,
        crate::PartyReference::X509Subject(_)
        | crate::PartyReference::PublicKey(_)
        | crate::PartyReference::Absent => {
            return Err(CredentialError::Status(
                CredentialStatusReason::InvalidEvidence,
            ));
        }
    };
    if status_list.issuer != *issuer
        || status_list.purpose != envelope.status.purpose
        || status_list.list_id != Some(envelope.status.status_list_id)
    {
        return Err(CredentialError::Status(
            CredentialStatusReason::StatusPointerMismatch,
        ));
    }
    Ok(())
}

fn map_revocation_status_error(error: StatusCheckError) -> CredentialError {
    match error {
        StatusCheckError::Revoked => CredentialError::Status(CredentialStatusReason::Revoked),
        StatusCheckError::Suspended => CredentialError::Status(CredentialStatusReason::Suspended),
        StatusCheckError::Expired => CredentialError::Status(CredentialStatusReason::Expired),
        StatusCheckError::NotYetValid => {
            CredentialError::Status(CredentialStatusReason::NotYetValid)
        }
        StatusCheckError::InvalidSignature => {
            CredentialError::Status(CredentialStatusReason::InvalidSignature)
        }
        StatusCheckError::InvalidIndex => {
            CredentialError::Status(CredentialStatusReason::StatusPointerMismatch)
        }
        StatusCheckError::InvalidList => {
            CredentialError::Status(CredentialStatusReason::InvalidEvidence)
        }
        StatusCheckError::Unavailable => {
            CredentialError::Status(CredentialStatusReason::Unavailable)
        }
        StatusCheckError::Unknown | StatusCheckError::Unsupported => {
            CredentialError::Status(CredentialStatusReason::Unavailable)
        }
    }
}

fn map_status_error(error: CredentialStatusError) -> CredentialError {
    match error {
        CredentialStatusError::Revoked => CredentialError::Status(CredentialStatusReason::Revoked),
        CredentialStatusError::Suspended => {
            CredentialError::Status(CredentialStatusReason::Suspended)
        }
        CredentialStatusError::Expired => CredentialError::Status(CredentialStatusReason::Expired),
        CredentialStatusError::NotYetValid => {
            CredentialError::Status(CredentialStatusReason::NotYetValid)
        }
        CredentialStatusError::InvalidSignature => {
            CredentialError::Status(CredentialStatusReason::InvalidSignature)
        }
        CredentialStatusError::InvalidInput(reason) => match reason {
            CredentialStatusInvalidReason::InvalidIndex => {
                CredentialError::Status(CredentialStatusReason::StatusPointerMismatch)
            }
            CredentialStatusInvalidReason::InvalidSignatureMetadata => {
                CredentialError::Status(CredentialStatusReason::InvalidSignature)
            }
            CredentialStatusInvalidReason::EmptyIssuer
            | CredentialStatusInvalidReason::InvalidLength
            | CredentialStatusInvalidReason::TooLarge
            | CredentialStatusInvalidReason::InvalidEncodedList
            | CredentialStatusInvalidReason::InvalidTimeWindow
            | CredentialStatusInvalidReason::UnsupportedPurpose
            | CredentialStatusInvalidReason::PayloadEncoding => {
                CredentialError::Status(CredentialStatusReason::InvalidEvidence)
            }
        },
    }
}
