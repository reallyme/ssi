// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use url::Url;

use crate::{country::is_iso_3166_alpha_2, ConformanceError, Result};

const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_URI_BYTES: usize = 2_048;
const MAX_REVOCATION_NOTIFICATION_DELAY_SECONDS: u64 = 24 * 60 * 60;

/// High-assurance mechanism used by a PID provider to identify itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PidProviderAuthentication {
    /// Wallet-relying party access certificate.
    WalletRelyingPartyAccessCertificate,
    /// Another mechanism from an eID scheme notified at assurance level high.
    NotifiedHighAssuranceEid,
}

/// Inputs required before issuing PID to a wallet unit.
pub struct PidIssuanceAuthorization<'a> {
    /// PID provider identity authenticated by the selected mechanism.
    pub provider_identifier: &'a str,
    /// Identity of the issuer represented in the resulting PID.
    pub credential_issuer_identifier: &'a str,
    /// Provider authentication mechanism.
    pub provider_authentication: PidProviderAuthentication,
    /// Issuance is performed under the applicable electronic identification scheme.
    pub electronic_identification_scheme_authorized: bool,
    /// Enrollment met the requirements for assurance level high.
    pub high_assurance_enrollment_complete: bool,
    /// Identity proofing and verification completed before issuance.
    pub identity_proofing_complete: bool,
    /// Wallet unit attestation authenticated and validated successfully.
    pub wallet_unit_attestation_valid: bool,
    /// The attested wallet solution is on the provider's accepted solution set.
    pub wallet_solution_accepted: bool,
    /// Issued PID contains the data necessary for its authentication and validation.
    pub authentication_data_complete: bool,
    /// Holder binding targets the authenticated wallet unit.
    pub cryptographically_bound_to_authenticated_wallet: bool,
}

/// Validate the CIR (EU) 2024/2977 PID issuance authorization boundary.
pub fn validate_pid_issuance_authorization(facts: &PidIssuanceAuthorization<'_>) -> Result<()> {
    if !valid_identifier(facts.provider_identifier)
        || facts.provider_identifier != facts.credential_issuer_identifier
        || !facts.electronic_identification_scheme_authorized
        || !facts.high_assurance_enrollment_complete
        || !facts.identity_proofing_complete
        || !facts.wallet_unit_attestation_valid
        || !facts.wallet_solution_accepted
        || !facts.authentication_data_complete
        || !facts.cryptographically_bound_to_authenticated_wallet
    {
        return Err(ConformanceError::InvalidPidIssuanceAuthorization);
    }
    Ok(())
}

/// Stable allocation key used to enforce Member-State PID uniqueness.
///
/// References are borrowed and intentionally lack logging/copying traits.
pub struct PidAllocationKey<'a> {
    /// Issuing Member State.
    pub member_state: &'a str,
    /// Provider-local stable subject reference.
    pub subject_reference: &'a [u8],
    /// Stable PID identifier allocated to that subject.
    pub pid_identifier: &'a [u8],
}

/// Validate one candidate PID allocation against existing Member-State allocations.
///
/// The relation is one-to-one: a subject cannot receive a different identifier
/// and an identifier cannot be reassigned to another subject in the same State.
pub fn validate_pid_allocation(
    candidate: &PidAllocationKey<'_>,
    existing: &[PidAllocationKey<'_>],
) -> Result<()> {
    validate_allocation_key(candidate)?;
    for allocation in existing {
        validate_allocation_key(allocation)?;
        if allocation.member_state != candidate.member_state {
            continue;
        }
        let same_subject = allocation.subject_reference == candidate.subject_reference;
        let same_pid = allocation.pid_identifier == candidate.pid_identifier;
        if same_subject != same_pid {
            return Err(ConformanceError::NonUniquePidAllocation);
        }
    }
    Ok(())
}

/// Trigger for a PID revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PidRevocationReason {
    /// Explicit wallet-user request.
    WalletUserRequest,
    /// Revocation of the wallet unit attestation.
    WalletUnitAttestationRevoked,
    /// Another cause stated in the provider's published policy.
    PublishedPolicyCause,
}

/// Actual revocation event data checked against CIR (EU) 2024/2977.
pub struct PidRevocationEvent<'a> {
    /// Issuer identifier authenticated from the PID.
    pub issuer_identifier: &'a str,
    /// Authenticated actor that performed the revocation.
    pub revoking_actor_identifier: &'a str,
    /// HTTPS location of the public validity-status policy.
    pub public_policy_uri: &'a str,
    /// HTTPS location of the privacy-preserving public status information.
    pub public_status_uri: &'a str,
    /// Regulatory revocation trigger.
    pub reason: PidRevocationReason,
    /// Unix time at which revocation became effective.
    pub revoked_at: u64,
    /// Unix time at which the wallet user was notified.
    pub user_notified_at: u64,
    /// Notification included the reason and used a dedicated secure channel.
    pub secure_notification_included_reason: bool,
    /// Status publication reveals no identity or cross-service correlation value.
    pub public_status_privacy_preserving: bool,
    /// The status transition is permanent.
    pub irreversible: bool,
    /// Non-identifying EAA use cases are unlinkable.
    pub unlinkability_enabled_when_identity_not_required: bool,
}

/// Validate revocation authority, timing, publication, and privacy requirements.
pub fn validate_pid_revocation(event: &PidRevocationEvent<'_>) -> Result<()> {
    if !valid_identifier(event.issuer_identifier)
        || event.issuer_identifier != event.revoking_actor_identifier
        || !valid_https_uri(event.public_policy_uri)
        || !valid_https_uri(event.public_status_uri)
        || !event.secure_notification_included_reason
        || !event.public_status_privacy_preserving
        || !event.irreversible
        || !event.unlinkability_enabled_when_identity_not_required
    {
        return Err(ConformanceError::InvalidPidRevocation);
    }
    let delay = event
        .user_notified_at
        .checked_sub(event.revoked_at)
        .ok_or(ConformanceError::InvalidPidRevocation)?;
    if delay > MAX_REVOCATION_NOTIFICATION_DELAY_SECONDS {
        return Err(ConformanceError::InvalidPidRevocation);
    }
    Ok(())
}

fn validate_allocation_key(key: &PidAllocationKey<'_>) -> Result<()> {
    if !is_iso_3166_alpha_2(key.member_state)
        || key.subject_reference.is_empty()
        || key.subject_reference.len() > MAX_IDENTIFIER_BYTES
        || key.pid_identifier.is_empty()
        || key.pid_identifier.len() > MAX_IDENTIFIER_BYTES
    {
        return Err(ConformanceError::NonUniquePidAllocation);
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_https_uri(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_URI_BYTES || value.trim() != value {
        return false;
    }
    let Ok(uri) = Url::parse(value) else {
        return false;
    };
    uri.scheme() == "https"
        && uri.host_str().is_some()
        && uri.username().is_empty()
        && uri.password().is_none()
        && uri.fragment().is_none()
}
