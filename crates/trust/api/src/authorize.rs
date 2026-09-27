// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use envelopes_x509::{X509Certificate, X509Chain, TSL_KEY_IDENTIFIER_BYTES};
use time::OffsetDateTime;

use crate::{AuthorizationPurpose, TrustApiError, TrustedListPolicyErrorReason};
use identity_trust_tsl_core::{
    AdditionalServiceInformation, ServiceDigitalIdentity, ServiceQualification, TrustService,
    TrustServiceHistoryEntry, TrustServiceStatus, TrustServiceType, TrustedList, TslError,
    TslTimestamp,
};
use reallyme_trust_core::{
    CertificatePosition as CoreCertificatePosition, CertificateStatus as CoreCertificateStatus,
    TrustDecision, TrustOutcome, TrustPolicyId as CoreTrustPolicyId,
    TrustPurpose as CoreTrustPurpose,
};

mod qualified;

mod sealed {
    /// Restricts [`super::AuthenticatedTrustedList`] to backend receipts.
    pub trait Sealed {}
}

/// A trusted list whose XMLDSig signature and signer trust were verified by a
/// supported backend.
///
/// The trait is sealed: only authenticated verification receipts (such as the
/// native `VerifiedTrustedList`) implement it. Unauthenticated parser output
/// therefore cannot be used to authorize an issuer. Builds without a trusted
/// list verification backend have no implementor, so TSL authorization fails
/// closed at compile time rather than accepting unverified lists.
pub trait AuthenticatedTrustedList: sealed::Sealed {
    /// Borrows the authenticated normalized trusted list.
    fn authenticated_list(&self) -> &TrustedList;
}

#[cfg(all(
    feature = "native",
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
mod native_receipt {
    use super::{sealed, AuthenticatedTrustedList, TrustedList};

    impl sealed::Sealed for crate::tsl::VerifiedTrustedList {}

    impl AuthenticatedTrustedList for crate::tsl::VerifiedTrustedList {
        fn authenticated_list(&self) -> &TrustedList {
            self.list()
        }
    }
}

/// Authorize a trusted certificate chain against an authenticated Trusted
/// List (TSL).
///
/// Preconditions:
/// - `decision.accepted == true`
/// - `decision.chain` is present and ordered leaf → root
///
/// This function:
/// - requires the list to be fresh at the decision's trusted evaluation time
///   (`ListIssueDateTime <= evaluated_at < NextUpdate`)
/// - selects each service state effective at that time from the complete,
///   unprojected service history
/// - finds the QTSP service key in the verified chain (for CA/QC services,
///   only issuing certificates above the leaf are considered)
/// - checks service status and validity
/// - applies service-wide and certificate-filtered authorization to the leaf
pub fn authorize_issuer<L>(
    decision: &TrustDecision,
    tsl: &L,
    purpose: AuthorizationPurpose,
) -> Result<(), TrustApiError>
where
    L: AuthenticatedTrustedList + ?Sized,
{
    authorize_issuer_in_list(decision, tsl.authenticated_list(), purpose)
}

pub(crate) fn authorize_issuer_in_list(
    decision: &TrustDecision,
    tsl: &TrustedList,
    purpose: AuthorizationPurpose,
) -> Result<(), TrustApiError> {
    if !decision.is_accepted() || decision.outcome() != TrustOutcome::Trusted {
        return Err(TrustApiError::NotTrusted);
    }
    if decision.evidence().certificate_status.iter().any(|status| {
        !matches!(status.position, CoreCertificatePosition::TrustAnchor)
            && status.status != CoreCertificateStatus::Good
    }) {
        return Err(TrustApiError::NotAuthorized);
    }
    if !decision_scope_matches(decision, purpose) {
        return Err(TrustApiError::NotAuthorized);
    }

    let chain = decision.chain().ok_or(TrustApiError::NotTrusted)?;
    authorize_validated_chain_in_list(chain, decision.evidence().evaluated_at, tsl, purpose)
}

/// Match the immutable receipt to the authorization purpose and its policy;
/// this prevents replaying a baseline decision across qualified profiles.
fn decision_scope_matches(decision: &TrustDecision, purpose: AuthorizationPurpose) -> bool {
    let expected = match purpose {
        AuthorizationPurpose::QeaaIssuer => {
            (CoreTrustPurpose::QeaaIssuer, CoreTrustPolicyId::EuQeaaV1)
        }
        AuthorizationPurpose::QwacTlsServer => {
            (CoreTrustPurpose::QwacTlsServer, CoreTrustPolicyId::EuQwacV1)
        }
        AuthorizationPurpose::QsealSigner => {
            (CoreTrustPurpose::QsealSigner, CoreTrustPolicyId::EuQsealV1)
        }
    };
    decision.evidence().purpose == expected.0 && decision.evidence().policy_id == expected.1
}

/// Applies trusted-list service authorization to a chain that has already
/// passed the sealed trust-decision gate above. Keeping this projection
/// separate lets the policy logic be tested without making trust receipts
/// constructible by callers.
pub(crate) fn authorize_validated_chain_in_list(
    chain: &X509Chain,
    evaluated_at: OffsetDateTime,
    tsl: &TrustedList,
    purpose: AuthorizationPurpose,
) -> Result<(), TrustApiError> {
    let leaf = chain.certs.first().ok_or(TrustApiError::NotTrusted)?;

    // The list was authenticated at its own verification time. Authorization
    // may run later or for an earlier trusted time, so freshness is re-checked
    // against the decision's evaluation time before any service is selected.
    identity_trust_tsl_core::validate_tsl_freshness(tsl, evaluated_at).map_err(
        |error| match error {
            TslError::Expired => {
                TrustApiError::TrustedListPolicy(TrustedListPolicyErrorReason::Expired)
            }
            other => TrustApiError::TrustedList(other),
        },
    )?;

    if let Some(qualified_purpose) = qualified_certificate_purpose(purpose) {
        return qualified::authorize_qualified_certificate(
            chain,
            leaf,
            evaluated_at,
            tsl,
            qualified_purpose,
        );
    }

    let mut matched_service = false;
    let mut active_service = false;
    let mut unknown_status = false;
    let mut known_type_mismatch = false;
    let mut unknown_type = false;

    for service in tsl.services() {
        let Some(state) = effective_service_state(service, evaluated_at) else {
            continue;
        };
        // A CA/QC service authorizes certificates it issued. Its key must
        // therefore appear above the leaf; a leaf that merely reuses the
        // service key does not make the service its issuer.
        let first_candidate = usize::from(state.requires_issuing_certificate());
        if !chain
            .certs
            .iter()
            .skip(first_candidate)
            .any(|certificate| state.matches_certificate(certificate))
        {
            continue;
        }
        matched_service = true;
        match verify_service_status(state) {
            Ok(()) => active_service = true,
            Err(TrustApiError::ServiceStatusUnknown) => {
                unknown_status = true;
                continue;
            }
            Err(TrustApiError::ServiceNotActive) => continue,
            Err(error) => return Err(error),
        }
        match verify_service_purpose(state, purpose) {
            Ok(()) => return Ok(()),
            Err(TrustApiError::ServiceTypeUnknown) => unknown_type = true,
            Err(TrustApiError::ServiceTypeMismatch) => known_type_mismatch = true,
            Err(error) => return Err(error),
        }
    }

    if !matched_service {
        Err(TrustApiError::NotAuthorized)
    } else if known_type_mismatch {
        Err(TrustApiError::ServiceTypeMismatch)
    } else if unknown_type && active_service {
        Err(TrustApiError::ServiceTypeUnknown)
    } else if unknown_status {
        Err(TrustApiError::ServiceStatusUnknown)
    } else {
        Err(TrustApiError::ServiceNotActive)
    }
}

/// Validate that the service was active at the decision's trusted evaluation time.
fn verify_service_status(service: EffectiveServiceState<'_>) -> Result<(), TrustApiError> {
    match service.status() {
        TrustServiceStatus::Granted => Ok(()),
        TrustServiceStatus::Indeterminate | TrustServiceStatus::Other(_) => {
            Err(TrustApiError::ServiceStatusUnknown)
        }
        _ => Err(TrustApiError::ServiceNotActive),
    }
}

/// Validate that the service authorizes the requested purpose.
fn verify_service_purpose(
    service: EffectiveServiceState<'_>,
    purpose: AuthorizationPurpose,
) -> Result<(), TrustApiError> {
    let allowed = match (purpose, service.service_type()) {
        (AuthorizationPurpose::QeaaIssuer, TrustServiceType::QualifiedElectronicAttestation) => {
            true
        }
        (AuthorizationPurpose::QwacTlsServer, TrustServiceType::CaQualifiedCertificates)
        | (AuthorizationPurpose::QsealSigner, TrustServiceType::CaQualifiedCertificates) => false,
        (_, TrustServiceType::Other(_)) => return Err(TrustApiError::ServiceTypeUnknown),
        _ => false,
    };

    if allowed {
        Ok(())
    } else {
        Err(TrustApiError::ServiceTypeMismatch)
    }
}

#[derive(Clone, Copy)]
pub(super) enum QualifiedCertificatePurpose {
    Website,
    ElectronicSeal,
}

fn qualified_certificate_purpose(
    purpose: AuthorizationPurpose,
) -> Option<QualifiedCertificatePurpose> {
    match purpose {
        AuthorizationPurpose::QwacTlsServer => Some(QualifiedCertificatePurpose::Website),
        AuthorizationPurpose::QsealSigner => Some(QualifiedCertificatePurpose::ElectronicSeal),
        AuthorizationPurpose::QeaaIssuer => None,
    }
}

#[derive(Clone, Copy)]
pub(super) enum EffectiveServiceState<'a> {
    Current(&'a TrustService),
    Historical(&'a TrustServiceHistoryEntry),
}

impl<'a> EffectiveServiceState<'a> {
    fn service_type(self) -> &'a TrustServiceType {
        match self {
            Self::Current(service) => &service.service_type,
            Self::Historical(service) => &service.service_type,
        }
    }

    fn status(self) -> &'a TrustServiceStatus {
        match self {
            Self::Current(service) => &service.status,
            Self::Historical(service) => &service.status,
        }
    }

    fn status_starting_time(self) -> TslTimestamp {
        match self {
            Self::Current(service) => service.status_starting_time,
            Self::Historical(service) => service.status_starting_time,
        }
    }

    fn qualifications(self) -> &'a [ServiceQualification] {
        match self {
            Self::Current(service) => &service.qualifications,
            Self::Historical(service) => &service.qualifications,
        }
    }

    fn additional_service_information(self) -> &'a [AdditionalServiceInformation] {
        match self {
            Self::Current(service) => &service.additional_service_information,
            Self::Historical(service) => &service.additional_service_information,
        }
    }

    fn requires_issuing_certificate(self) -> bool {
        matches!(
            self.service_type(),
            TrustServiceType::CaQualifiedCertificates
        )
    }

    fn matches_certificate(self, certificate: &X509Certificate) -> bool {
        match self {
            // TS 119 612 clause 5.5.3 identifies one service public key and
            // permits multiple certificate representations for that key.
            // Match the authenticated key, not one certificate encoding. The
            // canonical SubjectPublicKeyInfo was extracted and checked when
            // the list was parsed, so no certificate is re-parsed here.
            Self::Current(service) => match &service.digital_identity {
                ServiceDigitalIdentity::Pki(identity) => identity
                    .subject_public_key_info_der()
                    .is_some_and(|service_key| service_key == certificate.spki_der.as_slice()),
                ServiceDigitalIdentity::NonPki(_) => false,
            },
            // TS 119 612 v2.4.1 clause 5.6.3 intentionally removes
            // certificates from service history and retains X509SKI as the
            // machine-processable historical key identifier. The identifier
            // is compared with values computed from the candidate's
            // SubjectPublicKeyInfo, never with the candidate's self-asserted
            // SubjectKeyIdentifier extension. A history row without a usable
            // identifier is a non-authorizing barrier.
            Self::Historical(service) => service
                .digital_identity
                .as_ref()
                .and_then(ServiceDigitalIdentity::subject_key_identifier)
                .is_some_and(|historical| {
                    historical.len() == TSL_KEY_IDENTIFIER_BYTES
                        && certificate.matches_key_identifier(historical)
                }),
        }
    }
}

fn effective_service_state(
    service: &TrustService,
    evaluated_at: time::OffsetDateTime,
) -> Option<EffectiveServiceState<'_>> {
    // A parser-isolated anomaly makes this service key unusable for every
    // decision time. Falling back to an older row would turn malformed or
    // conflicting authenticated data into authorization and make the result
    // depend on XML document order.
    if matches!(service.status, TrustServiceStatus::Indeterminate) {
        return Some(EffectiveServiceState::Current(service));
    }
    // TS 119 612 service history is a sequence of effective-dated states. Selecting the
    // newest state first prevents an older certificate or status from remaining authorized
    // after a later rotation, withdrawal, or service-type change.
    let mut selected = None;

    let current = EffectiveServiceState::Current(service);
    if timestamp_not_after(current.status_starting_time(), evaluated_at) {
        selected = Some(current);
    }

    for history in &service.history {
        let candidate = EffectiveServiceState::Historical(history);
        if !timestamp_not_after(candidate.status_starting_time(), evaluated_at) {
            continue;
        }
        let replace = selected.is_none_or(|existing: EffectiveServiceState<'_>| {
            timestamp_is_after(
                candidate.status_starting_time(),
                existing.status_starting_time(),
            )
        });
        if replace {
            selected = Some(candidate);
        }
    }

    selected
}

fn timestamp_not_after(timestamp: TslTimestamp, evaluated_at: time::OffsetDateTime) -> bool {
    let timestamp_parts = (timestamp.unix_seconds(), timestamp.nanosecond());
    let evaluated_parts = (evaluated_at.unix_timestamp(), evaluated_at.nanosecond());
    timestamp_parts <= evaluated_parts
}

fn timestamp_is_after(left: TslTimestamp, right: TslTimestamp) -> bool {
    (left.unix_seconds(), left.nanosecond()) > (right.unix_seconds(), right.nanosecond())
}

#[cfg(test)]
#[path = "authorize_tests.rs"]
mod tests;
