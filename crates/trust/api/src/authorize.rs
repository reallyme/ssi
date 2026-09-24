// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use envelopes_x509::X509Certificate;

use identity_trust_tsl_core::{
    AdditionalServiceInformation, AdditionalServiceInformationKind, ServiceQualification,
    ServiceQualifierKind, TrustService, TrustServiceHistoryEntry, TrustServiceStatus,
    TrustServiceType, TrustedList, TslTimestamp,
};
use reallyme_trust_core::{TrustDecision, TrustOutcome};

use crate::{AuthorizationPurpose, TrustApiError};
use envelopes_x509::{CertificatePolicyId, QcStatementId, QcType};

/// Authorize a trusted certificate chain against a Trusted List (TSL).
///
/// Preconditions:
/// - `decision.accepted == true`
/// - `decision.chain` is present and ordered leaf → root
///
/// This function:
/// - finds the QTSP service key in the verified leaf-to-root chain
/// - checks service status and validity
/// - applies service-wide and certificate-filtered authorization to the leaf
pub fn authorize_issuer(
    decision: &TrustDecision,
    tsl: &TrustedList,
    purpose: AuthorizationPurpose,
) -> Result<(), TrustApiError> {
    if !decision.accepted || decision.outcome != TrustOutcome::Trusted {
        return Err(TrustApiError::NotTrusted);
    }

    let chain = decision.chain.as_ref().ok_or(TrustApiError::NotTrusted)?;

    let leaf = chain.certs.first().ok_or(TrustApiError::NotTrusted)?;

    let mut matched_service = false;
    let mut active_service = false;
    let mut unknown_status = false;
    let mut known_type_mismatch = false;
    let mut unknown_type = false;

    for service in tsl.services() {
        let Some(state) = effective_service_state(service, decision.evidence.evaluated_at) else {
            continue;
        };
        if !chain
            .certs
            .iter()
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
        match verify_service_purpose(state, leaf, purpose) {
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
        TrustServiceStatus::Other(_) => Err(TrustApiError::ServiceStatusUnknown),
        _ => Err(TrustApiError::ServiceNotActive),
    }
}

/// Validate that the service authorizes the requested purpose.
fn verify_service_purpose(
    service: EffectiveServiceState<'_>,
    leaf: &X509Certificate,
    purpose: AuthorizationPurpose,
) -> Result<(), TrustApiError> {
    let allowed = match (purpose, service.service_type()) {
        (AuthorizationPurpose::QeaaIssuer, TrustServiceType::QualifiedElectronicAttestation) => {
            true
        }
        (AuthorizationPurpose::QwacTlsServer, TrustServiceType::CaQualifiedCertificates) => {
            qualified_ca_authorizes(service, leaf, QualifiedCertificatePurpose::Website)
        }
        (AuthorizationPurpose::QsealSigner, TrustServiceType::CaQualifiedCertificates) => {
            qualified_ca_authorizes(service, leaf, QualifiedCertificatePurpose::ElectronicSeal)
        }
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
enum QualifiedCertificatePurpose {
    Website,
    ElectronicSeal,
}

fn qualified_ca_authorizes(
    service: EffectiveServiceState<'_>,
    leaf: &X509Certificate,
    purpose: QualifiedCertificatePurpose,
) -> bool {
    // TS 119 612 v2.4.1 clause 5.5.9.2 makes matching qualification
    // elements authoritative for the examined certificate. In particular,
    // NotQualified must override a certificate's own qualified claims.
    if crate::qualification::matching_service_qualifiers(leaf, service.qualifications())
        .any(|qualifier| matches!(&qualifier.kind, ServiceQualifierKind::NotQualified))
    {
        return false;
    }
    let service_qualifiers = service.qualifications();
    let qualified = crate::qualification::matching_service_qualifiers(leaf, service_qualifiers)
        .any(|qualifier| {
            matches!(
                &qualifier.kind,
                ServiceQualifierKind::QualifiedCertificateStatement
            )
        })
        || certificate_claims_qualified(leaf);
    let purpose_matches =
        crate::qualification::matching_service_qualifiers(leaf, service_qualifiers)
            .any(|qualifier| qualifier_matches_purpose(&qualifier.kind, purpose))
            || service
                .additional_service_information()
                .iter()
                .any(|information| additional_information_matches_purpose(information, purpose))
            || leaf
                .profile
                .qc_types
                .iter()
                .any(|kind| qc_type_matches_purpose(kind, purpose))
            || matches!(purpose, QualifiedCertificatePurpose::Website)
                && leaf
                    .profile
                    .certificate_policies
                    .iter()
                    .any(is_qualified_website_certificate_policy);

    // TS 119 612 clause 5.5.9.2 defines qualification and certificate purpose
    // as independent properties. For example, QCForWSA does not make an
    // otherwise non-qualified certificate qualified. Both properties must be
    // established before CA/QC can authorize a purpose-specific leaf.
    qualified && purpose_matches
}

fn certificate_claims_qualified(certificate: &X509Certificate) -> bool {
    certificate
        .profile
        .qc_statement_ids
        .contains(&QcStatementId::Compliance)
        || certificate
            .profile
            .certificate_policies
            .iter()
            .any(is_qualified_certificate_policy)
}

fn is_qualified_certificate_policy(policy: &CertificatePolicyId) -> bool {
    matches!(
        policy,
        CertificatePolicyId::QcpNaturalPerson
            | CertificatePolicyId::QcpLegalPerson
            | CertificatePolicyId::QcpNaturalPersonQscd
            | CertificatePolicyId::QcpLegalPersonQscd
            | CertificatePolicyId::QevcpWeb
            | CertificatePolicyId::QncpWeb
            | CertificatePolicyId::QncpWebGeneric
    )
}

fn is_qualified_website_certificate_policy(policy: &CertificatePolicyId) -> bool {
    // ETSI EN 319 411-2 v2.6.1 clause 5.3 defines these OIDs as policies for
    // EU qualified website-authentication certificates. Unlike a general
    // QCP-l/QCP-n identifier, each policy therefore establishes both the
    // qualified property and the website-authentication purpose.
    matches!(
        policy,
        CertificatePolicyId::QevcpWeb
            | CertificatePolicyId::QncpWeb
            | CertificatePolicyId::QncpWebGeneric
    )
}

fn qualifier_matches_purpose(
    kind: &ServiceQualifierKind,
    purpose: QualifiedCertificatePurpose,
) -> bool {
    matches!(
        (kind, purpose),
        (
            ServiceQualifierKind::QualifiedCertificateForWebsiteAuthentication,
            QualifiedCertificatePurpose::Website
        ) | (
            ServiceQualifierKind::QualifiedCertificateForElectronicSeal,
            QualifiedCertificatePurpose::ElectronicSeal
        )
    )
}

fn additional_information_matches_purpose(
    information: &AdditionalServiceInformation,
    purpose: QualifiedCertificatePurpose,
) -> bool {
    matches!(
        (&information.kind, purpose),
        (
            AdditionalServiceInformationKind::ForWebsiteAuthentication,
            QualifiedCertificatePurpose::Website
        ) | (
            AdditionalServiceInformationKind::ForElectronicSeals,
            QualifiedCertificatePurpose::ElectronicSeal
        )
    )
}

fn qc_type_matches_purpose(kind: &QcType, purpose: QualifiedCertificatePurpose) -> bool {
    matches!(
        (kind, purpose),
        (
            QcType::WebAuthentication,
            QualifiedCertificatePurpose::Website
        ) | (
            QcType::ElectronicSeal,
            QualifiedCertificatePurpose::ElectronicSeal
        )
    )
}

#[derive(Clone, Copy)]
enum EffectiveServiceState<'a> {
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

    fn matches_certificate(self, certificate: &X509Certificate) -> bool {
        match self {
            // TS 119 612 clause 5.5.3 identifies one service public key and
            // permits multiple certificate representations for that key.
            // Match the authenticated key, not one certificate encoding.
            Self::Current(service) => {
                service.certificates_der().first().is_some_and(|candidate| {
                    envelopes_x509::parse_cert_der(candidate).ok().is_some_and(
                        |service_certificate| service_certificate.spki_der == certificate.spki_der,
                    )
                })
            }
            // TS 119 612 v2.4.1 clause 5.6.3 intentionally removes
            // certificates from service history and retains X509SKI as the
            // machine-processable historical key identifier.
            Self::Historical(service) => service
                .digital_identity
                .subject_key_identifier()
                .zip(certificate.subject_key_identifier.as_deref())
                .is_some_and(|(historical, candidate)| historical == candidate),
        }
    }
}

fn effective_service_state(
    service: &TrustService,
    evaluated_at: time::OffsetDateTime,
) -> Option<EffectiveServiceState<'_>> {
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
