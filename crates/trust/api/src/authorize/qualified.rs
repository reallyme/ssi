// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use envelopes_x509::{CertificatePolicyId, QcStatementId, X509Certificate, X509Chain};
use identity_trust_tsl_core::{
    AdditionalServiceInformation, AdditionalServiceInformationKind, ServiceQualifierKind,
    TrustServiceStatus, TrustServiceType, TrustedList,
};
use time::OffsetDateTime;

use super::{effective_service_state, QualifiedCertificatePurpose};
use crate::TrustApiError;

const QUALIFIED_TYPE_DETERMINATION_EFFECTIVE_UNIX: i64 = 1_467_324_000;

pub(super) fn authorize_qualified_certificate(
    chain: &X509Chain,
    leaf: &X509Certificate,
    evaluated_at: OffsetDateTime,
    tsl: &TrustedList,
    purpose: QualifiedCertificatePurpose,
) -> Result<(), TrustApiError> {
    if leaf.not_before.unix_timestamp() < QUALIFIED_TYPE_DETERMINATION_EFFECTIVE_UNIX
        || evaluated_at.unix_timestamp() < QUALIFIED_TYPE_DETERMINATION_EFFECTIVE_UNIX
    {
        return Err(TrustApiError::ServiceTypeMismatch);
    }

    let mut matched_key = false;
    let mut matched_scope = false;
    let mut inactive_scope = false;
    let mut unknown_status = false;

    // Evaluate all CA/QC rows for one authenticated service key together.
    // ETSI purpose and qualification information is additive across those
    // rows, while a withdrawn row for the requested purpose is authoritative
    // and must not be masked by a granted sibling row.
    for certificate in chain.certs.iter().skip(1) {
        let states = tsl
            .services()
            .filter_map(|service| effective_service_state(service, evaluated_at))
            .filter(|state| {
                matches!(
                    state.service_type(),
                    TrustServiceType::CaQualifiedCertificates
                ) && state.matches_certificate(certificate)
            })
            .collect::<Vec<_>>();
        if states.is_empty() {
            continue;
        }
        matched_key = true;

        let scoped_states = states
            .iter()
            .copied()
            .filter(|state| {
                state
                    .additional_service_information()
                    .iter()
                    .any(|info| additional_information_matches_purpose(info, purpose))
            })
            .collect::<Vec<_>>();
        if scoped_states.is_empty() {
            continue;
        }
        matched_scope = true;

        let key_is_inactive = scoped_states.iter().any(|state| {
            !matches!(
                state.status(),
                TrustServiceStatus::Granted
                    | TrustServiceStatus::Indeterminate
                    | TrustServiceStatus::Other(_)
            )
        });
        if key_is_inactive {
            inactive_scope = true;
            continue;
        }
        if scoped_states.iter().any(|state| {
            matches!(
                state.status(),
                TrustServiceStatus::Indeterminate | TrustServiceStatus::Other(_)
            )
        }) {
            unknown_status = true;
            continue;
        }

        let matching_qualifiers = scoped_states
            .iter()
            .flat_map(|state| {
                crate::qualification::matching_service_qualifiers(leaf, state.qualifications())
            })
            .collect::<Vec<_>>();
        if matching_qualifiers
            .iter()
            .any(|qualifier| matches!(qualifier.kind, ServiceQualifierKind::NotQualified))
        {
            continue;
        }
        let qualified = matching_qualifiers.iter().any(|qualifier| {
            matches!(
                qualifier.kind,
                ServiceQualifierKind::QualifiedCertificateStatement
            )
        }) || certificate_claims_qualified(leaf);
        let typed_qualifiers = matching_qualifiers
            .iter()
            .filter(|qualifier| qualifier_defines_purpose(&qualifier.kind))
            .collect::<Vec<_>>();
        let qualifiers_allow_purpose = typed_qualifiers.is_empty()
            || typed_qualifiers
                .iter()
                .all(|qualifier| qualifier_matches_purpose(&qualifier.kind, purpose));
        if qualified && qualifiers_allow_purpose {
            return Ok(());
        }
    }

    if inactive_scope {
        Err(TrustApiError::ServiceNotActive)
    } else if unknown_status {
        Err(TrustApiError::ServiceStatusUnknown)
    } else if matched_scope || matched_key {
        Err(TrustApiError::ServiceTypeMismatch)
    } else {
        Err(TrustApiError::NotAuthorized)
    }
}

fn qualifier_defines_purpose(kind: &ServiceQualifierKind) -> bool {
    matches!(
        kind,
        ServiceQualifierKind::QualifiedCertificateForElectronicSignature
            | ServiceQualifierKind::QualifiedCertificateForElectronicSeal
            | ServiceQualifierKind::QualifiedCertificateForWebsiteAuthentication
    )
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
