// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use time::OffsetDateTime;

use crate::{X509Certificate, X509Error, X509PolicyFailure};

pub const TSL_SERVICE_TYPE_CA_QC: &str = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
pub const TSL_SERVICE_TYPE_OCSP_QC: &str = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC";
pub const TSL_SERVICE_STATUS_GRANTED: &str =
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TslServiceType {
    CaQc,
    OcspQc,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TslServiceStatus {
    Granted,
    Withdrawn,
    Deprecated,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TslCertificateBinding {
    pub certificate_der: Option<Vec<u8>>,
    pub subject_key_identifier: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TslTrustService {
    pub territory: String,
    pub provider_name: String,
    pub service_name: String,
    pub service_type: TslServiceType,
    pub status: TslServiceStatus,
    pub status_start_time: OffsetDateTime,
    pub certificate_bindings: Vec<TslCertificateBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TslValidationPolicy {
    pub required_territory: Option<String>,
    pub required_service_type: Option<TslServiceType>,
    pub require_granted_status: bool,
    pub require_leaf_binding: bool,
    pub validation_time: Option<OffsetDateTime>,
    pub max_status_age_seconds: Option<u64>,
}

impl TslValidationPolicy {
    pub fn eu_qualified_ca(territory: impl Into<String>, validation_time: OffsetDateTime) -> Self {
        Self {
            required_territory: Some(territory.into()),
            required_service_type: Some(TslServiceType::CaQc),
            require_granted_status: true,
            require_leaf_binding: true,
            validation_time: Some(validation_time),
            max_status_age_seconds: None,
        }
    }
}

pub fn service_type_from_uri(uri: &str) -> TslServiceType {
    match uri {
        TSL_SERVICE_TYPE_CA_QC => TslServiceType::CaQc,
        TSL_SERVICE_TYPE_OCSP_QC => TslServiceType::OcspQc,
        _ => TslServiceType::Other,
    }
}

pub fn service_status_from_uri(uri: &str) -> TslServiceStatus {
    match uri {
        TSL_SERVICE_STATUS_GRANTED => TslServiceStatus::Granted,
        _ => TslServiceStatus::Other,
    }
}

pub fn validate_tsl_trust_service_for_leaf(
    service: &TslTrustService,
    leaf: &X509Certificate,
    policy: &TslValidationPolicy,
) -> Result<(), X509Error> {
    validate_tsl_policy_metadata(service, policy)?;
    if policy.require_leaf_binding && !service_binds_leaf(service, leaf)? {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::TslCertificateBindingMismatch,
        ));
    }

    Ok(())
}

fn validate_tsl_policy_metadata(
    service: &TslTrustService,
    policy: &TslValidationPolicy,
) -> Result<(), X509Error> {
    if let Some(required_territory) = &policy.required_territory {
        if &service.territory != required_territory {
            return Err(X509Error::PolicyFailed(
                X509PolicyFailure::TslTerritoryMismatch,
            ));
        }
    }
    if let Some(required_service_type) = &policy.required_service_type {
        if &service.service_type != required_service_type {
            return Err(X509Error::PolicyFailed(
                X509PolicyFailure::TslServiceTypeMismatch,
            ));
        }
    }
    if policy.require_granted_status && service.status != TslServiceStatus::Granted {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::TslStatusNotGranted,
        ));
    }
    validate_tsl_status_time(service, policy)
}

fn validate_tsl_status_time(
    service: &TslTrustService,
    policy: &TslValidationPolicy,
) -> Result<(), X509Error> {
    let Some(validation_time) = policy.validation_time else {
        return Ok(());
    };
    if validation_time < service.status_start_time {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::TslStatusNotEffective,
        ));
    }
    let Some(max_status_age_seconds) = policy.max_status_age_seconds else {
        return Ok(());
    };
    let elapsed = validation_time
        .unix_timestamp()
        .checked_sub(service.status_start_time.unix_timestamp())
        .ok_or(X509Error::PolicyFailed(
            X509PolicyFailure::TslStatusNotEffective,
        ))?;
    let elapsed_u64 = u64::try_from(elapsed)
        .map_err(|_| X509Error::PolicyFailed(X509PolicyFailure::TslStatusNotEffective))?;
    if elapsed_u64 > max_status_age_seconds {
        return Err(X509Error::PolicyFailed(X509PolicyFailure::TslStatusTooOld));
    }

    Ok(())
}

fn service_binds_leaf(
    service: &TslTrustService,
    leaf: &X509Certificate,
) -> Result<bool, X509Error> {
    if service.certificate_bindings.is_empty() {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::TslCertificateBindingMissing,
        ));
    }

    Ok(service
        .certificate_bindings
        .iter()
        .any(|binding| binding_matches_leaf(binding, leaf)))
}

fn binding_matches_leaf(binding: &TslCertificateBinding, leaf: &X509Certificate) -> bool {
    let der_matches = binding
        .certificate_der
        .as_ref()
        .is_some_and(|certificate_der| certificate_der == &leaf.der);
    // A certificate's SubjectKeyIdentifier extension is self-asserted content;
    // matching it would let any certificate claim a trusted service's key.
    // Bind only against identifiers computed from the leaf's public key.
    let ski_matches = binding
        .subject_key_identifier
        .as_ref()
        .is_some_and(|binding_ski| leaf.matches_key_identifier(binding_ski));

    der_matches || ski_matches
}
