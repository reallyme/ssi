// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use time::OffsetDateTime;

use crate::{X509Certificate, X509Error, X509PolicyFailure};

/// ETSI URI identifying a qualified-certificate CA service.
pub const TSL_SERVICE_TYPE_CA_QC: &str = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
/// ETSI URI identifying a qualified-certificate OCSP service.
pub const TSL_SERVICE_TYPE_OCSP_QC: &str = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC";
/// ETSI URI identifying a currently granted trust-service status.
pub const TSL_SERVICE_STATUS_GRANTED: &str =
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
/// Strong key-identifier length admitted for trusted-list service binding.
pub const TSL_KEY_IDENTIFIER_BYTES: usize = 20;

/// Trust-service types recognized by X.509 policy evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TslServiceType {
    /// Qualified-certificate certification-authority service.
    CaQc,
    /// OCSP service for qualified certificates.
    OcspQc,
    /// Service type not recognized by this policy layer.
    Other,
}

/// Trust-service statuses recognized by X.509 policy evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TslServiceStatus {
    /// Service is granted.
    Granted,
    /// Service is withdrawn.
    Withdrawn,
    /// Service is deprecated.
    Deprecated,
    /// Status is not recognized by this policy layer.
    Other,
}

/// Certificate material that binds a trusted-list service to a key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TslCertificateBinding {
    /// DER-encoded certificate.
    pub certificate_der: Option<Vec<u8>>,
    /// Subject Key Identifier extension bytes when the certificate carries one.
    pub subject_key_identifier: Option<Vec<u8>>,
}

/// Caller-projected trust-service facts used by X.509 policy evaluation.
///
/// This value is deliberately an input model, not proof that a trusted list
/// was authenticated. Authorization code must populate it only from a sealed
/// verified-list result and retain that result as the trust capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TslServicePolicyInput {
    /// ISO territory code asserted by the trusted list.
    pub territory: String,
    /// Trust-service provider name.
    pub provider_name: String,
    /// Human-readable trust-service name.
    pub service_name: String,
    /// Closed service type used for policy matching.
    pub service_type: TslServiceType,
    /// Authenticated service status.
    pub status: TslServiceStatus,
    /// Time at which `status` became effective.
    pub status_start_time: OffsetDateTime,
    /// Certificate identities authorized for this service.
    pub certificate_bindings: Vec<TslCertificateBinding>,
}

/// Requirements applied when matching a certificate to a TSL service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TslValidationPolicy {
    /// Required scheme territory, when constrained.
    pub required_territory: Option<String>,
    /// Required trust-service type, when constrained.
    pub required_service_type: Option<TslServiceType>,
    /// Whether the service must have `Granted` status.
    pub require_granted_status: bool,
    /// Whether a CA/QC service identity must bind the evaluated CA certificate.
    pub require_ca_binding: bool,
    /// Evaluation time used for service-status intervals.
    pub validation_time: OffsetDateTime,
    /// Maximum status age seconds accepted before validation fails.
    pub max_status_age_seconds: Option<u64>,
}

impl TslValidationPolicy {
    /// Constructs policy for a granted EU qualified-certificate CA service.
    pub fn eu_qualified_ca(territory: impl Into<String>, validation_time: OffsetDateTime) -> Self {
        Self {
            required_territory: Some(territory.into()),
            required_service_type: Some(TslServiceType::CaQc),
            require_granted_status: true,
            require_ca_binding: true,
            validation_time,
            max_status_age_seconds: None,
        }
    }
}

/// Maps an ETSI service-type URI to its closed policy representation.
pub fn service_type_from_uri(uri: &str) -> TslServiceType {
    match uri {
        TSL_SERVICE_TYPE_CA_QC => TslServiceType::CaQc,
        TSL_SERVICE_TYPE_OCSP_QC => TslServiceType::OcspQc,
        _ => TslServiceType::Other,
    }
}

/// Maps an ETSI service-status URI to its closed policy representation.
pub fn service_status_from_uri(uri: &str) -> TslServiceStatus {
    match uri {
        TSL_SERVICE_STATUS_GRANTED => TslServiceStatus::Granted,
        _ => TslServiceStatus::Other,
    }
}

/// Evaluates authenticated service facts against a CA certificate.
///
/// This is a pure policy check. It does not authenticate `service`; callers
/// must project those facts from a sealed verified trusted-list result. CA/QC
/// bindings name the issuing CA certificate, never the end-entity leaf.
pub fn evaluate_tsl_service_policy_for_ca(
    service: &TslServicePolicyInput,
    ca_certificate: &X509Certificate,
    policy: &TslValidationPolicy,
) -> Result<(), X509Error> {
    validate_tsl_policy_metadata(service, policy)?;
    if policy.require_ca_binding {
        let is_ca = ca_certificate
            .basic_constraints
            .as_ref()
            .is_some_and(|constraints| constraints.ca)
            && ca_certificate
                .key_usage
                .as_ref()
                .is_some_and(|usage| usage.key_cert_sign);
        if !is_ca || !service_binds_certificate(service, ca_certificate)? {
            return Err(X509Error::PolicyFailed(
                X509PolicyFailure::TslCertificateBindingMismatch,
            ));
        }
    }

    Ok(())
}

fn validate_tsl_policy_metadata(
    service: &TslServicePolicyInput,
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
    service: &TslServicePolicyInput,
    policy: &TslValidationPolicy,
) -> Result<(), X509Error> {
    let validation_time = policy.validation_time;
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

fn service_binds_certificate(
    service: &TslServicePolicyInput,
    certificate: &X509Certificate,
) -> Result<bool, X509Error> {
    if service.certificate_bindings.is_empty() {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::TslCertificateBindingMissing,
        ));
    }

    Ok(service
        .certificate_bindings
        .iter()
        .any(|binding| binding_matches_certificate(binding, certificate)))
}

fn binding_matches_certificate(
    binding: &TslCertificateBinding,
    certificate: &X509Certificate,
) -> bool {
    let der_matches = binding
        .certificate_der
        .as_ref()
        .is_some_and(|certificate_der| certificate_der == &certificate.der);
    // A certificate's SubjectKeyIdentifier extension is self-asserted content;
    // matching it would let any certificate claim a trusted service's key.
    // Bind only against identifiers computed from the certificate's public key.
    let ski_matches = binding
        .subject_key_identifier
        .as_ref()
        .is_some_and(|binding_ski| {
            binding_ski.len() == TSL_KEY_IDENTIFIER_BYTES
                && certificate.matches_key_identifier(binding_ski)
        });

    der_matches || ski_matches
}
