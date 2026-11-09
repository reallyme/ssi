// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Structural validation for ETSI TS 119 472-3 `issuer_info` entries.
//!
//! Signature, certificate-path, and registration-certificate authentication
//! remain the caller's responsibility. This module only validates the
//! authenticated JSON value against the Part 3 registrar-dataset contract.

use serde_json::{Map, Value};
use url::Url;

const REGISTRAR_DATASET_FORMAT: &str = "registrar_dataset";
const REGISTRATION_CERTIFICATE_FORMAT: &str = "registration_cert";
const MAX_ISSUER_INFORMATION_ENTRIES: usize = 32;
const MAX_FORMAT_BYTES: usize = 128;
const MAX_REGISTRAR_DATASET_MEMBERS: usize = 64;
const MAX_SERVICE_DESCRIPTIONS: usize = 32;
const MAX_PROVIDED_ATTESTATIONS: usize = 128;
const MAX_TEXT_BYTES: usize = 2_048;

/// One authenticated, protocol-decoded `issuer_info` element.
#[derive(Clone, Copy)]
pub struct IssuerInformationEntry<'a> {
    /// Profile-defined format label.
    pub format: &'a str,
    /// Profile-defined JSON data member.
    pub data: &'a Value,
}

/// Stable, privacy-safe failure reason for issuer-information validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IssuerInformationErrorReason {
    /// The mandatory `issuer_info` array is absent or empty at this boundary.
    EmptyIssuerInformation,
    /// An array or object exceeds a fixed validation bound.
    ResourceLimitExceeded,
    /// An entry has an empty, oversized, or control-bearing format label.
    InvalidFormat,
    /// No structurally valid `registrar_dataset` entry was supplied.
    MissingRegistrarDataset,
    /// A registrar dataset is not a non-empty JSON object.
    InvalidRegistrarDataset,
    /// The PID/EAA Provider identifier is absent or malformed.
    InvalidIdentifier,
    /// The registered service description collection is malformed.
    InvalidServiceDescription,
    /// The Registrar URI is absent or is not an absolute URI.
    InvalidRegistryUri,
    /// The registered attestation-type collection is malformed.
    InvalidProvidedAttestation,
    /// A registration-certificate container has no JSON value.
    InvalidRegistrationCertificate,
}

/// Typed issuer-information validation failure without untrusted values.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("ETSI issuer-information validation failed: {reason:?}")]
pub struct IssuerInformationError {
    reason: IssuerInformationErrorReason,
}

impl IssuerInformationError {
    const fn new(reason: IssuerInformationErrorReason) -> Self {
        Self { reason }
    }

    /// Return the stable failure reason.
    #[must_use]
    pub const fn reason(self) -> IssuerInformationErrorReason {
        self.reason
    }
}

/// Non-identifying facts derived from authenticated issuer information.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IssuerInformationSummary {
    registrar_dataset_count: u16,
    registration_certificate_count: u16,
    provided_attestation_count: u16,
}

impl IssuerInformationSummary {
    /// Number of validated registrar datasets.
    #[must_use]
    pub const fn registrar_dataset_count(self) -> u16 {
        self.registrar_dataset_count
    }

    /// Number of registration-certificate containers.
    ///
    /// This is evidence of structural presence only. It does not assert that
    /// the certificate representation or its proof has been authenticated.
    #[must_use]
    pub const fn registration_certificate_count(self) -> u16 {
        self.registration_certificate_count
    }

    /// Total number of structurally valid registered attestation types.
    #[must_use]
    pub const fn provided_attestation_count(self) -> u16 {
        self.provided_attestation_count
    }

    /// Whether the optional registration-certificate container is present.
    #[must_use]
    pub const fn registration_certificate_present(self) -> bool {
        self.registration_certificate_count != 0
    }
}

/// Validate authenticated `issuer_info` data for ETSI TS 119 472-3.
///
/// Unknown format labels remain extensible as required by the underlying
/// OpenID4VP-shaped container. Part 3 does not require the two known labels to
/// be unique, so this validator does not impose a stronger rule.
pub fn validate_issuer_information(
    entries: &[IssuerInformationEntry<'_>],
) -> core::result::Result<IssuerInformationSummary, IssuerInformationError> {
    if entries.is_empty() {
        return Err(IssuerInformationError::new(
            IssuerInformationErrorReason::EmptyIssuerInformation,
        ));
    }
    if entries.len() > MAX_ISSUER_INFORMATION_ENTRIES {
        return Err(IssuerInformationError::new(
            IssuerInformationErrorReason::ResourceLimitExceeded,
        ));
    }

    let mut registrar_dataset_count = 0_u16;
    let mut registration_certificate_count = 0_u16;
    let mut provided_attestation_count = 0_u16;
    for entry in entries {
        validate_text(entry.format, MAX_FORMAT_BYTES).map_err(|_| {
            IssuerInformationError::new(IssuerInformationErrorReason::InvalidFormat)
        })?;
        match entry.format {
            REGISTRAR_DATASET_FORMAT => {
                let count = validate_registrar_dataset(entry.data)?;
                registrar_dataset_count =
                    registrar_dataset_count.checked_add(1).ok_or_else(|| {
                        IssuerInformationError::new(
                            IssuerInformationErrorReason::ResourceLimitExceeded,
                        )
                    })?;
                provided_attestation_count = provided_attestation_count
                    .checked_add(count)
                    .ok_or_else(|| {
                        IssuerInformationError::new(
                            IssuerInformationErrorReason::ResourceLimitExceeded,
                        )
                    })?;
            }
            REGISTRATION_CERTIFICATE_FORMAT => {
                if entry.data.is_null() {
                    return Err(IssuerInformationError::new(
                        IssuerInformationErrorReason::InvalidRegistrationCertificate,
                    ));
                }
                registration_certificate_count = registration_certificate_count
                    .checked_add(1)
                    .ok_or_else(|| {
                        IssuerInformationError::new(
                            IssuerInformationErrorReason::ResourceLimitExceeded,
                        )
                    })?;
            }
            _ => {}
        }
    }
    if registrar_dataset_count == 0 {
        return Err(IssuerInformationError::new(
            IssuerInformationErrorReason::MissingRegistrarDataset,
        ));
    }

    Ok(IssuerInformationSummary {
        registrar_dataset_count,
        registration_certificate_count,
        provided_attestation_count,
    })
}

fn validate_registrar_dataset(data: &Value) -> Result<u16, IssuerInformationError> {
    let object = data.as_object().ok_or_else(|| {
        IssuerInformationError::new(IssuerInformationErrorReason::InvalidRegistrarDataset)
    })?;
    if object.is_empty() {
        return Err(IssuerInformationError::new(
            IssuerInformationErrorReason::InvalidRegistrarDataset,
        ));
    }
    if object.len() > MAX_REGISTRAR_DATASET_MEMBERS {
        return Err(IssuerInformationError::new(
            IssuerInformationErrorReason::ResourceLimitExceeded,
        ));
    }

    validate_identifier(required_member(object, "identifier")?)?;
    validate_service_descriptions(required_member(object, "srvDescription")?)?;
    validate_registry_uri(required_member(object, "registryURI")?)?;
    validate_provided_attestations(required_member(object, "providesAttestations")?)
}

fn validate_identifier(value: &Value) -> Result<(), IssuerInformationError> {
    let identifier = value.as_object().ok_or_else(|| {
        IssuerInformationError::new(IssuerInformationErrorReason::InvalidIdentifier)
    })?;
    let kind = string_member(
        identifier,
        "type",
        IssuerInformationErrorReason::InvalidIdentifier,
    )?;
    validate_absolute_uri(kind).map_err(|_| {
        IssuerInformationError::new(IssuerInformationErrorReason::InvalidIdentifier)
    })?;
    let value = string_member(
        identifier,
        "identifier",
        IssuerInformationErrorReason::InvalidIdentifier,
    )?;
    validate_text(value, MAX_TEXT_BYTES)
        .map_err(|_| IssuerInformationError::new(IssuerInformationErrorReason::InvalidIdentifier))
}

fn validate_service_descriptions(value: &Value) -> Result<(), IssuerInformationError> {
    let descriptions = value.as_array().ok_or_else(|| {
        IssuerInformationError::new(IssuerInformationErrorReason::InvalidServiceDescription)
    })?;
    if descriptions.is_empty() {
        return Err(IssuerInformationError::new(
            IssuerInformationErrorReason::InvalidServiceDescription,
        ));
    }
    if descriptions.len() > MAX_SERVICE_DESCRIPTIONS {
        return Err(IssuerInformationError::new(
            IssuerInformationErrorReason::ResourceLimitExceeded,
        ));
    }
    for description in descriptions {
        let description = description.as_object().ok_or_else(|| {
            IssuerInformationError::new(IssuerInformationErrorReason::InvalidServiceDescription)
        })?;
        let language = string_member(
            description,
            "lang",
            IssuerInformationErrorReason::InvalidServiceDescription,
        )?;
        if language.len() != 2 || !language.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            return Err(IssuerInformationError::new(
                IssuerInformationErrorReason::InvalidServiceDescription,
            ));
        }
        let content = string_member(
            description,
            "content",
            IssuerInformationErrorReason::InvalidServiceDescription,
        )?;
        validate_text(content, MAX_TEXT_BYTES).map_err(|_| {
            IssuerInformationError::new(IssuerInformationErrorReason::InvalidServiceDescription)
        })?;
    }
    Ok(())
}

fn validate_registry_uri(value: &Value) -> Result<(), IssuerInformationError> {
    let uri = value.as_str().ok_or_else(|| {
        IssuerInformationError::new(IssuerInformationErrorReason::InvalidRegistryUri)
    })?;
    validate_absolute_uri(uri)
        .map_err(|_| IssuerInformationError::new(IssuerInformationErrorReason::InvalidRegistryUri))
}

fn validate_provided_attestations(value: &Value) -> Result<u16, IssuerInformationError> {
    let attestations = value.as_array().ok_or_else(|| {
        IssuerInformationError::new(IssuerInformationErrorReason::InvalidProvidedAttestation)
    })?;
    if attestations.len() > MAX_PROVIDED_ATTESTATIONS {
        return Err(IssuerInformationError::new(
            IssuerInformationErrorReason::ResourceLimitExceeded,
        ));
    }
    for attestation in attestations {
        let attestation = attestation.as_object().ok_or_else(|| {
            IssuerInformationError::new(IssuerInformationErrorReason::InvalidProvidedAttestation)
        })?;
        let format = string_member(
            attestation,
            "format",
            IssuerInformationErrorReason::InvalidProvidedAttestation,
        )?;
        validate_text(format, MAX_FORMAT_BYTES).map_err(|_| {
            IssuerInformationError::new(IssuerInformationErrorReason::InvalidProvidedAttestation)
        })?;
        let kind = string_member(
            attestation,
            "type",
            IssuerInformationErrorReason::InvalidProvidedAttestation,
        )?;
        validate_text(kind, MAX_TEXT_BYTES).map_err(|_| {
            IssuerInformationError::new(IssuerInformationErrorReason::InvalidProvidedAttestation)
        })?;
    }
    u16::try_from(attestations.len()).map_err(|_| {
        IssuerInformationError::new(IssuerInformationErrorReason::ResourceLimitExceeded)
    })
}

fn required_member<'a>(
    object: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a Value, IssuerInformationError> {
    object.get(name).ok_or_else(|| {
        IssuerInformationError::new(IssuerInformationErrorReason::InvalidRegistrarDataset)
    })
}

fn string_member<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    reason: IssuerInformationErrorReason,
) -> Result<&'a str, IssuerInformationError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| IssuerInformationError::new(reason))
}

fn validate_absolute_uri(value: &str) -> Result<(), IssuerInformationErrorReason> {
    validate_text(value, MAX_TEXT_BYTES)?;
    Url::parse(value)
        .map(|_| ())
        .map_err(|_| IssuerInformationErrorReason::InvalidRegistryUri)
}

fn validate_text(value: &str, max_bytes: usize) -> Result<(), IssuerInformationErrorReason> {
    if value.is_empty()
        || value.len() > max_bytes
        || value
            .chars()
            .any(|character| character.is_control() || character == '\u{202e}')
    {
        Err(IssuerInformationErrorReason::InvalidFormat)
    } else {
        Ok(())
    }
}
