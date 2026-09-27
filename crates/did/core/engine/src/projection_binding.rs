// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical commitment for DID Document fields projected outside `DidCore`.

use reallyme_codec::cbor::{encode_dag_cbor, CborValue};
use reallyme_crypto::sha2::digest as sha2_256_digest;
use reallyme_did_types::{DNSBinding, DomainVerification, WellKnownBinding};

use crate::error::{CanonicalStateViolation, DidCoreError};

/// Borrowed fields that are published in a did:me document but are not
/// otherwise represented directly in the canonical core.
pub struct ProjectionBinding<'a> {
    /// JSON-LD contexts in published order.
    pub context: &'a [String],
    /// Additional subject identifiers.
    pub also_known_as: &'a [String],
    /// Hardware protection assertion.
    pub hardware_bound: Option<bool>,
    /// Biometric protection assertion.
    pub biometric_protected: Option<bool>,
    /// User-verification method label.
    pub user_verification_method: Option<&'a str>,
    /// Device model label.
    pub device_model: Option<&'a str>,
    /// Ordered prior core identifiers.
    pub key_history: &'a [String],
    /// Domain-control assertions.
    pub domain_verification: &'a [DomainVerification],
    /// EUDI level-of-assurance profile.
    pub eudi_level_of_assurance: Option<&'a str>,
    /// EUDI schema version.
    pub eudi_schema_version: Option<&'a str>,
}

/// Hash the canonical projection fields committed into the signed core.
pub fn projection_binding_hash(binding: &ProjectionBinding<'_>) -> Result<[u8; 32], DidCoreError> {
    let encoded = encode_dag_cbor(&projection_to_cbor(binding))
        .map_err(|_| DidCoreError::InvalidCanonicalState(CanonicalStateViolation::CborEncoding))?;
    Ok(sha2_256_digest(encoded.as_slice()).into_bytes())
}

fn projection_to_cbor(binding: &ProjectionBinding<'_>) -> CborValue {
    use CborValue::{Array, Bool, Map, String};

    let mut entries = vec![
        (
            "context".into(),
            Array(binding.context.iter().cloned().map(String).collect()),
        ),
        (
            "alsoKnownAs".into(),
            Array(binding.also_known_as.iter().cloned().map(String).collect()),
        ),
        (
            "keyHistory".into(),
            Array(binding.key_history.iter().cloned().map(String).collect()),
        ),
        (
            "domainVerification".into(),
            Array(
                binding
                    .domain_verification
                    .iter()
                    .map(domain_verification_to_cbor)
                    .collect(),
            ),
        ),
    ];

    if let Some(value) = binding.hardware_bound {
        entries.push(("hardwareBound".into(), Bool(value)));
    }
    if let Some(value) = binding.biometric_protected {
        entries.push(("biometricProtected".into(), Bool(value)));
    }
    if let Some(value) = binding.user_verification_method {
        entries.push(("userVerificationMethod".into(), String(value.into())));
    }
    if let Some(value) = binding.device_model {
        entries.push(("deviceModel".into(), String(value.into())));
    }
    if let Some(value) = binding.eudi_level_of_assurance {
        entries.push(("eudiLevelOfAssurance".into(), String(value.into())));
    }
    if let Some(value) = binding.eudi_schema_version {
        entries.push(("eudiSchemaVersion".into(), String(value.into())));
    }

    Map(entries)
}

fn domain_verification_to_cbor(verification: &DomainVerification) -> CborValue {
    use CborValue::{Map, String};

    let mut entries = vec![
        (
            "type".into(),
            String(verification.verification_type.clone()),
        ),
        ("method".into(), String(verification.method.clone())),
        ("domain".into(), String(verification.domain.clone())),
    ];
    if let Some(dns) = &verification.dns {
        entries.push(("dns".into(), dns_to_cbor(dns)));
    }
    if let Some(wellknown) = &verification.wellknown {
        entries.push(("wellknown".into(), wellknown_to_cbor(wellknown)));
    }
    Map(entries)
}

fn dns_to_cbor(binding: &DNSBinding) -> CborValue {
    use CborValue::{Map, String};
    Map(vec![
        ("recordName".into(), String(binding.record_name.clone())),
        ("txtValue".into(), String(binding.txt_value.clone())),
    ])
}

fn wellknown_to_cbor(binding: &WellKnownBinding) -> CborValue {
    use CborValue::{Map, String};
    Map(vec![
        ("uri".into(), String(binding.uri.clone())),
        ("content".into(), String(binding.content.clone())),
    ])
}
