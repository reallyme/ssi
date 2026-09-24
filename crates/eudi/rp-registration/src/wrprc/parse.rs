// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{
    ParsedRegistrationCertificate, RegistrationCertificatePolicy, ETSI_TS_119_475_WRPRC_POLICY_OID,
};
use crate::json::{canonical_json, deserialize_strict, StrictValue};
use crate::{
    ArtifactDigest, BoundedText, RegistrationError, RegistrationErrorReason, WrpEntitlement,
};

const MAX_WRPRC_VALIDITY_SECONDS: u64 = 31_622_400;

/// Parses strict TS 119 475 WRPRC payload claims without authenticating them.
pub fn parse_registration_certificate(
    payload: &[u8],
) -> Result<ParsedRegistrationCertificate, RegistrationError> {
    let raw: RawWrprc = deserialize_strict(payload)?;
    if raw.iat == 0 || raw.exp <= raw.iat {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidValidityInterval,
        ));
    }
    let duration = raw.exp.checked_sub(raw.iat).ok_or_else(|| {
        RegistrationError::from_reason(RegistrationErrorReason::InvalidValidityInterval)
    })?;
    if duration > MAX_WRPRC_VALIDITY_SECONDS {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidValidityInterval,
        ));
    }
    let registry_uri = canonical_uri(&raw.registry_uri)?;
    let status_uri = canonical_uri(&raw.status.status_list.uri)?;
    let certificate_policy_uri = canonical_uri(&raw.certificate_policy)?;
    let _name = BoundedText::try_new(&raw.name)?;
    let _country = BoundedText::try_new(&raw.country)?;
    for value in [
        raw.sub_ln.as_deref(),
        raw.given_name.as_deref(),
        raw.family_name.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let _ = BoundedText::try_new(value)?;
    }
    validate_collection_value(&raw.purpose)?;
    validate_collection_value(&raw.credentials)?;
    let certificate_policy = validate_policy_identifiers(&raw.policy_id)?;
    let entitlements = validate_wrprc_entitlements(&raw.entitlements)?;
    let provides_attestations_required = entitlements
        .iter()
        .copied()
        .any(WrpEntitlement::provides_wallet_attestations);
    if let Some(value) = raw.provides_attestations.as_ref() {
        validate_collection_value(value)?;
    }
    if provides_attestations_required != raw.provides_attestations.is_some() {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::SemanticBindingMismatch,
        ));
    }
    let semantic = SemanticClaims {
        name: &raw.name,
        country: &raw.country,
        subject_legal_name: raw.sub_ln.as_deref(),
        subject_given_name: raw.given_name.as_deref(),
        subject_family_name: raw.family_name.as_deref(),
        purpose: &raw.purpose,
        credentials: &raw.credentials,
        policy_id: &raw.policy_id,
        certificate_policy: &raw.certificate_policy,
        service_description: &raw.srv_description,
        entitlements: &raw.entitlements,
        privacy_policy: &raw.privacy_policy,
        info_uri: &raw.info_uri,
        support_uri: &raw.support_uri,
        supervisory_authority: &raw.supervisory_authority,
        provides_attestations: raw.provides_attestations.as_ref(),
        intermediary: raw.intermediary.as_ref().or(raw.act.as_ref()),
    };
    let canonical_semantic = Zeroizing::new(canonical_json(&semantic)?);
    let semantic_content_digest = ArtifactDigest::of(&canonical_semantic);
    if raw.intermediary.is_some() && raw.act.is_some() {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::SemanticBindingMismatch,
        ));
    }
    let intermediary_id = raw
        .intermediary
        .as_ref()
        .or(raw.act.as_ref())
        .map(|value| {
            let _name = BoundedText::try_new(&value.name)?;
            BoundedText::try_new(&value.sub)
        })
        .transpose()?;
    Ok(ParsedRegistrationCertificate {
        payload_digest: ArtifactDigest::of(payload),
        relying_party_id: BoundedText::try_new(&raw.sub)?,
        intermediary_id,
        registry_reference_digest: ArtifactDigest::of(registry_uri.as_bytes()),
        status_list_uri_digest: ArtifactDigest::of(status_uri.as_bytes()),
        status_list_index: raw.status.status_list.idx,
        issued_at: raw.iat,
        expires_at: raw.exp,
        certificate_policy,
        certificate_policy_uri_digest: ArtifactDigest::of(certificate_policy_uri.as_bytes()),
        semantic_content_digest,
    })
}

/// Binds one or both authenticated WRPRC encodings to the same claims and
/// local issuance receipt.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct RawWrprc {
    name: String,
    sub: String,
    sub_ln: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    country: String,
    registry_uri: String,
    srv_description: StrictValue,
    entitlements: StrictValue,
    privacy_policy: StrictValue,
    info_uri: StrictValue,
    support_uri: StrictValue,
    supervisory_authority: StrictValue,
    policy_id: Vec<String>,
    certificate_policy: String,
    iat: u64,
    exp: u64,
    status: RawStatus,
    purpose: StrictValue,
    credentials: StrictValue,
    #[serde(default)]
    provides_attestations: Option<StrictValue>,
    intermediary: Option<RawIntermediary>,
    act: Option<RawIntermediary>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct RawStatus {
    status_list: RawStatusList,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct RawStatusList {
    idx: u64,
    uri: String,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct RawIntermediary {
    sub: String,
    name: String,
}

#[derive(Serialize)]
struct SemanticClaims<'a> {
    name: &'a str,
    country: &'a str,
    subject_legal_name: Option<&'a str>,
    subject_given_name: Option<&'a str>,
    subject_family_name: Option<&'a str>,
    purpose: &'a StrictValue,
    credentials: &'a StrictValue,
    policy_id: &'a [String],
    certificate_policy: &'a str,
    service_description: &'a StrictValue,
    entitlements: &'a StrictValue,
    privacy_policy: &'a StrictValue,
    info_uri: &'a StrictValue,
    support_uri: &'a StrictValue,
    supervisory_authority: &'a StrictValue,
    provides_attestations: Option<&'a StrictValue>,
    intermediary: Option<&'a RawIntermediary>,
}

fn canonical_uri(value: &str) -> Result<Zeroizing<String>, RegistrationError> {
    let parsed = Url::parse(value)
        .map_err(|_error| RegistrationError::from_reason(RegistrationErrorReason::InvalidUri))?;
    let invalid_uri = parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some();
    let parsed = Zeroizing::new(String::from(parsed));
    if invalid_uri {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidUri,
        ));
    }
    Ok(parsed)
}

fn validate_policy_identifiers(
    policy_identifiers: &[String],
) -> Result<RegistrationCertificatePolicy, RegistrationError> {
    if policy_identifiers.len() == 1
        && policy_identifiers
            .first()
            .is_some_and(|value| value == ETSI_TS_119_475_WRPRC_POLICY_OID)
    {
        return Ok(RegistrationCertificatePolicy::EtsiTs119475Wrprc);
    }
    Err(RegistrationError::from_reason(
        RegistrationErrorReason::CertificateProfileMismatch,
    ))
}

fn validate_collection_value(value: &StrictValue) -> Result<(), RegistrationError> {
    match value {
        StrictValue::Array(values) if !values.is_empty() => Ok(()),
        StrictValue::Object(values) if !values.is_empty() => Ok(()),
        _ => Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidField,
        )),
    }
}

fn validate_wrprc_entitlements(
    value: &StrictValue,
) -> Result<Vec<WrpEntitlement>, RegistrationError> {
    let StrictValue::Array(values) = value else {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidField,
        ));
    };
    if values.is_empty() {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidField,
        ));
    }
    values
        .iter()
        .map(|value| match value {
            StrictValue::String(value) => WrpEntitlement::parse(value),
            _ => Err(RegistrationError::from_reason(
                RegistrationErrorReason::InvalidField,
            )),
        })
        .collect()
}
