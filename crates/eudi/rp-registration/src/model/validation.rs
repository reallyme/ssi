// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use url::Url;
use zeroize::Zeroizing;

use super::payload::{CredentialMetadata, DcSdJwtMetadata, MsoMdocMetadata, PolicyReference};
use super::raw::RawPolicy;
use super::{BoundedText, WrpEntitlement};
use crate::json::{parse_strict, StrictValue};
use crate::{RegistrationError, RegistrationErrorReason};

const MAX_URI_BYTES: usize = 4_096;
const MAX_COLLECTION_ITEMS: usize = 128;
pub(super) const MAX_SERVICE_DEPTH: usize = 4;
const MAX_CERTIFICATE_HISTORY_BYTES: usize = 131_072;

pub(super) fn validate_metadata(
    mut meta: BTreeMap<String, StrictValue>,
) -> Result<CredentialMetadata, RegistrationError> {
    if meta.len() != 1 {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidField,
        ));
    }
    if let Some(mut value) = meta.remove("vct_values") {
        let Some(values) = value.take_array() else {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::InvalidField,
            ));
        };
        validate_items(&values, true)?;
        let mut texts_out = Vec::new();
        for mut value in values {
            let Some(text) = value.take_string() else {
                return Err(RegistrationError::from_reason(
                    RegistrationErrorReason::InvalidField,
                ));
            };
            texts_out.push(BoundedText::try_from_owned(text)?);
        }
        return Ok(CredentialMetadata::DcSdJwt(DcSdJwtMetadata {
            vct_values: texts_out,
        }));
    }
    if let Some(mut value) = meta.remove("doctype_value") {
        let Some(value) = value.take_string() else {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::InvalidField,
            ));
        };
        return Ok(CredentialMetadata::MsoMdoc(MsoMdocMetadata {
            doctype_value: BoundedText::try_from_owned(value)?,
        }));
    }
    Err(RegistrationError::from_reason(
        RegistrationErrorReason::InvalidField,
    ))
}

pub(super) fn validate_claim_path(path: &str) -> Result<(), RegistrationError> {
    let mut value = parse_strict(path.as_bytes())?;
    let Some(segments) = value.take_array() else {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidClaimPath,
        ));
    };
    if segments.is_empty() || segments.len() > 32 {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidClaimPath,
        ));
    }
    if segments.iter().any(|segment| match segment {
        StrictValue::Null | StrictValue::String(_) => false,
        StrictValue::Number(number) => number.as_u64().is_none(),
        _ => true,
    }) {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidClaimPath,
        ));
    }
    Ok(())
}

pub(super) fn validate_policies(
    values: Vec<RawPolicy>,
) -> Result<Vec<PolicyReference>, RegistrationError> {
    values
        .into_iter()
        .map(|mut value| {
            Ok(PolicyReference {
                policy_uri: uri_text_owned(core::mem::take(&mut value.policy_uri))?,
                kind: BoundedText::try_from_owned(core::mem::take(&mut value.kind))?,
            })
        })
        .collect()
}

pub(super) fn texts(values: Vec<String>) -> Result<Vec<BoundedText>, RegistrationError> {
    values
        .into_iter()
        .map(BoundedText::try_from_owned)
        .collect()
}

pub(super) fn validate_entitlements(
    values: Vec<String>,
) -> Result<Vec<WrpEntitlement>, RegistrationError> {
    let mut entitlements = Vec::new();
    entitlements
        .try_reserve_exact(values.len())
        .map_err(|_error| {
            RegistrationError::from_reason(RegistrationErrorReason::CapacityUnavailable)
        })?;
    for value in values {
        let value = Zeroizing::new(value);
        let entitlement = WrpEntitlement::parse(&value)?;
        if entitlements.contains(&entitlement) {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::InvalidField,
            ));
        }
        entitlements.push(entitlement);
    }
    Ok(entitlements)
}

pub(super) fn uri_text_owned(value: String) -> Result<BoundedText, RegistrationError> {
    let mut value = Zeroizing::new(value);
    super::validate_text(&value, MAX_URI_BYTES)?;
    let parsed = Url::parse(&value)
        .map_err(|_error| RegistrationError::from_reason(RegistrationErrorReason::InvalidUri))?;
    let invalid_uri =
        parsed.cannot_be_a_base() || parsed.host_str().is_none() || parsed.fragment().is_some();
    let _parsed_serialization = Zeroizing::new(String::from(parsed));
    if invalid_uri {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidUri,
        ));
    }
    Ok(BoundedText(core::mem::take(&mut *value)))
}

pub(super) fn validate_certificate_history(
    value: String,
) -> Result<BoundedText, RegistrationError> {
    let mut value = Zeroizing::new(value);
    if value.len() > MAX_CERTIFICATE_HISTORY_BYTES || value.is_empty() {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::ResourceLimitExceeded,
        ));
    }
    Ok(BoundedText(core::mem::take(&mut *value)))
}

pub(super) fn validate_items<T>(
    values: &[T],
    require_nonempty: bool,
) -> Result<(), RegistrationError> {
    if (require_nonempty && values.is_empty()) || values.len() > MAX_COLLECTION_ITEMS {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::ResourceLimitExceeded,
        ));
    }
    Ok(())
}
