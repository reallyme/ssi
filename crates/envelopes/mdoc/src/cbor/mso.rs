// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ISO 18013-5 Mobile Security Object CBOR projection.

use super::{
    cbor_value_to_bytes, expect_array, expect_map, expect_text, integer_to_u64, map_get,
    mso_status, DeviceKeyAuthorizations, DeviceKeyInfo, MdocEnvelopeError, MdocInvalidInputReason,
    MobileSecurityObject, OffsetDateTime, Rfc3339, ValidityInfo, Value, ValueDigests,
    DEVICE_KEY_INFO_KEYS, KEY_AUTHORIZATION_KEYS, MAX_MDOC_ELEMENTS_PER_NAMESPACE,
    MAX_MDOC_NAMESPACES, MOBILE_SECURITY_OBJECT_KEYS, MOBILE_SECURITY_OBJECT_STATUS_KEY,
    VALIDITY_INFO_KEYS, VALIDITY_INFO_REQUIRED_KEYS,
};

#[cfg(feature = "mdoc-crypto")]
pub(super) fn value_digests_to_cbor(value_digests: &ValueDigests) -> Value {
    Value::Map(
        value_digests
            .iter()
            .map(|(namespace, digest_map)| {
                let digests = digest_map
                    .iter()
                    .map(|(digest_id, digest)| {
                        (
                            Value::Integer((*digest_id).into()),
                            Value::Bytes(digest.clone()),
                        )
                    })
                    .collect();
                (Value::Text(namespace.clone()), Value::Map(digests))
            })
            .collect(),
    )
}

#[cfg(feature = "mdoc-crypto")]
pub(super) fn mobile_security_object_from_cbor(
    value: &Value,
) -> Result<MobileSecurityObject, MdocEnvelopeError> {
    let reason = MdocInvalidInputReason::MalformedMobileSecurityObject;
    let entries = expect_map(value, reason)?;
    validate_mso_keys(entries, reason)?;

    let version = get_mso_text(entries, "version")?;
    let digest_algorithm = get_mso_text(entries, "digestAlgorithm")?;
    let doc_type = get_mso_text(entries, "docType")?;
    let validity_info = validity_info_from_cbor(get_mso_map(entries, "validityInfo")?)?;
    let device_key_info = device_key_info_from_cbor(get_mso_map(entries, "deviceKeyInfo")?)?;
    let value_digests = value_digests_from_cbor(get_mso_map(entries, "valueDigests")?)?;
    let status = map_get(entries, MOBILE_SECURITY_OBJECT_STATUS_KEY)
        .map(mso_status::status_from_cbor)
        .transpose()?;

    Ok(MobileSecurityObject {
        version,
        digest_algorithm,
        doc_type,
        validity_info,
        device_key_info,
        value_digests,
        status,
    })
}

#[cfg(feature = "mdoc-crypto")]
fn validate_mso_keys(
    entries: &[(Value, Value)],
    reason: MdocInvalidInputReason,
) -> Result<(), MdocEnvelopeError> {
    let maximum_keys =
        MOBILE_SECURITY_OBJECT_KEYS
            .len()
            .checked_add(1)
            .ok_or(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::IntegerOutOfRange,
            ))?;
    if entries.len() < MOBILE_SECURITY_OBJECT_KEYS.len() || entries.len() > maximum_keys {
        return Err(MdocEnvelopeError::InvalidInput(reason));
    }

    for (key, _) in entries {
        let Value::Text(key) = key else {
            return Err(MdocEnvelopeError::InvalidInput(reason));
        };
        if !MOBILE_SECURITY_OBJECT_KEYS.contains(&key.as_str())
            && key != MOBILE_SECURITY_OBJECT_STATUS_KEY
        {
            return Err(MdocEnvelopeError::InvalidInput(reason));
        }
    }

    for expected_key in MOBILE_SECURITY_OBJECT_KEYS {
        let occurrences = entries
            .iter()
            .filter(|(key, _)| matches!(key, Value::Text(text) if text == expected_key))
            .count();
        if occurrences != 1 {
            return Err(MdocEnvelopeError::InvalidInput(reason));
        }
    }
    let status_occurrences = entries
        .iter()
        .filter(|(key, _)| {
            matches!(key, Value::Text(text) if text == MOBILE_SECURITY_OBJECT_STATUS_KEY)
        })
        .count();
    if status_occurrences > 1 {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::DuplicateMsoStatusMember,
        ));
    }
    Ok(())
}

#[cfg(feature = "mdoc-crypto")]
fn validity_info_from_cbor(entries: &[(Value, Value)]) -> Result<ValidityInfo, MdocEnvelopeError> {
    let reason = MdocInvalidInputReason::MalformedMobileSecurityObject;
    validate_optional_text_keys(entries, "signed", &VALIDITY_INFO_KEYS, reason)?;
    for required in VALIDITY_INFO_REQUIRED_KEYS {
        if map_get(entries, required).is_none() {
            return Err(MdocEnvelopeError::InvalidInput(reason));
        }
    }
    Ok(ValidityInfo {
        signed: get_tdate(entries, "signed")?,
        valid_from: get_tdate(entries, "validFrom")?,
        valid_until: get_tdate(entries, "validUntil")?,
        expected_update: map_get(entries, "expectedUpdate")
            .map(|_| get_tdate(entries, "expectedUpdate"))
            .transpose()?,
    })
}

#[cfg(feature = "mdoc-crypto")]
fn device_key_info_from_cbor(
    entries: &[(Value, Value)],
) -> Result<DeviceKeyInfo, MdocEnvelopeError> {
    let reason = MdocInvalidInputReason::MalformedMobileSecurityObject;
    validate_optional_text_keys(entries, "deviceKey", &DEVICE_KEY_INFO_KEYS, reason)?;
    let device_key =
        map_get(entries, "deviceKey").ok_or(MdocEnvelopeError::InvalidInput(reason))?;
    expect_map(device_key, reason)?;
    let key_info_cbor = map_get(entries, "keyInfo")
        .map(|value| {
            expect_map(value, reason)?;
            let encoded = cbor_value_to_bytes(value)?;
            if encoded.len() > crate::MAX_MDOC_KEY_INFO_BYTES {
                return Err(MdocEnvelopeError::InvalidInput(
                    MdocInvalidInputReason::KeyInfoTooLarge,
                ));
            }
            Ok(encoded)
        })
        .transpose()?;
    Ok(DeviceKeyInfo {
        device_key_cose_key_cbor: cbor_value_to_bytes(device_key)?,
        key_authorizations: map_get(entries, "keyAuthorizations")
            .map(key_authorizations_from_cbor)
            .transpose()?,
        key_info_cbor,
    })
}

#[cfg(feature = "mdoc-crypto")]
pub(super) fn key_authorizations_to_cbor(authorizations: &DeviceKeyAuthorizations) -> Value {
    let mut entries = Vec::new();
    if !authorizations.name_spaces.is_empty() {
        entries.push((
            Value::Text("nameSpaces".to_owned()),
            Value::Array(
                authorizations
                    .name_spaces
                    .iter()
                    .cloned()
                    .map(Value::Text)
                    .collect(),
            ),
        ));
    }
    if !authorizations.data_elements.is_empty() {
        entries.push((
            Value::Text("dataElements".to_owned()),
            Value::Map(
                authorizations
                    .data_elements
                    .iter()
                    .map(|(namespace, elements)| {
                        (
                            Value::Text(namespace.clone()),
                            Value::Array(elements.iter().cloned().map(Value::Text).collect()),
                        )
                    })
                    .collect(),
            ),
        ));
    }
    Value::Map(entries)
}

#[cfg(feature = "mdoc-crypto")]
fn key_authorizations_from_cbor(
    value: &Value,
) -> Result<DeviceKeyAuthorizations, MdocEnvelopeError> {
    let reason = MdocInvalidInputReason::MalformedMobileSecurityObject;
    let entries = expect_map(value, reason)?;
    if entries.is_empty() {
        return Err(MdocEnvelopeError::InvalidInput(reason));
    }
    validate_optional_text_keys(entries, "", &KEY_AUTHORIZATION_KEYS, reason)?;
    let name_spaces = map_get(entries, "nameSpaces")
        .map(|value| bounded_unique_text_array(value, reason))
        .transpose()?
        .unwrap_or_default();
    let mut data_elements = std::collections::BTreeMap::new();
    if let Some(value) = map_get(entries, "dataElements") {
        let namespace_entries = expect_map(value, reason)?;
        if namespace_entries.len() > MAX_MDOC_NAMESPACES {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::TooManyNamespaces,
            ));
        }
        for (namespace, elements) in namespace_entries {
            let Value::Text(namespace) = namespace else {
                return Err(MdocEnvelopeError::InvalidInput(reason));
            };
            if namespace.is_empty()
                || data_elements
                    .insert(
                        namespace.clone(),
                        bounded_unique_text_array(elements, reason)?,
                    )
                    .is_some()
            {
                return Err(MdocEnvelopeError::InvalidInput(reason));
            }
        }
    }
    Ok(DeviceKeyAuthorizations {
        name_spaces,
        data_elements,
    })
}

#[cfg(feature = "mdoc-crypto")]
fn bounded_unique_text_array(
    value: &Value,
    reason: MdocInvalidInputReason,
) -> Result<Vec<String>, MdocEnvelopeError> {
    let values = expect_array(value, reason)?;
    if values.is_empty() || values.len() > MAX_MDOC_ELEMENTS_PER_NAMESPACE {
        return Err(MdocEnvelopeError::InvalidInput(reason));
    }
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let text = expect_text(value, reason)?;
        if text.is_empty() || output.iter().any(|existing| existing == text) {
            return Err(MdocEnvelopeError::InvalidInput(reason));
        }
        output.push(text.to_owned());
    }
    Ok(output)
}

#[cfg(feature = "mdoc-crypto")]
fn validate_optional_text_keys(
    entries: &[(Value, Value)],
    required: &str,
    allowed: &[&str],
    reason: MdocInvalidInputReason,
) -> Result<(), MdocEnvelopeError> {
    if entries.is_empty() || entries.len() > allowed.len() {
        return Err(MdocEnvelopeError::InvalidInput(reason));
    }
    for (index, (key, _)) in entries.iter().enumerate() {
        let Value::Text(key) = key else {
            return Err(MdocEnvelopeError::InvalidInput(reason));
        };
        if !allowed.contains(&key.as_str())
            || entries
                .iter()
                .take(index)
                .any(|(prior, _)| matches!(prior, Value::Text(prior) if prior == key))
        {
            return Err(MdocEnvelopeError::InvalidInput(reason));
        }
    }
    if !required.is_empty() && map_get(entries, required).is_none() {
        return Err(MdocEnvelopeError::InvalidInput(reason));
    }
    Ok(())
}

#[cfg(feature = "mdoc-crypto")]
fn value_digests_from_cbor(entries: &[(Value, Value)]) -> Result<ValueDigests, MdocEnvelopeError> {
    if entries.len() > MAX_MDOC_NAMESPACES {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::TooManyNamespaces,
        ));
    }

    let mut out = ValueDigests::new();

    for (namespace_value, value) in entries {
        let Value::Text(namespace) = namespace_value else {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::MalformedMobileSecurityObject,
            ));
        };
        let digest_entries =
            expect_map(value, MdocInvalidInputReason::MalformedMobileSecurityObject)?;
        if digest_entries.len() > MAX_MDOC_ELEMENTS_PER_NAMESPACE {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::TooManyElementsPerNamespace,
            ));
        }

        let mut digests = std::collections::BTreeMap::new();
        for (digest_id_value, digest_value) in digest_entries {
            let Value::Integer(digest_id_value) = digest_id_value else {
                return Err(MdocEnvelopeError::InvalidInput(
                    MdocInvalidInputReason::MalformedMobileSecurityObject,
                ));
            };
            let digest_id = integer_to_u64(digest_id_value)?;
            let Value::Bytes(digest) = digest_value else {
                return Err(MdocEnvelopeError::InvalidInput(
                    MdocInvalidInputReason::MalformedMobileSecurityObject,
                ));
            };
            if digests.insert(digest_id, digest.clone()).is_some() {
                return Err(MdocEnvelopeError::InvalidInput(
                    MdocInvalidInputReason::MalformedMobileSecurityObject,
                ));
            }
        }
        if out.insert(namespace.clone(), digests).is_some() {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::MalformedMobileSecurityObject,
            ));
        }
    }

    Ok(out)
}

#[cfg(feature = "mdoc-crypto")]
fn get_mso_map<'a>(
    entries: &'a [(Value, Value)],
    key: &str,
) -> Result<&'a [(Value, Value)], MdocEnvelopeError> {
    match map_get(entries, key) {
        Some(Value::Map(value)) => Ok(value),
        _ => Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::MalformedMobileSecurityObject,
        )),
    }
}

#[cfg(feature = "mdoc-crypto")]
fn get_mso_text(entries: &[(Value, Value)], key: &str) -> Result<String, MdocEnvelopeError> {
    match map_get(entries, key) {
        Some(Value::Text(value)) => Ok(value.clone()),
        _ => Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::MalformedMobileSecurityObject,
        )),
    }
}

#[cfg(feature = "mdoc-crypto")]
fn get_tdate(entries: &[(Value, Value)], key: &str) -> Result<u64, MdocEnvelopeError> {
    match map_get(entries, key) {
        Some(Value::Tag(0, value)) => match value.as_ref() {
            Value::Text(timestamp) => tdate_to_unix_seconds(timestamp),
            _ => Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::MalformedMobileSecurityObject,
            )),
        },
        _ => Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::MalformedMobileSecurityObject,
        )),
    }
}

#[cfg(feature = "mdoc-crypto")]
pub(super) fn unix_seconds_to_tdate(value: u64) -> Result<Value, MdocEnvelopeError> {
    let unix_seconds = i64::try_from(value)
        .map_err(|_| MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::IntegerOutOfRange))?;
    let timestamp = OffsetDateTime::from_unix_timestamp(unix_seconds)
        .map_err(|_| MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::IntegerOutOfRange))?
        .format(&Rfc3339)
        .map_err(|_| MdocEnvelopeError::Cbor)?;
    Ok(Value::Tag(0, Box::new(Value::Text(timestamp))))
}

#[cfg(feature = "mdoc-crypto")]
fn tdate_to_unix_seconds(value: &str) -> Result<u64, MdocEnvelopeError> {
    if value.len() != 20 || value.as_bytes().get(19) != Some(&b'Z') {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::MalformedMobileSecurityObject,
        ));
    }
    let timestamp = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedMobileSecurityObject)
    })?;
    let canonical = timestamp
        .format(&Rfc3339)
        .map_err(|_| MdocEnvelopeError::Cbor)?;
    if canonical != value {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::MalformedMobileSecurityObject,
        ));
    }
    u64::try_from(timestamp.unix_timestamp()).map_err(|_| {
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedMobileSecurityObject)
    })
}
