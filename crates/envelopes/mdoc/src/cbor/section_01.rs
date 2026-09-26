// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(feature = "mdoc-crypto")]
use crate::model::{DeviceKeyInfo, IssuerSignedItem, MobileSecurityObject, ValidityInfo};
use crate::model::{
    IssuerSigned, IssuerSignedItemBytes, MdocDeviceDocument, MdocDeviceResponse, MdocDeviceSigned,
    MdocIssuerSignedDocument, MAX_MDOC_CBOR_ARRAY_ITEMS, MAX_MDOC_CBOR_DEPTH,
    MAX_MDOC_CBOR_MAP_ENTRIES, MAX_MDOC_DEVICE_RESPONSE_DOCUMENTS, MAX_MDOC_ELEMENTS_PER_NAMESPACE,
    MAX_MDOC_NAMESPACES,
};
#[cfg(feature = "mdoc-crypto")]
use crate::ValueDigests;
use crate::{MdocEnvelopeError, MdocInvalidInputReason};
use ciborium::value::Value;
use std::io::Cursor;
use std::ops::Deref;
#[cfg(feature = "mdoc-crypto")]
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zeroize::Zeroize;
#[cfg(feature = "mdoc-crypto")]
use zeroize::Zeroizing;

#[cfg(feature = "mdoc-crypto")]
const ISSUER_SIGNED_ITEM_KEYS: [&str; 4] =
    ["digestID", "random", "elementIdentifier", "elementValue"];

#[cfg(feature = "mdoc-crypto")]
const MOBILE_SECURITY_OBJECT_KEYS: [&str; 6] = [
    "version",
    "digestAlgorithm",
    "docType",
    "valueDigests",
    "deviceKeyInfo",
    "validityInfo",
];

#[cfg(feature = "mdoc-crypto")]
const MOBILE_SECURITY_OBJECT_STATUS_KEY: &str = "status";

#[cfg(feature = "mdoc-crypto")]
const VALIDITY_INFO_KEYS: [&str; 3] = ["signed", "validFrom", "validUntil"];

#[cfg(feature = "mdoc-crypto")]
const DEVICE_KEY_INFO_KEYS: [&str; 1] = ["deviceKey"];

/// Owns a decoded CBOR tree and recursively scrubs all text and byte buffers.
///
/// `ciborium::Value` does not implement `Zeroize`, so decoded identity data
/// must not be returned as a bare value. Keeping cleanup in `Drop` guarantees
/// that parse failures, validation failures, and successful extraction paths
/// all scrub the original allocation graph.
pub(crate) struct ZeroizingCborValue {
    value: Value,
}

impl ZeroizingCborValue {
    fn new(value: Value) -> Self {
        Self { value }
    }

    pub(crate) fn as_value(&self) -> &Value {
        &self.value
    }
}

impl Deref for ZeroizingCborValue {
    type Target = Value;

    fn deref(&self) -> &Self::Target {
        self.as_value()
    }
}

impl Drop for ZeroizingCborValue {
    fn drop(&mut self) {
        zeroize_cbor_value(&mut self.value);
    }
}

#[cfg(feature = "mdoc-crypto")]
pub(crate) fn encode_issuer_signed_item(
    item: &IssuerSignedItem,
) -> Result<IssuerSignedItemBytes, MdocEnvelopeError> {
    let element_value = cbor_bytes_to_value(&item.element_value_cbor).map_err(|_| {
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedIssuerSignedItem)
    })?;
    let value = ZeroizingCborValue::new(Value::Map(vec![
        (
            Value::Text("digestID".to_owned()),
            Value::Integer(item.digest_id.into()),
        ),
        (
            Value::Text("random".to_owned()),
            Value::Bytes(item.random.clone()),
        ),
        (
            Value::Text("elementIdentifier".to_owned()),
            Value::Text(item.element_identifier.clone()),
        ),
        (
            Value::Text("elementValue".to_owned()),
            element_value.as_value().clone(),
        ),
    ]));

    let encoded_item = cbor_value_to_bytes(&value)?;
    Ok(IssuerSignedItemBytes::new_tag24(encoded_item))
}

/// Decode one bounded tag-24 ISO `IssuerSignedItemBytes` value.
#[cfg(feature = "mdoc-crypto")]
pub fn decode_issuer_signed_item(
    item_bytes: &IssuerSignedItemBytes,
) -> Result<IssuerSignedItem, MdocEnvelopeError> {
    let reason = MdocInvalidInputReason::MalformedIssuerSignedItem;
    if item_bytes.tag != crate::ENCODED_CBOR_DATA_ITEM_TAG {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::InvalidTaggedItem,
        ));
    }
    let value = cbor_bytes_to_value(&item_bytes.bstr)
        .map_err(|_| MdocEnvelopeError::InvalidInput(reason))?;
    let entries = expect_map(&value, reason)?;
    validate_exact_text_keys(entries, &ISSUER_SIGNED_ITEM_KEYS, reason)?;

    let digest_id = match map_get(entries, "digestID") {
        Some(Value::Integer(value)) => integer_to_u64(value)?,
        _ => {
            return Err(MdocEnvelopeError::InvalidInput(reason));
        }
    };
    let random = match map_get(entries, "random") {
        Some(Value::Bytes(value)) => {
            crate::validate_item_random::validate_decoded_item_random(value)?;
            value.clone()
        }
        _ => {
            return Err(MdocEnvelopeError::InvalidInput(reason));
        }
    };
    let element_identifier = expect_text(
        map_get(entries, "elementIdentifier").ok_or(MdocEnvelopeError::InvalidInput(reason))?,
        reason,
    )?
    .to_owned();
    let element_value_cbor = cbor_value_to_bytes(
        map_get(entries, "elementValue").ok_or(MdocEnvelopeError::InvalidInput(reason))?,
    )?;

    Ok(IssuerSignedItem {
        digest_id,
        random,
        element_identifier,
        element_value_cbor,
    })
}

#[cfg(feature = "mdoc-crypto")]
pub(crate) fn encode_mso_cbor(mso: &MobileSecurityObject) -> Result<Vec<u8>, MdocEnvelopeError> {
    let validity = Value::Map(vec![
        (
            Value::Text("signed".to_owned()),
            unix_seconds_to_tdate(mso.validity_info.signed)?,
        ),
        (
            Value::Text("validFrom".to_owned()),
            unix_seconds_to_tdate(mso.validity_info.valid_from)?,
        ),
        (
            Value::Text("validUntil".to_owned()),
            unix_seconds_to_tdate(mso.validity_info.valid_until)?,
        ),
    ]);
    let device_key =
        cbor_bytes_to_value(&mso.device_key_info.device_key_cose_key_cbor).map_err(|_| {
            MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedMobileSecurityObject)
        })?;
    expect_map(
        &device_key,
        MdocInvalidInputReason::MalformedMobileSecurityObject,
    )?;
    let device_key_info = Value::Map(vec![(
        Value::Text("deviceKey".to_owned()),
        device_key.as_value().clone(),
    )]);

    let mut entries = vec![
        (
            Value::Text("version".to_owned()),
            Value::Text(mso.version.clone()),
        ),
        (
            Value::Text("digestAlgorithm".to_owned()),
            Value::Text(mso.digest_algorithm.clone()),
        ),
        (
            Value::Text("valueDigests".to_owned()),
            value_digests_to_cbor(&mso.value_digests),
        ),
        (Value::Text("deviceKeyInfo".to_owned()), device_key_info),
        (
            Value::Text("docType".to_owned()),
            Value::Text(mso.doc_type.clone()),
        ),
        (Value::Text("validityInfo".to_owned()), validity),
    ];
    if let Some(status) = &mso.status {
        entries.push((
            Value::Text(MOBILE_SECURITY_OBJECT_STATUS_KEY.to_owned()),
            mso_status::status_to_cbor(status)?,
        ));
    }
    let value = ZeroizingCborValue::new(Value::Map(entries));

    cbor_value_to_bytes(&value)
}

#[cfg(feature = "mdoc-crypto")]
pub(crate) fn decode_mso_cbor(bytes: &[u8]) -> Result<MobileSecurityObject, MdocEnvelopeError> {
    let encoded_mso = decode_tagged_cbor_bytes(bytes)?;
    let value = cbor_bytes_to_value(&encoded_mso).map_err(|_| {
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedMobileSecurityObject)
    })?;
    mobile_security_object_from_cbor(&value)
}

#[cfg(feature = "mdoc-crypto")]
pub(crate) fn encode_tagged_cbor_bytes(bytes: &[u8]) -> Result<Vec<u8>, MdocEnvelopeError> {
    cbor_value_to_bytes(&Value::Tag(
        crate::ENCODED_CBOR_DATA_ITEM_TAG,
        Box::new(Value::Bytes(bytes.to_vec())),
    ))
}

#[cfg(feature = "mdoc-crypto")]
fn decode_tagged_cbor_bytes(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, MdocEnvelopeError> {
    let value = cbor_bytes_to_value(bytes).map_err(|_| {
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedMobileSecurityObject)
    })?;
    match value.as_value() {
        Value::Tag(crate::ENCODED_CBOR_DATA_ITEM_TAG, inner) => match inner.as_ref() {
            Value::Bytes(encoded) => Ok(Zeroizing::new(encoded.clone())),
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
fn value_digests_to_cbor(value_digests: &ValueDigests) -> Value {
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
fn mobile_security_object_from_cbor(
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
    let maximum_keys = MOBILE_SECURITY_OBJECT_KEYS
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
    validate_exact_text_keys(entries, &VALIDITY_INFO_KEYS, reason)?;
    Ok(ValidityInfo {
        signed: get_tdate(entries, "signed")?,
        valid_from: get_tdate(entries, "validFrom")?,
        valid_until: get_tdate(entries, "validUntil")?,
    })
}

#[cfg(feature = "mdoc-crypto")]
fn device_key_info_from_cbor(
    entries: &[(Value, Value)],
) -> Result<DeviceKeyInfo, MdocEnvelopeError> {
    let reason = MdocInvalidInputReason::MalformedMobileSecurityObject;
    validate_exact_text_keys(entries, &DEVICE_KEY_INFO_KEYS, reason)?;
    let device_key =
        map_get(entries, "deviceKey").ok_or(MdocEnvelopeError::InvalidInput(reason))?;
    expect_map(device_key, reason)?;
    Ok(DeviceKeyInfo {
        device_key_cose_key_cbor: cbor_value_to_bytes(device_key)?,
    })
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
fn unix_seconds_to_tdate(value: u64) -> Result<Value, MdocEnvelopeError> {
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
    let timestamp = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedMobileSecurityObject)
    })?;
    u64::try_from(timestamp.unix_timestamp()).map_err(|_| {
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedMobileSecurityObject)
    })
}

pub(crate) fn cbor_value_to_bytes(value: &Value) -> Result<Vec<u8>, MdocEnvelopeError> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).map_err(|_| MdocEnvelopeError::Cbor)?;
    Ok(out)
}
