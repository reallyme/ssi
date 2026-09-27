// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(feature = "mdoc-crypto")]
use crate::model::{
    DeviceKeyAuthorizations, DeviceKeyInfo, IssuerSignedItem, MobileSecurityObject, ValidityInfo,
};
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
use mso::{
    key_authorizations_to_cbor, mobile_security_object_from_cbor, unix_seconds_to_tdate,
    value_digests_to_cbor,
};

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
const VALIDITY_INFO_REQUIRED_KEYS: [&str; 3] = ["signed", "validFrom", "validUntil"];

#[cfg(feature = "mdoc-crypto")]
const VALIDITY_INFO_KEYS: [&str; 4] = ["signed", "validFrom", "validUntil", "expectedUpdate"];

#[cfg(feature = "mdoc-crypto")]
const DEVICE_KEY_INFO_KEYS: [&str; 3] = ["deviceKey", "keyAuthorizations", "keyInfo"];

#[cfg(feature = "mdoc-crypto")]
const KEY_AUTHORIZATION_KEYS: [&str; 2] = ["nameSpaces", "dataElements"];

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
    let mut validity_entries = vec![
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
    ];
    if let Some(expected_update) = mso.validity_info.expected_update {
        validity_entries.push((
            Value::Text("expectedUpdate".to_owned()),
            unix_seconds_to_tdate(expected_update)?,
        ));
    }
    let validity = Value::Map(validity_entries);
    let device_key =
        cbor_bytes_to_value(&mso.device_key_info.device_key_cose_key_cbor).map_err(|_| {
            MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedMobileSecurityObject)
        })?;
    expect_map(
        &device_key,
        MdocInvalidInputReason::MalformedMobileSecurityObject,
    )?;
    let mut device_key_info_entries = vec![(
        Value::Text("deviceKey".to_owned()),
        device_key.as_value().clone(),
    )];
    if let Some(authorizations) = &mso.device_key_info.key_authorizations {
        device_key_info_entries.push((
            Value::Text("keyAuthorizations".to_owned()),
            key_authorizations_to_cbor(authorizations),
        ));
    }
    if let Some(key_info_cbor) = &mso.device_key_info.key_info_cbor {
        let key_info = cbor_bytes_to_value(key_info_cbor).map_err(|_| {
            MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedMobileSecurityObject)
        })?;
        expect_map(
            &key_info,
            MdocInvalidInputReason::MalformedMobileSecurityObject,
        )?;
        device_key_info_entries.push((
            Value::Text("keyInfo".to_owned()),
            key_info.as_value().clone(),
        ));
    }
    let device_key_info = Value::Map(device_key_info_entries);

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

pub(crate) fn cbor_value_to_bytes(value: &Value) -> Result<Vec<u8>, MdocEnvelopeError> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).map_err(|_| MdocEnvelopeError::Cbor)?;
    Ok(out)
}
