// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pub(crate) fn cbor_bytes_to_value(bytes: &[u8]) -> Result<ZeroizingCborValue, MdocEnvelopeError> {
    if bytes.len() > crate::MAX_MDOC_CBOR_INPUT_BYTES {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::CborInputTooLarge,
        ));
    }
    // Enforce depth, container, item-count, and declared-length limits before
    // the tree decoder allocates any values for untrusted input.
    scan_cbor_limits::scan_cbor_limits(bytes)?;
    let expected_len = u64::try_from(bytes.len())
        .map_err(|_| MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::IntegerOutOfRange))?;
    let mut reader = Cursor::new(bytes);
    let value = ciborium::de::from_reader(&mut reader).map_err(|_| MdocEnvelopeError::Cbor)?;
    let value = ZeroizingCborValue::new(value);
    if reader.position() != expected_len {
        return Err(MdocEnvelopeError::Cbor);
    }
    validate_ciborium_value(&value, 0)?;
    Ok(value)
}

pub(crate) fn empty_cbor_map() -> Result<Vec<u8>, MdocEnvelopeError> {
    cbor_value_to_bytes(&Value::Map(Vec::new()))
}

pub(crate) fn encode_device_response_cbor(
    response: &MdocDeviceResponse,
) -> Result<Vec<u8>, MdocEnvelopeError> {
    let entries = vec![
        (
            Value::Text("version".to_owned()),
            Value::Text(response.version.clone()),
        ),
        (
            Value::Text("documents".to_owned()),
            Value::Array(
                response
                    .documents
                    .iter()
                    .map(device_document_to_value)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        ),
        (
            Value::Text("status".to_owned()),
            Value::Integer(response.status.into()),
        ),
    ];

    let value = ZeroizingCborValue::new(Value::Map(entries));
    cbor_value_to_bytes(&value)
}

pub(crate) fn decode_device_response_cbor(
    bytes: &[u8],
) -> Result<MdocDeviceResponse, MdocEnvelopeError> {
    let value = cbor_bytes_to_value(bytes)?;
    let entries = expect_map(&value, MdocInvalidInputReason::MalformedDeviceResponse)?;
    let version = expect_text(
        map_get(entries, "version").ok_or(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::MalformedDeviceResponse,
        ))?,
        MdocInvalidInputReason::MalformedDeviceResponse,
    )?
    .to_owned();
    let documents_value = map_get(entries, "documents").ok_or(MdocEnvelopeError::InvalidInput(
        MdocInvalidInputReason::MalformedDeviceResponse,
    ))?;
    let documents = expect_array(
        documents_value,
        MdocInvalidInputReason::MalformedDeviceResponse,
    )?;
    if documents.len() > MAX_MDOC_DEVICE_RESPONSE_DOCUMENTS {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::TooManyDocuments,
        ));
    }
    let documents = documents
        .iter()
        .map(value_to_device_document)
        .collect::<Result<Vec<_>, _>>()?;
    let status = match map_get(entries, "status") {
        Some(Value::Integer(value)) => integer_to_u64(value)?,
        _ => {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::MalformedDeviceResponse,
            ));
        }
    };

    Ok(MdocDeviceResponse {
        version,
        documents,
        status,
    })
}

pub(crate) fn expect_map(
    value: &Value,
    reason: MdocInvalidInputReason,
) -> Result<&[(Value, Value)], MdocEnvelopeError> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(MdocEnvelopeError::InvalidInput(reason)),
    }
}

pub(crate) fn expect_array(
    value: &Value,
    reason: MdocInvalidInputReason,
) -> Result<&[Value], MdocEnvelopeError> {
    match value {
        Value::Array(items) => Ok(items),
        _ => Err(MdocEnvelopeError::InvalidInput(reason)),
    }
}

pub(crate) fn expect_text(
    value: &Value,
    reason: MdocInvalidInputReason,
) -> Result<&str, MdocEnvelopeError> {
    match value {
        Value::Text(text) => Ok(text.as_str()),
        _ => Err(MdocEnvelopeError::InvalidInput(reason)),
    }
}

pub(crate) fn map_get<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(candidate, _)| matches!(candidate, Value::Text(text) if text == key))
        .map(|(_, value)| value)
}

fn validate_exact_text_keys(
    entries: &[(Value, Value)],
    expected: &[&str],
    reason: MdocInvalidInputReason,
) -> Result<(), MdocEnvelopeError> {
    if entries.len() != expected.len() {
        return Err(MdocEnvelopeError::InvalidInput(reason));
    }

    for (key, _) in entries {
        let Value::Text(key) = key else {
            return Err(MdocEnvelopeError::InvalidInput(reason));
        };
        if !expected.contains(&key.as_str()) {
            return Err(MdocEnvelopeError::InvalidInput(reason));
        }
    }

    for expected_key in expected {
        let occurrences = entries
            .iter()
            .filter(|(key, _)| matches!(key, Value::Text(text) if text == expected_key))
            .count();
        if occurrences != 1 {
            return Err(MdocEnvelopeError::InvalidInput(reason));
        }
    }

    Ok(())
}

fn device_document_to_value(document: &MdocDeviceDocument) -> Result<Value, MdocEnvelopeError> {
    Ok(Value::Map(vec![
        (
            Value::Text("docType".to_owned()),
            Value::Text(document.doc_type.clone()),
        ),
        (
            Value::Text("issuerSigned".to_owned()),
            issuer_signed_to_value(&document.issuer_signed.issuer_signed)?,
        ),
        (
            Value::Text("deviceSigned".to_owned()),
            device_signed_to_value(&document.device_signed)?,
        ),
    ]))
}

fn value_to_device_document(value: &Value) -> Result<MdocDeviceDocument, MdocEnvelopeError> {
    let entries = expect_map(value, MdocInvalidInputReason::MalformedDeviceResponse)?;
    let doc_type = expect_text(
        map_get(entries, "docType").ok_or(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::MalformedDeviceResponse,
        ))?,
        MdocInvalidInputReason::MalformedDeviceResponse,
    )?
    .to_owned();
    let issuer_signed = value_to_issuer_signed(map_get(entries, "issuerSigned").ok_or(
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedDeviceResponse),
    )?)?;
    let device_signed = value_to_device_signed(map_get(entries, "deviceSigned").ok_or(
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedDeviceResponse),
    )?)?;

    Ok(MdocDeviceDocument {
        doc_type: doc_type.clone(),
        issuer_signed: MdocIssuerSignedDocument {
            doc_type,
            issuer_signed,
        },
        device_signed,
    })
}

pub(crate) fn encode_issuer_signed_cbor(
    issuer_signed: &IssuerSigned,
) -> Result<Vec<u8>, MdocEnvelopeError> {
    cbor_value_to_bytes(&issuer_signed_to_value(issuer_signed)?)
}

pub(crate) fn decode_issuer_signed_cbor(
    bytes: &[u8],
) -> Result<IssuerSigned, MdocEnvelopeError> {
    let value = cbor_bytes_to_value(bytes)?;
    value_to_issuer_signed(&value)
}

fn issuer_signed_to_value(issuer_signed: &IssuerSigned) -> Result<Value, MdocEnvelopeError> {
    let mut entries = Vec::new();
    if let Some(name_spaces) = &issuer_signed.name_spaces {
        entries.push((
            Value::Text("nameSpaces".to_owned()),
            issuer_namespaces_to_value(name_spaces),
        ));
    }
    entries.push((
        Value::Text("issuerAuth".to_owned()),
        embedded_cose_sign1(&issuer_signed.issuer_auth)?,
    ));
    Ok(Value::Map(entries))
}

fn embedded_cose_sign1(bytes: &[u8]) -> Result<Value, MdocEnvelopeError> {
    let value = cbor_bytes_to_value(bytes)?;
    validate_embedded_cose_sign1(value.as_value(), MdocEnvelopeError::Cbor)?;
    Ok(value.as_value().clone())
}

fn validate_embedded_cose_sign1(
    value: &Value,
    error: MdocEnvelopeError,
) -> Result<(), MdocEnvelopeError> {
    let body = match value {
        Value::Tag(18, body) => body.as_ref(),
        body => body,
    };
    let Value::Array(fields) = body else {
        return Err(error);
    };
    if fields.len() != 4 {
        return Err(error);
    }
    Ok(())
}

fn embedded_cose_sign1_to_bytes(
    value: &Value,
    reason: MdocInvalidInputReason,
) -> Result<Vec<u8>, MdocEnvelopeError> {
    validate_embedded_cose_sign1(value, MdocEnvelopeError::InvalidInput(reason))?;
    cbor_value_to_bytes(value)
}

fn value_to_issuer_signed(value: &Value) -> Result<IssuerSigned, MdocEnvelopeError> {
    let reason = MdocInvalidInputReason::MalformedIssuerSignedDocument;
    let entries = expect_map(value, reason)?;
    validate_issuer_signed_keys(entries, reason)?;
    let issuer_auth = embedded_cose_sign1_to_bytes(
        map_get(entries, "issuerAuth").ok_or(MdocEnvelopeError::InvalidInput(
            reason,
        ))?,
        reason,
    )?;
    let name_spaces = match map_get(entries, "nameSpaces") {
        Some(value) => Some(value_to_issuer_namespaces(value)?),
        None => None,
    };

    Ok(IssuerSigned {
        name_spaces,
        issuer_auth,
    })
}

fn validate_issuer_signed_keys(
    entries: &[(Value, Value)],
    reason: MdocInvalidInputReason,
) -> Result<(), MdocEnvelopeError> {
    if !(1..=2).contains(&entries.len()) {
        return Err(MdocEnvelopeError::InvalidInput(reason));
    }
    let mut issuer_auth_count = 0_usize;
    let mut name_spaces_count = 0_usize;
    for (key, _) in entries {
        match key {
            Value::Text(key) if key == "issuerAuth" => {
                issuer_auth_count = issuer_auth_count
                    .checked_add(1)
                    .ok_or(MdocEnvelopeError::InvalidInput(reason))?;
            }
            Value::Text(key) if key == "nameSpaces" => {
                name_spaces_count = name_spaces_count
                    .checked_add(1)
                    .ok_or(MdocEnvelopeError::InvalidInput(reason))?;
            }
            _ => return Err(MdocEnvelopeError::InvalidInput(reason)),
        }
    }
    if issuer_auth_count != 1 || name_spaces_count > 1 {
        return Err(MdocEnvelopeError::InvalidInput(reason));
    }
    Ok(())
}

fn issuer_namespaces_to_value(name_spaces: &crate::IssuerNameSpaces) -> Value {
    Value::Map(
        name_spaces
            .iter()
            .map(|(namespace, items)| {
                (
                    Value::Text(namespace.clone()),
                    Value::Array(
                        items
                            .iter()
                            .map(|item| {
                                Value::Tag(item.tag, Box::new(Value::Bytes(item.bstr.clone())))
                            })
                            .collect(),
                    ),
                )
            })
            .collect(),
    )
}

fn value_to_issuer_namespaces(value: &Value) -> Result<crate::IssuerNameSpaces, MdocEnvelopeError> {
    let reason = MdocInvalidInputReason::MalformedIssuerSignedDocument;
    let entries = expect_map(value, reason)?;
    if entries.len() > MAX_MDOC_NAMESPACES {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::TooManyNamespaces,
        ));
    }

    let mut out = crate::IssuerNameSpaces::new();

    for (namespace_value, items_value) in entries {
        let Value::Text(namespace) = namespace_value else {
            return Err(MdocEnvelopeError::InvalidInput(reason));
        };
        let items = expect_array(items_value, reason)?;
        if items.len() > MAX_MDOC_ELEMENTS_PER_NAMESPACE {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::TooManyElementsPerNamespace,
            ));
        }
        let item_bytes = items
            .iter()
            .map(value_to_issuer_signed_item_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        if out.insert(namespace.clone(), item_bytes).is_some() {
            return Err(MdocEnvelopeError::InvalidInput(reason));
        }
    }

    Ok(out)
}

fn value_to_issuer_signed_item_bytes(
    value: &Value,
) -> Result<IssuerSignedItemBytes, MdocEnvelopeError> {
    let reason = MdocInvalidInputReason::MalformedIssuerSignedDocument;
    match value {
        Value::Tag(tag, inner) if *tag == crate::ENCODED_CBOR_DATA_ITEM_TAG => match inner.as_ref() {
            Value::Bytes(bytes) => Ok(IssuerSignedItemBytes {
                tag: *tag,
                bstr: bytes.clone(),
            }),
            _ => Err(MdocEnvelopeError::InvalidInput(reason)),
        },
        _ => Err(MdocEnvelopeError::InvalidInput(reason)),
    }
}

fn device_signed_to_value(device_signed: &MdocDeviceSigned) -> Result<Value, MdocEnvelopeError> {
    let name_spaces = cbor_bytes_to_value(&device_signed.name_spaces_cbor)?;
    expect_map(
        &name_spaces,
        MdocInvalidInputReason::InvalidDeviceNameSpaces,
    )?;
    Ok(Value::Map(vec![
        (
            Value::Text("nameSpaces".to_owned()),
            Value::Tag(
                crate::ENCODED_CBOR_DATA_ITEM_TAG,
                Box::new(Value::Bytes(device_signed.name_spaces_cbor.clone())),
            ),
        ),
        (
            Value::Text("deviceAuth".to_owned()),
            Value::Map(vec![(
                Value::Text("deviceSignature".to_owned()),
                embedded_cose_sign1(&device_signed.device_auth)?,
            )]),
        ),
    ]))
}

fn value_to_device_signed(value: &Value) -> Result<MdocDeviceSigned, MdocEnvelopeError> {
    let entries = expect_map(value, MdocInvalidInputReason::MalformedDeviceResponse)?;
    validate_exact_text_keys(
        entries,
        &["nameSpaces", "deviceAuth"],
        MdocInvalidInputReason::MalformedDeviceResponse,
    )?;
    let name_spaces_value = map_get(entries, "nameSpaces").ok_or(
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedDeviceResponse),
    )?;
    let name_spaces_cbor = match name_spaces_value {
        Value::Tag(tag, inner) if *tag == crate::ENCODED_CBOR_DATA_ITEM_TAG => {
            let Value::Bytes(bytes) = inner.as_ref() else {
                return Err(MdocEnvelopeError::InvalidInput(
                    MdocInvalidInputReason::InvalidDeviceNameSpaces,
                ));
            };
            let decoded = cbor_bytes_to_value(bytes).map_err(|_| {
                MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidDeviceNameSpaces)
            })?;
            expect_map(&decoded, MdocInvalidInputReason::InvalidDeviceNameSpaces)?;
            bytes.clone()
        }
        _ => {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::InvalidDeviceNameSpaces,
            ));
        }
    };
    let device_auth_entries = expect_map(
        map_get(entries, "deviceAuth").ok_or(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::MalformedDeviceResponse,
        ))?,
        MdocInvalidInputReason::MalformedDeviceResponse,
    )?;
    validate_exact_text_keys(
        device_auth_entries,
        &["deviceSignature"],
        MdocInvalidInputReason::MalformedDeviceResponse,
    )?;
    // OpenID4VP 1.0 Appendix B.2.6 uses DeviceSignature for mdoc holder
    // binding. Missing DeviceAuth and DeviceMac-only inputs fail closed; this
    // verifier never substitutes issuerAuth for proof of possession of the
    // MSO-authenticated device key.
    let device_auth = embedded_cose_sign1_to_bytes(
        map_get(device_auth_entries, "deviceSignature").ok_or(
            MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedDeviceResponse),
        )?,
        MdocInvalidInputReason::MalformedDeviceResponse,
    )?;

    Ok(MdocDeviceSigned {
        name_spaces_cbor,
        device_auth,
    })
}

fn integer_to_u64(value: &ciborium::value::Integer) -> Result<u64, MdocEnvelopeError> {
    let value_i128 = i128::from(*value);
    if value_i128 < 0 {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::IntegerOutOfRange,
        ));
    }
    u64::try_from(value_i128)
        .map_err(|_| MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::IntegerOutOfRange))
}
