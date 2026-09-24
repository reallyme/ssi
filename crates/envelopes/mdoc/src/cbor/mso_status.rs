// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{cbor_bytes_to_value, cbor_value_to_bytes, expect_map, integer_to_u64};
use crate::{
    MdocEnvelopeError, MdocIdentifierList, MdocInvalidInputReason, MdocStatus, MdocStatusExtension,
    MdocStatusList,
};
use ciborium::value::Value;

const STATUS_LIST: &str = "status_list";
const IDENTIFIER_LIST: &str = "identifier_list";
const STATUS_LIST_MEMBERS: [&str; 3] = ["idx", "uri", "certificate"];
const IDENTIFIER_LIST_MEMBERS: [&str; 3] = ["id", "uri", "certificate"];

pub(super) fn status_to_cbor(status: &MdocStatus) -> Result<Value, MdocEnvelopeError> {
    status.validate()?;
    let mut status_entries = Vec::new();
    if let Some(status) = status.status_list_ref() {
        let mut entries = vec![
            (
                Value::Text("idx".to_owned()),
                Value::Integer(status.index().into()),
            ),
            (
                Value::Text("uri".to_owned()),
                Value::Text(status.uri().to_owned()),
            ),
        ];
        append_certificate(&mut entries, status.certificate_der());
        append_extensions(&mut entries, status.extensions())?;
        status_entries.push((Value::Text(STATUS_LIST.to_owned()), Value::Map(entries)));
    }
    if let Some(status) = status.identifier_list_ref() {
        let mut entries = vec![
            (
                Value::Text("id".to_owned()),
                Value::Bytes(status.identifier().to_vec()),
            ),
            (
                Value::Text("uri".to_owned()),
                Value::Text(status.uri().to_owned()),
            ),
        ];
        append_certificate(&mut entries, status.certificate_der());
        append_extensions(&mut entries, status.extensions())?;
        status_entries.push((Value::Text(IDENTIFIER_LIST.to_owned()), Value::Map(entries)));
    }
    append_extensions(&mut status_entries, status.extensions())?;
    Ok(Value::Map(status_entries))
}

fn append_extensions(
    entries: &mut Vec<(Value, Value)>,
    extensions: &[MdocStatusExtension],
) -> Result<(), MdocEnvelopeError> {
    for extension in extensions {
        let value = cbor_bytes_to_value(extension.value_cbor())?;
        entries.push((
            Value::Text(extension.name().to_owned()),
            value.as_value().clone(),
        ));
    }
    Ok(())
}

fn extension_from_value(
    name: &str,
    value: &Value,
) -> Result<MdocStatusExtension, MdocEnvelopeError> {
    MdocStatusExtension::new(name.to_owned(), cbor_value_to_bytes(value)?)
}

fn collect_extensions(
    entries: &[(Value, Value)],
    known: &[&str],
) -> Result<Vec<MdocStatusExtension>, MdocEnvelopeError> {
    let mut extensions = Vec::new();
    for (key, value) in entries {
        let Value::Text(key) = key else {
            return Err(invalid(MdocInvalidInputReason::UnknownMsoStatusMember));
        };
        if !known.contains(&key.as_str()) {
            if extensions
                .iter()
                .any(|existing: &MdocStatusExtension| existing.name() == key)
            {
                return Err(invalid(MdocInvalidInputReason::DuplicateMsoStatusMember));
            }
            extensions.push(extension_from_value(key, value)?);
        }
    }
    Ok(extensions)
}

pub(super) fn status_from_cbor(value: &Value) -> Result<MdocStatus, MdocEnvelopeError> {
    let entries = expect_map(value, MdocInvalidInputReason::MalformedMsoStatus)?;
    if entries.is_empty() {
        return Err(invalid(MdocInvalidInputReason::UnknownMsoStatusMechanism));
    }

    let mut seen_members = Vec::with_capacity(entries.len());
    for (key, _) in entries {
        let Value::Text(key) = key else {
            return Err(invalid(MdocInvalidInputReason::UnknownMsoStatusMechanism));
        };
        if seen_members.iter().any(|existing| *existing == key) {
            return Err(invalid(MdocInvalidInputReason::DuplicateMsoStatusMember));
        }
        seen_members.push(key.as_str());
    }

    let mut status_list = None;
    let mut identifier_list = None;
    let mut extensions = Vec::new();
    for (key, value) in entries {
        let Value::Text(key) = key else {
            return Err(invalid(MdocInvalidInputReason::UnknownMsoStatusMechanism));
        };
        match key.as_str() {
            STATUS_LIST => {
                status_list = Some(parse_status_list(value)?);
            }
            IDENTIFIER_LIST => {
                identifier_list = Some(parse_identifier_list(value)?);
            }
            _ => {
                extensions.push(extension_from_value(key, value)?);
            }
        }
    }
    MdocStatus::from_parts(status_list, identifier_list, extensions)
}

fn parse_status_list(value: &Value) -> Result<MdocStatusList, MdocEnvelopeError> {
    let entries = expect_map(value, MdocInvalidInputReason::MalformedMsoStatus)?;
    let index = match unique_member(entries, "idx")? {
        Some(Value::Integer(index)) => {
            let index = integer_to_u64(index)
                .map_err(|_| invalid(MdocInvalidInputReason::InvalidMsoStatusListIndex))?;
            if i64::try_from(index).is_err() {
                return Err(invalid(MdocInvalidInputReason::InvalidMsoStatusListIndex));
            }
            index
        }
        _ => return Err(invalid(MdocInvalidInputReason::InvalidMsoStatusListIndex)),
    };
    let uri = parse_uri(entries)?;
    let certificate = parse_certificate(entries)?;
    let extensions = collect_extensions(entries, &STATUS_LIST_MEMBERS)?;
    MdocStatusList::new_with_extensions(index, uri, certificate, extensions)
}

fn parse_identifier_list(value: &Value) -> Result<MdocIdentifierList, MdocEnvelopeError> {
    let entries = expect_map(value, MdocInvalidInputReason::MalformedMsoStatus)?;
    let identifier = match unique_member(entries, "id")? {
        Some(Value::Bytes(identifier)) => identifier.clone(),
        _ => return Err(invalid(MdocInvalidInputReason::InvalidMsoStatusIdentifier)),
    };
    let uri = parse_uri(entries)?;
    let certificate = parse_certificate(entries)?;
    let extensions = collect_extensions(entries, &IDENTIFIER_LIST_MEMBERS)?;
    MdocIdentifierList::new_with_extensions(identifier, uri, certificate, extensions)
}

fn parse_uri(entries: &[(Value, Value)]) -> Result<String, MdocEnvelopeError> {
    match unique_member(entries, "uri")? {
        Some(Value::Text(uri)) => Ok(uri.clone()),
        _ => Err(invalid(MdocInvalidInputReason::InvalidMsoStatusUri)),
    }
}

fn parse_certificate(entries: &[(Value, Value)]) -> Result<Option<Vec<u8>>, MdocEnvelopeError> {
    match unique_member(entries, "certificate")? {
        Some(Value::Bytes(certificate)) => Ok(Some(certificate.clone())),
        Some(_) => Err(invalid(MdocInvalidInputReason::InvalidMsoStatusCertificate)),
        None => Ok(None),
    }
}

fn unique_member<'a>(
    entries: &'a [(Value, Value)],
    name: &str,
) -> Result<Option<&'a Value>, MdocEnvelopeError> {
    let mut matching = entries.iter().filter_map(|(key, value)| match key {
        Value::Text(key) if key == name => Some(value),
        _ => None,
    });
    let first = matching.next();
    if matching.next().is_some() {
        return Err(invalid(MdocInvalidInputReason::DuplicateMsoStatusMember));
    }
    Ok(first)
}

fn append_certificate(entries: &mut Vec<(Value, Value)>, certificate: Option<&[u8]>) {
    if let Some(certificate) = certificate {
        entries.push((
            Value::Text("certificate".to_owned()),
            Value::Bytes(certificate.to_vec()),
        ));
    }
}

const fn invalid(reason: MdocInvalidInputReason) -> MdocEnvelopeError {
    MdocEnvelopeError::InvalidInput(reason)
}
