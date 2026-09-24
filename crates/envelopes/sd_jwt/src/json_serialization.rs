// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use serde_json::Value;

use crate::compact::{validate_disclosure, validate_disclosure_count};
use crate::{
    serialize_sd_jwt_compact, serialize_sd_jwt_kb_compact, SdJwtCompact, SdJwtEnvelopeError,
    SdJwtWithKbCompact,
};

const PAYLOAD_MEMBER: &str = "payload";
const PROTECTED_MEMBER: &str = "protected";
const SIGNATURE_MEMBER: &str = "signature";
const HEADER_MEMBER: &str = "header";
const DISCLOSURES_MEMBER: &str = "disclosures";
const KB_JWT_MEMBER: &str = "kb_jwt";
const SIGNATURES_MEMBER: &str = "signatures";

/// Maximum bytes accepted for a JWS JSON serialized SD-JWT.
pub const MAX_SD_JWT_JSON_BYTES: usize = 3 * 1024 * 1024;

/// Maximum signatures accepted in the general JWS JSON form.
pub const MAX_SD_JWT_JSON_SIGNATURES: usize = 32;

#[derive(PartialEq, Eq)]
pub enum SdJwtJsonSerialization {
    SdJwt(SdJwtCompact),
    SdJwtWithKb(SdJwtWithKbCompact),
}

impl fmt::Debug for SdJwtJsonSerialization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SdJwtJsonSerialization([REDACTED])")
    }
}

impl SdJwtJsonSerialization {
    pub fn issuer_signed_jwt(&self) -> &str {
        match self {
            SdJwtJsonSerialization::SdJwt(value) => &value.issuer_signed_jwt,
            SdJwtJsonSerialization::SdJwtWithKb(value) => &value.issuer_signed_jwt,
        }
    }

    pub fn disclosures(&self) -> &[String] {
        match self {
            SdJwtJsonSerialization::SdJwt(value) => &value.disclosures,
            SdJwtJsonSerialization::SdJwtWithKb(value) => &value.disclosures,
        }
    }

    pub fn key_binding_jwt(&self) -> Option<&str> {
        match self {
            SdJwtJsonSerialization::SdJwt(_) => None,
            SdJwtJsonSerialization::SdJwtWithKb(value) => Some(&value.key_binding_jwt),
        }
    }

    pub fn to_compact(&self) -> Result<String, SdJwtEnvelopeError> {
        match self {
            SdJwtJsonSerialization::SdJwt(value) => {
                serialize_sd_jwt_compact(&value.issuer_signed_jwt, &value.disclosures)
            }
            SdJwtJsonSerialization::SdJwtWithKb(value) => serialize_sd_jwt_kb_compact(
                &value.issuer_signed_jwt,
                &value.disclosures,
                &value.key_binding_jwt,
            ),
        }
    }
}

#[derive(PartialEq, Eq)]
pub struct SdJwtJsonSerializationSet {
    pub entries: Vec<SdJwtJsonSerialization>,
}

impl fmt::Debug for SdJwtJsonSerializationSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SdJwtJsonSerializationSet([REDACTED])")
    }
}

pub fn parse_sd_jwt_json_serialization(
    input: &str,
) -> Result<SdJwtJsonSerializationSet, SdJwtEnvelopeError> {
    if input.len() > MAX_SD_JWT_JSON_BYTES {
        return Err(SdJwtEnvelopeError::InputTooLarge);
    }
    let value: Value =
        serde_json::from_str(input).map_err(|_| SdJwtEnvelopeError::Serialization)?;
    let object = value
        .as_object()
        .ok_or(SdJwtEnvelopeError::InvalidJsonSerialization)?;

    let payload = object
        .get(PAYLOAD_MEMBER)
        .and_then(Value::as_str)
        .ok_or(SdJwtEnvelopeError::InvalidJsonSerialization)?;
    let payload = clean_compact_string(payload)?;

    if let Some(signatures) = object.get(SIGNATURES_MEMBER) {
        let signatures = signatures
            .as_array()
            .ok_or(SdJwtEnvelopeError::InvalidJsonSerialization)?;
        if signatures.is_empty() {
            return Err(SdJwtEnvelopeError::InvalidJsonSerialization);
        }
        if signatures.len() > MAX_SD_JWT_JSON_SIGNATURES {
            return Err(SdJwtEnvelopeError::TooManySignatures);
        }

        let mut entries = Vec::with_capacity(signatures.len());
        for signature in signatures {
            entries.push(parse_signature_entry(&payload, signature)?);
        }
        return Ok(SdJwtJsonSerializationSet { entries });
    }

    Ok(SdJwtJsonSerializationSet {
        entries: vec![parse_signature_entry(&payload, &value)?],
    })
}

fn parse_signature_entry(
    payload: &str,
    signature_entry: &Value,
) -> Result<SdJwtJsonSerialization, SdJwtEnvelopeError> {
    let object = signature_entry
        .as_object()
        .ok_or(SdJwtEnvelopeError::InvalidJsonSerialization)?;
    let protected = object
        .get(PROTECTED_MEMBER)
        .and_then(Value::as_str)
        .ok_or(SdJwtEnvelopeError::InvalidJsonSerialization)?;
    let signature = object
        .get(SIGNATURE_MEMBER)
        .and_then(Value::as_str)
        .ok_or(SdJwtEnvelopeError::InvalidJsonSerialization)?;
    let protected = clean_compact_string(protected)?;
    let signature = clean_compact_string(signature)?;

    let header = object.get(HEADER_MEMBER);
    let disclosures = parse_disclosures(header)?;
    let issuer_signed_jwt = format!("{protected}.{payload}.{signature}");

    match parse_key_binding_jwt(header)? {
        Some(key_binding_jwt) => Ok(SdJwtJsonSerialization::SdJwtWithKb(SdJwtWithKbCompact {
            issuer_signed_jwt,
            disclosures,
            key_binding_jwt,
        })),
        None => Ok(SdJwtJsonSerialization::SdJwt(SdJwtCompact {
            issuer_signed_jwt,
            disclosures,
        })),
    }
}

fn parse_disclosures(header: Option<&Value>) -> Result<Vec<String>, SdJwtEnvelopeError> {
    let Some(header) = header else {
        return Ok(Vec::new());
    };
    let object = header
        .as_object()
        .ok_or(SdJwtEnvelopeError::InvalidJsonSerialization)?;
    let Some(disclosures) = object.get(DISCLOSURES_MEMBER) else {
        return Ok(Vec::new());
    };
    let disclosures = disclosures
        .as_array()
        .ok_or(SdJwtEnvelopeError::InvalidJsonSerialization)?;
    validate_disclosure_count(disclosures.len())?;

    let mut parsed = Vec::with_capacity(disclosures.len());
    for disclosure in disclosures {
        let disclosure = disclosure
            .as_str()
            .ok_or(SdJwtEnvelopeError::InvalidJsonSerialization)?;
        let disclosure = clean_compact_string(disclosure)?;
        validate_disclosure(&disclosure)?;
        parsed.push(disclosure);
    }

    Ok(parsed)
}

fn parse_key_binding_jwt(header: Option<&Value>) -> Result<Option<String>, SdJwtEnvelopeError> {
    let Some(header) = header else {
        return Ok(None);
    };
    let object = header
        .as_object()
        .ok_or(SdJwtEnvelopeError::InvalidJsonSerialization)?;
    let Some(kb_jwt) = object.get(KB_JWT_MEMBER) else {
        return Ok(None);
    };
    let kb_jwt = kb_jwt
        .as_str()
        .ok_or(SdJwtEnvelopeError::InvalidJsonSerialization)?;
    let kb_jwt = clean_compact_string(kb_jwt)?;
    if kb_jwt.split('.').count() != 3 {
        return Err(SdJwtEnvelopeError::InvalidJsonSerialization);
    }

    Ok(Some(kb_jwt))
}

fn clean_compact_string(value: &str) -> Result<String, SdJwtEnvelopeError> {
    if value.is_empty() || !value.is_ascii() {
        return Err(SdJwtEnvelopeError::InvalidJsonSerialization);
    }

    let cleaned: String = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    if cleaned.is_empty() {
        return Err(SdJwtEnvelopeError::InvalidJsonSerialization);
    }

    Ok(cleaned)
}
