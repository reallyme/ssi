// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_codec::jcs::canonicalize_json_text;
use serde_json::Value;
use zeroize::Zeroizing;

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

/// SD-JWT JSON entry with or without holder key binding.
#[derive(PartialEq, Eq)]
#[non_exhaustive]
pub enum SdJwtJsonSerialization {
    /// SD-JWT without a holder key-binding JWT.
    SdJwt(SdJwtCompact),
    /// SD-JWT followed by a holder key-binding JWT.
    SdJwtWithKb(SdJwtWithKbCompact),
}

impl fmt::Debug for SdJwtJsonSerialization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SdJwtJsonSerialization([REDACTED])")
    }
}

impl SdJwtJsonSerialization {
    /// Issuer signed JWT after validating all caller-supplied inputs.
    pub fn issuer_signed_jwt(&self) -> &str {
        match self {
            SdJwtJsonSerialization::SdJwt(value) => &value.issuer_signed_jwt,
            SdJwtJsonSerialization::SdJwtWithKb(value) => &value.issuer_signed_jwt,
        }
    }

    /// Returns the disclosures in their authenticated serialization order.
    pub fn disclosures(&self) -> &[String] {
        match self {
            SdJwtJsonSerialization::SdJwt(value) => &value.disclosures,
            SdJwtJsonSerialization::SdJwtWithKb(value) => &value.disclosures,
        }
    }

    /// Returns the optional compact holder key-binding JWT.
    pub fn key_binding_jwt(&self) -> Option<&str> {
        match self {
            SdJwtJsonSerialization::SdJwt(_) => None,
            SdJwtJsonSerialization::SdJwtWithKb(value) => Some(&value.key_binding_jwt),
        }
    }

    /// Serializes this value in the canonical compact form.
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

/// Bounded collection decoded from an SD-JWT JSON serialization.
#[derive(PartialEq, Eq)]
pub struct SdJwtJsonSerializationSet {
    /// Validated SD-JWT entries decoded from the JSON serialization.
    pub entries: Vec<SdJwtJsonSerialization>,
}

impl fmt::Debug for SdJwtJsonSerializationSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SdJwtJsonSerializationSet([REDACTED])")
    }
}

/// Parses a bounded SD-JWT JWS JSON serialization.
pub fn parse_sd_jwt_json_serialization(
    input: &str,
) -> Result<SdJwtJsonSerializationSet, SdJwtEnvelopeError> {
    if input.len() > MAX_SD_JWT_JSON_BYTES {
        return Err(SdJwtEnvelopeError::InputTooLarge);
    }
    // RFC 8259 leaves duplicate member handling implementation-defined and
    // `serde_json::Value` keeps the last one. Canonicalizing first rejects
    // duplicates so two parsers can never disagree on which member was signed.
    let canonical = Zeroizing::new(
        canonicalize_json_text(input).map_err(|_| SdJwtEnvelopeError::InvalidJsonSerialization)?,
    );
    let value: Value =
        serde_json::from_str(&canonical).map_err(|_| SdJwtEnvelopeError::Serialization)?;
    let object = value
        .as_object()
        .ok_or(SdJwtEnvelopeError::InvalidJsonSerialization)?;
    let general = object.contains_key(SIGNATURES_MEMBER);
    let allowed_root = if general {
        [PAYLOAD_MEMBER, SIGNATURES_MEMBER].as_slice()
    } else {
        [
            PAYLOAD_MEMBER,
            PROTECTED_MEMBER,
            SIGNATURE_MEMBER,
            HEADER_MEMBER,
        ]
        .as_slice()
    };
    if object
        .keys()
        .any(|key| !allowed_root.contains(&key.as_str()))
    {
        return Err(SdJwtEnvelopeError::InvalidJsonSerialization);
    }

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
        for (index, signature) in signatures.iter().enumerate() {
            entries.push(parse_signature_entry(&payload, signature, index == 0)?);
        }
        return Ok(SdJwtJsonSerializationSet { entries });
    }

    Ok(SdJwtJsonSerializationSet {
        entries: vec![parse_signature_entry(&payload, &value, true)?],
    })
}

fn parse_signature_entry(
    payload: &str,
    signature_entry: &Value,
    allow_sd_header: bool,
) -> Result<SdJwtJsonSerialization, SdJwtEnvelopeError> {
    let object = signature_entry
        .as_object()
        .ok_or(SdJwtEnvelopeError::InvalidJsonSerialization)?;
    if object.keys().any(|key| {
        ![
            PAYLOAD_MEMBER,
            PROTECTED_MEMBER,
            SIGNATURE_MEMBER,
            HEADER_MEMBER,
        ]
        .contains(&key.as_str())
    }) {
        return Err(SdJwtEnvelopeError::InvalidJsonSerialization);
    }
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
    validate_unprotected_header(header, allow_sd_header)?;
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

fn validate_unprotected_header(
    header: Option<&Value>,
    allow_sd_header: bool,
) -> Result<(), SdJwtEnvelopeError> {
    let Some(header) = header else {
        return Ok(());
    };
    let object = header
        .as_object()
        .ok_or(SdJwtEnvelopeError::InvalidJsonSerialization)?;
    // JWS permits application-defined unprotected parameters such as `kid`.
    // Only the two SD-JWT serialization parameters are position-sensitive:
    // RFC 9901 carries them on the first signature entry so they cannot be
    // repeated with conflicting values on sibling signatures.
    if !allow_sd_header
        && object
            .keys()
            .any(|key| [DISCLOSURES_MEMBER, KB_JWT_MEMBER].contains(&key.as_str()))
    {
        return Err(SdJwtEnvelopeError::InvalidJsonSerialization);
    }
    Ok(())
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
    // JWS JSON members carry base64url text only. Whitespace is not part of
    // that alphabet, and silently stripping it would let distinct inputs
    // collapse onto the same signed or hashed value.
    if value.is_empty() || !value.is_ascii() || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(SdJwtEnvelopeError::InvalidJsonSerialization);
    }

    Ok(value.to_owned())
}
