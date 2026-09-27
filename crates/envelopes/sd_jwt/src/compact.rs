// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::sensitive::zeroize_strings;
use crate::SdJwtEnvelopeError;

const JWT_COMPACT_PARTS: usize = 3;

/// Maximum disclosure entries accepted in one SD-JWT presentation.
pub const MAX_SD_JWT_DISCLOSURES: usize = 256;

/// Maximum encoded bytes accepted for one SD-JWT disclosure.
pub const MAX_SD_JWT_DISCLOSURE_BYTES: usize = 4096;

/// Maximum bytes accepted for one complete compact SD-JWT presentation.
pub const MAX_SD_JWT_COMPACT_BYTES: usize = 2 * 1024 * 1024;

const MAX_SD_JWT_COMPACT_PARTS: usize = MAX_SD_JWT_DISCLOSURES + 2;

/// Parsed SD-JWT compact serialization without a holder key-binding JWT.
#[derive(PartialEq, Eq)]
pub struct SdJwtCompact {
    /// Compact issuer-signed JWT whose signature authenticates the SD-JWT payload.
    pub issuer_signed_jwt: String,
    /// Encoded disclosures carried by this SD-JWT value.
    pub disclosures: Vec<String>,
}

impl fmt::Debug for SdJwtCompact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SdJwtCompact([REDACTED])")
    }
}

impl Zeroize for SdJwtCompact {
    fn zeroize(&mut self) {
        self.issuer_signed_jwt.zeroize();
        zeroize_strings(&mut self.disclosures);
    }
}

impl Drop for SdJwtCompact {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SdJwtCompact {}

/// Parsed SD-JWT compact serialization that includes a holder key-binding JWT.
#[derive(PartialEq, Eq)]
pub struct SdJwtWithKbCompact {
    /// Compact issuer-signed JWT whose signature authenticates the SD-JWT payload.
    pub issuer_signed_jwt: String,
    /// Encoded disclosures carried by this SD-JWT value.
    pub disclosures: Vec<String>,
    /// Compact key-binding JWT that binds the presentation to its audience and nonce.
    pub key_binding_jwt: String,
}

impl fmt::Debug for SdJwtWithKbCompact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SdJwtWithKbCompact([REDACTED])")
    }
}

impl Zeroize for SdJwtWithKbCompact {
    fn zeroize(&mut self) {
        self.issuer_signed_jwt.zeroize();
        zeroize_strings(&mut self.disclosures);
        self.key_binding_jwt.zeroize();
    }
}

impl Drop for SdJwtWithKbCompact {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SdJwtWithKbCompact {}

/// Parsed compact SD-JWT with or without holder key binding.
#[derive(PartialEq, Eq)]
#[non_exhaustive]
pub enum SdJwtOrKbCompact {
    /// SD-JWT without a holder key-binding JWT.
    SdJwt(SdJwtCompact),
    /// SD-JWT followed by a holder key-binding JWT.
    SdJwtWithKb(SdJwtWithKbCompact),
}

impl fmt::Debug for SdJwtOrKbCompact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SdJwtOrKbCompact([REDACTED])")
    }
}

/// Parses a bounded compact SD-JWT without holder key binding.
pub fn parse_sd_jwt_compact(input: &str) -> Result<SdJwtCompact, SdJwtEnvelopeError> {
    validate_compact_input(input)?;
    let parts: Vec<&str> = input.split('~').collect();
    let last = parts
        .last()
        .ok_or(SdJwtEnvelopeError::InvalidCompactSerialization)?;
    if !last.is_empty() {
        return Err(SdJwtEnvelopeError::InvalidCompactSerialization);
    }

    let body = parts
        .get(..parts.len().saturating_sub(1))
        .ok_or(SdJwtEnvelopeError::InvalidCompactSerialization)?;
    parse_sd_jwt_parts(body)
}

/// Parses a bounded compact SD-JWT with optional holder key binding.
pub fn parse_sd_jwt_or_kb_compact(input: &str) -> Result<SdJwtOrKbCompact, SdJwtEnvelopeError> {
    validate_compact_input(input)?;
    let parts: Vec<&str> = input.split('~').collect();
    let last = parts
        .last()
        .ok_or(SdJwtEnvelopeError::InvalidCompactSerialization)?;

    if last.is_empty() {
        return parse_sd_jwt_compact(input).map(SdJwtOrKbCompact::SdJwt);
    }

    validate_jwt_compact(last, SdJwtEnvelopeError::InvalidKeyBindingJwt)?;
    let body = parts
        .get(..parts.len().saturating_sub(1))
        .ok_or(SdJwtEnvelopeError::InvalidCompactSerialization)?;
    let mut sd_jwt = parse_sd_jwt_parts(body)?;
    Ok(SdJwtOrKbCompact::SdJwtWithKb(SdJwtWithKbCompact {
        issuer_signed_jwt: core::mem::take(&mut sd_jwt.issuer_signed_jwt),
        disclosures: core::mem::take(&mut sd_jwt.disclosures),
        key_binding_jwt: (*last).to_owned(),
    }))
}

/// Serializes an issuer JWT and disclosures in compact SD-JWT form.
pub fn serialize_sd_jwt_compact(
    issuer_signed_jwt: &str,
    disclosures: &[String],
) -> Result<String, SdJwtEnvelopeError> {
    validate_jwt_compact(issuer_signed_jwt, SdJwtEnvelopeError::InvalidIssuerJwt)?;
    validate_disclosures(disclosures)?;

    let mut output_bytes = issuer_signed_jwt
        .len()
        .checked_add(1)
        .ok_or(SdJwtEnvelopeError::InputTooLarge)?;
    for disclosure in disclosures {
        output_bytes = output_bytes
            .checked_add(disclosure.len())
            .and_then(|value| value.checked_add(1))
            .ok_or(SdJwtEnvelopeError::InputTooLarge)?;
    }
    if output_bytes > MAX_SD_JWT_COMPACT_BYTES {
        return Err(SdJwtEnvelopeError::InputTooLarge);
    }

    let mut output = String::with_capacity(output_bytes);
    output.push_str(issuer_signed_jwt);
    output.push('~');
    for disclosure in disclosures {
        output.push_str(disclosure);
        output.push('~');
    }
    Ok(output)
}

/// Serializes an issuer JWT, disclosures, and key-binding JWT in compact form.
pub fn serialize_sd_jwt_kb_compact(
    issuer_signed_jwt: &str,
    disclosures: &[String],
    key_binding_jwt: &str,
) -> Result<String, SdJwtEnvelopeError> {
    let mut output = serialize_sd_jwt_compact(issuer_signed_jwt, disclosures)?;
    validate_jwt_compact(key_binding_jwt, SdJwtEnvelopeError::InvalidKeyBindingJwt)?;
    let output_bytes = output
        .len()
        .checked_add(key_binding_jwt.len())
        .ok_or(SdJwtEnvelopeError::InputTooLarge)?;
    if output_bytes > MAX_SD_JWT_COMPACT_BYTES {
        return Err(SdJwtEnvelopeError::InputTooLarge);
    }
    output.push_str(key_binding_jwt);
    Ok(output)
}

fn parse_sd_jwt_parts(parts: &[&str]) -> Result<SdJwtCompact, SdJwtEnvelopeError> {
    let issuer_signed_jwt = parts
        .first()
        .ok_or(SdJwtEnvelopeError::InvalidCompactSerialization)?;
    validate_jwt_compact(issuer_signed_jwt, SdJwtEnvelopeError::InvalidIssuerJwt)?;

    let mut disclosures = Vec::new();
    let disclosures_slice = parts
        .get(1..)
        .ok_or(SdJwtEnvelopeError::InvalidCompactSerialization)?;
    for disclosure in disclosures_slice {
        validate_disclosure(disclosure)?;
        disclosures.push((*disclosure).to_owned());
    }
    validate_disclosure_count(disclosures.len())?;

    Ok(SdJwtCompact {
        issuer_signed_jwt: (*issuer_signed_jwt).to_owned(),
        disclosures,
    })
}

pub(crate) fn validate_disclosures(disclosures: &[String]) -> Result<(), SdJwtEnvelopeError> {
    validate_disclosure_count(disclosures.len())?;
    for disclosure in disclosures {
        validate_disclosure(disclosure)?;
    }

    Ok(())
}

pub(crate) fn validate_disclosure_count(count: usize) -> Result<(), SdJwtEnvelopeError> {
    if count > MAX_SD_JWT_DISCLOSURES {
        return Err(SdJwtEnvelopeError::TooManyDisclosures);
    }

    Ok(())
}

pub(crate) fn validate_disclosure(disclosure: &str) -> Result<(), SdJwtEnvelopeError> {
    if disclosure.is_empty() || !disclosure.is_ascii() {
        return Err(SdJwtEnvelopeError::InvalidDisclosureEncoding);
    }

    if disclosure.len() > MAX_SD_JWT_DISCLOSURE_BYTES {
        return Err(SdJwtEnvelopeError::DisclosureTooLarge);
    }

    Ok(())
}

fn validate_jwt_compact(input: &str, error: SdJwtEnvelopeError) -> Result<(), SdJwtEnvelopeError> {
    if input.is_empty() || !input.is_ascii() || input.split('.').count() != JWT_COMPACT_PARTS {
        return Err(error);
    }

    Ok(())
}

fn validate_compact_input(input: &str) -> Result<(), SdJwtEnvelopeError> {
    if input.len() > MAX_SD_JWT_COMPACT_BYTES {
        return Err(SdJwtEnvelopeError::InputTooLarge);
    }
    if input.split('~').count() > MAX_SD_JWT_COMPACT_PARTS {
        return Err(SdJwtEnvelopeError::TooManyDisclosures);
    }
    Ok(())
}
