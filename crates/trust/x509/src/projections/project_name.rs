// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::read_der::{finish, invalid, oid, one, require, sorted_set, take};
use super::{
    Asn1Class, DecodedNameValue, EncodedDistinguishedName, EncodedNameAttribute,
    EncodedRelativeName, EncodedValue, ProjectionError, ProjectionErrorReason,
    MAX_PROJECTION_NAME_ATTRIBUTES,
};
use zeroize::Zeroizing;

#[derive(Default)]
pub(super) struct Budget {
    pub attributes: usize,
    pub general_names: usize,
    pub der_elements: usize,
}

pub(super) fn name<'a>(
    der: &'a [u8],
    budget: &mut Budget,
) -> Result<EncodedDistinguishedName<'a>, ProjectionError> {
    let encoded = one(der)?;
    require(&encoded, Asn1Class::Universal, 16, true)?;
    let mut content = encoded.content;
    let mut rdns = Vec::new();
    while !content.is_empty() {
        let rdn = take(&mut content)?;
        require(&rdn, Asn1Class::Universal, 17, true)?;
        rdns.push(relative_name(rdn, budget)?);
    }
    Ok(EncodedDistinguishedName { encoded, rdns })
}

pub(super) fn relative_name<'a>(
    encoded: EncodedValue<'a>,
    budget: &mut Budget,
) -> Result<EncodedRelativeName<'a>, ProjectionError> {
    if encoded.content.is_empty() {
        return Err(invalid());
    }
    sorted_set(encoded.content)?;
    let mut content = encoded.content;
    let mut attributes = Vec::new();
    while !content.is_empty() {
        budget.attributes = budget
            .attributes
            .checked_add(1)
            .ok_or(ProjectionErrorReason::TooManyNameAttributes)?;
        if budget.attributes > MAX_PROJECTION_NAME_ATTRIBUTES {
            return Err(ProjectionErrorReason::TooManyNameAttributes.into());
        }
        let attribute = take(&mut content)?;
        require(&attribute, Asn1Class::Universal, 16, true)?;
        let mut fields = attribute.content;
        let oid_value = take(&mut fields)?;
        require(&oid_value, Asn1Class::Universal, 6, false)?;
        oid(oid_value.content)?;
        let value = take(&mut fields)?;
        finish(fields)?;
        let decoded = decode_value(&value)?;
        attributes.push(EncodedNameAttribute {
            oid: oid_value,
            value,
            decoded,
        });
    }
    Ok(EncodedRelativeName {
        encoded,
        attributes,
    })
}

/// Validate the declared syntax without allocating decoded identifying text.
pub(super) fn validate_string<'a>(
    value: &EncodedValue<'a>,
) -> Result<Option<&'a str>, ProjectionError> {
    if value.encoding.class != Asn1Class::Universal {
        return Ok(None);
    }
    let tag = value.encoding.tag_number;
    if matches!(tag, 12 | 18..=22 | 26..=28 | 30) && value.encoding.constructed {
        return Err(invalid());
    }
    let bytes = value.content;
    match tag {
        12 | 18 | 19 | 22 | 26 => {
            let text = core::str::from_utf8(bytes).map_err(|_| invalid_string())?;
            let valid = match tag {
                12 => true,
                18 => bytes.iter().all(|b| b.is_ascii_digit() || *b == b' '),
                19 => bytes
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(b)),
                22 => bytes.is_ascii(),
                26 => bytes.iter().all(|b| (0x20..=0x7e).contains(b)),
                _ => false,
            };
            if !valid {
                return Err(invalid_string());
            }
            Ok(Some(text))
        }
        28 | 30 => {
            let width = if tag == 28 { 4 } else { 2 };
            if !bytes.len().is_multiple_of(width) {
                return Err(invalid_string());
            }
            for chunk in bytes.chunks_exact(width) {
                let _ = decode_scalar(chunk)?;
            }
            Ok(None)
        }
        _ => Ok(None),
    }
}

fn invalid_string() -> ProjectionError {
    ProjectionErrorReason::InvalidStringEncoding.into()
}

fn decode_scalar(chunk: &[u8]) -> Result<char, ProjectionError> {
    let mut scalar = 0u32;
    for byte in chunk {
        scalar = scalar
            .checked_mul(256)
            .and_then(|n| n.checked_add(u32::from(*byte)))
            .ok_or_else(invalid_string)?;
    }
    char::from_u32(scalar).ok_or_else(invalid_string)
}

/// Never infer a charset from the bytes. In particular, a UTF-8 byte sequence
/// does not make a PrintableString valid. Legacy Teletex remains uninterpreted.
pub(crate) fn decode_value<'a>(
    value: &EncodedValue<'a>,
) -> Result<DecodedNameValue<'a>, ProjectionError> {
    if let Some(text) = validate_string(value)? {
        return Ok(DecodedNameValue::Text(text));
    }
    let tag = value.encoding.tag_number;
    if value.encoding.class != Asn1Class::Universal || !matches!(tag, 28 | 30) {
        return Ok(DecodedNameValue::Unsupported);
    }
    let bytes = value.content;
    let width = if tag == 28 { 4 } else { 2 };
    // Allocate once: growing a secret-bearing String could leave an old
    // allocation behind before the final owner is zeroized.
    let capacity = if tag == 30 {
        bytes.len().checked_div(2).and_then(|n| n.checked_mul(3))
    } else {
        Some(bytes.len())
    }
    .ok_or_else(invalid_string)?;
    let mut text = Zeroizing::new(String::with_capacity(capacity));
    for chunk in bytes.chunks_exact(width) {
        text.push(decode_scalar(chunk)?);
    }
    Ok(DecodedNameValue::Unicode(super::ProtectedNameText(text)))
}
