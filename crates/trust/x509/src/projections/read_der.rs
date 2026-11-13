// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    Asn1Class, AttributeEncoding, EncodedValue, ProjectionError, ProjectionErrorReason,
    MAX_PROJECTION_DER_DEPTH, MAX_PROJECTION_DER_ELEMENTS,
};

pub(super) fn invalid() -> ProjectionError {
    ProjectionErrorReason::InvalidDer.into()
}

pub(super) fn take<'a>(input: &mut &'a [u8]) -> Result<EncodedValue<'a>, ProjectionError> {
    let original = *input;
    let (&first, mut rest) = original.split_first().ok_or_else(invalid)?;
    let class = match first >> 6 {
        0 => Asn1Class::Universal,
        1 => Asn1Class::Application,
        2 => Asn1Class::ContextSpecific,
        _ => Asn1Class::Private,
    };
    let mut tag_number = u32::from(first & 0x1f);
    if tag_number == 0x1f {
        tag_number = 0;
        let mut initial = true;
        loop {
            let (&byte, tail) = rest.split_first().ok_or_else(invalid)?;
            rest = tail;
            if initial && byte & 0x7f == 0 {
                return Err(invalid());
            }
            initial = false;
            tag_number = tag_number
                .checked_mul(128)
                .and_then(|n| n.checked_add(u32::from(byte & 0x7f)))
                .ok_or_else(invalid)?;
            if byte & 0x80 == 0 {
                break;
            }
        }
        if tag_number < 31 {
            return Err(invalid());
        }
    }
    let (&length_byte, tail) = rest.split_first().ok_or_else(invalid)?;
    rest = tail;
    let length = if length_byte & 0x80 == 0 {
        usize::from(length_byte)
    } else {
        let octets = usize::from(length_byte & 0x7f);
        if octets == 0 || octets > core::mem::size_of::<usize>() {
            return Err(invalid());
        }
        let bytes = rest.get(..octets).ok_or_else(invalid)?;
        if bytes.first() == Some(&0) {
            return Err(invalid());
        }
        let mut length = 0usize;
        for byte in bytes {
            length = length
                .checked_mul(256)
                .and_then(|n| n.checked_add(usize::from(*byte)))
                .ok_or_else(invalid)?;
        }
        if length < 128 {
            return Err(invalid());
        }
        rest = rest.get(octets..).ok_or_else(invalid)?;
        length
    };
    let content = rest.get(..length).ok_or_else(invalid)?;
    let remaining = rest.get(length..).ok_or_else(invalid)?;
    let total = original
        .len()
        .checked_sub(remaining.len())
        .ok_or_else(invalid)?;
    let der = original.get(..total).ok_or_else(invalid)?;
    *input = remaining;
    Ok(EncodedValue {
        encoding: AttributeEncoding {
            class,
            tag_number,
            constructed: first & 0x20 != 0,
        },
        der,
        content,
    })
}

pub(super) fn one(input: &[u8]) -> Result<EncodedValue<'_>, ProjectionError> {
    let mut rest = input;
    let value = take(&mut rest)?;
    finish(rest)?;
    Ok(value)
}

pub(super) fn finish(rest: &[u8]) -> Result<(), ProjectionError> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(invalid())
    }
}

pub(super) fn require(
    value: &EncodedValue<'_>,
    class: Asn1Class,
    tag: u32,
    constructed: bool,
) -> Result<(), ProjectionError> {
    if value.encoding
        == (AttributeEncoding {
            class,
            tag_number: tag,
            constructed,
        })
    {
        Ok(())
    } else {
        Err(invalid())
    }
}

pub(super) fn oid(content: &[u8]) -> Result<(), ProjectionError> {
    if content.is_empty() {
        return Err(invalid());
    }
    let mut start = true;
    for byte in content {
        if start && *byte == 0x80 {
            return Err(invalid());
        }
        start = byte & 0x80 == 0;
    }
    if start {
        Ok(())
    } else {
        Err(invalid())
    }
}

pub(super) fn bit_string(content: &[u8]) -> Result<(), ProjectionError> {
    let (&unused, bytes) = content.split_first().ok_or_else(invalid)?;
    if unused > 7 || (bytes.is_empty() && unused != 0) {
        return Err(invalid());
    }
    if let Some(last) = bytes.last() {
        let mask = (1u16 << unused).checked_sub(1).ok_or_else(invalid)?;
        if u16::from(*last) & mask != 0 {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Validate framing before allocating projection collections. Extension OCTET
/// STRING payloads are validated separately according to their selected syntax.
pub(super) fn validate_tree_with_budget(
    input: &[u8],
    elements: &mut usize,
) -> Result<(), ProjectionError> {
    validate_level(input, 0, elements)
}
fn validate_level(
    mut input: &[u8],
    depth: usize,
    elements: &mut usize,
) -> Result<(), ProjectionError> {
    if depth > MAX_PROJECTION_DER_DEPTH {
        return Err(ProjectionErrorReason::DerComplexityLimit.into());
    }
    while !input.is_empty() {
        *elements = elements
            .checked_add(1)
            .ok_or(ProjectionErrorReason::DerComplexityLimit)?;
        if *elements > MAX_PROJECTION_DER_ELEMENTS {
            return Err(ProjectionErrorReason::DerComplexityLimit.into());
        }
        let value = take(&mut input)?;
        if value.encoding.class == Asn1Class::Universal {
            match value.encoding.tag_number {
                0 => return Err(invalid()),
                16 | 17 if !value.encoding.constructed => return Err(invalid()),
                1..=7 | 9 | 10 | 12..=15 | 18..=28 | 30 if value.encoding.constructed => {
                    return Err(invalid())
                }
                1 if value.content != [0] && value.content != [0xff] => return Err(invalid()),
                2 | 10 => {
                    if value.content.is_empty() {
                        return Err(invalid());
                    }
                    if let [first, second, ..] = value.content {
                        if (*first == 0 && second & 0x80 == 0)
                            || (*first == 0xff && second & 0x80 != 0)
                        {
                            return Err(invalid());
                        }
                    }
                }
                3 => bit_string(value.content)?,
                5 if !value.content.is_empty() => return Err(invalid()),
                6 => oid(value.content)?,
                _ => {}
            }
            let _ = super::project_name::validate_string(&value)?;
        }
        if value.encoding.constructed {
            let next = depth
                .checked_add(1)
                .ok_or(ProjectionErrorReason::DerComplexityLimit)?;
            validate_level(value.content, next, elements)?;
            if value.encoding.class == Asn1Class::Universal && value.encoding.tag_number == 17 {
                sorted_set(value.content)?;
            }
        }
    }
    Ok(())
}

pub(super) fn sorted_set(mut content: &[u8]) -> Result<(), ProjectionError> {
    let mut previous: Option<&[u8]> = None;
    while !content.is_empty() {
        let element = take(&mut content)?;
        if previous.is_some_and(|previous| previous > element.der) {
            return Err(invalid());
        }
        previous = Some(element.der);
    }
    Ok(())
}
