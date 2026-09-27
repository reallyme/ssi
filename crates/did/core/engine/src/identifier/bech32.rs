// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{DidMeError, DidMeErrorReason, IDENTIFIER_PAYLOAD_LEN};

const BECH32_CHECKSUM_LEN: usize = 6;
/// BIP-173 maximum applied to the method-specific identifier.
const MAX_BECH32_LEN: usize = 90;
const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GENERATOR: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

pub(super) fn decode_bech32_payload(
    encoded: &str,
    expected_hrp: &str,
) -> Result<[u8; IDENTIFIER_PAYLOAD_LEN], DidMeError> {
    if encoded.len() > MAX_BECH32_LEN {
        return Err(DidMeError::new(DidMeErrorReason::IdentifierTooLong));
    }
    let separator = encoded
        .rfind('1')
        .ok_or(DidMeError::new(DidMeErrorReason::InvalidHrp))?;
    let (hrp, data_with_separator) = encoded.split_at(separator);
    if hrp != expected_hrp {
        return Err(DidMeError::new(DidMeErrorReason::InvalidHrp));
    }
    let data_part = data_with_separator
        .strip_prefix('1')
        .ok_or(DidMeError::new(DidMeErrorReason::InvalidData))?;
    if data_part.len() <= BECH32_CHECKSUM_LEN {
        return Err(DidMeError::new(DidMeErrorReason::InvalidData));
    }
    let values = bech32_values(data_part.as_bytes())?;
    if !verify_checksum(hrp, &values)? {
        return Err(DidMeError::new(DidMeErrorReason::InvalidChecksum));
    }
    let payload_values_len = values
        .len()
        .checked_sub(BECH32_CHECKSUM_LEN)
        .ok_or(DidMeError::new(DidMeErrorReason::InvalidData))?;
    let payload_values = values
        .get(..payload_values_len)
        .ok_or(DidMeError::new(DidMeErrorReason::InvalidData))?;
    let payload = convert_bits_5_to_8(payload_values)?;
    <[u8; IDENTIFIER_PAYLOAD_LEN]>::try_from(payload.as_slice())
        .map_err(|_| DidMeError::new(DidMeErrorReason::InvalidPayloadLength))
}

pub(super) fn bech32_encode(
    hrp: &str,
    payload: &[u8; IDENTIFIER_PAYLOAD_LEN],
) -> Result<String, DidMeError> {
    if hrp.is_empty()
        || !hrp
            .bytes()
            .all(|byte| (33..=126).contains(&byte) && !byte.is_ascii_uppercase())
    {
        return Err(DidMeError::new(DidMeErrorReason::InvalidHrp));
    }
    let mut data = convert_bits_8_to_5(payload)?;
    let checksum = create_checksum(hrp, &data)?;
    data.extend_from_slice(&checksum);
    let output_len = hrp
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(data.len()))
        .ok_or(DidMeError::new(DidMeErrorReason::IdentifierTooLong))?;
    let mut out = String::with_capacity(output_len);
    out.push_str(hrp);
    out.push('1');
    for value in data {
        let character = BECH32_CHARSET
            .get(usize::from(value))
            .ok_or(DidMeError::new(DidMeErrorReason::InvalidCharacter))?;
        out.push(char::from(*character));
    }
    Ok(out)
}

fn bech32_values(data: &[u8]) -> Result<Vec<u8>, DidMeError> {
    let mut out = Vec::with_capacity(data.len());
    for byte in data {
        out.push(bech32_value(*byte).ok_or(DidMeError::new(DidMeErrorReason::InvalidCharacter))?);
    }
    Ok(out)
}

fn convert_bits_8_to_5(payload: &[u8; IDENTIFIER_PAYLOAD_LEN]) -> Result<Vec<u8>, DidMeError> {
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    let mut output = Vec::with_capacity(26);
    for value in payload {
        accumulator = (accumulator << 8) | u32::from(*value);
        bits = bits
            .checked_add(8)
            .ok_or(DidMeError::new(DidMeErrorReason::InvalidData))?;
        while bits >= 5 {
            bits = bits
                .checked_sub(5)
                .ok_or(DidMeError::new(DidMeErrorReason::InvalidData))?;
            output.push(((accumulator >> bits) & 0x1f) as u8);
        }
    }
    if bits > 0 {
        let shift = 5_u8
            .checked_sub(bits)
            .ok_or(DidMeError::new(DidMeErrorReason::InvalidData))?;
        output.push(((accumulator << shift) & 0x1f) as u8);
    }
    Ok(output)
}

fn convert_bits_5_to_8(values: &[u8]) -> Result<Vec<u8>, DidMeError> {
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    let mut output = Vec::with_capacity(IDENTIFIER_PAYLOAD_LEN);
    for value in values {
        if *value > 31 {
            return Err(DidMeError::new(DidMeErrorReason::InvalidData));
        }
        accumulator = (accumulator << 5) | u32::from(*value);
        bits = bits
            .checked_add(5)
            .ok_or(DidMeError::new(DidMeErrorReason::InvalidData))?;
        while bits >= 8 {
            bits = bits
                .checked_sub(8)
                .ok_or(DidMeError::new(DidMeErrorReason::InvalidData))?;
            output.push(
                u8::try_from((accumulator >> bits) & 0xff)
                    .map_err(|_| DidMeError::new(DidMeErrorReason::InvalidData))?,
            );
        }
    }
    // With padding disabled, BIP-173 requires fewer than one source group of
    // leftover bits and requires every leftover bit to be zero. Merely checking
    // for zero accepted an extra zero 5-bit group as a second encoding of the
    // same fixed-width did:me payload.
    let padding_shift = 8_u8
        .checked_sub(bits)
        .ok_or(DidMeError::new(DidMeErrorReason::InvalidData))?;
    if bits >= 5 || (bits > 0 && ((accumulator << padding_shift) & 0xff) != 0) {
        return Err(DidMeError::new(DidMeErrorReason::InvalidData));
    }
    Ok(output)
}

fn bech32_value(byte: u8) -> Option<u8> {
    let mut index = 0_u8;
    for candidate in BECH32_CHARSET {
        if *candidate == byte {
            return Some(index);
        }
        index = index.checked_add(1)?;
    }
    None
}

fn verify_checksum(hrp: &str, values: &[u8]) -> Result<bool, DidMeError> {
    let mut expanded = hrp_expand(hrp)?;
    expanded.extend_from_slice(values);
    Ok(polymod(&expanded) == 1)
}

fn create_checksum(hrp: &str, data: &[u8]) -> Result<[u8; BECH32_CHECKSUM_LEN], DidMeError> {
    let mut values = hrp_expand(hrp)?;
    values.extend_from_slice(data);
    values.extend_from_slice(&[0_u8; BECH32_CHECKSUM_LEN]);
    let checksum = polymod(&values) ^ 1;
    Ok([
        ((checksum >> 25) & 0x1f) as u8,
        ((checksum >> 20) & 0x1f) as u8,
        ((checksum >> 15) & 0x1f) as u8,
        ((checksum >> 10) & 0x1f) as u8,
        ((checksum >> 5) & 0x1f) as u8,
        (checksum & 0x1f) as u8,
    ])
}

fn hrp_expand(hrp: &str) -> Result<Vec<u8>, DidMeError> {
    let capacity = hrp
        .len()
        .checked_mul(2)
        .and_then(|length| length.checked_add(1))
        .ok_or(DidMeError::new(DidMeErrorReason::IdentifierTooLong))?;
    let mut output = Vec::with_capacity(capacity);
    output.extend(hrp.bytes().map(|byte| byte >> 5));
    output.push(0);
    output.extend(hrp.bytes().map(|byte| byte & 0x1f));
    Ok(output)
}

fn polymod(values: &[u8]) -> u32 {
    let mut checksum = 1_u32;
    for value in values {
        let top = checksum >> 25;
        checksum = ((checksum & 0x1ff_ffff) << 5) ^ u32::from(*value);
        for (index, generator) in BECH32_GENERATOR.iter().enumerate() {
            if ((top >> index) & 1) == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

#[cfg(test)]
#[path = "bech32_tests.rs"]
mod tests;
