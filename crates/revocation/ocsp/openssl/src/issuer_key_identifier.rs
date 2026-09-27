// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Issuer key identifier derivation used to match OCSP responses to
//! certificates through their authorityKeyIdentifier.

use identity_revocation_ocsp_core::OcspError;

const DER_TAG_SEQUENCE: u8 = 0x30;
const DER_TAG_BIT_STRING: u8 = 0x03;
/// Long-form DER lengths above four octets are never needed for a public key.
const MAX_DER_LENGTH_OCTETS: usize = 4;

/// Extract the subjectPublicKey BIT STRING contents from a DER
/// SubjectPublicKeyInfo: `SEQUENCE { AlgorithmIdentifier, BIT STRING }`.
pub(crate) fn subject_public_key_bits(spki_der: &[u8]) -> Result<&[u8], OcspError> {
    let (spki, trailing) = read_tlv(spki_der, DER_TAG_SEQUENCE)?;
    if !trailing.is_empty() {
        return Err(OcspError::InvalidResponse);
    }
    let (_algorithm, rest) = read_tlv(spki, DER_TAG_SEQUENCE)?;
    let (bit_string, rest) = read_tlv(rest, DER_TAG_BIT_STRING)?;
    if !rest.is_empty() {
        return Err(OcspError::InvalidResponse);
    }
    match bit_string.split_first() {
        Some((0, key_bits)) if !key_bits.is_empty() => Ok(key_bits),
        _ => Err(OcspError::InvalidResponse),
    }
}

/// Read one definite-length DER TLV with the expected tag, returning its
/// contents and the remaining input.
fn read_tlv(input: &[u8], expected_tag: u8) -> Result<(&[u8], &[u8]), OcspError> {
    let (&tag, rest) = input.split_first().ok_or(OcspError::InvalidResponse)?;
    if tag != expected_tag {
        return Err(OcspError::InvalidResponse);
    }
    let (&first_length_octet, rest) = rest.split_first().ok_or(OcspError::InvalidResponse)?;
    let (length, rest) = if first_length_octet & 0x80 == 0 {
        (usize::from(first_length_octet), rest)
    } else {
        let octets = usize::from(first_length_octet & 0x7F);
        if octets == 0 || octets > MAX_DER_LENGTH_OCTETS || octets > rest.len() {
            return Err(OcspError::InvalidResponse);
        }
        let (length_bytes, rest) = rest.split_at(octets);
        let mut length = 0_usize;
        for byte in length_bytes {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or(OcspError::InvalidResponse)?;
        }
        (length, rest)
    };
    if length > rest.len() {
        return Err(OcspError::InvalidResponse);
    }
    Ok(rest.split_at(length))
}

#[cfg(test)]
#[path = "issuer_key_identifier_tests.rs"]
mod tests;
