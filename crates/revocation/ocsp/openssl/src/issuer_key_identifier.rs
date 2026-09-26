// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Issuer key identifier derivation used to match OCSP responses to
//! certificates through their authorityKeyIdentifier.

use identity_revocation_ocsp_core::OcspError;
use openssl::sha::sha1;
use openssl::x509::X509;

const DER_TAG_SEQUENCE: u8 = 0x30;
const DER_TAG_BIT_STRING: u8 = 0x03;
/// Long-form DER lengths above four octets are never needed for a public key.
const MAX_DER_LENGTH_OCTETS: usize = 4;

/// Return the issuer's key identifier.
///
/// The subjectKeyIdentifier extension is preferred. Without it, the
/// identifier is derived with RFC 5280 Section 4.2.1.2 method (1): the SHA-1
/// hash of the value of the subjectPublicKey BIT STRING (excluding the tag,
/// length, and unused-bits octet), which is also the construction used by
/// RFC 6960 `issuerKeyHash`.
pub(crate) fn issuer_key_identifier(issuer: &X509) -> Result<Vec<u8>, OcspError> {
    if let Some(ski) = issuer.subject_key_id() {
        return Ok(ski.as_slice().to_vec());
    }

    let spki_der = issuer
        .public_key()
        .and_then(|key| key.public_key_to_der())
        .map_err(|_| OcspError::InvalidResponse)?;
    let subject_public_key = subject_public_key_bits(&spki_der)?;
    Ok(sha1(subject_public_key).to_vec())
}

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
