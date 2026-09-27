// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict, bounded selection of one OCSP `SingleResponse` for a certificate.

use envelopes_x509::parse_cert_der;
use identity_revocation_ocsp_core::{OcspError, MAX_OCSP_NONCE_BYTES};
use openssl::hash::{hash, MessageDigest};

use crate::issuer_key_identifier::subject_public_key_bits;

const MAX_DER_LENGTH_OCTETS: usize = 4;
const OID_BASIC_OCSP_RESPONSE: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
const OID_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_OCSP_NONCE: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];
const OID_MD5_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04];
const OID_SHA1_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
const OID_ECDSA_WITH_SHA1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01];
const OID_DSA_WITH_SHA1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x03];
const OID_OIW_SHA1_WITH_RSA: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1d];
const MAX_OCSP_EXTENSIONS: usize = 64;

/// Digest algorithm of the unique matching `SingleResponse`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MatchingDigest {
    Sha1,
    Sha256,
}

struct ExpectedCertId {
    sha1_name: Vec<u8>,
    sha1_key: Vec<u8>,
    sha256_name: Vec<u8>,
    sha256_key: Vec<u8>,
    serial: Vec<u8>,
}

/// Require exactly one logical `SingleResponse` for `cert` and return its
/// digest algorithm. Duplicate entries, including one SHA-1 and one SHA-256
/// entry for the same certificate, are rejected as ambiguous.
pub(crate) fn unique_matching_digest(
    response_der: &[u8],
    cert_der: &[u8],
    issuer_der: &[u8],
) -> Result<MatchingDigest, OcspError> {
    let expected = expected_cert_id(cert_der, issuer_der)?;
    let fields = response_data_fields(response_der)?;
    unique_matching_digest_in_responses(fields.responses, &expected)
}

/// Validate the response signature digest floor and return signed `producedAt`.
pub(crate) fn validated_response_produced_at(response_der: &[u8]) -> Result<&[u8], OcspError> {
    let fields = response_data_fields(response_der)?;
    if matches!(
        fields.signature_algorithm_oid,
        OID_MD5_WITH_RSA
            | OID_SHA1_WITH_RSA
            | OID_ECDSA_WITH_SHA1
            | OID_DSA_WITH_SHA1
            | OID_OIW_SHA1_WITH_RSA
    ) {
        return Err(OcspError::InvalidResponse);
    }
    Ok(fields.produced_at)
}

/// Return the exact DER encodings of responder certificates embedded in a
/// BasicOCSPResponse. These certificates are authenticated by the response
/// signature but still require responder-policy screening before OpenSSL may
/// use them for path construction.
pub(crate) fn embedded_responder_certificates(
    response_der: &[u8],
) -> Result<Vec<&[u8]>, OcspError> {
    let fields = response_data_fields(response_der)?;
    let Some(mut certificates) = fields.certificates else {
        return Ok(Vec::new());
    };
    let mut result = Vec::new();
    while !certificates.is_empty() {
        if result.len() >= 16 {
            return Err(OcspError::InvalidResponse);
        }
        let before = certificates;
        let (_, remaining) = read_tlv(before, 0x30)?;
        let encoded_len = before
            .len()
            .checked_sub(remaining.len())
            .ok_or(OcspError::InvalidResponse)?;
        result.push(
            before
                .get(..encoded_len)
                .ok_or(OcspError::InvalidResponse)?,
        );
        certificates = remaining;
    }
    Ok(result)
}

#[derive(Clone, Copy)]
enum ResponseExtensionError {
    InvalidResponse,
    InvalidNonce,
}

fn authenticated_response_nonce_inner(
    response_der: &[u8],
) -> Result<Option<Vec<u8>>, ResponseExtensionError> {
    let fields =
        response_data_fields(response_der).map_err(|_| ResponseExtensionError::InvalidResponse)?;
    let Some(mut extensions) = fields.extensions else {
        return Ok(None);
    };
    let mut nonce = None;
    let mut nonce_error = false;
    let mut seen_oids: Vec<&[u8]> = Vec::new();
    while !extensions.is_empty() {
        if seen_oids.len() >= MAX_OCSP_EXTENSIONS {
            return Err(ResponseExtensionError::InvalidResponse);
        }
        let (extension, remaining) =
            read_tlv(extensions, 0x30).map_err(|_| ResponseExtensionError::InvalidResponse)?;
        extensions = remaining;
        let (oid, rest) =
            read_tlv(extension, 0x06).map_err(|_| ResponseExtensionError::InvalidResponse)?;
        if seen_oids.contains(&oid) {
            return Err(ResponseExtensionError::InvalidResponse);
        }
        seen_oids.push(oid);
        let (critical, rest) = if rest.first() == Some(&0x01) {
            let (encoded, rest) =
                read_tlv(rest, 0x01).map_err(|_| ResponseExtensionError::InvalidResponse)?;
            let critical = match encoded {
                [0x00] => false,
                [0xff] => true,
                _ => return Err(ResponseExtensionError::InvalidResponse),
            };
            (critical, rest)
        } else {
            (false, rest)
        };
        let (value, trailing) =
            read_tlv(rest, 0x04).map_err(|_| ResponseExtensionError::InvalidResponse)?;
        if !trailing.is_empty() {
            return Err(ResponseExtensionError::InvalidResponse);
        }
        if oid == OID_OCSP_NONCE {
            if critical {
                return Err(ResponseExtensionError::InvalidResponse);
            }
            if nonce.is_some() {
                nonce_error = true;
                continue;
            }
            match read_tlv(value, 0x04) {
                Ok((decoded_nonce, trailing))
                    if trailing.is_empty()
                        && !decoded_nonce.is_empty()
                        && decoded_nonce.len() <= MAX_OCSP_NONCE_BYTES =>
                {
                    nonce = Some(decoded_nonce.to_vec());
                }
                Ok(_) | Err(_) => nonce_error = true,
            }
        } else if critical {
            // RFC 6960 inherits the X.509 extension rule: an implementation
            // must reject a critical extension whose semantics it does not
            // understand rather than treating the response as authenticated.
            return Err(ResponseExtensionError::InvalidResponse);
        }
    }
    if nonce_error {
        Err(ResponseExtensionError::InvalidNonce)
    } else {
        Ok(nonce)
    }
}

/// Parse a response nonce according to whether the corresponding request used
/// one. A present malformed nonce always fails closed, even when the request
/// did not carry a nonce, because it is part of the authenticated response.
pub(crate) fn response_nonce_for_request(
    response_der: &[u8],
    _nonce_was_requested: bool,
) -> Result<Option<Vec<u8>>, OcspError> {
    match authenticated_response_nonce_inner(response_der) {
        Ok(nonce) => Ok(nonce),
        Err(ResponseExtensionError::InvalidNonce | ResponseExtensionError::InvalidResponse) => {
            Err(OcspError::InvalidResponse)
        }
    }
}

fn unique_matching_digest_in_responses(
    responses: &[u8],
    expected: &ExpectedCertId,
) -> Result<MatchingDigest, OcspError> {
    let mut input = responses;
    let mut matching: Option<MatchingDigest> = None;

    while !input.is_empty() {
        let (single_response, remaining) = read_tlv(input, 0x30)?;
        input = remaining;
        let (cert_id, rest) = read_tlv(single_response, 0x30)?;
        if let Some(digest) = matches_cert_id(cert_id, expected)? {
            if matching.is_some() {
                return Err(OcspError::InvalidResponse);
            }
            validate_matching_single_response(rest)?;
            matching = Some(digest);
        }
    }

    matching.ok_or(OcspError::Unavailable)
}

fn validate_matching_single_response(mut input: &[u8]) -> Result<(), OcspError> {
    let status_tag = input.first().copied().ok_or(OcspError::InvalidResponse)?;
    if !matches!(status_tag, 0x80 | 0xa1 | 0x82) {
        return Err(OcspError::InvalidResponse);
    }
    let (status_value, remaining) = read_tlv(input, status_tag)?;
    if matches!(status_tag, 0x80 | 0x82) && !status_value.is_empty() {
        return Err(OcspError::InvalidResponse);
    }
    let (_, remaining) = read_tlv(remaining, 0x18)?;
    input = remaining;

    if input.first() == Some(&0xa0) {
        let (next_update, remaining) = read_tlv(input, 0xa0)?;
        let (_, trailing) = read_tlv(next_update, 0x18)?;
        if !trailing.is_empty() {
            return Err(OcspError::InvalidResponse);
        }
        input = remaining;
    }

    if input.first() == Some(&0xa1) {
        let (explicit_extensions, remaining) = read_tlv(input, 0xa1)?;
        let (extensions, trailing) = read_tlv(explicit_extensions, 0x30)?;
        if !trailing.is_empty() {
            return Err(OcspError::InvalidResponse);
        }
        reject_critical_single_extensions(extensions)?;
        input = remaining;
    }

    if input.is_empty() {
        Ok(())
    } else {
        Err(OcspError::InvalidResponse)
    }
}

fn reject_critical_single_extensions(mut extensions: &[u8]) -> Result<(), OcspError> {
    let mut seen_oids: Vec<&[u8]> = Vec::new();
    while !extensions.is_empty() {
        if seen_oids.len() >= MAX_OCSP_EXTENSIONS {
            return Err(OcspError::InvalidResponse);
        }
        let (extension, remaining) = read_tlv(extensions, 0x30)?;
        extensions = remaining;
        let (oid, rest) = read_tlv(extension, 0x06)?;
        if seen_oids.contains(&oid) {
            return Err(OcspError::InvalidResponse);
        }
        seen_oids.push(oid);
        let (critical, rest) = if rest.first() == Some(&0x01) {
            let (encoded, remaining) = read_tlv(rest, 0x01)?;
            let critical = match encoded {
                [0x00] => false,
                [0xff] => true,
                _ => return Err(OcspError::InvalidResponse),
            };
            (critical, remaining)
        } else {
            (false, rest)
        };
        let (_, trailing) = read_tlv(rest, 0x04)?;
        if !trailing.is_empty() || critical {
            return Err(OcspError::InvalidResponse);
        }
    }
    Ok(())
}

fn expected_cert_id(cert_der: &[u8], issuer_der: &[u8]) -> Result<ExpectedCertId, OcspError> {
    let cert = parse_cert_der(cert_der).map_err(|_| OcspError::InvalidResponse)?;
    let issuer = parse_cert_der(issuer_der).map_err(|_| OcspError::InvalidResponse)?;
    if cert.issuer_der != issuer.subject_der {
        return Err(OcspError::InvalidResponse);
    }
    if cert
        .authority_key_identifier
        .as_deref()
        .is_some_and(|identifier| !issuer.matches_key_identifier(identifier))
    {
        return Err(OcspError::InvalidResponse);
    }
    let key_bits = subject_public_key_bits(&issuer.spki_der)?;

    Ok(ExpectedCertId {
        sha1_name: hash(MessageDigest::sha1(), &issuer.subject_der)
            .map_err(|_| OcspError::InvalidResponse)?
            .to_vec(),
        sha1_key: hash(MessageDigest::sha1(), key_bits)
            .map_err(|_| OcspError::InvalidResponse)?
            .to_vec(),
        sha256_name: hash(MessageDigest::sha256(), &issuer.subject_der)
            .map_err(|_| OcspError::InvalidResponse)?
            .to_vec(),
        sha256_key: hash(MessageDigest::sha256(), key_bits)
            .map_err(|_| OcspError::InvalidResponse)?
            .to_vec(),
        serial: normalize_positive_integer(&cert.serial),
    })
}

fn matches_cert_id(
    cert_id: &[u8],
    expected: &ExpectedCertId,
) -> Result<Option<MatchingDigest>, OcspError> {
    let (algorithm, rest) = read_tlv(cert_id, 0x30)?;
    let (name_hash, rest) = read_tlv(rest, 0x04)?;
    let (key_hash, rest) = read_tlv(rest, 0x04)?;
    let (serial, rest) = read_tlv(rest, 0x02)?;
    if !rest.is_empty() || serial.is_empty() || serial.first().is_some_and(|byte| byte & 0x80 != 0)
    {
        return Err(OcspError::InvalidResponse);
    }

    let serial = normalize_positive_integer(serial);
    let Some(digest) = parse_algorithm(algorithm)? else {
        // An unsupported digest prevents us from authenticating the issuer
        // hashes. A response for the target serial therefore cannot be
        // treated as unrelated: doing so would let a conflicting status hide
        // behind an unknown AlgorithmIdentifier.
        if serial == expected.serial {
            return Err(OcspError::InvalidResponse);
        }
        return Ok(None);
    };
    let matches = match digest {
        MatchingDigest::Sha1 => {
            name_hash == expected.sha1_name
                && key_hash == expected.sha1_key
                && serial == expected.serial
        }
        MatchingDigest::Sha256 => {
            name_hash == expected.sha256_name
                && key_hash == expected.sha256_key
                && serial == expected.serial
        }
    };
    Ok(matches.then_some(digest))
}

fn parse_algorithm(algorithm: &[u8]) -> Result<Option<MatchingDigest>, OcspError> {
    let (oid, rest) = read_tlv(algorithm, 0x06)?;
    if !rest.is_empty() {
        let (parameters, remaining) = read_tlv(rest, 0x05)?;
        if !parameters.is_empty() || !remaining.is_empty() {
            return Err(OcspError::InvalidResponse);
        }
    }
    match oid {
        OID_SHA1 => Ok(Some(MatchingDigest::Sha1)),
        OID_SHA256 => Ok(Some(MatchingDigest::Sha256)),
        _ => Ok(None),
    }
}

struct ResponseDataFields<'a> {
    responses: &'a [u8],
    extensions: Option<&'a [u8]>,
    produced_at: &'a [u8],
    signature_algorithm_oid: &'a [u8],
    certificates: Option<&'a [u8]>,
}

fn response_data_fields(response_der: &[u8]) -> Result<ResponseDataFields<'_>, OcspError> {
    let (response, trailing) = read_tlv(response_der, 0x30)?;
    if !trailing.is_empty() {
        return Err(OcspError::InvalidResponse);
    }
    let (_status, rest) = read_tlv(response, 0x0a)?;
    let (response_bytes_explicit, rest) = read_tlv(rest, 0xa0)?;
    if !rest.is_empty() {
        return Err(OcspError::InvalidResponse);
    }
    let (response_bytes, trailing) = read_tlv(response_bytes_explicit, 0x30)?;
    if !trailing.is_empty() {
        return Err(OcspError::InvalidResponse);
    }
    let (response_type, rest) = read_tlv(response_bytes, 0x06)?;
    if response_type != OID_BASIC_OCSP_RESPONSE {
        return Err(OcspError::InvalidResponse);
    }
    let (basic_der, rest) = read_tlv(rest, 0x04)?;
    if !rest.is_empty() {
        return Err(OcspError::InvalidResponse);
    }
    let (basic, trailing) = read_tlv(basic_der, 0x30)?;
    if !trailing.is_empty() {
        return Err(OcspError::InvalidResponse);
    }
    let (response_data, basic_rest) = read_tlv(basic, 0x30)?;
    let (signature_algorithm, basic_rest) = read_tlv(basic_rest, 0x30)?;
    let (signature_algorithm_oid, _) = read_tlv(signature_algorithm, 0x06)?;
    let (_, basic_rest) = read_tlv(basic_rest, 0x03)?;
    let certificates = if !basic_rest.is_empty() {
        let (explicit, trailing) = read_tlv(basic_rest, 0xa0)?;
        if !trailing.is_empty() {
            return Err(OcspError::InvalidResponse);
        }
        let (certificates, trailing) = read_tlv(explicit, 0x30)?;
        if !trailing.is_empty() {
            return Err(OcspError::InvalidResponse);
        }
        Some(certificates)
    } else {
        None
    };
    let mut rest = response_data;
    if rest.first() == Some(&0xa0) {
        let (_, remaining) = read_tlv(rest, 0xa0)?;
        rest = remaining;
    }
    let responder_tag = rest.first().copied().ok_or(OcspError::InvalidResponse)?;
    if responder_tag != 0xa1 && responder_tag != 0xa2 {
        return Err(OcspError::InvalidResponse);
    }
    let (_, remaining) = read_tlv(rest, responder_tag)?;
    let (produced_at, remaining) = read_tlv(remaining, 0x18)?;
    let (responses, remaining) = read_tlv(remaining, 0x30)?;
    let extensions = if remaining.is_empty() {
        None
    } else {
        let (explicit, trailing) = read_tlv(remaining, 0xa1)?;
        if !trailing.is_empty() {
            return Err(OcspError::InvalidResponse);
        }
        let (extensions, trailing) = read_tlv(explicit, 0x30)?;
        if !trailing.is_empty() {
            return Err(OcspError::InvalidResponse);
        }
        Some(extensions)
    };
    Ok(ResponseDataFields {
        responses,
        extensions,
        produced_at,
        signature_algorithm_oid,
        certificates,
    })
}

fn normalize_positive_integer(value: &[u8]) -> Vec<u8> {
    let first_nonzero = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    value.get(first_nonzero..).unwrap_or_default().to_vec()
}

fn read_tlv(input: &[u8], expected_tag: u8) -> Result<(&[u8], &[u8]), OcspError> {
    let (&tag, rest) = input.split_first().ok_or(OcspError::InvalidResponse)?;
    if tag != expected_tag {
        return Err(OcspError::InvalidResponse);
    }
    let (&first, rest) = rest.split_first().ok_or(OcspError::InvalidResponse)?;
    let (length, rest) = if first & 0x80 == 0 {
        (usize::from(first), rest)
    } else {
        let octets = usize::from(first & 0x7f);
        if octets == 0 || octets > MAX_DER_LENGTH_OCTETS || octets > rest.len() {
            return Err(OcspError::InvalidResponse);
        }
        let (encoded_length, rest) = rest.split_at(octets);
        if encoded_length.first() == Some(&0) {
            return Err(OcspError::InvalidResponse);
        }
        let mut length = 0_usize;
        for byte in encoded_length {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or(OcspError::InvalidResponse)?;
        }
        if length < 128 {
            return Err(OcspError::InvalidResponse);
        }
        (length, rest)
    };
    if length > rest.len() {
        return Err(OcspError::InvalidResponse);
    }
    Ok(rest.split_at(length))
}

#[cfg(test)]
#[path = "cert_id_match_tests.rs"]
mod tests;
