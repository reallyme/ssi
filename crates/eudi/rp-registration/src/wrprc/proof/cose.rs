// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded TS 119 475 WRPRC COSE_Sign1 authentication.

use zeroize::Zeroizing;

use super::RegistrationCertificateCoseAlgorithm;
use crate::{RegistrationError, RegistrationErrorReason};

const COSE_SIGN1_TAG: u64 = 18;
const COSE_ALGORITHM_LABEL: u64 = 1;
const COSE_TYPE_LABEL: u64 = 16;
const COSE_X5CHAIN_LABEL: u64 = 33;
const MAX_PROTECTED_HEADER_BYTES: usize = 786_432;
const MAX_HEADER_PARAMETERS: usize = 3;
const MAX_CERTIFICATE_CHAIN_LENGTH: usize = 10;
const WRPRC_CWT_TYPE: &str = "rc-wrp+cwt";
const SIGNATURE_CONTEXT: &[u8] = b"Signature1";
const ES256_COSE_ALGORITHM: i64 = -7;
const EDDSA_COSE_ALGORITHM: i64 = -8;
const ES256_SIGNATURE_BYTES: usize = 64;
const ED25519_SIGNATURE_BYTES: usize = 64;

pub(super) fn authenticate_attached_cose_sign1<'a>(
    cose_sign1: &'a [u8],
    expected_signer_certificate_der: &[u8],
    allowed_algorithms: &[RegistrationCertificateCoseAlgorithm],
) -> Result<&'a [u8], RegistrationError> {
    let certificate = reallyme_trust_x509::parse_cert_der(expected_signer_certificate_der)
        .map_err(|_error| invalid(RegistrationErrorReason::InvalidCertificate))?;
    let subject_public_key =
        reallyme_trust_x509::parse_subject_public_key_info_der(certificate.spki_der.as_slice())
            .map_err(|_error| invalid(RegistrationErrorReason::InvalidCertificate))?;
    let parsed = parse_cose_sign1(cose_sign1, expected_signer_certificate_der)?;

    if !allowed_algorithms.contains(&parsed.algorithm) {
        return Err(invalid(RegistrationErrorReason::UnsupportedProfile));
    }
    let signing_input = build_signature_structure(parsed.protected, parsed.payload)?;
    match (parsed.algorithm, subject_public_key.algorithm) {
        (
            RegistrationCertificateCoseAlgorithm::Es256,
            reallyme_trust_x509::SubjectPublicKeyAlgorithm::P256,
        ) => {
            if parsed.signature.len() != ES256_SIGNATURE_BYTES {
                return Err(invalid(
                    RegistrationErrorReason::SignatureVerificationFailed,
                ));
            }
            reallyme_jose::jws::suites::es256::verify_p256_jose_prehash(
                parsed.signature,
                signing_input.as_slice(),
                subject_public_key.public_key.as_slice(),
            )
            .map_err(|_error| invalid(RegistrationErrorReason::SignatureVerificationFailed))?;
        }
        (
            RegistrationCertificateCoseAlgorithm::Ed25519,
            reallyme_trust_x509::SubjectPublicKeyAlgorithm::Ed25519,
        ) => {
            if parsed.signature.len() != ED25519_SIGNATURE_BYTES {
                return Err(invalid(
                    RegistrationErrorReason::SignatureVerificationFailed,
                ));
            }
            reallyme_crypto::ed25519::verify_ed25519(
                subject_public_key.public_key.as_slice(),
                signing_input.as_slice(),
                parsed.signature,
            )
            .map_err(|_error| invalid(RegistrationErrorReason::SignatureVerificationFailed))?;
        }
        _ => return Err(invalid(RegistrationErrorReason::UnsupportedProfile)),
    }
    Ok(parsed.payload)
}

struct ParsedCoseSign1<'a> {
    protected: &'a [u8],
    payload: &'a [u8],
    signature: &'a [u8],
    algorithm: RegistrationCertificateCoseAlgorithm,
}

fn parse_cose_sign1<'a>(
    input: &'a [u8],
    expected_signer_certificate_der: &[u8],
) -> Result<ParsedCoseSign1<'a>, RegistrationError> {
    let mut decoder = Decoder::new(input);
    if decoder.peek_major_type()? == Some(6) && decoder.read_tag()? != COSE_SIGN1_TAG {
        return Err(invalid(RegistrationErrorReason::InvalidField));
    }
    if decoder.read_array_length()? != 4 {
        return Err(invalid(RegistrationErrorReason::InvalidField));
    }

    let protected = decoder.read_byte_string()?;
    if protected.is_empty() || protected.len() > MAX_PROTECTED_HEADER_BYTES {
        return Err(invalid(RegistrationErrorReason::ResourceLimitExceeded));
    }
    let protected_facts = parse_protected_headers(protected, expected_signer_certificate_der)?;
    let unprotected_has_x5chain =
        parse_unprotected_headers(&mut decoder, expected_signer_certificate_der)?;
    if protected_facts.has_x5chain == unprotected_has_x5chain {
        let reason = if protected_facts.has_x5chain {
            RegistrationErrorReason::InvalidField
        } else {
            RegistrationErrorReason::MissingSignerCertificate
        };
        return Err(invalid(reason));
    }

    let payload = decoder.read_byte_string()?;
    if payload.is_empty() || payload.len() > crate::json::MAX_JSON_BYTES {
        return Err(invalid(RegistrationErrorReason::InputTooLarge));
    }
    let signature = decoder.read_byte_string()?;
    if signature.is_empty() || !decoder.is_finished() {
        return Err(invalid(RegistrationErrorReason::InvalidField));
    }

    Ok(ParsedCoseSign1 {
        protected,
        payload,
        signature,
        algorithm: protected_facts.algorithm,
    })
}

struct ProtectedHeaderFacts {
    algorithm: RegistrationCertificateCoseAlgorithm,
    has_x5chain: bool,
}

fn parse_protected_headers(
    encoded: &[u8],
    expected_signer_certificate_der: &[u8],
) -> Result<ProtectedHeaderFacts, RegistrationError> {
    let mut decoder = Decoder::new(encoded);
    let count = decoder.read_map_length()?;
    if count == 0 || count > MAX_HEADER_PARAMETERS {
        return Err(invalid(RegistrationErrorReason::InvalidField));
    }
    let mut previous_label = None;
    let mut algorithm = None;
    let mut saw_type = false;
    let mut saw_x5chain = false;

    // ETSI TS 119 475 V1.2.1 GEN-5.2.3-01 and Table 6 require alg,
    // RFC 9596 typ = rc-wrp+cwt, and RFC 9360 x5chain. The explicit type
    // stays protected as required by RFC 9596 section 2.
    for _ in 0..count {
        let label = decoder.read_unsigned()?;
        validate_header_label_order(previous_label, label)?;
        previous_label = Some(label);
        match label {
            COSE_ALGORITHM_LABEL => {
                algorithm = Some(parse_algorithm(&mut decoder)?);
            }
            COSE_TYPE_LABEL => {
                if decoder.read_text_string()? != WRPRC_CWT_TYPE {
                    return Err(invalid(RegistrationErrorReason::UnsupportedProfile));
                }
                saw_type = true;
            }
            COSE_X5CHAIN_LABEL => {
                validate_x5chain(&mut decoder, expected_signer_certificate_der)?;
                saw_x5chain = true;
            }
            _ => return Err(invalid(RegistrationErrorReason::InvalidField)),
        }
    }
    if !decoder.is_finished() {
        return Err(invalid(RegistrationErrorReason::InvalidField));
    }
    let algorithm = algorithm.ok_or_else(|| invalid(RegistrationErrorReason::MissingField))?;
    if !saw_type {
        return Err(invalid(RegistrationErrorReason::MissingField));
    }
    Ok(ProtectedHeaderFacts {
        algorithm,
        has_x5chain: saw_x5chain,
    })
}

fn parse_unprotected_headers(
    decoder: &mut Decoder<'_>,
    expected_signer_certificate_der: &[u8],
) -> Result<bool, RegistrationError> {
    let count = decoder.read_map_length()?;
    if count > 1 {
        return Err(invalid(RegistrationErrorReason::InvalidField));
    }
    if count == 0 {
        return Ok(false);
    }
    let label = decoder.read_unsigned()?;
    if label != COSE_X5CHAIN_LABEL {
        return Err(invalid(RegistrationErrorReason::InvalidField));
    }
    validate_x5chain(decoder, expected_signer_certificate_der)?;
    Ok(true)
}

fn validate_header_label_order(
    previous: Option<u64>,
    current: u64,
) -> Result<(), RegistrationError> {
    if previous.is_some_and(|value| value >= current) {
        return Err(invalid(RegistrationErrorReason::InvalidField));
    }
    Ok(())
}

fn parse_algorithm(
    decoder: &mut Decoder<'_>,
) -> Result<RegistrationCertificateCoseAlgorithm, RegistrationError> {
    match decoder.read_integer()? {
        ES256_COSE_ALGORITHM => Ok(RegistrationCertificateCoseAlgorithm::Es256),
        EDDSA_COSE_ALGORITHM => Ok(RegistrationCertificateCoseAlgorithm::Ed25519),
        _ => Err(invalid(RegistrationErrorReason::UnsupportedProfile)),
    }
}

fn validate_x5chain(
    decoder: &mut Decoder<'_>,
    expected_signer_certificate_der: &[u8],
) -> Result<(), RegistrationError> {
    match decoder.peek_major_type()? {
        Some(2) => validate_certificate(
            decoder.read_byte_string()?,
            expected_signer_certificate_der,
            true,
        ),
        Some(4) => {
            let count = decoder.read_array_length()?;
            if !(2..=MAX_CERTIFICATE_CHAIN_LENGTH).contains(&count) {
                return Err(invalid(RegistrationErrorReason::ResourceLimitExceeded));
            }
            for index in 0..count {
                validate_certificate(
                    decoder.read_byte_string()?,
                    expected_signer_certificate_der,
                    index == 0,
                )?;
            }
            Ok(())
        }
        _ => Err(invalid(RegistrationErrorReason::InvalidCertificate)),
    }
}

fn validate_certificate(
    certificate_der: &[u8],
    expected_signer_certificate_der: &[u8],
    is_leaf: bool,
) -> Result<(), RegistrationError> {
    if certificate_der.is_empty()
        || certificate_der.len() > super::super::MAX_SIGNER_CERTIFICATE_BYTES
    {
        return Err(invalid(RegistrationErrorReason::InvalidCertificate));
    }
    reallyme_trust_x509::parse_cert_der(certificate_der)
        .map_err(|_error| invalid(RegistrationErrorReason::InvalidCertificate))?;
    if is_leaf && certificate_der != expected_signer_certificate_der {
        return Err(invalid(
            RegistrationErrorReason::AuthenticationReceiptMismatch,
        ));
    }
    Ok(())
}

fn build_signature_structure(
    protected: &[u8],
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, RegistrationError> {
    const ARRAY_AND_CONTEXT_HEADER_BYTES: usize = 2;
    const EMPTY_EXTERNAL_AAD_BYTES: usize = 1;
    const MAX_BYTE_STRING_HEADER_BYTES: usize = 9;
    let capacity = ARRAY_AND_CONTEXT_HEADER_BYTES
        .checked_add(SIGNATURE_CONTEXT.len())
        .and_then(|value| value.checked_add(MAX_BYTE_STRING_HEADER_BYTES))
        .and_then(|value| value.checked_add(protected.len()))
        .and_then(|value| value.checked_add(EMPTY_EXTERNAL_AAD_BYTES))
        .and_then(|value| value.checked_add(MAX_BYTE_STRING_HEADER_BYTES))
        .and_then(|value| value.checked_add(payload.len()))
        .ok_or_else(|| invalid(RegistrationErrorReason::CapacityUnavailable))?;
    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(capacity)
        .map_err(|_error| invalid(RegistrationErrorReason::CapacityUnavailable))?;
    encoded.push(0x84);
    encoded.push(0x6a);
    encoded.extend_from_slice(SIGNATURE_CONTEXT);
    append_byte_string(&mut encoded, protected)?;
    encoded.push(0x40);
    append_byte_string(&mut encoded, payload)?;
    Ok(encoded)
}

fn append_byte_string(output: &mut Vec<u8>, value: &[u8]) -> Result<(), RegistrationError> {
    append_major_length(output, 2, value.len())?;
    output.extend_from_slice(value);
    Ok(())
}

fn append_major_length(
    output: &mut Vec<u8>,
    major: u8,
    length: usize,
) -> Result<(), RegistrationError> {
    let value = u64::try_from(length)
        .map_err(|_error| invalid(RegistrationErrorReason::CapacityUnavailable))?;
    let prefix = major
        .checked_shl(5)
        .ok_or_else(|| invalid(RegistrationErrorReason::SerializationFailed))?;
    if value <= 23 {
        let encoded = u8::try_from(value)
            .map_err(|_error| invalid(RegistrationErrorReason::SerializationFailed))?;
        output.push(prefix | encoded);
    } else if value <= u64::from(u8::MAX) {
        output.push(prefix | 24);
        output.push(
            u8::try_from(value)
                .map_err(|_error| invalid(RegistrationErrorReason::SerializationFailed))?,
        );
    } else if value <= u64::from(u16::MAX) {
        output.push(prefix | 25);
        output.extend_from_slice(
            &u16::try_from(value)
                .map_err(|_error| invalid(RegistrationErrorReason::SerializationFailed))?
                .to_be_bytes(),
        );
    } else if value <= u64::from(u32::MAX) {
        output.push(prefix | 26);
        output.extend_from_slice(
            &u32::try_from(value)
                .map_err(|_error| invalid(RegistrationErrorReason::SerializationFailed))?
                .to_be_bytes(),
        );
    } else {
        output.push(prefix | 27);
        output.extend_from_slice(&value.to_be_bytes());
    }
    Ok(())
}

struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn peek_major_type(&self) -> Result<Option<u8>, RegistrationError> {
        Ok(self.input.get(self.offset).map(|value| value >> 5))
    }

    fn read_tag(&mut self) -> Result<u64, RegistrationError> {
        self.read_expected_argument(6)
    }

    fn read_array_length(&mut self) -> Result<usize, RegistrationError> {
        self.read_length(4)
    }

    fn read_map_length(&mut self) -> Result<usize, RegistrationError> {
        self.read_length(5)
    }

    fn read_byte_string(&mut self) -> Result<&'a [u8], RegistrationError> {
        let length = self.read_length(2)?;
        self.take(length)
    }

    fn read_text_string(&mut self) -> Result<&'a str, RegistrationError> {
        let length = self.read_length(3)?;
        let bytes = self.take(length)?;
        core::str::from_utf8(bytes).map_err(|_error| invalid(RegistrationErrorReason::InvalidField))
    }

    fn read_unsigned(&mut self) -> Result<u64, RegistrationError> {
        self.read_expected_argument(0)
    }

    fn read_integer(&mut self) -> Result<i64, RegistrationError> {
        let (major, value) = self.read_head()?;
        match major {
            0 => i64::try_from(value)
                .map_err(|_error| invalid(RegistrationErrorReason::InvalidField)),
            1 => {
                let magnitude = i64::try_from(value)
                    .map_err(|_error| invalid(RegistrationErrorReason::InvalidField))?;
                (-1_i64)
                    .checked_sub(magnitude)
                    .ok_or_else(|| invalid(RegistrationErrorReason::InvalidField))
            }
            _ => Err(invalid(RegistrationErrorReason::InvalidField)),
        }
    }

    fn read_length(&mut self, expected_major: u8) -> Result<usize, RegistrationError> {
        let value = self.read_expected_argument(expected_major)?;
        usize::try_from(value).map_err(|_error| invalid(RegistrationErrorReason::InputTooLarge))
    }

    fn read_expected_argument(&mut self, expected_major: u8) -> Result<u64, RegistrationError> {
        let (major, value) = self.read_head()?;
        if major != expected_major {
            return Err(invalid(RegistrationErrorReason::InvalidField));
        }
        Ok(value)
    }

    fn read_head(&mut self) -> Result<(u8, u64), RegistrationError> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        let value = match additional {
            0..=23 => u64::from(additional),
            24 => {
                let value = u64::from(self.read_byte()?);
                if value < 24 {
                    return Err(invalid(RegistrationErrorReason::InvalidField));
                }
                value
            }
            25 => {
                let bytes = <[u8; 2]>::try_from(self.take(2)?)
                    .map_err(|_error| invalid(RegistrationErrorReason::InvalidField))?;
                let value = u64::from(u16::from_be_bytes(bytes));
                if value <= u64::from(u8::MAX) {
                    return Err(invalid(RegistrationErrorReason::InvalidField));
                }
                value
            }
            26 => {
                let bytes = <[u8; 4]>::try_from(self.take(4)?)
                    .map_err(|_error| invalid(RegistrationErrorReason::InvalidField))?;
                let value = u64::from(u32::from_be_bytes(bytes));
                if value <= u64::from(u16::MAX) {
                    return Err(invalid(RegistrationErrorReason::InvalidField));
                }
                value
            }
            27 => {
                let bytes = <[u8; 8]>::try_from(self.take(8)?)
                    .map_err(|_error| invalid(RegistrationErrorReason::InvalidField))?;
                let value = u64::from_be_bytes(bytes);
                if value <= u64::from(u32::MAX) {
                    return Err(invalid(RegistrationErrorReason::InvalidField));
                }
                value
            }
            _ => return Err(invalid(RegistrationErrorReason::InvalidField)),
        };
        Ok((major, value))
    }

    fn read_byte(&mut self) -> Result<u8, RegistrationError> {
        let value = self
            .input
            .get(self.offset)
            .copied()
            .ok_or_else(|| invalid(RegistrationErrorReason::InvalidField))?;
        self.offset = self
            .offset
            .checked_add(1)
            .ok_or_else(|| invalid(RegistrationErrorReason::InputTooLarge))?;
        Ok(value)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RegistrationError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| invalid(RegistrationErrorReason::InputTooLarge))?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or_else(|| invalid(RegistrationErrorReason::InvalidField))?;
        self.offset = end;
        Ok(value)
    }

    const fn is_finished(&self) -> bool {
        self.offset == self.input.len()
    }
}

const fn invalid(reason: RegistrationErrorReason) -> RegistrationError {
    RegistrationError::from_reason(reason)
}
