// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

const DID_KEY_PREFIX: &str = "did:key:";
const BASE58BTC_MULTIBASE_PREFIX: char = 'z';
/// Maximum encoded method-specific identifier length accepted before Base58 decoding.
///
/// The largest supported key (compressed P-384, 49 bytes plus a two-byte
/// multicodec header) encodes to at most 70 Base58 characters; the cap bounds
/// the quadratic Base58 decoder on hostile input.
const MAX_METHOD_SPECIFIC_ID_LEN: usize = 128;
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Public-key multicodecs supported by the did:key specification profile here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidKeyMulticodec {
    /// `secp256k1-pub`, compressed, multicodec `0xe7`.
    Secp256k1,
    /// `x25519-pub`, multicodec `0xec`.
    X25519,
    /// `ed25519-pub`, multicodec `0xed`.
    Ed25519,
    /// `p256-pub`, compressed, multicodec `0x1200`.
    P256,
    /// `p384-pub`, compressed, multicodec `0x1201`.
    P384,
}

impl DidKeyMulticodec {
    const fn code(self) -> u64 {
        match self {
            DidKeyMulticodec::Secp256k1 => 0xe7,
            DidKeyMulticodec::X25519 => 0xec,
            DidKeyMulticodec::Ed25519 => 0xed,
            DidKeyMulticodec::P256 => 0x1200,
            DidKeyMulticodec::P384 => 0x1201,
        }
    }

    const fn public_key_len(self) -> usize {
        match self {
            DidKeyMulticodec::Secp256k1 | DidKeyMulticodec::P256 => 33,
            DidKeyMulticodec::X25519 | DidKeyMulticodec::Ed25519 => 32,
            DidKeyMulticodec::P384 => 49,
        }
    }

    const fn from_code(code: u64) -> Option<Self> {
        match code {
            0xe7 => Some(DidKeyMulticodec::Secp256k1),
            0xec => Some(DidKeyMulticodec::X25519),
            0xed => Some(DidKeyMulticodec::Ed25519),
            0x1200 => Some(DidKeyMulticodec::P256),
            0x1201 => Some(DidKeyMulticodec::P384),
            _ => None,
        }
    }
}

/// Multibase encodings allowed by the did:key ABNF.
///
/// The did:key ABNF permits only Base58 BTC (`z`). Accepting further encodings
/// would give one key several distinct DIDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidKeyMultibase {
    /// Multibase Base58 BTC, `z` prefix.
    Base58Btc,
}

/// Audit-safe did:key failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidKeyErrorReason {
    /// The DID did not start with `did:key:`.
    InvalidPrefix,
    /// The method-specific identifier was empty.
    EmptyIdentifier,
    /// The multibase prefix is not supported by the did:key ABNF.
    UnsupportedMultibase,
    /// The identifier contained an invalid Base58 BTC character.
    InvalidBase58,
    /// The identifier contained invalid unpadded base64url.
    InvalidBase64Url,
    /// The decoded multicodec varint was malformed.
    InvalidVarint,
    /// The decoded multicodec is not part of the supported public key profile.
    UnsupportedMulticodec,
    /// The decoded key byte length does not match the multicodec.
    InvalidPublicKeyLength,
    /// Checked arithmetic failed while converting between bases.
    ArithmeticOverflow,
    /// The method-specific identifier exceeded the supported length.
    IdentifierTooLong,
}

/// Typed did:key method error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("invalid did:key method identifier")]
pub struct DidKeyError {
    /// Audit-safe reason for the failure.
    pub reason: DidKeyErrorReason,
}

impl DidKeyError {
    const fn new(reason: DidKeyErrorReason) -> Self {
        Self { reason }
    }
}

impl From<DidKeyErrorReason> for IdentityCoreErrorReason {
    fn from(reason: DidKeyErrorReason) -> Self {
        match reason {
            DidKeyErrorReason::InvalidPrefix => Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_PREFIX,
            DidKeyErrorReason::EmptyIdentifier => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_EMPTY_IDENTIFIER
            }
            DidKeyErrorReason::UnsupportedMultibase => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_UNSUPPORTED_MULTIBASE
            }
            DidKeyErrorReason::InvalidBase58 => Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_BASE58,
            DidKeyErrorReason::InvalidBase64Url => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_BASE64URL
            }
            DidKeyErrorReason::InvalidVarint => Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_VARINT,
            DidKeyErrorReason::UnsupportedMulticodec => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_UNSUPPORTED_MULTICODEC
            }
            DidKeyErrorReason::ArithmeticOverflow => {
                Self::IDENTITY_CORE_ERROR_REASON_ARITHMETIC_OVERFLOW
            }
            DidKeyErrorReason::InvalidPublicKeyLength => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_PUBLIC_KEY_LENGTH
            }
            DidKeyErrorReason::IdentifierTooLong => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_METHOD_IDENTIFIER
            }
        }
    }
}

impl From<DidKeyError> for IdentityCoreErrorReason {
    fn from(error: DidKeyError) -> Self {
        error.reason.into()
    }
}

#[cfg(test)]
#[path = "lib_proto_error_tests.rs"]
mod proto_error_tests;

/// Decoded did:key identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidKeyIdentifier {
    /// Multibase encoding used by the identifier.
    pub multibase: DidKeyMultibase,
    /// Public-key multicodec.
    pub multicodec: DidKeyMulticodec,
    /// Raw public key bytes after the multicodec prefix.
    pub public_key: Vec<u8>,
}

/// Generate a did:key identifier from a public-key multicodec and raw key bytes.
pub fn generate_did_key(
    multicodec: DidKeyMulticodec,
    public_key: &[u8],
    multibase: DidKeyMultibase,
) -> Result<String, DidKeyError> {
    if public_key.len() != multicodec.public_key_len() {
        return Err(DidKeyError::new(DidKeyErrorReason::InvalidPublicKeyLength));
    }

    let header = encode_varint(multicodec.code())?;
    let capacity = header
        .len()
        .checked_add(public_key.len())
        .ok_or(DidKeyError::new(DidKeyErrorReason::ArithmeticOverflow))?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(public_key);

    let encoded = match multibase {
        DidKeyMultibase::Base58Btc => {
            format!("{BASE58BTC_MULTIBASE_PREFIX}{}", base58_encode(&bytes)?)
        }
    };

    Ok(format!("{DID_KEY_PREFIX}{encoded}"))
}

/// Return the primary verification method fragment for a did:key identifier.
pub fn did_key_url(did: &str) -> Result<String, DidKeyError> {
    let method_specific = did
        .strip_prefix(DID_KEY_PREFIX)
        .ok_or(DidKeyError::new(DidKeyErrorReason::InvalidPrefix))?;
    parse_did_key(did)?;
    Ok(format!("{did}#{method_specific}"))
}

/// Validate and decode a did:key identifier.
pub fn parse_did_key(did: &str) -> Result<DidKeyIdentifier, DidKeyError> {
    let method_specific = did
        .strip_prefix(DID_KEY_PREFIX)
        .ok_or(DidKeyError::new(DidKeyErrorReason::InvalidPrefix))?;
    if method_specific.is_empty() {
        return Err(DidKeyError::new(DidKeyErrorReason::EmptyIdentifier));
    }
    if method_specific.len() > MAX_METHOD_SPECIFIC_ID_LEN {
        return Err(DidKeyError::new(DidKeyErrorReason::IdentifierTooLong));
    }

    let mut chars = method_specific.chars();
    let prefix = chars
        .next()
        .ok_or(DidKeyError::new(DidKeyErrorReason::EmptyIdentifier))?;
    let encoded = chars.as_str();
    if encoded.is_empty() {
        return Err(DidKeyError::new(DidKeyErrorReason::EmptyIdentifier));
    }

    let (multibase, decoded) = match prefix {
        BASE58BTC_MULTIBASE_PREFIX => (DidKeyMultibase::Base58Btc, base58_decode(encoded)?),
        _ => return Err(DidKeyError::new(DidKeyErrorReason::UnsupportedMultibase)),
    };

    let (code, consumed) = decode_varint(&decoded)?;
    let multicodec = DidKeyMulticodec::from_code(code)
        .ok_or(DidKeyError::new(DidKeyErrorReason::UnsupportedMulticodec))?;
    let public_key = decoded
        .get(consumed..)
        .ok_or(DidKeyError::new(DidKeyErrorReason::InvalidVarint))?;
    if public_key.len() != multicodec.public_key_len() {
        return Err(DidKeyError::new(DidKeyErrorReason::InvalidPublicKeyLength));
    }

    Ok(DidKeyIdentifier {
        multibase,
        multicodec,
        public_key: public_key.to_vec(),
    })
}

/// Return true when the DID is a syntactically valid did:key identifier.
pub fn is_valid_did_key(did: &str) -> bool {
    parse_did_key(did).is_ok()
}

fn encode_varint(mut value: u64) -> Result<Vec<u8>, DidKeyError> {
    let mut out = Vec::new();
    loop {
        let low = u8::try_from(value & 0x7f)
            .map_err(|_| DidKeyError::new(DidKeyErrorReason::ArithmeticOverflow))?;
        value >>= 7;
        if value == 0 {
            out.push(low);
            return Ok(out);
        }
        out.push(low | 0x80);
    }
}

fn decode_varint(bytes: &[u8]) -> Result<(u64, usize), DidKeyError> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for (index, byte) in bytes.iter().enumerate() {
        let part = u64::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or(DidKeyError::new(DidKeyErrorReason::InvalidVarint))?;
        value = value
            .checked_add(part)
            .ok_or(DidKeyError::new(DidKeyErrorReason::ArithmeticOverflow))?;
        if byte & 0x80 == 0 {
            // Unsigned-varint requires minimal encoding: a final zero byte after
            // continuation bytes would give one multicodec several encodings.
            if index > 0 && *byte == 0 {
                return Err(DidKeyError::new(DidKeyErrorReason::InvalidVarint));
            }
            let consumed = index
                .checked_add(1)
                .ok_or(DidKeyError::new(DidKeyErrorReason::ArithmeticOverflow))?;
            return Ok((value, consumed));
        }
        shift = shift
            .checked_add(7)
            .ok_or(DidKeyError::new(DidKeyErrorReason::ArithmeticOverflow))?;
        if shift >= 64 {
            return Err(DidKeyError::new(DidKeyErrorReason::InvalidVarint));
        }
    }

    Err(DidKeyError::new(DidKeyErrorReason::InvalidVarint))
}

fn base58_encode(input: &[u8]) -> Result<String, DidKeyError> {
    if input.is_empty() {
        return Err(DidKeyError::new(DidKeyErrorReason::EmptyIdentifier));
    }

    let mut digits = vec![0u8];
    for byte in input {
        let mut carry = u32::from(*byte);
        for digit in &mut digits {
            let value = u32::from(*digit)
                .checked_mul(256)
                .and_then(|current| current.checked_add(carry))
                .ok_or(DidKeyError::new(DidKeyErrorReason::ArithmeticOverflow))?;
            *digit = u8::try_from(value % 58)
                .map_err(|_| DidKeyError::new(DidKeyErrorReason::ArithmeticOverflow))?;
            carry = value / 58;
        }

        while carry > 0 {
            digits.push(
                u8::try_from(carry % 58)
                    .map_err(|_| DidKeyError::new(DidKeyErrorReason::ArithmeticOverflow))?,
            );
            carry /= 58;
        }
    }

    let mut out = String::new();
    for byte in input {
        if *byte == 0 {
            out.push('1');
        } else {
            break;
        }
    }

    for digit in digits.iter().rev() {
        let index = usize::from(*digit);
        let ch = BASE58_ALPHABET
            .get(index)
            .ok_or(DidKeyError::new(DidKeyErrorReason::InvalidBase58))?;
        out.push(char::from(*ch));
    }

    Ok(out)
}

fn base58_decode(input: &str) -> Result<Vec<u8>, DidKeyError> {
    if input.is_empty() {
        return Err(DidKeyError::new(DidKeyErrorReason::EmptyIdentifier));
    }

    let mut bytes = vec![0u8];
    for ch in input.bytes() {
        let mut carry =
            u32::from(base58_value(ch).ok_or(DidKeyError::new(DidKeyErrorReason::InvalidBase58))?);
        for byte in &mut bytes {
            let value = u32::from(*byte)
                .checked_mul(58)
                .and_then(|current| current.checked_add(carry))
                .ok_or(DidKeyError::new(DidKeyErrorReason::ArithmeticOverflow))?;
            *byte = u8::try_from(value & 0xff)
                .map_err(|_| DidKeyError::new(DidKeyErrorReason::ArithmeticOverflow))?;
            carry = value >> 8;
        }

        while carry > 0 {
            bytes.push(
                u8::try_from(carry & 0xff)
                    .map_err(|_| DidKeyError::new(DidKeyErrorReason::ArithmeticOverflow))?,
            );
            carry >>= 8;
        }
    }

    for ch in input.bytes() {
        if ch == b'1' {
            bytes.push(0);
        } else {
            break;
        }
    }

    bytes.reverse();
    Ok(bytes)
}

fn base58_value(byte: u8) -> Option<u8> {
    let mut index = 0u8;
    for candidate in BASE58_ALPHABET {
        if *candidate == byte {
            return Some(index);
        }
        index = index.checked_add(1)?;
    }
    None
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
