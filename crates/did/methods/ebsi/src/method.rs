// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

const DID_EBSI_PREFIX: &str = "did:ebsi:";
const BASE58BTC_MULTIBASE_PREFIX: char = 'z';
const EBSI_V1_VERSION_BYTE: u8 = 0x01;
/// Exact legal-entity subject length defined by did:ebsi version 1.
pub const EBSI_V1_PAYLOAD_LEN: usize = 16;
const EBSI_V1_ENVELOPE_LEN: usize = EBSI_V1_PAYLOAD_LEN + 1;
// Seventeen bytes require at most 24 base58btc digits. Bounding before decode
// prevents an attacker from making the base-conversion workspace grow without limit.
const MAX_EBSI_V1_BASE58_DIGITS: usize = 24;
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// EBSI method identifier versions supported by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbsiDidVersion {
    /// Version 1 Legal Entity identifier envelope.
    LegalEntity,
}

impl EbsiDidVersion {
    const fn version_byte(self) -> u8 {
        match self {
            EbsiDidVersion::LegalEntity => EBSI_V1_VERSION_BYTE,
        }
    }

    const fn payload_len(self) -> usize {
        match self {
            EbsiDidVersion::LegalEntity => EBSI_V1_PAYLOAD_LEN,
        }
    }

    const fn from_version_byte(byte: u8) -> Option<Self> {
        match byte {
            EBSI_V1_VERSION_BYTE => Some(EbsiDidVersion::LegalEntity),
            _ => None,
        }
    }
}

/// Audit-safe did:ebsi failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidEbsiErrorReason {
    /// The DID did not start with `did:ebsi:`.
    InvalidPrefix,
    /// The method-specific identifier was empty.
    EmptyIdentifier,
    /// The identifier did not use multibase Base58 BTC.
    MissingMultibasePrefix,
    /// The identifier contained a character outside the Bitcoin Base58 alphabet.
    InvalidBase58,
    /// The identifier was not the unique base58btc encoding of its byte envelope.
    NonCanonicalEncoding,
    /// The method-specific identifier exceeded the legal-entity envelope bound.
    IdentifierTooLong,
    /// The decoded version byte is not supported.
    UnsupportedVersion,
    /// The decoded payload length does not match the version envelope.
    InvalidPayloadLength,
    /// Checked arithmetic failed while converting between bases.
    ArithmeticOverflow,
    /// A registry document was malformed or violated the legal-entity profile.
    InvalidDocument,
    /// The registry document identifier did not match the requested DID.
    DocumentIdentifierMismatch,
    /// The JSON response exceeded its byte, depth, or node limit.
    DocumentLimitExceeded,
    /// Version selectors were ambiguous or a timestamp was not RFC 3339.
    InvalidVersionSelector,
    /// The registry returned a version outside the requested historical point.
    HistoricalVersionMismatch,
    /// Registry status and document metadata contradicted each other.
    ResolutionResultInvalid,
    /// A verification method used an algorithm outside the supported profile.
    UnsupportedAlgorithm,
    /// A public JWK contained inconsistent use or key-operations metadata.
    InvalidKeyUsage,
    /// A write-capable document had no usable capabilityInvocation method.
    CapabilityInvocationMissing,
    /// A requested registry mutation was not authorized by the current document.
    UnauthorizedWrite,
    /// No authenticated registry provider was supplied.
    ProviderUnavailable,
    /// The supplied registry provider was not authenticated for the operation.
    ProviderUnauthenticated,
    /// The registry provider failed without exposing backend response text.
    ProviderFailure,
    /// A document or verification-method validity interval was malformed.
    InvalidTimeline,
    /// A provider result regressed below a caller-observed registry version.
    RollbackDetected,
    /// A DID URL was relative, malformed, or not in canonical form.
    InvalidDidUrl,
}

/// Typed did:ebsi method error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("invalid did:ebsi method identifier")]
pub struct DidEbsiError {
    /// Audit-safe reason for the failure.
    pub reason: DidEbsiErrorReason,
}

impl DidEbsiError {
    pub(crate) const fn new(reason: DidEbsiErrorReason) -> Self {
        Self { reason }
    }
}

impl From<DidEbsiErrorReason> for IdentityCoreErrorReason {
    fn from(reason: DidEbsiErrorReason) -> Self {
        match reason {
            DidEbsiErrorReason::InvalidPrefix => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_PREFIX
            }
            DidEbsiErrorReason::EmptyIdentifier => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_EMPTY_IDENTIFIER
            }
            DidEbsiErrorReason::MissingMultibasePrefix => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_UNSUPPORTED_MULTIBASE
            }
            DidEbsiErrorReason::InvalidBase58 => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_BASE58
            }
            DidEbsiErrorReason::NonCanonicalEncoding => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_CANONICAL_ENCODING_FAILED
            }
            DidEbsiErrorReason::IdentifierTooLong => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_PAYLOAD_LENGTH
            }
            DidEbsiErrorReason::UnsupportedVersion => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_UNSUPPORTED_VERSION
            }
            DidEbsiErrorReason::InvalidPayloadLength => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_PAYLOAD_LENGTH
            }
            DidEbsiErrorReason::ArithmeticOverflow => {
                Self::IDENTITY_CORE_ERROR_REASON_ARITHMETIC_OVERFLOW
            }
            DidEbsiErrorReason::UnsupportedAlgorithm => {
                Self::IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_ALGORITHM
            }
            DidEbsiErrorReason::InvalidKeyUsage => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_PUBLIC_JWK
            }
            DidEbsiErrorReason::ProviderUnavailable => {
                Self::IDENTITY_CORE_ERROR_REASON_BACKEND_UNAVAILABLE
            }
            DidEbsiErrorReason::UnauthorizedWrite | DidEbsiErrorReason::ProviderUnauthenticated => {
                Self::IDENTITY_CORE_ERROR_REASON_POLICY_VIOLATION
            }
            DidEbsiErrorReason::InvalidDocument
            | DidEbsiErrorReason::DocumentIdentifierMismatch
            | DidEbsiErrorReason::DocumentLimitExceeded
            | DidEbsiErrorReason::InvalidVersionSelector
            | DidEbsiErrorReason::HistoricalVersionMismatch
            | DidEbsiErrorReason::ResolutionResultInvalid
            | DidEbsiErrorReason::CapabilityInvocationMissing
            | DidEbsiErrorReason::ProviderFailure
            | DidEbsiErrorReason::InvalidTimeline
            | DidEbsiErrorReason::RollbackDetected
            | DidEbsiErrorReason::InvalidDidUrl => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOCUMENT
            }
        }
    }
}

impl From<DidEbsiError> for IdentityCoreErrorReason {
    fn from(error: DidEbsiError) -> Self {
        error.reason.into()
    }
}

#[cfg(test)]
#[path = "lib_proto_error_tests.rs"]
mod proto_error_tests;

/// Decoded did:ebsi method-specific identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbsiDidIdentifier {
    /// Identifier envelope version.
    pub version: EbsiDidVersion,
    /// Version-specific payload bytes.
    pub payload: Vec<u8>,
}

/// Generate a did:ebsi identifier from a version and version-specific payload.
pub fn generate_did_ebsi(version: EbsiDidVersion, payload: &[u8]) -> Result<String, DidEbsiError> {
    if payload.len() != version.payload_len() {
        return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidPayloadLength));
    }

    let capacity = payload
        .len()
        .checked_add(1)
        .ok_or(DidEbsiError::new(DidEbsiErrorReason::ArithmeticOverflow))?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.push(version.version_byte());
    bytes.extend_from_slice(payload);

    Ok(format!(
        "{DID_EBSI_PREFIX}{BASE58BTC_MULTIBASE_PREFIX}{}",
        base58_encode(&bytes)?
    ))
}

/// Validate and decode a did:ebsi identifier.
pub fn parse_did_ebsi(did: &str) -> Result<EbsiDidIdentifier, DidEbsiError> {
    let method_specific = did
        .strip_prefix(DID_EBSI_PREFIX)
        .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidPrefix))?;
    if method_specific.is_empty() {
        return Err(DidEbsiError::new(DidEbsiErrorReason::EmptyIdentifier));
    }
    let encoded = method_specific
        .strip_prefix(BASE58BTC_MULTIBASE_PREFIX)
        .ok_or(DidEbsiError::new(
            DidEbsiErrorReason::MissingMultibasePrefix,
        ))?;
    if encoded.is_empty() {
        return Err(DidEbsiError::new(DidEbsiErrorReason::EmptyIdentifier));
    }
    if encoded.len() > MAX_EBSI_V1_BASE58_DIGITS {
        return Err(DidEbsiError::new(DidEbsiErrorReason::IdentifierTooLong));
    }
    // Version 1 starts with byte 0x01, so a leading base58 zero is never part
    // of its canonical representation even if the decoded length later fails.
    if encoded.starts_with('1') {
        return Err(DidEbsiError::new(DidEbsiErrorReason::NonCanonicalEncoding));
    }

    let decoded = base58_decode(encoded)?;
    if decoded.len() != EBSI_V1_ENVELOPE_LEN {
        return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidPayloadLength));
    }
    if base58_encode(&decoded)?.as_str() != encoded {
        return Err(DidEbsiError::new(DidEbsiErrorReason::NonCanonicalEncoding));
    }
    let (version_byte, payload) = decoded
        .split_first()
        .ok_or(DidEbsiError::new(DidEbsiErrorReason::EmptyIdentifier))?;
    let version = EbsiDidVersion::from_version_byte(*version_byte)
        .ok_or(DidEbsiError::new(DidEbsiErrorReason::UnsupportedVersion))?;
    if payload.len() != version.payload_len() {
        return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidPayloadLength));
    }

    Ok(EbsiDidIdentifier {
        version,
        payload: payload.to_vec(),
    })
}

/// Return true when the DID is a syntactically valid did:ebsi identifier.
pub fn is_valid_did_ebsi(did: &str) -> bool {
    parse_did_ebsi(did).is_ok()
}

fn base58_encode(input: &[u8]) -> Result<String, DidEbsiError> {
    if input.is_empty() {
        return Err(DidEbsiError::new(DidEbsiErrorReason::EmptyIdentifier));
    }

    let mut digits = vec![0u8];
    for byte in input {
        let mut carry = u32::from(*byte);
        for digit in &mut digits {
            let value = u32::from(*digit)
                .checked_mul(256)
                .and_then(|current| current.checked_add(carry))
                .ok_or(DidEbsiError::new(DidEbsiErrorReason::ArithmeticOverflow))?;
            *digit = u8::try_from(value % 58)
                .map_err(|_| DidEbsiError::new(DidEbsiErrorReason::ArithmeticOverflow))?;
            carry = value / 58;
        }

        while carry > 0 {
            digits.push(
                u8::try_from(carry % 58)
                    .map_err(|_| DidEbsiError::new(DidEbsiErrorReason::ArithmeticOverflow))?,
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
            .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidBase58))?;
        out.push(char::from(*ch));
    }

    Ok(out)
}

fn base58_decode(input: &str) -> Result<Vec<u8>, DidEbsiError> {
    if input.is_empty() {
        return Err(DidEbsiError::new(DidEbsiErrorReason::EmptyIdentifier));
    }

    let mut bytes = vec![0u8];
    for ch in input.bytes() {
        let mut carry = u32::from(
            base58_value(ch).ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidBase58))?,
        );
        for byte in &mut bytes {
            let value = u32::from(*byte)
                .checked_mul(58)
                .and_then(|current| current.checked_add(carry))
                .ok_or(DidEbsiError::new(DidEbsiErrorReason::ArithmeticOverflow))?;
            *byte = u8::try_from(value & 0xff)
                .map_err(|_| DidEbsiError::new(DidEbsiErrorReason::ArithmeticOverflow))?;
            carry = value >> 8;
        }

        while carry > 0 {
            bytes.push(
                u8::try_from(carry & 0xff)
                    .map_err(|_| DidEbsiError::new(DidEbsiErrorReason::ArithmeticOverflow))?,
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
