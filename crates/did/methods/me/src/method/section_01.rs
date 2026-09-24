// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_core_primitives::algorithm_map::alg_to_did_alg_str;
use identity_core_primitives::Algorithm;
use reallyme_codec::cbor::{encode_dag_cbor, CborValue};
use reallyme_crypto::sha2::digest as sha2_256_digest;
use reallyme_did_core::{CoreVerificationMethod, UpdatePolicy};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

const DID_ME_PREFIX: &str = "did:me:";
const DID_ME_HRP: &str = "me";
const IDENTIFIER_PAYLOAD_LEN: usize = 16;
/// Domain-separation tag for deterministic did:me genesis identifiers.
pub const GENESIS_DOMAIN_TAG: &[u8] = b"did:me:v1:genesis";
/// Domain-separation tag for did:me core attestations.
pub const CORE_SIGNATURE_DOMAIN_TAG: &[u8] = b"did:me:v1:core";
/// Required nonce length for did:me v1 genesis bindings.
pub const GENESIS_NONCE_LEN: usize = 16;
const BECH32_CHECKSUM_LEN: usize = 6;
const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

/// Non-secret reason codes for did:me method identifier failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidMeErrorReason {
    /// The DID did not start with the required method prefix.
    InvalidPrefix,
    /// The Bech32 human-readable part was not the did:me v1 `me` HRP.
    InvalidHrp,
    /// The method-specific identifier contained characters outside Bech32.
    InvalidCharacter,
    /// The Bech32 checksum did not verify.
    InvalidChecksum,
    /// The Bech32 data payload was malformed or used non-zero padding.
    InvalidData,
    /// The decoded identifier payload was not the did:me v1 16-byte payload.
    InvalidPayloadLength,
    /// The genesis nonce was missing or did not have the did:me v1 length.
    InvalidGenesisNonce,
    /// A CBOR core value omitted `updatePolicy` or encoded it with the wrong shape.
    InvalidUpdatePolicy,
    /// A CBOR core value omitted `controllerKeys` or encoded them with the wrong shape.
    InvalidControllerKeys,
    /// A CBOR controller key algorithm was not recognized.
    InvalidAlgorithm,
    /// The derived genesis identifier did not match the supplied DID.
    GenesisIdentifierMismatch,
    /// Canonical DAG-CBOR encoding failed.
    CanonicalEncoding,
}

/// Typed did:me method error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("invalid did:me method identifier")]
pub struct DidMeError {
    /// Audit-safe reason for the failure.
    pub reason: DidMeErrorReason,
}

impl DidMeError {
    const fn new(reason: DidMeErrorReason) -> Self {
        Self { reason }
    }
}

impl From<DidMeErrorReason> for IdentityCoreErrorReason {
    fn from(reason: DidMeErrorReason) -> Self {
        match reason {
            DidMeErrorReason::InvalidPrefix => Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_PREFIX,
            DidMeErrorReason::InvalidHrp
            | DidMeErrorReason::InvalidCharacter
            | DidMeErrorReason::InvalidData => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_METHOD_IDENTIFIER
            }
            DidMeErrorReason::InvalidChecksum => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_CHECKSUM
            }
            DidMeErrorReason::InvalidPayloadLength => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_PAYLOAD_LENGTH
            }
            DidMeErrorReason::InvalidGenesisNonce => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_GENESIS_NONCE
            }
            DidMeErrorReason::InvalidUpdatePolicy => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_UPDATE_POLICY
            }
            DidMeErrorReason::InvalidControllerKeys => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_CONTROLLER_KEYS
            }
            DidMeErrorReason::InvalidAlgorithm => {
                Self::IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_ALGORITHM
            }
            DidMeErrorReason::GenesisIdentifierMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_GENESIS_IDENTIFIER_MISMATCH
            }
            DidMeErrorReason::CanonicalEncoding => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_CANONICAL_ENCODING_FAILED
            }
        }
    }
}

impl From<DidMeError> for IdentityCoreErrorReason {
    fn from(error: DidMeError) -> Self {
        error.reason.into()
    }
}

#[cfg(test)]
#[path = "../lib_proto_error_tests.rs"]
mod proto_error_tests;

/// Decoded did:me method-specific identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DidMeIdentifier {
    /// The 16-byte genesis payload encoded in the Bech32 data part.
    pub payload: [u8; IDENTIFIER_PAYLOAD_LEN],
}

/// Build the byte string signed by did:me core attestation keys.
pub fn core_signature_input(core_bytes: &[u8]) -> Result<Vec<u8>, DidMeError> {
    let capacity = CORE_SIGNATURE_DOMAIN_TAG
        .len()
        .checked_add(core_bytes.len())
        .ok_or(DidMeError::new(DidMeErrorReason::CanonicalEncoding))?;
    let mut input = Vec::with_capacity(capacity);
    input.extend_from_slice(CORE_SIGNATURE_DOMAIN_TAG);
    input.extend_from_slice(core_bytes);
    Ok(input)
}

/// Encode the deterministic GenesisBinding object from did:me v1 Section 2.5.
pub fn genesis_binding_cbor(
    nonce: &[u8],
    update_policy: &UpdatePolicy,
    controller_keys: &[CoreVerificationMethod],
) -> Result<Vec<u8>, DidMeError> {
    if nonce.len() != GENESIS_NONCE_LEN {
        return Err(DidMeError::new(DidMeErrorReason::InvalidGenesisNonce));
    }

    let mut sorted_controller_keys = controller_keys.to_vec();
    sorted_controller_keys.sort_by(|a, b| a.id.as_bytes().cmp(b.id.as_bytes()));

    let value = CborValue::Map(vec![
        ("nonce".into(), CborValue::Bytes(nonce.to_vec())),
        ("updatePolicy".into(), update_policy_to_cbor(update_policy)?),
        (
            "controllerKeys".into(),
            CborValue::Array(
                sorted_controller_keys
                    .iter()
                    .map(core_key_to_cbor)
                    .collect(),
            ),
        ),
    ]);

    encode_dag_cbor(&value).map_err(|_| DidMeError::new(DidMeErrorReason::CanonicalEncoding))
}

/// Derive the fixed 128-bit did:me identifier payload from a canonical GenesisBinding.
pub fn derive_identifier_payload(
    binding_cbor: &[u8],
) -> Result<[u8; IDENTIFIER_PAYLOAD_LEN], DidMeError> {
    let capacity = GENESIS_DOMAIN_TAG
        .len()
        .checked_add(binding_cbor.len())
        .ok_or(DidMeError::new(DidMeErrorReason::CanonicalEncoding))?;
    let mut input = Vec::with_capacity(capacity);
    input.extend_from_slice(GENESIS_DOMAIN_TAG);
    input.extend_from_slice(binding_cbor);

    let digest = sha2_256_digest(&input);
    let mut payload = [0u8; IDENTIFIER_PAYLOAD_LEN];
    payload.copy_from_slice(&digest.as_bytes()[..IDENTIFIER_PAYLOAD_LEN]);
    Ok(payload)
}

/// Generate the did:me DID bound to a sequence-one genesis binding.
pub fn generate_did_me(
    nonce: &[u8],
    update_policy: &UpdatePolicy,
    controller_keys: &[CoreVerificationMethod],
) -> Result<String, DidMeError> {
    let binding = genesis_binding_cbor(nonce, update_policy, controller_keys)?;
    let payload = derive_identifier_payload(&binding)?;
    let bech32 = bech32_encode(DID_ME_HRP, &payload)?;
    Ok(format!("{DID_ME_PREFIX}{bech32}"))
}

/// Verify a did:me DID against a decoded genesis core CBOR value.
pub fn verify_genesis_core_identifier(did: &str, core: &CborValue) -> Result<(), DidMeError> {
    let nonce = match map_get(core, "nonce") {
        Some(CborValue::Bytes(nonce)) if nonce.len() == GENESIS_NONCE_LEN => nonce,
        _ => return Err(DidMeError::new(DidMeErrorReason::InvalidGenesisNonce)),
    };
    let update_policy = parse_update_policy(core)?;
    let controller_keys = parse_controller_keys(core)?;
    if !controller_keys_are_sorted_by_id(&controller_keys) {
        return Err(DidMeError::new(DidMeErrorReason::InvalidControllerKeys));
    }
    let expected = generate_did_me(nonce, &update_policy, &controller_keys)?;
    if expected == did {
        Ok(())
    } else {
        Err(DidMeError::new(DidMeErrorReason::GenesisIdentifierMismatch))
    }
}

/// Validate and decode a did:me identifier.
pub fn parse_did_me(did: &str) -> Result<DidMeIdentifier, DidMeError> {
    let method_specific = did
        .strip_prefix(DID_ME_PREFIX)
        .ok_or(DidMeError::new(DidMeErrorReason::InvalidPrefix))?;

    let separator = method_specific
        .rfind('1')
        .ok_or(DidMeError::new(DidMeErrorReason::InvalidHrp))?;
    let (hrp, data_with_separator) = method_specific.split_at(separator);
    if hrp != DID_ME_HRP {
        return Err(DidMeError::new(DidMeErrorReason::InvalidHrp));
    }

    let data_part = data_with_separator
        .strip_prefix('1')
        .ok_or(DidMeError::new(DidMeErrorReason::InvalidData))?;
    if data_part.len() <= BECH32_CHECKSUM_LEN {
        return Err(DidMeError::new(DidMeErrorReason::InvalidData));
    }

    let values = bech32_values(data_part.as_bytes())?;
    if !verify_checksum(hrp, &values) {
        return Err(DidMeError::new(DidMeErrorReason::InvalidChecksum));
    }

    let payload_values_len = values
        .len()
        .checked_sub(BECH32_CHECKSUM_LEN)
        .ok_or(DidMeError::new(DidMeErrorReason::InvalidData))?;
    let payload = convert_bits_5_to_8(&values[..payload_values_len])?;
    let fixed_payload = <[u8; IDENTIFIER_PAYLOAD_LEN]>::try_from(payload.as_slice())
        .map_err(|_| DidMeError::new(DidMeErrorReason::InvalidPayloadLength))?;

    Ok(DidMeIdentifier {
        payload: fixed_payload,
    })
}

/// Return true when a DID is a syntactically valid did:me v1 identifier.
pub fn is_valid_did_me(did: &str) -> bool {
    parse_did_me(did).is_ok()
}

fn bech32_values(data: &[u8]) -> Result<Vec<u8>, DidMeError> {
    let mut out = Vec::with_capacity(data.len());
    for byte in data {
        let value =
            bech32_value(*byte).ok_or(DidMeError::new(DidMeErrorReason::InvalidCharacter))?;
        out.push(value);
    }
    Ok(out)
}

fn bech32_encode(hrp: &str, payload: &[u8; IDENTIFIER_PAYLOAD_LEN]) -> Result<String, DidMeError> {
    if hrp.is_empty()
        || !hrp
            .bytes()
            .all(|byte| (33..=126).contains(&byte) && !byte.is_ascii_uppercase())
    {
        return Err(DidMeError::new(DidMeErrorReason::InvalidHrp));
    }

    let mut data = convert_bits_8_to_5(payload);
    let checksum = create_checksum(hrp, &data);
    data.extend_from_slice(&checksum);

    let mut out = String::with_capacity(hrp.len() + 1 + data.len());
    out.push_str(hrp);
    out.push('1');

    for value in data {
        let ch = BECH32_CHARSET
            .get(usize::from(value))
            .ok_or(DidMeError::new(DidMeErrorReason::InvalidCharacter))?;
        out.push(char::from(*ch));
    }

    Ok(out)
}

fn convert_bits_8_to_5(payload: &[u8; IDENTIFIER_PAYLOAD_LEN]) -> Vec<u8> {
    let mut acc: u32 = 0;
    let mut bits: u8 = 0;
    let mut ret = Vec::with_capacity(26);

    for value in payload {
        acc = (acc << 8) | u32::from(*value);
        bits += 8;

        while bits >= 5 {
            bits -= 5;
            ret.push(((acc >> bits) & 0x1f) as u8);
        }
    }

    if bits > 0 {
        ret.push(((acc << (5 - bits)) & 0x1f) as u8);
    }

    ret
}

fn bech32_value(byte: u8) -> Option<u8> {
    let mut index = 0u8;
    for candidate in BECH32_CHARSET {
        if *candidate == byte {
            return Some(index);
        }
        index = index.checked_add(1)?;
    }
    None
}

fn verify_checksum(hrp: &str, values: &[u8]) -> bool {
    let mut expanded = hrp_expand(hrp);
    expanded.extend_from_slice(values);
    polymod(&expanded) == 1
}

fn create_checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);

    let pm = polymod(&values) ^ 1;
    [
        ((pm >> 25) & 0x1f) as u8,
        ((pm >> 20) & 0x1f) as u8,
        ((pm >> 15) & 0x1f) as u8,
        ((pm >> 10) & 0x1f) as u8,
        ((pm >> 5) & 0x1f) as u8,
        (pm & 0x1f) as u8,
    ]
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hrp.len().saturating_mul(2).saturating_add(1));
    out.extend(hrp.bytes().map(|byte| byte >> 5));
    out.push(0);
    out.extend(hrp.bytes().map(|byte| byte & 0x1f));
    out
}

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;

    for value in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(*value);

        for (i, generator) in BECH32_GENERATOR.iter().enumerate() {
            if ((top >> i) & 1) == 1 {
                chk ^= generator;
            }
        }
    }

    chk
}

fn convert_bits_5_to_8(values: &[u8]) -> Result<Vec<u8>, DidMeError> {
    let mut acc: u32 = 0;
    let mut bits: u8 = 0;
    let mut out = Vec::with_capacity(IDENTIFIER_PAYLOAD_LEN);

    for value in values {
        if *value > 31 {
            return Err(DidMeError::new(DidMeErrorReason::InvalidData));
        }
        acc = (acc << 5) | u32::from(*value);
        bits = bits
            .checked_add(5)
            .ok_or(DidMeError::new(DidMeErrorReason::InvalidData))?;

        while bits >= 8 {
            bits -= 8;
            let byte = u8::try_from((acc >> bits) & 0xff)
                .map_err(|_| DidMeError::new(DidMeErrorReason::InvalidData))?;
            out.push(byte);
        }
    }

    if bits > 0 {
        let padding = (acc << (8 - bits)) & 0xff;
        if padding != 0 {
            return Err(DidMeError::new(DidMeErrorReason::InvalidData));
        }
    }

    Ok(out)
}

fn update_policy_to_cbor(p: &UpdatePolicy) -> Result<CborValue, DidMeError> {
    let mut entries = vec![(
        "allowedVerificationMethods".into(),
        CborValue::Array(
            p.allowed_verification_methods
                .iter()
                .cloned()
                .map(CborValue::String)
                .collect(),
        ),
    )];

    if let Some(threshold) = p.threshold {
        let threshold = i64::try_from(threshold)
            .map_err(|_| DidMeError::new(DidMeErrorReason::InvalidUpdatePolicy))?;
        entries.push(("threshold".into(), CborValue::Int(threshold)));
    }

    Ok(CborValue::Map(entries))
}
