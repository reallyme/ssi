// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{CoreVerificationMethod, UpdatePolicy};
use identity_core_primitives::algorithm_map::alg_to_did_alg_str;
use identity_core_primitives::Algorithm;
use reallyme_codec::cbor::{encode_dag_cbor, CborValue};
use reallyme_crypto::sha2::digest as sha2_256_digest;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

use crate::error::DidCoreError;

mod bech32;

use bech32::{bech32_encode, decode_bech32_payload};

const DID_ME_PREFIX: &str = "did:me:";
const DID_ME_HRP: &str = "me";
const IDENTIFIER_PAYLOAD_LEN: usize = 16;
/// Domain-separation tag for deterministic did:me genesis identifiers.
pub const GENESIS_DOMAIN_TAG: &[u8] = b"did:me:v1:genesis";
/// Domain-separation tag for did:me core attestations.
///
/// Re-exported from the core engine so signing and verification share one definition.
pub const CORE_SIGNATURE_DOMAIN_TAG: &[u8] = b"did:me:v1:core";
/// Required nonce length for did:me v1 genesis bindings.
pub const GENESIS_NONCE_LEN: usize = 16;

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
    /// The method-specific identifier exceeded the Bech32 length limit.
    IdentifierTooLong,
}

/// Typed did:me method error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("invalid did:me method identifier")]
pub struct DidMeError {
    /// Audit-safe reason for the failure.
    pub reason: DidMeErrorReason,
}

impl DidMeError {
    pub(super) const fn new(reason: DidMeErrorReason) -> Self {
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
            DidMeErrorReason::IdentifierTooLong => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_METHOD_IDENTIFIER
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
#[path = "identifier_proto_error_tests.rs"]
mod proto_error_tests;

/// Decoded did:me method-specific identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DidMeIdentifier {
    /// The 16-byte genesis payload encoded in the Bech32 data part.
    pub payload: [u8; IDENTIFIER_PAYLOAD_LEN],
}

/// Build the byte string signed by did:me core attestation keys.
pub fn core_signature_input(core_bytes: &[u8]) -> Result<Vec<u8>, DidCoreError> {
    let capacity = CORE_SIGNATURE_DOMAIN_TAG
        .len()
        .checked_add(core_bytes.len())
        .ok_or(DidCoreError::InternalInvariant)?;
    let mut input = Vec::with_capacity(capacity);
    input.extend_from_slice(CORE_SIGNATURE_DOMAIN_TAG);
    input.extend_from_slice(core_bytes);
    Ok(input)
}

/// Reject genesis update policies that could never be satisfied.
fn validate_genesis_update_policy(update_policy: &UpdatePolicy) -> Result<(), DidMeError> {
    match update_policy.threshold {
        None => Ok(()),
        Some(threshold) => {
            let threshold = usize::try_from(threshold)
                .map_err(|_| DidMeError::new(DidMeErrorReason::InvalidUpdatePolicy))?;
            if threshold == 0 || threshold > update_policy.allowed_verification_methods.len() {
                Err(DidMeError::new(DidMeErrorReason::InvalidUpdatePolicy))
            } else {
                Ok(())
            }
        }
    }
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
    validate_genesis_update_policy(update_policy)?;
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
    let fixed_payload = decode_bech32_payload(method_specific, DID_ME_HRP)?;

    Ok(DidMeIdentifier {
        payload: fixed_payload,
    })
}

/// Return true when a DID is a syntactically valid did:me v1 identifier.
pub fn is_valid_did_me(did: &str) -> bool {
    parse_did_me(did).is_ok()
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

fn core_key_to_cbor(vm: &CoreVerificationMethod) -> CborValue {
    CborValue::Map(vec![
        ("id".into(), CborValue::String(vm.id.clone())),
        ("type".into(), CborValue::String(vm.vm_type.clone())),
        (
            "algorithm".into(),
            CborValue::String(alg_to_did_alg_str(vm.algorithm).into()),
        ),
        (
            "publicKeyMultibase".into(),
            CborValue::String(vm.public_key_multibase.clone()),
        ),
    ])
}

fn parse_update_policy(core: &CborValue) -> Result<UpdatePolicy, DidMeError> {
    let policy = map_get(core, "updatePolicy")
        .ok_or(DidMeError::new(DidMeErrorReason::InvalidUpdatePolicy))?;

    let allowed = match map_get(policy, "allowedVerificationMethods") {
        Some(CborValue::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    CborValue::String(value) => out.push(value.clone()),
                    _ => return Err(DidMeError::new(DidMeErrorReason::InvalidUpdatePolicy)),
                }
            }
            out
        }
        _ => return Err(DidMeError::new(DidMeErrorReason::InvalidUpdatePolicy)),
    };

    let threshold = match map_get(policy, "threshold") {
        Some(CborValue::Int(value)) if *value > 0 => Some(
            u64::try_from(*value)
                .map_err(|_| DidMeError::new(DidMeErrorReason::InvalidUpdatePolicy))?,
        ),
        Some(_) => return Err(DidMeError::new(DidMeErrorReason::InvalidUpdatePolicy)),
        None => None,
    };

    Ok(UpdatePolicy {
        allowed_verification_methods: allowed,
        threshold,
    })
}

fn parse_controller_keys(core: &CborValue) -> Result<Vec<CoreVerificationMethod>, DidMeError> {
    let keys = match map_get(core, "controllerKeys") {
        Some(CborValue::Array(items)) => items,
        _ => return Err(DidMeError::new(DidMeErrorReason::InvalidControllerKeys)),
    };

    let mut out = Vec::with_capacity(keys.len());
    for key in keys {
        let id = map_get_string(key, "id")
            .ok_or(DidMeError::new(DidMeErrorReason::InvalidControllerKeys))?
            .to_owned();
        let vm_type = map_get_string(key, "type")
            .ok_or(DidMeError::new(DidMeErrorReason::InvalidControllerKeys))?
            .to_owned();
        let algorithm = map_get_string(key, "algorithm")
            .ok_or(DidMeError::new(DidMeErrorReason::InvalidControllerKeys))?;
        let public_key_multibase = map_get_string(key, "publicKeyMultibase")
            .ok_or(DidMeError::new(DidMeErrorReason::InvalidControllerKeys))?
            .to_owned();
        let algorithm = algorithm
            .parse::<Algorithm>()
            .map_err(|_| DidMeError::new(DidMeErrorReason::InvalidAlgorithm))?;

        out.push(CoreVerificationMethod {
            id,
            vm_type,
            algorithm,
            public_key_multibase,
        });
    }

    Ok(out)
}

/// Controller keys must be strictly ascending by id, which also rejects duplicate ids.
fn controller_keys_are_sorted_by_id(keys: &[CoreVerificationMethod]) -> bool {
    keys.windows(2)
        .all(|pair| matches!(pair, [left, right] if left.id.as_bytes() < right.id.as_bytes()))
}

fn map_get<'a>(core: &'a CborValue, key: &str) -> Option<&'a CborValue> {
    match core {
        CborValue::Map(entries) => {
            entries
                .iter()
                .find_map(|(candidate, value)| if candidate == key { Some(value) } else { None })
        }
        _ => None,
    }
}

fn map_get_string<'a>(core: &'a CborValue, key: &str) -> Option<&'a str> {
    match map_get(core, key) {
        Some(CborValue::String(value)) => Some(value),
        _ => None,
    }
}
