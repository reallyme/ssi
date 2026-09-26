// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

const DID_ION_PREFIX: &str = "did:ion:";
const MAX_DID_BYTES: usize = 24_000;
const TESTNET3_NETWORK: &str = "testnet3";

/// ION network segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IonNetwork {
    /// Mainnet / production network, represented by omitting a network segment.
    Mainnet,
    /// Bitcoin Testnet3 network segment.
    Testnet3,
}

/// Audit-safe did:ion failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidIonErrorReason {
    /// The DID did not start with `did:ion:`.
    InvalidPrefix,
    /// The DID suffix was empty.
    EmptySuffix,
    /// The network segment is not supported by this crate.
    UnsupportedNetwork,
    /// The DID suffix was not unpadded base64url.
    InvalidSuffix,
    /// The long-form suffix data segment was not unpadded base64url.
    InvalidLongFormSuffixData,
    /// The DID had too many colon-separated method-specific segments.
    UnexpectedSegment,
    /// The identifier exceeds the resource budget.
    TooLarge,
    /// The initial-state JSON is malformed, ambiguous, or noncanonical.
    InvalidInitialState,
    /// The canonical suffix data does not hash to the DID suffix.
    SuffixMismatch,
    /// The canonical delta does not hash to the committed delta hash.
    DeltaHashMismatch,
}

/// Typed did:ion method error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("invalid did:ion method identifier")]
pub struct DidIonError {
    /// Audit-safe reason for the failure.
    pub reason: DidIonErrorReason,
}

impl DidIonError {
    pub(crate) const fn new(reason: DidIonErrorReason) -> Self {
        Self { reason }
    }
}

impl From<DidIonErrorReason> for IdentityCoreErrorReason {
    fn from(reason: DidIonErrorReason) -> Self {
        match reason {
            DidIonErrorReason::InvalidPrefix => Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_PREFIX,
            DidIonErrorReason::EmptySuffix => Self::IDENTITY_CORE_ERROR_REASON_DID_EMPTY_IDENTIFIER,
            DidIonErrorReason::UnsupportedNetwork => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_UNSUPPORTED_NETWORK
            }
            DidIonErrorReason::InvalidSuffix | DidIonErrorReason::InvalidLongFormSuffixData => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_BASE64URL
            }
            DidIonErrorReason::TooLarge
            | DidIonErrorReason::InvalidInitialState
            | DidIonErrorReason::SuffixMismatch
            | DidIonErrorReason::DeltaHashMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_INVALID_ENCODING
            }
            DidIonErrorReason::UnexpectedSegment => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_UNEXPECTED_SEGMENT
            }
        }
    }
}

impl From<DidIonError> for IdentityCoreErrorReason {
    fn from(error: DidIonError) -> Self {
        error.reason.into()
    }
}

#[cfg(test)]
#[path = "lib_proto_error_tests.rs"]
mod proto_error_tests;

/// Decoded did:ion identifier shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IonDidIdentifier<'a> {
    /// ION network.
    pub network: IonNetwork,
    /// Sidetree DID suffix.
    pub did_suffix: &'a str,
    /// Optional long-form suffix data segment.
    pub long_form_suffix_data: Option<&'a str>,
}

/// Generate a short-form did:ion identifier.
pub fn generate_did_ion(network: IonNetwork, did_suffix: &str) -> Result<String, DidIonError> {
    crate::validate_initial_state::validate_suffix(did_suffix)?;

    match network {
        IonNetwork::Mainnet => Ok(format!("{DID_ION_PREFIX}{did_suffix}")),
        IonNetwork::Testnet3 => Ok(format!("{DID_ION_PREFIX}{TESTNET3_NETWORK}:{did_suffix}")),
    }
}

/// Generate a long-form did:ion identifier.
pub fn generate_long_form_did_ion(
    network: IonNetwork,
    did_suffix: &str,
    long_form_suffix_data: &str,
) -> Result<String, DidIonError> {
    crate::validate_initial_state::validate_suffix(did_suffix)?;
    crate::validate_initial_state::validate_initial_state(did_suffix, long_form_suffix_data)?;

    match network {
        IonNetwork::Mainnet => Ok(format!(
            "{DID_ION_PREFIX}{did_suffix}:{long_form_suffix_data}"
        )),
        IonNetwork::Testnet3 => Ok(format!(
            "{DID_ION_PREFIX}{TESTNET3_NETWORK}:{did_suffix}:{long_form_suffix_data}"
        )),
    }
}

/// Return the short-form equivalent for a did:ion identifier.
pub fn short_form_did_ion(did: &str) -> Result<String, DidIonError> {
    let parsed = parse_did_ion(did)?;
    generate_did_ion(parsed.network, parsed.did_suffix)
}

/// Validate and decode a did:ion identifier.
pub fn parse_did_ion(did: &str) -> Result<IonDidIdentifier<'_>, DidIonError> {
    if did.len() > MAX_DID_BYTES {
        return Err(DidIonError::new(DidIonErrorReason::TooLarge));
    }
    let method_specific = did
        .strip_prefix(DID_ION_PREFIX)
        .ok_or(DidIonError::new(DidIonErrorReason::InvalidPrefix))?;
    let parts: Vec<&str> = method_specific.splitn(5, ':').collect();

    match parts.as_slice() {
        [suffix] => parse_mainnet_short(suffix),
        [TESTNET3_NETWORK, suffix] => parse_network_short(suffix),
        [network, _suffix] if is_network_like(network) => {
            Err(DidIonError::new(DidIonErrorReason::UnsupportedNetwork))
        }
        [suffix, long_form_suffix_data] => parse_mainnet_long(suffix, long_form_suffix_data),
        [TESTNET3_NETWORK, suffix, long_form_suffix_data] => {
            parse_network_long(suffix, long_form_suffix_data)
        }
        [network, _suffix, _long_form_suffix_data] => {
            if is_network_like(network) {
                Err(DidIonError::new(DidIonErrorReason::UnsupportedNetwork))
            } else {
                Err(DidIonError::new(DidIonErrorReason::UnexpectedSegment))
            }
        }
        _ => Err(DidIonError::new(DidIonErrorReason::UnexpectedSegment)),
    }
}

/// Return true when the DID is a syntactically valid did:ion identifier.
pub fn is_valid_did_ion(did: &str) -> bool {
    parse_did_ion(did).is_ok()
}

fn parse_mainnet_short(suffix: &str) -> Result<IonDidIdentifier<'_>, DidIonError> {
    crate::validate_initial_state::validate_suffix(suffix)?;
    Ok(IonDidIdentifier {
        network: IonNetwork::Mainnet,
        did_suffix: suffix,
        long_form_suffix_data: None,
    })
}

fn parse_network_short(suffix: &str) -> Result<IonDidIdentifier<'_>, DidIonError> {
    crate::validate_initial_state::validate_suffix(suffix)?;
    Ok(IonDidIdentifier {
        network: IonNetwork::Testnet3,
        did_suffix: suffix,
        long_form_suffix_data: None,
    })
}

fn parse_mainnet_long<'a>(
    suffix: &'a str,
    long_form_suffix_data: &'a str,
) -> Result<IonDidIdentifier<'a>, DidIonError> {
    crate::validate_initial_state::validate_suffix(suffix)?;
    crate::validate_initial_state::validate_initial_state(suffix, long_form_suffix_data)?;
    Ok(IonDidIdentifier {
        network: IonNetwork::Mainnet,
        did_suffix: suffix,
        long_form_suffix_data: Some(long_form_suffix_data),
    })
}

fn parse_network_long<'a>(
    suffix: &'a str,
    long_form_suffix_data: &'a str,
) -> Result<IonDidIdentifier<'a>, DidIonError> {
    crate::validate_initial_state::validate_suffix(suffix)?;
    crate::validate_initial_state::validate_initial_state(suffix, long_form_suffix_data)?;
    Ok(IonDidIdentifier {
        network: IonNetwork::Testnet3,
        did_suffix: suffix,
        long_form_suffix_data: Some(long_form_suffix_data),
    })
}

fn is_network_like(segment: &str) -> bool {
    segment.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
    })
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
