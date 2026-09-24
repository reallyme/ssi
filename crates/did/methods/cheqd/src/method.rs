// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

const DID_CHEQD_PREFIX: &str = "did:cheqd:";
const UUID_LEN: usize = 36;
const UUID_HYPHEN_POSITIONS: [usize; 4] = [8, 13, 18, 23];
const INDY_ID_MIN_LEN: usize = 21;
const INDY_ID_MAX_LEN: usize = 22;
const DEFAULT_NAMESPACE: &str = "mainnet";

/// cheqd unique identifier family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheqdIdentifierKind {
    /// UUID-style identifier, preferred by the cheqd method ADR.
    Uuid,
    /// Indy-style alphanumeric identifier.
    IndyStyle,
}

/// Audit-safe did:cheqd failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidCheqdErrorReason {
    /// The DID did not start with `did:cheqd:`.
    InvalidPrefix,
    /// The method-specific identifier was empty.
    EmptyIdentifier,
    /// The namespace segment was empty or not alphanumeric.
    InvalidNamespace,
    /// The unique identifier was empty or malformed.
    InvalidUniqueIdentifier,
    /// The DID had too many colon-separated method-specific segments.
    UnexpectedSegment,
}

/// Typed did:cheqd method error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("invalid did:cheqd method identifier")]
pub struct DidCheqdError {
    /// Audit-safe reason for the failure.
    pub reason: DidCheqdErrorReason,
}

impl DidCheqdError {
    const fn new(reason: DidCheqdErrorReason) -> Self {
        Self { reason }
    }
}

impl From<DidCheqdErrorReason> for IdentityCoreErrorReason {
    fn from(reason: DidCheqdErrorReason) -> Self {
        match reason {
            DidCheqdErrorReason::InvalidPrefix => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_PREFIX
            }
            DidCheqdErrorReason::EmptyIdentifier => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_EMPTY_IDENTIFIER
            }
            DidCheqdErrorReason::InvalidNamespace => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_NAMESPACE
            }
            DidCheqdErrorReason::InvalidUniqueIdentifier => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_UNIQUE_IDENTIFIER
            }
            DidCheqdErrorReason::UnexpectedSegment => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_UNEXPECTED_SEGMENT
            }
        }
    }
}

impl From<DidCheqdError> for IdentityCoreErrorReason {
    fn from(error: DidCheqdError) -> Self {
        error.reason.into()
    }
}

#[cfg(test)]
#[path = "lib_proto_error_tests.rs"]
mod proto_error_tests;

/// Decoded did:cheqd identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheqdDidIdentifier<'a> {
    /// Optional namespace segment. Absence defaults to the target ledger namespace.
    pub namespace: Option<&'a str>,
    /// Unique identifier segment.
    pub unique_id: &'a str,
    /// Unique identifier family.
    pub kind: CheqdIdentifierKind,
}

/// Generate a did:cheqd identifier.
pub fn generate_did_cheqd(
    namespace: Option<&str>,
    unique_id: &str,
) -> Result<String, DidCheqdError> {
    let kind = validate_unique_id(unique_id)?;
    if let Some(namespace) = namespace {
        validate_namespace(namespace)?;
        let did = format!("{DID_CHEQD_PREFIX}{namespace}:{unique_id}");
        parse_did_cheqd(&did)?;
        return Ok(did);
    }

    let did = format!("{DID_CHEQD_PREFIX}{unique_id}");
    let parsed = parse_did_cheqd(&did)?;
    if parsed.kind != kind {
        return Err(DidCheqdError::new(
            DidCheqdErrorReason::InvalidUniqueIdentifier,
        ));
    }
    Ok(did)
}

/// Return the effective namespace for a did:cheqd identifier.
pub fn effective_namespace(did: &str) -> Result<&str, DidCheqdError> {
    let parsed = parse_did_cheqd(did)?;
    Ok(parsed.namespace.unwrap_or(DEFAULT_NAMESPACE))
}

/// Validate and decode a did:cheqd identifier.
pub fn parse_did_cheqd(did: &str) -> Result<CheqdDidIdentifier<'_>, DidCheqdError> {
    let method_specific = did
        .strip_prefix(DID_CHEQD_PREFIX)
        .ok_or(DidCheqdError::new(DidCheqdErrorReason::InvalidPrefix))?;
    if method_specific.is_empty() {
        return Err(DidCheqdError::new(DidCheqdErrorReason::EmptyIdentifier));
    }

    let parts: Vec<&str> = method_specific.split(':').collect();
    match parts.as_slice() {
        [unique_id] => {
            let kind = validate_unique_id(unique_id)?;
            Ok(CheqdDidIdentifier {
                namespace: None,
                unique_id,
                kind,
            })
        }
        [namespace, unique_id] => {
            validate_namespace(namespace)?;
            let kind = validate_unique_id(unique_id)?;
            Ok(CheqdDidIdentifier {
                namespace: Some(namespace),
                unique_id,
                kind,
            })
        }
        _ => Err(DidCheqdError::new(DidCheqdErrorReason::UnexpectedSegment)),
    }
}

/// Return true when the DID is a syntactically valid did:cheqd identifier.
pub fn is_valid_did_cheqd(did: &str) -> bool {
    parse_did_cheqd(did).is_ok()
}

fn validate_namespace(namespace: &str) -> Result<(), DidCheqdError> {
    if namespace.is_empty() || !namespace.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(DidCheqdError::new(DidCheqdErrorReason::InvalidNamespace));
    }
    Ok(())
}

fn validate_unique_id(unique_id: &str) -> Result<CheqdIdentifierKind, DidCheqdError> {
    if unique_id.is_empty() {
        return Err(DidCheqdError::new(
            DidCheqdErrorReason::InvalidUniqueIdentifier,
        ));
    }
    if is_uuid(unique_id) {
        return Ok(CheqdIdentifierKind::Uuid);
    }
    if is_indy_style_id(unique_id) {
        return Ok(CheqdIdentifierKind::IndyStyle);
    }
    Err(DidCheqdError::new(
        DidCheqdErrorReason::InvalidUniqueIdentifier,
    ))
}

fn is_uuid(value: &str) -> bool {
    if value.len() != UUID_LEN {
        return false;
    }

    for (index, byte) in value.bytes().enumerate() {
        if UUID_HYPHEN_POSITIONS.contains(&index) {
            if byte != b'-' {
                return false;
            }
            continue;
        }
        if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn is_indy_style_id(value: &str) -> bool {
    if value.len() < INDY_ID_MIN_LEN || value.len() > INDY_ID_MAX_LEN {
        return false;
    }
    value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
