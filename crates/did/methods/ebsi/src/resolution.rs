// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Historical-selection invariants for injected EBSI registry resolution.

use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{parse_did_ebsi, DidEbsiDocument, DidEbsiError, DidEbsiErrorReason};

const MAX_SELECTOR_BYTES: usize = 4096;
const MAX_METADATA_BYTES: usize = 1024;

/// Canonical inputs forwarded to an injected EBSI registry resolver.
pub struct DidEbsiResolveRequest {
    /// Legal-entity DID to resolve.
    pub did: String,
    /// Exact registry version identifier, when selected by identifier.
    pub version_id: Option<String>,
    /// RFC 3339 instant at which the registry document must have been valid.
    pub version_time: Option<String>,
    /// Lowest registry sequence the caller has already accepted for this DID.
    pub minimum_version_sequence: Option<u64>,
}

impl core::fmt::Debug for DidEbsiResolveRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidEbsiResolveRequest(<redacted>)")
    }
}

impl Zeroize for DidEbsiResolveRequest {
    fn zeroize(&mut self) {
        self.did.zeroize();
        self.version_id.zeroize();
        self.version_time.zeroize();
        self.minimum_version_sequence = None;
    }
}

impl Drop for DidEbsiResolveRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DidEbsiResolveRequest {}

/// Stable lifecycle state returned by an EBSI registry adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidEbsiResolutionStatus {
    /// A usable document was valid at the selected point.
    Active,
    /// The selected registry state has no usable keys.
    Deactivated,
    /// No registry entry exists at the selected point.
    Absent,
}

/// Verification strength achieved by an EBSI registry adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidEbsiResolutionAssurance {
    /// The adapter verified controller attestations.
    AttestationVerified,
    /// The adapter verified the registry history chain.
    ChainVerified,
}

/// Registry timeline metadata used to prove historical selection.
pub struct DidEbsiRegistryMetadata {
    /// Stable registry version identifier.
    pub version_id: String,
    /// Monotonic registry sequence for rollback detection.
    pub version_sequence: u64,
    /// Previous registry version identifier, absent only for sequence one.
    pub previous_version_id: Option<String>,
    /// Inclusive RFC 3339 start of this version's validity interval.
    pub valid_from: String,
    /// Exclusive RFC 3339 end, or no end for the current version.
    pub valid_until: Option<String>,
}

impl core::fmt::Debug for DidEbsiRegistryMetadata {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidEbsiRegistryMetadata(<redacted>)")
    }
}

impl Zeroize for DidEbsiRegistryMetadata {
    fn zeroize(&mut self) {
        self.version_id.zeroize();
        self.version_sequence = 0;
        self.previous_version_id.zeroize();
        self.valid_from.zeroize();
        self.valid_until.zeroize();
    }
}

impl Drop for DidEbsiRegistryMetadata {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DidEbsiRegistryMetadata {}

/// Provider-produced EBSI resolution awaiting canonical invariant checks.
pub struct DidEbsiResolution {
    /// Validated registry document for active or deactivated states.
    pub document: Option<DidEbsiDocument>,
    /// Registry timeline metadata for a present document.
    pub registry_metadata: Option<DidEbsiRegistryMetadata>,
    /// Lifecycle state at the selected version or time.
    pub status: DidEbsiResolutionStatus,
    /// RFC 3339 instant at which the registry response was observed.
    pub retrieved_at: Option<String>,
    /// Stable non-secret resolver identifier.
    pub resolver: Option<String>,
    /// Verification strength achieved for this result.
    pub assurance_achieved: Option<DidEbsiResolutionAssurance>,
}

impl core::fmt::Debug for DidEbsiResolution {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidEbsiResolution(<redacted>)")
    }
}

impl Zeroize for DidEbsiResolution {
    fn zeroize(&mut self) {
        self.document = None;
        self.registry_metadata = None;
        self.retrieved_at.zeroize();
        self.resolver.zeroize();
        self.assurance_achieved = None;
    }
}

impl Drop for DidEbsiResolution {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DidEbsiResolution {}

/// Validate exact identifier and historical-version correlation.
pub fn validate_did_ebsi_resolution(
    request: &DidEbsiResolveRequest,
    result: &DidEbsiResolution,
) -> Result<(), DidEbsiError> {
    validate_request(request)?;
    if !optional_timestamp_is_valid(result.retrieved_at.as_deref())
        || !optional_metadata_is_valid(result.resolver.as_deref())
    {
        return Err(error(DidEbsiErrorReason::ResolutionResultInvalid));
    }
    match result.status {
        DidEbsiResolutionStatus::Absent => {
            if result.document.is_some() || result.registry_metadata.is_some() {
                return Err(error(DidEbsiErrorReason::ResolutionResultInvalid));
            }
            if (request.version_time.is_some() || request.minimum_version_sequence.is_some())
                && result.assurance_achieved != Some(DidEbsiResolutionAssurance::ChainVerified)
            {
                return Err(error(DidEbsiErrorReason::HistoricalVersionMismatch));
            }
            Ok(())
        }
        DidEbsiResolutionStatus::Active | DidEbsiResolutionStatus::Deactivated => {
            validate_present(request, result)
        }
    }
}

fn optional_timestamp_is_valid(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        !value.is_empty()
            && value.len() <= MAX_METADATA_BYTES
            && OffsetDateTime::parse(value, &Rfc3339).is_ok()
    })
}

fn optional_metadata_is_valid(value: Option<&str>) -> bool {
    value.is_none_or(|value| !value.is_empty() && value.len() <= MAX_METADATA_BYTES)
}

fn validate_request(request: &DidEbsiResolveRequest) -> Result<(), DidEbsiError> {
    parse_did_ebsi(&request.did)?;
    if request.version_id.is_some() && request.version_time.is_some() {
        return Err(error(DidEbsiErrorReason::InvalidVersionSelector));
    }
    if request
        .version_id
        .as_deref()
        .is_some_and(|value| value.is_empty() || value.len() > MAX_SELECTOR_BYTES)
    {
        return Err(error(DidEbsiErrorReason::InvalidVersionSelector));
    }
    if request.version_time.as_deref().is_some_and(|value| {
        value.is_empty()
            || value.len() > MAX_SELECTOR_BYTES
            || OffsetDateTime::parse(value, &Rfc3339).is_err()
    }) {
        return Err(error(DidEbsiErrorReason::InvalidVersionSelector));
    }
    Ok(())
}

fn validate_present(
    request: &DidEbsiResolveRequest,
    result: &DidEbsiResolution,
) -> Result<(), DidEbsiError> {
    let document = result
        .document
        .as_ref()
        .ok_or(error(DidEbsiErrorReason::ResolutionResultInvalid))?;
    let metadata = result
        .registry_metadata
        .as_ref()
        .ok_or(error(DidEbsiErrorReason::ResolutionResultInvalid))?;
    if document.id() != Some(request.did.as_str())
        || metadata.version_id.is_empty()
        || metadata.version_id.len() > MAX_SELECTOR_BYTES
        || metadata.version_sequence == 0
        || metadata
            .previous_version_id
            .as_deref()
            .is_some_and(|value| {
                value.is_empty() || value.len() > MAX_SELECTOR_BYTES || value == metadata.version_id
            })
    {
        return Err(error(DidEbsiErrorReason::ResolutionResultInvalid));
    }
    if (metadata.version_sequence == 1 && metadata.previous_version_id.is_some())
        || (metadata.version_sequence > 1 && metadata.previous_version_id.is_none())
    {
        return Err(error(DidEbsiErrorReason::ResolutionResultInvalid));
    }
    if request
        .minimum_version_sequence
        .is_some_and(|minimum| metadata.version_sequence < minimum)
    {
        return Err(error(DidEbsiErrorReason::RollbackDetected));
    }
    if request
        .version_id
        .as_ref()
        .is_some_and(|selected| selected != &metadata.version_id)
    {
        return Err(error(DidEbsiErrorReason::HistoricalVersionMismatch));
    }
    let valid_from = parse_timestamp(&metadata.valid_from)?;
    let valid_until = metadata
        .valid_until
        .as_deref()
        .map(parse_timestamp)
        .transpose()?;
    if valid_until.is_some_and(|end| end <= valid_from) {
        return Err(error(DidEbsiErrorReason::ResolutionResultInvalid));
    }
    if request.version_id.is_none()
        && request.version_time.is_none()
        && metadata.valid_until.is_some()
    {
        return Err(error(DidEbsiErrorReason::HistoricalVersionMismatch));
    }
    if let Some(selected) = request.version_time.as_deref() {
        if result.assurance_achieved != Some(DidEbsiResolutionAssurance::ChainVerified) {
            return Err(error(DidEbsiErrorReason::HistoricalVersionMismatch));
        }
        let selected = parse_timestamp(selected)?;
        if selected < valid_from || valid_until.is_some_and(|end| selected >= end) {
            return Err(error(DidEbsiErrorReason::HistoricalVersionMismatch));
        }
    }
    Ok(())
}

fn parse_timestamp(value: &str) -> Result<OffsetDateTime, DidEbsiError> {
    if value.is_empty() || value.len() > MAX_SELECTOR_BYTES {
        return Err(error(DidEbsiErrorReason::ResolutionResultInvalid));
    }
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| error(DidEbsiErrorReason::ResolutionResultInvalid))
}

const fn error(reason: DidEbsiErrorReason) -> DidEbsiError {
    DidEbsiError::new(reason)
}

#[cfg(test)]
#[path = "resolution_tests.rs"]
mod tests;
