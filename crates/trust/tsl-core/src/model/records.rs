// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Historical service state used for decisions at an earlier validation time.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct TrustServiceHistoryEntry {
    pub service_type: TrustServiceType,
    pub service_names: Vec<LocalizedText>,
    pub status: TrustServiceStatus,
    pub status_starting_time: TslTimestamp,
    pub digital_identity: ServiceDigitalIdentity,
    pub qualifications: Vec<ServiceQualification>,
    pub additional_service_information: Vec<AdditionalServiceInformation>,
}

/// Normalized, version-aware trusted list.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TrustedList {
    pub name: String,
    pub version: TslVersion,
    pub sequence_number: u64,
    pub tsl_type: TslUri,
    pub scheme_operator_names: Vec<LocalizedText>,
    pub scheme_operator_address: TslAddress,
    pub scheme_names: Vec<LocalizedText>,
    pub scheme_information_uris: Vec<LocalizedUri>,
    pub status_determination_approach: TslUri,
    pub scheme_type_community_rules: Vec<LocalizedUri>,
    pub scheme_territory: Option<String>,
    pub historical_information_period_days: u64,
    pub issue_date_time: TslTimestamp,
    pub next_update: Option<TslTimestamp>,
    pub pointers: Vec<TslPointer>,
    pub providers: Vec<TrustServiceProvider>,
}

impl TrustedList {
    /// Iterate services without erasing their owning provider boundary.
    pub fn services(&self) -> impl Iterator<Item = &TrustService> {
        self.providers
            .iter()
            .flat_map(|provider| provider.services.iter())
    }
}

impl core::fmt::Debug for TrustedList {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TrustedList")
            .field("version", &self.version)
            .field("sequence_number", &self.sequence_number)
            .field("name", &"<redacted>")
            .field("pointers", &"<redacted>")
            .field("providers", &"<redacted>")
            .finish()
    }
}

/// Pointer from a LOTL to another trusted list.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TslPointer {
    /// TS 119 612 clause 5.3.13 issuer identities used to authenticate the child list.
    pub digital_identities: Vec<ServiceDigitalIdentity>,
    pub url: TslUri,
    pub tsl_type: TslUri,
    pub scheme_operator_names: Vec<LocalizedText>,
    pub scheme_type_community_rules: Vec<LocalizedUri>,
    pub territory: String,
    pub media_type: TslMediaType,
}

impl core::fmt::Debug for TslPointer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TslPointer")
            .field("url", &"<redacted>")
            .field("tsl_type", &"<redacted>")
            .field("territory", &self.territory)
            .field("media_type", &self.media_type)
            .field("scheme_operator_names", &"<redacted>")
            .field("scheme_type_community_rules", &"<redacted>")
            .field("digital_identities", &"<redacted>")
            .finish()
    }
}

impl TslPointer {
    /// Iterate every certificate without erasing its authenticated identity grouping.
    pub fn certificates_der(&self) -> impl Iterator<Item = &[u8]> {
        self.digital_identities
            .iter()
            .flat_map(|identity| identity.certificates_der().iter().map(Vec::as_slice))
    }
}

/// Normalized trust-service entry, including current and historical state.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TrustService {
    pub service_names: Vec<LocalizedText>,
    pub service_type: TrustServiceType,
    pub status: TrustServiceStatus,
    pub status_starting_time: TslTimestamp,
    pub supply_points: Vec<TslUri>,
    pub digital_identity: ServiceDigitalIdentity,
    pub qualifications: Vec<ServiceQualification>,
    pub additional_service_information: Vec<AdditionalServiceInformation>,
    pub history: Vec<TrustServiceHistoryEntry>,
}

impl TrustService {
    /// Certificate representations of the current service identity.
    pub fn certificates_der(&self) -> &[Vec<u8>] {
        self.digital_identity.certificates_der()
    }
}

impl core::fmt::Debug for TrustService {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TrustService")
            .field("service_type", &self.service_type)
            .field("status", &self.status)
            .field("service_names", &"<redacted>")
            .field("digital_identity", &"<redacted>")
            .field("history", &"<redacted>")
            .finish()
    }
}

/// One authenticated TSP record and its grouped services.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TrustServiceProvider {
    pub names: Vec<LocalizedText>,
    pub trade_names: Vec<LocalizedText>,
    pub registration_identifiers: Vec<TspRegistrationIdentifier>,
    pub address: TslAddress,
    pub information_uris: Vec<LocalizedUri>,
    pub services: Vec<TrustService>,
}

impl core::fmt::Debug for TrustServiceProvider {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TrustServiceProvider")
            .field("registration_identifiers", &"<redacted>")
            .field("names", &"<redacted>")
            .field("trade_names", &"<redacted>")
            .field("address", &"<redacted>")
            .field("information_uris", &"<redacted>")
            .field("services", &"<redacted>")
            .finish()
    }
}

/// Caller-owned constraints for recursively following LOTL pointers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerTraversalPolicy {
    pub max_depth: u8,
    pub max_documents: u16,
    pub max_total_bytes: u64,
    pub require_https: bool,
    pub allowed_origins: Vec<TslOrigin>,
    pub allowed_media_types: Vec<TslMediaType>,
}

/// Immutable state checked before accepting one fetched pointer document.
pub struct PointerTraversalContext<'a> {
    pub depth: u8,
    pub documents_seen: u16,
    pub total_bytes_seen: u64,
    pub fetched_bytes: u64,
    pub fetched_media_type: TslMediaType,
    pub target: &'a TslUri,
    pub ancestor_urls: &'a [TslUri],
}
