// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Historical service state used for decisions at an earlier validation time.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct TrustServiceHistoryEntry {
    /// Service type effective for this historical interval.
    pub service_type: TrustServiceType,
    /// Localized service names effective for this interval.
    pub service_names: Vec<LocalizedText>,
    /// Service status effective for this interval.
    pub status: TrustServiceStatus,
    /// Inclusive start of this historical interval.
    pub status_starting_time: TslTimestamp,
    /// Historical key identity, or `None` when the authenticated row cannot
    /// identify a prior key (missing or inconsistent `X509SKI`).
    ///
    /// A `None` row is retained as a non-authorizing barrier: it still ends
    /// the effective interval of every older row, so a restrictive state that
    /// cannot be matched to a key never lets an older granted state govern.
    pub digital_identity: Option<ServiceDigitalIdentity>,
    /// Certificate qualifications effective for this interval.
    pub qualifications: Vec<ServiceQualification>,
    /// Additional service classifications effective for this interval.
    pub additional_service_information: Vec<AdditionalServiceInformation>,
}

/// Normalized, version-aware trusted list.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TrustedList {
    /// Trusted-list scheme name.
    pub name: String,
    /// Parsed trusted-list format version.
    pub version: TslVersion,
    /// Monotonic publication sequence number.
    pub sequence_number: u64,
    /// Trusted-list type URI.
    pub tsl_type: TslUri,
    /// Localized scheme-operator names.
    pub scheme_operator_names: Vec<LocalizedText>,
    /// Scheme-operator postal and electronic addresses.
    pub scheme_operator_address: TslAddress,
    /// Localized scheme names.
    pub scheme_names: Vec<LocalizedText>,
    /// Scheme-information URIs.
    pub scheme_information_uris: Vec<LocalizedUri>,
    /// Status-determination approach URI.
    pub status_determination_approach: TslUri,
    /// Scheme-type or community-rule URIs.
    pub scheme_type_community_rules: Vec<LocalizedUri>,
    /// Scheme territory when supplied by the profile.
    pub scheme_territory: Option<String>,
    /// Required retention period for historical service information, in days.
    pub historical_information_period_days: u64,
    /// Trusted-list publication time.
    pub issue_date_time: TslTimestamp,
    /// Deadline for the next publication, when present.
    pub next_update: Option<TslTimestamp>,
    /// Authenticated pointers to subordinate trusted lists.
    pub pointers: Vec<TslPointer>,
    /// Trust-service providers listed by the scheme.
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
    /// Absolute URL of the referenced trusted list.
    pub url: TslUri,
    /// Declared type of the referenced trusted list.
    pub tsl_type: TslUri,
    /// Expected scheme-operator names for the referenced list.
    pub scheme_operator_names: Vec<LocalizedText>,
    /// Expected scheme-type or community-rule URIs.
    pub scheme_type_community_rules: Vec<LocalizedUri>,
    /// Expected scheme territory.
    pub territory: String,
    /// Declared media type of the referenced representation.
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
    /// Localized service names.
    pub service_names: Vec<LocalizedText>,
    /// Service-type URI projected into a typed value.
    pub service_type: TrustServiceType,
    /// Current service status.
    pub status: TrustServiceStatus,
    /// Inclusive start of the current status interval.
    pub status_starting_time: TslTimestamp,
    /// Service supply-point URIs.
    pub supply_points: Vec<TslUri>,
    /// Certificate or key identity authorized for the service.
    pub digital_identity: ServiceDigitalIdentity,
    /// Conditional certificate qualifications.
    pub qualifications: Vec<ServiceQualification>,
    /// Additional service classifications.
    pub additional_service_information: Vec<AdditionalServiceInformation>,
    /// Prior service states in publication order.
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
    /// Localized provider names.
    pub names: Vec<LocalizedText>,
    /// Localized provider trade names.
    pub trade_names: Vec<LocalizedText>,
    /// Structured provider registration identifiers.
    pub registration_identifiers: Vec<TspRegistrationIdentifier>,
    /// Provider postal and electronic addresses.
    pub address: TslAddress,
    /// Provider-information URIs.
    pub information_uris: Vec<LocalizedUri>,
    /// Services operated by this provider.
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
    /// Maximum pointer nesting depth.
    pub max_depth: u8,
    /// Maximum documents accepted before validation fails.
    pub max_documents: u16,
    /// Maximum total bytes accepted before validation fails.
    pub max_total_bytes: u64,
    /// Whether every pointer target must use HTTPS.
    pub require_https: bool,
    /// Network origins authorized for pointer targets.
    pub allowed_origins: Vec<TslOrigin>,
    /// Media types authorized for fetched trusted lists.
    pub allowed_media_types: Vec<TslMediaType>,
}

/// Immutable state checked before accepting one fetched pointer document.
pub struct PointerTraversalContext<'a> {
    /// Depth of the candidate document below the root LOTL.
    pub depth: u8,
    /// Number of pointer documents already accepted in this traversal.
    pub documents_seen: u16,
    /// Aggregate bytes already accepted in this traversal.
    pub total_bytes_seen: u64,
    /// Byte length of the candidate document.
    pub fetched_bytes: u64,
    /// Media type established by the fetch boundary.
    pub fetched_media_type: TslMediaType,
    /// Validated target URI of the candidate document.
    pub target: &'a TslUri,
    /// Previously visited URIs used for cycle detection.
    pub ancestor_urls: &'a [TslUri],
}
