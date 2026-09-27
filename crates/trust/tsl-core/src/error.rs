// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

/// Typed failures returned while parsing or validating an ETSI trusted list.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslError {
    /// Invalid TSL XML.
    #[error("invalid TSL XML")]
    InvalidXml,
    /// Trusted-list XML boundary is invalid.
    #[error("trusted-list XML boundary is invalid")]
    Xml(TslXmlFailure),
    /// Trusted-list structure is invalid.
    #[error("trusted-list structure is invalid")]
    InvalidStructure(TslStructureFailure),
    /// Trusted-list tag is not the TS 119 612 TSLTag URI.
    #[error("trusted-list tag is not the TS 119 612 TSLTag URI")]
    InvalidTag,
    /// Missing required TSL field.
    #[error("missing required TSL field")]
    MissingField(TslRequiredField),
    /// Trusted-list field is invalid.
    #[error("trusted-list field is invalid")]
    InvalidField(TslRequiredField),
    /// Unsupported trusted-list version.
    #[error("unsupported trusted-list version")]
    UnsupportedVersion,
    /// Invalid trusted-list UTC timestamp.
    #[error("invalid trusted-list UTC timestamp")]
    InvalidTimestamp,
    /// Trusted-list next-update interval is invalid.
    #[error("trusted-list next-update interval is invalid")]
    InvalidUpdateWindow,
    /// Closed trusted list contains a non-expired service.
    #[error("closed trusted list contains a non-expired service")]
    ClosedListNonExpiredService,
    /// Trusted list is expired.
    #[error("trusted list is expired")]
    Expired,
    /// Trusted-list issue time is later than the evaluation time.
    #[error("trusted-list issue time is later than the evaluation time")]
    NotYetIssued,
    /// Trusted-list sequence number is older than the last accepted list.
    #[error("trusted-list sequence number is older than the last accepted list")]
    SequenceRollback,
    /// Invalid or oversized trusted-list URI.
    #[error("invalid or oversized trusted-list URI")]
    InvalidUri,
    /// Invalid embedded certificate.
    #[error("invalid embedded certificate")]
    InvalidCertificate,
    /// Trusted-list service digital identity is invalid.
    #[error("trusted-list service digital identity is invalid")]
    DigitalIdentity(TslDigitalIdentityFailure),
    /// Trusted-list provider identity is invalid.
    #[error("trusted-list provider identity is invalid")]
    Provider(TslProviderFailure),
    /// Trusted-list address is invalid.
    #[error("trusted-list address is invalid")]
    Address(TslAddressContext, TslAddressFailure),
    /// Trusted-list qualification is invalid.
    #[error("trusted-list qualification is invalid")]
    Qualification(TslQualificationFailure),
    /// Unsupported critical trusted-list extension.
    #[error("unsupported critical trusted-list extension")]
    UnsupportedCriticalExtension,
    /// Trusted-list resource limit exceeded.
    #[error("trusted-list resource limit exceeded")]
    ResourceLimit(TslResourceLimit),
    /// Trusted-list pointer policy failed.
    #[error("trusted-list pointer policy failed")]
    PointerPolicy(TslPointerPolicyFailure),
    /// Trusted-list pointer qualifier validation failed.
    #[error("trusted-list pointer qualifier validation failed")]
    PointerQualifier(TslPointerQualifierFailure),
}

include!("error/reasons.rs");

/// Required trusted-list field associated with a validation failure.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslRequiredField {
    /// Trusted-list tag.
    #[error("trusted-list tag")]
    Tag,
    /// Scheme information.
    #[error("scheme information")]
    SchemeInformation,
    /// Trusted-list version.
    #[error("trusted-list version")]
    Version,
    /// Sequence number.
    #[error("sequence number")]
    SequenceNumber,
    /// Trusted-list type.
    #[error("trusted-list type")]
    ListType,
    /// Scheme operator name.
    #[error("scheme operator name")]
    SchemeOperatorName,
    /// Scheme operator address.
    #[error("scheme operator address")]
    SchemeOperatorAddress,
    /// Scheme name.
    #[error("scheme name")]
    SchemeName,
    /// Scheme information URI.
    #[error("scheme information URI")]
    SchemeInformationUri,
    /// Status determination approach.
    #[error("status determination approach")]
    StatusDeterminationApproach,
    /// Scheme type or community rules.
    #[error("scheme type or community rules")]
    SchemeTypeCommunityRules,
    /// Scheme territory.
    #[error("scheme territory")]
    SchemeTerritory,
    /// Policy or legal notice.
    #[error("policy or legal notice")]
    PolicyOrLegalNotice,
    /// Historical information period.
    #[error("historical information period")]
    HistoricalInformationPeriod,
    /// Pointers to other trusted lists.
    #[error("pointers to other trusted lists")]
    PointersToOtherTsl,
    /// Issue date and time.
    #[error("issue date time")]
    IssueDateTime,
    /// Next update.
    #[error("next update")]
    NextUpdate,
    /// Service information.
    #[error("service information")]
    ServiceInformation,
    /// Trust-service-provider information.
    #[error("trust-service-provider information")]
    ProviderInformation,
    /// Trust-service-provider name.
    #[error("trust-service-provider name")]
    ProviderName,
    /// Trust-service-provider trade name.
    #[error("trust-service-provider trade name")]
    ProviderTradeName,
    /// Trust-service-provider address.
    #[error("trust-service-provider address")]
    ProviderAddress,
    /// Trust-service-provider information URI.
    #[error("trust-service-provider information URI")]
    ProviderInformationUri,
    /// Trust-service-provider services.
    #[error("trust-service-provider services")]
    ProviderServices,
    /// Service type.
    #[error("service type")]
    ServiceType,
    /// Service name.
    #[error("service name")]
    ServiceName,
    /// Service digital identity.
    #[error("service digital identity")]
    ServiceDigitalIdentity,
    /// Service status.
    #[error("service status")]
    ServiceStatus,
    /// Service status starting time.
    #[error("service status starting time")]
    ServiceStatusStartingTime,
    /// Pointer location.
    #[error("pointer location")]
    PointerLocation,
}

/// Typed TSL digital identity failure reasons reported to callers.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslDigitalIdentityFailure {
    /// Digital identity has no representation.
    #[error("digital identity has no representation")]
    Empty,
    /// Digital identity contains too many representations.
    #[error("digital identity contains too many representations")]
    RepresentationLimit,
    /// Digital identity representation is malformed.
    #[error("digital identity representation is malformed")]
    MalformedRepresentation,
    /// Digital identity representation is duplicated.
    #[error("digital identity representation is duplicated")]
    DuplicateRepresentation,
    /// PKI service identity does not contain a certificate.
    #[error("PKI service identity does not contain a certificate")]
    MissingCertificate,
    /// Historical service identity does not contain an X509SKI.
    #[error("historical service identity does not contain an X509SKI")]
    MissingHistoricalSubjectKeyIdentifier,
    /// Historical PKI service identity contains a certificate.
    #[error("historical PKI service identity contains a certificate")]
    HistoricalCertificate,
    /// Digital identity mixes PKI and non-PKI representations.
    #[error("digital identity mixes PKI and non-PKI representations")]
    MixedRepresentations,
    /// Digital identity representations identify different public keys.
    #[error("digital identity representations identify different public keys")]
    PublicKeyMismatch,
    /// Certificate representations have different subject names.
    #[error("certificate representations have different subject names")]
    SubjectNameMismatch,
    /// Certificate representations disagree on certificate-authority status.
    #[error("certificate representations disagree on certificate-authority status")]
    CertificateAuthorityMismatch,
    /// X509SKI does not identify the represented public key.
    #[error("X509SKI does not identify the represented public key")]
    SubjectKeyIdentifierMismatch,
    /// Non-PKI digital identity is not a URI.
    #[error("non-PKI digital identity is not a URI")]
    InvalidNonPkiIdentifier,
    /// Unsupported XMLDSig key-value representation.
    #[error("unsupported XMLDSig key-value representation")]
    UnsupportedKeyValue,
    /// Unsupported scheme-defined digital-identity representation.
    #[error("unsupported service digital-identity Other representation")]
    UnsupportedOtherRepresentation,
    /// The same public key appears more than once for one service type.
    #[error("the same public key appears more than once for one service type")]
    DuplicateServiceKey,
}

/// Typed TSL provider failure reasons reported to callers.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslProviderFailure {
    /// Provider registration identifier is missing.
    #[error("provider registration identifier is missing")]
    MissingRegistrationIdentifier,
    /// Provider registration identifier is malformed.
    #[error("provider registration identifier is malformed")]
    MalformedRegistrationIdentifier,
    /// Provider has contradictory registration identifiers.
    #[error("provider has contradictory registration identifiers")]
    ContradictoryRegistrationIdentifier,
    /// Provider address is malformed.
    #[error("provider address is malformed")]
    InvalidAddress,
}

/// Typed TSL qualification failure reasons reported to callers.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslQualificationFailure {
    /// Qualification structure is malformed.
    #[error("qualification structure is malformed")]
    Malformed,
    /// Qualification element sequence is empty or exceeds its bound.
    #[error("qualification element sequence is empty or exceeds its bound")]
    ElementCount,
    /// Qualification qualifier sequence is missing, empty, or exceeds its bound.
    #[error("qualification qualifier sequence is missing, empty, or exceeds its bound")]
    Qualifiers,
    /// Qualification criteria list is missing.
    #[error("qualification criteria list is missing")]
    MissingCriteria,
    /// Qualification assertion is invalid.
    #[error("qualification assertion is invalid")]
    InvalidAssertion,
    /// Qualification key-usage assertion is malformed.
    #[error("qualification key-usage assertion is malformed")]
    KeyUsage,
    /// Qualification key-usage bit is duplicated.
    #[error("qualification key-usage bit is duplicated")]
    DuplicateKeyUsage,
    /// Qualification criteria list has no assertions.
    #[error("qualification criteria list has no assertions")]
    EmptyCriteria,
    /// Qualification object-identifier list is empty or exceeds its bound.
    #[error("qualification object-identifier list is empty or exceeds its bound")]
    IdentifierCount,
    /// Qualification policy identifier is malformed.
    #[error("qualification policy identifier is malformed")]
    PolicyIdentifier,
    /// Qualification descriptive metadata is malformed.
    #[error("qualification descriptive metadata is malformed")]
    DescriptiveMetadata,
    /// Qualification semantics are not supported.
    #[error("qualification semantics are not supported")]
    UnsupportedSemantics,
    /// Qualification is attached to a non-CA/QC service.
    #[error("qualification is attached to a non-CA/QC service")]
    WrongServiceType,
}

/// Typed TSL resource limit reasons reported to callers.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslResourceLimit {
    /// XML byte limit.
    #[error("XML byte limit")]
    XmlBytes,
    /// XML depth limit.
    #[error("XML depth limit")]
    XmlDepth,
    /// XML element limit.
    #[error("XML element limit")]
    XmlElements,
    /// XML text limit.
    #[error("XML text limit")]
    XmlText,
    /// Pointer count limit.
    #[error("pointer count limit")]
    Pointers,
    /// Pointer digital-identity count limit.
    #[error("pointer digital-identity count limit")]
    PointerIdentities,
    /// Provider count limit.
    #[error("provider count limit")]
    Providers,
    /// Service count limit.
    #[error("service count limit")]
    Services,
    /// History count limit.
    #[error("history count limit")]
    History,
    /// Certificate count limit.
    #[error("certificate count limit")]
    Certificates,
    /// Supply-point count limit.
    #[error("supply-point count limit")]
    SupplyPoints,
}

/// Typed TSL pointer policy failure reasons reported to callers.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslPointerPolicyFailure {
    /// Pointer depth exceeded.
    #[error("pointer depth exceeded")]
    Depth,
    /// Pointer document count exceeded.
    #[error("pointer document count exceeded")]
    DocumentCount,
    /// Pointer total bytes exceeded.
    #[error("pointer total bytes exceeded")]
    TotalBytes,
    /// Pointer cycle detected.
    #[error("pointer cycle detected")]
    Cycle,
    /// Pointer transport must be HTTPS.
    #[error("pointer transport must be HTTPS")]
    InsecureTransport,
    /// Pointer origin is not authorized.
    #[error("pointer origin is not authorized")]
    Origin,
    /// Pointer media type is not authorized.
    #[error("pointer media type is not authorized")]
    MediaType,
    /// Fetched trusted-list metadata does not match authenticated pointer qualifiers.
    #[error("fetched trusted-list metadata does not match authenticated pointer qualifiers")]
    TargetMetadataMismatch,
}

/// Typed TSL pointer qualifier failure reasons reported to callers.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslPointerQualifierFailure {
    /// Required pointer qualifier is missing.
    #[error("required pointer qualifier is missing")]
    Missing,
    /// Pointer qualifier is duplicated.
    #[error("pointer qualifier is duplicated")]
    Duplicate,
    /// Duplicated pointer qualifiers contradict each other.
    #[error("duplicated pointer qualifiers contradict each other")]
    Contradictory,
    /// Pointer qualifier is malformed.
    #[error("pointer qualifier is malformed")]
    Malformed,
    /// Pointer issuer digital identity is missing.
    #[error("pointer issuer digital identity is missing")]
    MissingIssuerIdentity,
    /// Pointer MIME type is not the normative trusted-list media type.
    #[error("pointer MIME type is not the normative trusted-list media type")]
    NonNormativeMimeType,
}

include!("error/map_to_proto.rs");

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
