// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslError {
    #[error("invalid TSL XML")]
    InvalidXml,
    #[error("trusted-list XML boundary is invalid")]
    Xml(TslXmlFailure),
    #[error("trusted-list structure is invalid")]
    InvalidStructure(TslStructureFailure),
    #[error("trusted-list tag is not the TS 119 612 TSLTag URI")]
    InvalidTag,
    #[error("missing required TSL field")]
    MissingField(TslRequiredField),
    #[error("trusted-list field is invalid")]
    InvalidField(TslRequiredField),
    #[error("unsupported trusted-list version")]
    UnsupportedVersion,
    #[error("invalid trusted-list UTC timestamp")]
    InvalidTimestamp,
    #[error("trusted-list next-update interval is invalid")]
    InvalidUpdateWindow,
    #[error("closed trusted list contains a non-expired service")]
    ClosedListNonExpiredService,
    #[error("trusted list is expired")]
    Expired,
    #[error("trusted-list issue time is later than the evaluation time")]
    NotYetIssued,
    #[error("trusted-list sequence number is older than the last accepted list")]
    SequenceRollback,
    #[error("invalid or oversized trusted-list URI")]
    InvalidUri,
    #[error("invalid embedded certificate")]
    InvalidCertificate,
    #[error("trusted-list service digital identity is invalid")]
    DigitalIdentity(TslDigitalIdentityFailure),
    #[error("trusted-list provider identity is invalid")]
    Provider(TslProviderFailure),
    #[error("trusted-list address is invalid")]
    Address(TslAddressContext, TslAddressFailure),
    #[error("trusted-list qualification is invalid")]
    Qualification(TslQualificationFailure),
    #[error("unsupported critical trusted-list extension")]
    UnsupportedCriticalExtension,
    #[error("trusted-list resource limit exceeded")]
    ResourceLimit(TslResourceLimit),
    #[error("trusted-list pointer policy failed")]
    PointerPolicy(TslPointerPolicyFailure),
    #[error("trusted-list pointer qualifier validation failed")]
    PointerQualifier(TslPointerQualifierFailure),
}

include!("error/reasons.rs");

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslRequiredField {
    #[error("trusted-list tag")]
    Tag,
    #[error("scheme information")]
    SchemeInformation,
    #[error("trusted-list version")]
    Version,
    #[error("sequence number")]
    SequenceNumber,
    #[error("trusted-list type")]
    ListType,
    #[error("scheme operator name")]
    SchemeOperatorName,
    #[error("scheme operator address")]
    SchemeOperatorAddress,
    #[error("scheme name")]
    SchemeName,
    #[error("scheme information URI")]
    SchemeInformationUri,
    #[error("status determination approach")]
    StatusDeterminationApproach,
    #[error("scheme type or community rules")]
    SchemeTypeCommunityRules,
    #[error("scheme territory")]
    SchemeTerritory,
    #[error("policy or legal notice")]
    PolicyOrLegalNotice,
    #[error("historical information period")]
    HistoricalInformationPeriod,
    #[error("pointers to other trusted lists")]
    PointersToOtherTsl,
    #[error("issue date time")]
    IssueDateTime,
    #[error("next update")]
    NextUpdate,
    #[error("service information")]
    ServiceInformation,
    #[error("trust-service-provider information")]
    ProviderInformation,
    #[error("trust-service-provider name")]
    ProviderName,
    #[error("trust-service-provider trade name")]
    ProviderTradeName,
    #[error("trust-service-provider address")]
    ProviderAddress,
    #[error("trust-service-provider information URI")]
    ProviderInformationUri,
    #[error("trust-service-provider services")]
    ProviderServices,
    #[error("service type")]
    ServiceType,
    #[error("service name")]
    ServiceName,
    #[error("service digital identity")]
    ServiceDigitalIdentity,
    #[error("service status")]
    ServiceStatus,
    #[error("service status starting time")]
    ServiceStatusStartingTime,
    #[error("pointer location")]
    PointerLocation,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslDigitalIdentityFailure {
    #[error("digital identity has no representation")]
    Empty,
    #[error("digital identity contains too many representations")]
    RepresentationLimit,
    #[error("digital identity representation is malformed")]
    MalformedRepresentation,
    #[error("digital identity representation is duplicated")]
    DuplicateRepresentation,
    #[error("PKI service identity does not contain a certificate")]
    MissingCertificate,
    #[error("historical service identity does not contain an X509SKI")]
    MissingHistoricalSubjectKeyIdentifier,
    #[error("historical PKI service identity contains a certificate")]
    HistoricalCertificate,
    #[error("digital identity mixes PKI and non-PKI representations")]
    MixedRepresentations,
    #[error("digital identity representations identify different public keys")]
    PublicKeyMismatch,
    #[error("certificate representations have different subject names")]
    SubjectNameMismatch,
    #[error("X509SKI does not identify the represented public key")]
    SubjectKeyIdentifierMismatch,
    #[error("non-PKI digital identity is not a URI")]
    InvalidNonPkiIdentifier,
    #[error("unsupported XMLDSig key-value representation")]
    UnsupportedKeyValue,
    #[error("unsupported service digital-identity Other representation")]
    UnsupportedOtherRepresentation,
    #[error("the same public key appears more than once for one service type")]
    DuplicateServiceKey,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslProviderFailure {
    #[error("provider registration identifier is missing")]
    MissingRegistrationIdentifier,
    #[error("provider registration identifier is malformed")]
    MalformedRegistrationIdentifier,
    #[error("provider has contradictory registration identifiers")]
    ContradictoryRegistrationIdentifier,
    #[error("provider address is malformed")]
    InvalidAddress,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslQualificationFailure {
    #[error("qualification structure is malformed")]
    Malformed,
    #[error("qualification element sequence is empty or exceeds its bound")]
    ElementCount,
    #[error("qualification qualifier sequence is missing, empty, or exceeds its bound")]
    Qualifiers,
    #[error("qualification criteria list is missing")]
    MissingCriteria,
    #[error("qualification assertion is invalid")]
    InvalidAssertion,
    #[error("qualification key-usage assertion is malformed")]
    KeyUsage,
    #[error("qualification key-usage bit is duplicated")]
    DuplicateKeyUsage,
    #[error("qualification criteria list has no assertions")]
    EmptyCriteria,
    #[error("qualification object-identifier list is empty or exceeds its bound")]
    IdentifierCount,
    #[error("qualification policy identifier is malformed")]
    PolicyIdentifier,
    #[error("qualification descriptive metadata is malformed")]
    DescriptiveMetadata,
    #[error("qualification semantics are not supported")]
    UnsupportedSemantics,
    #[error("qualification is attached to a non-CA/QC service")]
    WrongServiceType,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslResourceLimit {
    #[error("XML byte limit")]
    XmlBytes,
    #[error("XML depth limit")]
    XmlDepth,
    #[error("XML element limit")]
    XmlElements,
    #[error("XML text limit")]
    XmlText,
    #[error("pointer count limit")]
    Pointers,
    #[error("pointer digital-identity count limit")]
    PointerIdentities,
    #[error("provider count limit")]
    Providers,
    #[error("service count limit")]
    Services,
    #[error("history count limit")]
    History,
    #[error("certificate count limit")]
    Certificates,
    #[error("supply-point count limit")]
    SupplyPoints,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslPointerPolicyFailure {
    #[error("pointer depth exceeded")]
    Depth,
    #[error("pointer document count exceeded")]
    DocumentCount,
    #[error("pointer total bytes exceeded")]
    TotalBytes,
    #[error("pointer cycle detected")]
    Cycle,
    #[error("pointer transport must be HTTPS")]
    InsecureTransport,
    #[error("pointer origin is not authorized")]
    Origin,
    #[error("pointer media type is not authorized")]
    MediaType,
    #[error("fetched trusted-list metadata does not match authenticated pointer qualifiers")]
    TargetMetadataMismatch,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslPointerQualifierFailure {
    #[error("required pointer qualifier is missing")]
    Missing,
    #[error("pointer qualifier is duplicated")]
    Duplicate,
    #[error("duplicated pointer qualifiers contradict each other")]
    Contradictory,
    #[error("pointer qualifier is malformed")]
    Malformed,
    #[error("pointer issuer digital identity is missing")]
    MissingIssuerIdentity,
    #[error("pointer MIME type is not the normative trusted-list media type")]
    NonNormativeMimeType,
}

impl From<TslError> for IdentityCoreErrorReason {
    fn from(reason: TslError) -> Self {
        match reason {
            TslError::InvalidXml => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_XML
            }
            TslError::Xml(_) => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_XML
            }
            TslError::InvalidStructure(_) => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_XML
            }
            TslError::InvalidTag => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_TAG
            }
            TslError::MissingField(_) => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_MISSING_FIELD
            }
            TslError::InvalidField(_) => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_URI
            }
            TslError::UnsupportedVersion => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_UNSUPPORTED_VERSION
            }
            TslError::InvalidTimestamp => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_TIMESTAMP
            }
            TslError::InvalidUpdateWindow => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_UPDATE_WINDOW
            }
            TslError::ClosedListNonExpiredService => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_CLOSED_LIST_NON_EXPIRED_SERVICE
            }
            TslError::Expired => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_EXPIRED
            }
            TslError::NotYetIssued => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_TIMESTAMP
            }
            // A superseded list is stale for the caller: a newer authentic
            // publication has already been accepted for this location.
            TslError::SequenceRollback => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_EXPIRED
            }
            TslError::InvalidUri => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_URI
            }
            TslError::InvalidCertificate => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_CERTIFICATE
            }
            TslError::DigitalIdentity(reason) => match reason {
                TslDigitalIdentityFailure::Empty => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_EMPTY
                }
                TslDigitalIdentityFailure::RepresentationLimit => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_REPRESENTATION_LIMIT
                }
                TslDigitalIdentityFailure::MalformedRepresentation => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_MALFORMED_REPRESENTATION
                }
                TslDigitalIdentityFailure::DuplicateRepresentation => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_DUPLICATE_REPRESENTATION
                }
                TslDigitalIdentityFailure::MissingCertificate => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_MISSING_CERTIFICATE
                }
                TslDigitalIdentityFailure::MissingHistoricalSubjectKeyIdentifier => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_HISTORY_MISSING_SKI
                }
                TslDigitalIdentityFailure::HistoricalCertificate => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_HISTORY_CONTAINS_CERTIFICATE
                }
                TslDigitalIdentityFailure::MixedRepresentations => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_MIXED_REPRESENTATIONS
                }
                TslDigitalIdentityFailure::PublicKeyMismatch => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_PUBLIC_KEY_MISMATCH
                }
                TslDigitalIdentityFailure::SubjectNameMismatch => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_SUBJECT_NAME_MISMATCH
                }
                TslDigitalIdentityFailure::SubjectKeyIdentifierMismatch => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_SKI_MISMATCH
                }
                TslDigitalIdentityFailure::InvalidNonPkiIdentifier => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_INVALID_NON_PKI_IDENTIFIER
                }
                TslDigitalIdentityFailure::UnsupportedKeyValue => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_UNSUPPORTED_KEY_VALUE
                }
                TslDigitalIdentityFailure::UnsupportedOtherRepresentation => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_MALFORMED_REPRESENTATION
                }
                TslDigitalIdentityFailure::DuplicateServiceKey => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_DUPLICATE_SERVICE_KEY
                }
            },
            TslError::Provider(reason) => match reason {
                TslProviderFailure::MissingRegistrationIdentifier => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_PROVIDER_MISSING_REGISTRATION_IDENTIFIER
                }
                TslProviderFailure::MalformedRegistrationIdentifier => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_PROVIDER_MALFORMED_REGISTRATION_IDENTIFIER
                }
                TslProviderFailure::ContradictoryRegistrationIdentifier => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_PROVIDER_CONTRADICTORY_REGISTRATION_IDENTIFIER
                }
                TslProviderFailure::InvalidAddress => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_PROVIDER_INVALID_ADDRESS
                }
            },
            TslError::Address(context, _) => match context {
                TslAddressContext::SchemeOperator => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_XML
                }
                TslAddressContext::Provider => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_PROVIDER_INVALID_ADDRESS
                }
            },
            TslError::Qualification(reason) => match reason {
                TslQualificationFailure::Malformed
                | TslQualificationFailure::ElementCount
                | TslQualificationFailure::Qualifiers
                | TslQualificationFailure::MissingCriteria
                | TslQualificationFailure::InvalidAssertion
                | TslQualificationFailure::KeyUsage
                | TslQualificationFailure::DuplicateKeyUsage
                | TslQualificationFailure::EmptyCriteria
                | TslQualificationFailure::IdentifierCount
                | TslQualificationFailure::PolicyIdentifier
                | TslQualificationFailure::DescriptiveMetadata => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_QUALIFICATION_MALFORMED
                }
                TslQualificationFailure::UnsupportedSemantics => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_QUALIFICATION_UNSUPPORTED_SEMANTICS
                }
                TslQualificationFailure::WrongServiceType => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_QUALIFICATION_WRONG_SERVICE_TYPE
                }
            },
            TslError::UnsupportedCriticalExtension => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_UNSUPPORTED_CRITICAL_EXTENSION
            }
            TslError::ResourceLimit(_) => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_RESOURCE_LIMIT
            }
            TslError::PointerPolicy(reason) => match reason {
                TslPointerPolicyFailure::Depth => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_DEPTH
                }
                TslPointerPolicyFailure::DocumentCount => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_DOCUMENT_COUNT
                }
                TslPointerPolicyFailure::TotalBytes => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_TOTAL_BYTES
                }
                TslPointerPolicyFailure::Cycle => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_CYCLE
                }
                TslPointerPolicyFailure::InsecureTransport => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_INSECURE_TRANSPORT
                }
                TslPointerPolicyFailure::Origin => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_ORIGIN
                }
                TslPointerPolicyFailure::MediaType => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_MEDIA_TYPE
                }
                TslPointerPolicyFailure::TargetMetadataMismatch => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_TARGET_METADATA_MISMATCH
                }
            },
            TslError::PointerQualifier(reason) => match reason {
                TslPointerQualifierFailure::Missing => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_MISSING_QUALIFIER
                }
                TslPointerQualifierFailure::Duplicate => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_DUPLICATE_QUALIFIER
                }
                TslPointerQualifierFailure::Contradictory => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_CONTRADICTORY_QUALIFIER
                }
                TslPointerQualifierFailure::Malformed => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_MALFORMED_QUALIFIER
                }
                TslPointerQualifierFailure::MissingIssuerIdentity => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_MISSING_ISSUER_IDENTITY
                }
                TslPointerQualifierFailure::NonNormativeMimeType => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_NON_NORMATIVE_MIME_TYPE
                }
            },
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
