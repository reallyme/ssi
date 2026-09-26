// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Current implementation status for mdoc envelope support.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MdocEnvelopeStatus {
    /// Structural mdoc CBOR model encoding and decoding are available.
    StructureReady,

    /// Issuer-signed mdoc issuance and verification are available.
    IssuerSignedReady,

    /// Issuer-signed mdoc and DeviceResponse presentation support are available.
    PresentationReady,
}

/// Stable reason codes for invalid mdoc inputs and malformed signed content.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MdocInvalidInputReason {
    /// `docType` is absent or empty.
    #[error("empty mdoc document type")]
    EmptyDocType,

    /// The holder device key is absent.
    #[error("empty mdoc device key")]
    EmptyDeviceKey,

    /// Validity timestamps are zero or not ordered as signed <= validFrom < validUntil.
    #[error("invalid mdoc validity window")]
    InvalidValidityWindow,

    /// No issuer-signed data elements were supplied.
    #[error("empty mdoc element set")]
    EmptyElements,

    /// The issuer-signed data element set exceeds the accepted bounded profile.
    #[error("too many mdoc elements")]
    TooManyElements,

    /// The issuer-signed namespace count exceeds the accepted bounded profile.
    #[error("too many mdoc namespaces")]
    TooManyNamespaces,

    /// A single issuer-signed namespace contains too many elements.
    #[error("too many mdoc elements in namespace")]
    TooManyElementsPerNamespace,

    /// A DeviceResponse contains too many documents.
    #[error("too many mdoc device response documents")]
    TooManyDocuments,

    /// Decoded CBOR nesting exceeds the accepted mdoc boundary profile.
    #[error("mdoc cbor nesting depth exceeded")]
    CborDepthExceeded,

    /// A decoded CBOR map exceeds the accepted mdoc boundary profile.
    #[error("mdoc cbor map is too large")]
    CborMapTooLarge,

    /// A decoded CBOR array exceeds the accepted mdoc boundary profile.
    #[error("mdoc cbor array is too large")]
    CborArrayTooLarge,

    /// Serialized CBOR exceeds the parsing boundary before allocation-heavy decoding.
    #[error("mdoc cbor input is too large")]
    CborInputTooLarge,

    /// Serialized CBOR declares more data items than the bounded mdoc profile.
    #[error("mdoc cbor input contains too many items")]
    CborTooManyItems,

    /// A namespace is absent or empty.
    #[error("empty mdoc namespace")]
    EmptyNamespace,

    /// A data element identifier is absent or empty.
    #[error("empty mdoc element identifier")]
    EmptyElementIdentifier,

    /// Two issuer-signed inputs use the same identifier in the same namespace.
    #[error("duplicate mdoc element identifier")]
    DuplicateElementIdentifier,

    /// One encoded issuer-signed element value exceeds the bounded profile.
    #[error("mdoc element value is too large")]
    ElementValueTooLarge,

    /// Combined encoded issuer-signed values exceed the bounded issuance profile.
    #[error("mdoc aggregate element values are too large")]
    TotalElementValuesTooLarge,

    /// An ISO 23220 relationship value was not a non-empty array of
    /// a non-empty array of PersonalData maps with unique text identifiers.
    #[error("malformed ISO 23220 relationship value")]
    MalformedIso23220Relationship,

    /// A PersonalData map repeated the same data-element identifier.
    #[error("duplicate ISO 23220 personal data identifier")]
    DuplicateIso23220PersonalDataIdentifier,

    /// A data element value is absent or empty.
    #[error("empty mdoc element value")]
    EmptyElementValue,

    /// Randomizer bytes for an issuer-signed item are absent.
    #[error("empty mdoc item randomizer")]
    EmptyRandom,

    /// Randomizer bytes for an issuer-signed item are outside the accepted length range.
    #[error("invalid mdoc item randomizer length")]
    InvalidRandomLength,

    /// A numeric value cannot be represented by the supported canonical CBOR profile.
    #[error("mdoc integer is out of range")]
    IntegerOutOfRange,

    /// The digest algorithm is not the supported SHA-256 profile.
    #[error("unsupported mdoc digest algorithm")]
    UnsupportedDigestAlgorithm,

    /// The authenticated MobileSecurityObject version is unsupported.
    #[error("unsupported mdoc mobile security object version")]
    UnsupportedMsoVersion,

    /// A signed item tag was not the ISO encoded-CBOR data-item tag.
    #[error("invalid mdoc tagged item")]
    InvalidTaggedItem,

    /// The document type in the mdoc container does not match the signed MSO.
    #[error("mdoc document type mismatch")]
    DocTypeMismatch,

    /// An issuer-signed item could not be decoded from the expected map shape.
    #[error("malformed mdoc issuer-signed item")]
    MalformedIssuerSignedItem,

    /// An IssuerSigned transport value was malformed, ambiguous, or contained duplicate fields.
    #[error("malformed mdoc issuer-signed document")]
    MalformedIssuerSignedDocument,

    /// The MobileSecurityObject could not be decoded from the expected map shape.
    #[error("malformed mdoc mobile security object")]
    MalformedMobileSecurityObject,

    /// The MSO `status` member was not a single supported mechanism map.
    #[error("malformed mdoc status structure")]
    MalformedMsoStatus,

    /// The MSO `status` map names a mechanism not defined by this ISO profile.
    #[error("unknown mdoc status mechanism")]
    UnknownMsoStatusMechanism,

    /// The MSO `status` map contains more than one mechanism.
    #[error("ambiguous mdoc status mechanism")]
    AmbiguousMsoStatusMechanism,

    /// A status mechanism or one of its members occurs more than once.
    #[error("duplicate mdoc status member")]
    DuplicateMsoStatusMember,

    /// A status mechanism contains a member outside its defined ISO shape.
    #[error("unknown mdoc status member")]
    UnknownMsoStatusMember,

    /// A forward-compatible Status member has an empty/oversized name or empty value.
    #[error("invalid mdoc status extension")]
    InvalidMsoStatusExtension,

    /// A Status map contains more bounded forward-compatible members than permitted.
    #[error("too many mdoc status extensions")]
    TooManyMsoStatusExtensions,

    /// A forward-compatible Status member value exceeds the bounded CBOR profile.
    #[error("mdoc status extension is too long")]
    MsoStatusExtensionTooLong,

    /// A status-list index is absent, is not an unsigned integer, or exceeds the i64-safe profile.
    #[error("invalid mdoc status-list index")]
    InvalidMsoStatusListIndex,

    /// A status URI is absent or is not a valid absolute URI.
    #[error("invalid mdoc status uri")]
    InvalidMsoStatusUri,

    /// A status URI is empty.
    #[error("empty mdoc status uri")]
    EmptyMsoStatusUri,

    /// A status URI exceeds the bounded protocol profile.
    #[error("mdoc status uri is too long")]
    MsoStatusUriTooLong,

    /// An identifier-list credential identifier is empty.
    #[error("empty mdoc status identifier")]
    EmptyMsoStatusIdentifier,

    /// An identifier-list credential identifier is absent or has the wrong CBOR type.
    #[error("invalid mdoc status identifier")]
    InvalidMsoStatusIdentifier,

    /// An identifier-list credential identifier exceeds the bounded protocol profile.
    #[error("mdoc status identifier is too long")]
    MsoStatusIdentifierTooLong,

    /// An optional status trust certificate is empty or has the wrong CBOR type.
    #[error("invalid mdoc status certificate")]
    InvalidMsoStatusCertificate,

    /// An optional status trust certificate exceeds the bounded protocol profile.
    #[error("mdoc status certificate is too long")]
    MsoStatusCertificateTooLong,

    /// A DeviceResponse could not be decoded from the expected ISO map shape.
    #[error("malformed mdoc device response")]
    MalformedDeviceResponse,

    /// DeviceResponse version is not supported.
    #[error("unsupported mdoc device response version")]
    UnsupportedDeviceResponseVersion,

    /// DeviceResponse status indicates an error or is not supported.
    #[error("invalid mdoc device response status")]
    InvalidDeviceResponseStatus,

    /// Device-signed namespaces were not encoded as a CBOR map.
    #[error("invalid mdoc device namespaces")]
    InvalidDeviceNameSpaces,

    /// DeviceAuthentication payload was malformed or did not bind expected values.
    #[error("invalid mdoc device authentication")]
    InvalidDeviceAuthentication,

    /// The DeviceAuth COSE algorithm does not match the MSO device key type and curve.
    #[error("mdoc device key algorithm mismatch")]
    DeviceKeyAlgorithmMismatch,

    /// SessionTranscript CBOR input was absent or malformed.
    #[error("invalid mdoc session transcript")]
    InvalidSessionTranscript,

    /// A requested issuer-signed disclosure was not present in the mdoc.
    #[error("missing requested mdoc disclosure")]
    MissingDisclosedElement,
}

/// Error type for mdoc issuance, issuer authentication, and presentation support.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MdocEnvelopeError {
    /// Input or signed content was structurally invalid.
    #[error("invalid mdoc input")]
    InvalidInput(MdocInvalidInputReason),

    /// Canonical CBOR encoding or decoding failed.
    #[error("mdoc cbor error")]
    Cbor,

    /// Issuer authentication signing failed.
    #[error("mdoc signing failed")]
    Signing,

    /// Secure digest identifier generation failed or repeatedly collided.
    #[error("mdoc randomness unavailable")]
    RandomnessUnavailable,

    /// Issuer authentication signature verification failed.
    #[error("invalid mdoc issuer signature")]
    InvalidSignature,

    /// Device authentication signature verification failed.
    #[error("invalid mdoc device signature")]
    InvalidDeviceSignature,

    /// An issuer-signed item digest was missing or did not match the MSO.
    #[error("invalid mdoc value digest")]
    InvalidDigest,

    /// The MobileSecurityObject validity window does not include the supplied time.
    #[error("expired mdoc")]
    Expired,

    /// The current provider lane does not support the requested operation.
    #[error("unsupported mdoc operation")]
    UnsupportedOperation,
}

impl From<MdocInvalidInputReason> for IdentityCoreErrorReason {
    fn from(reason: MdocInvalidInputReason) -> Self {
        match reason {
            MdocInvalidInputReason::EmptyDocType => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_EMPTY_DOCTYPE
            }
            MdocInvalidInputReason::EmptyDeviceKey => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_EMPTY_DEVICE_KEY
            }
            MdocInvalidInputReason::InvalidValidityWindow => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_INVALID_VALIDITY_WINDOW
            }
            MdocInvalidInputReason::EmptyElements => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_EMPTY_ELEMENTS
            }
            MdocInvalidInputReason::TooManyElements => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_TOO_MANY_ELEMENTS
            }
            MdocInvalidInputReason::TooManyNamespaces => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_TOO_MANY_NAMESPACES
            }
            MdocInvalidInputReason::TooManyElementsPerNamespace => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_TOO_MANY_ELEMENTS_PER_NAMESPACE
            }
            MdocInvalidInputReason::TooManyDocuments => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_TOO_MANY_DOCUMENTS
            }
            MdocInvalidInputReason::CborDepthExceeded => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_CBOR_DEPTH_EXCEEDED
            }
            MdocInvalidInputReason::CborMapTooLarge => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_CBOR_MAP_TOO_LARGE
            }
            MdocInvalidInputReason::CborArrayTooLarge => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_CBOR_ARRAY_TOO_LARGE
            }
            MdocInvalidInputReason::CborInputTooLarge
            | MdocInvalidInputReason::CborTooManyItems
            | MdocInvalidInputReason::ElementValueTooLarge
            | MdocInvalidInputReason::TotalElementValuesTooLarge => {
                Self::IDENTITY_CORE_ERROR_REASON_RESOURCE_LIMIT_EXCEEDED
            }
            MdocInvalidInputReason::EmptyNamespace => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_EMPTY_NAMESPACE
            }
            MdocInvalidInputReason::EmptyElementIdentifier => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_EMPTY_ELEMENT_IDENTIFIER
            }
            MdocInvalidInputReason::DuplicateElementIdentifier => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_MALFORMED_ISSUER_SIGNED_ITEM
            }
            MdocInvalidInputReason::MalformedIso23220Relationship
            | MdocInvalidInputReason::DuplicateIso23220PersonalDataIdentifier => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_MALFORMED_ISSUER_SIGNED_ITEM
            }
            MdocInvalidInputReason::EmptyElementValue => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_EMPTY_ELEMENT_VALUE
            }
            MdocInvalidInputReason::EmptyRandom => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_EMPTY_RANDOM
            }
            MdocInvalidInputReason::InvalidRandomLength => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_MALFORMED_ISSUER_SIGNED_ITEM
            }
            MdocInvalidInputReason::IntegerOutOfRange => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_INTEGER_OUT_OF_RANGE
            }
            MdocInvalidInputReason::UnsupportedDigestAlgorithm => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_UNSUPPORTED_DIGEST_ALGORITHM
            }
            MdocInvalidInputReason::UnsupportedMsoVersion => {
                Self::IDENTITY_CORE_ERROR_REASON_INVALID_INPUT
            }
            MdocInvalidInputReason::InvalidTaggedItem => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_INVALID_TAGGED_ITEM
            }
            MdocInvalidInputReason::DocTypeMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_DOCTYPE_MISMATCH
            }
            MdocInvalidInputReason::MalformedIssuerSignedItem
            | MdocInvalidInputReason::MalformedIssuerSignedDocument => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_MALFORMED_ISSUER_SIGNED_ITEM
            }
            MdocInvalidInputReason::MalformedMobileSecurityObject
            | MdocInvalidInputReason::MalformedMsoStatus
            | MdocInvalidInputReason::UnknownMsoStatusMechanism
            | MdocInvalidInputReason::AmbiguousMsoStatusMechanism
            | MdocInvalidInputReason::DuplicateMsoStatusMember
            | MdocInvalidInputReason::UnknownMsoStatusMember
            | MdocInvalidInputReason::InvalidMsoStatusExtension
            | MdocInvalidInputReason::TooManyMsoStatusExtensions
            | MdocInvalidInputReason::MsoStatusExtensionTooLong
            | MdocInvalidInputReason::InvalidMsoStatusListIndex
            | MdocInvalidInputReason::InvalidMsoStatusUri
            | MdocInvalidInputReason::EmptyMsoStatusUri
            | MdocInvalidInputReason::MsoStatusUriTooLong
            | MdocInvalidInputReason::EmptyMsoStatusIdentifier
            | MdocInvalidInputReason::InvalidMsoStatusIdentifier
            | MdocInvalidInputReason::MsoStatusIdentifierTooLong
            | MdocInvalidInputReason::InvalidMsoStatusCertificate
            | MdocInvalidInputReason::MsoStatusCertificateTooLong => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_MALFORMED_MOBILE_SECURITY_OBJECT
            }
            MdocInvalidInputReason::MalformedDeviceResponse => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_MALFORMED_DEVICE_RESPONSE
            }
            MdocInvalidInputReason::UnsupportedDeviceResponseVersion => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_UNSUPPORTED_DEVICE_RESPONSE_VERSION
            }
            MdocInvalidInputReason::InvalidDeviceResponseStatus => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_INVALID_DEVICE_RESPONSE_STATUS
            }
            MdocInvalidInputReason::InvalidDeviceNameSpaces => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_INVALID_DEVICE_NAMESPACES
            }
            MdocInvalidInputReason::InvalidDeviceAuthentication => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_INVALID_DEVICE_AUTHENTICATION
            }
            MdocInvalidInputReason::DeviceKeyAlgorithmMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_INVALID_DEVICE_AUTH
            }
            MdocInvalidInputReason::InvalidSessionTranscript => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_INVALID_SESSION_TRANSCRIPT
            }
            MdocInvalidInputReason::MissingDisclosedElement => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_MISSING_DISCLOSED_ELEMENT
            }
        }
    }
}

impl From<MdocEnvelopeError> for IdentityCoreErrorReason {
    fn from(error: MdocEnvelopeError) -> Self {
        match error {
            MdocEnvelopeError::InvalidInput(reason) => reason.into(),
            MdocEnvelopeError::InvalidSignature => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_INVALID_ISSUER_AUTH
            }
            MdocEnvelopeError::InvalidDeviceSignature => {
                Self::IDENTITY_CORE_ERROR_REASON_MDOC_INVALID_DEVICE_AUTH
            }
            MdocEnvelopeError::InvalidDigest => Self::IDENTITY_CORE_ERROR_REASON_INVALID_PROOF,
            MdocEnvelopeError::Expired => Self::IDENTITY_CORE_ERROR_REASON_INVALID_STATE,
            MdocEnvelopeError::UnsupportedOperation => {
                Self::IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_FORMAT
            }
            MdocEnvelopeError::Cbor => Self::IDENTITY_CORE_ERROR_REASON_INVALID_ENCODING,
            MdocEnvelopeError::RandomnessUnavailable => {
                Self::IDENTITY_CORE_ERROR_REASON_INVALID_STATE
            }
            MdocEnvelopeError::Signing => Self::IDENTITY_CORE_ERROR_REASON_INVALID_SIGNATURE,
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
