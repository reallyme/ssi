// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stable, privacy-safe did:web errors.

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Audit-safe did:web failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DidWebErrorReason {
    /// The input does not use the did:web prefix.
    InvalidPrefix,
    /// The identifier exceeds the supported byte limit.
    IdentifierTooLong,
    /// The authority is not a canonical DNS name.
    InvalidDomain,
    /// The encoded port is invalid.
    InvalidPort,
    /// A path segment is invalid.
    InvalidPath,
    /// A percent escape is malformed or non-canonical.
    InvalidPercentEncoding,
    /// A document DID URL is not absolute and canonical.
    InvalidDidUrl,
    /// The JSON value is not a supported DID document.
    InvalidDocument,
    /// A JSON-LD document was supplied without an injected JSON-LD processor.
    JsonLdProcessorUnavailable,
    /// The injected JSON-LD processor rejected the document.
    InvalidJsonLd,
    /// The returned document identifies a different DID.
    DocumentIdentifierMismatch,
    /// A controller is invalid.
    InvalidController,
    /// A verification method is invalid.
    InvalidVerificationMethod,
    /// A relationship reference does not select a verification method.
    UnresolvedRelationshipReference,
    /// A service entry is invalid.
    InvalidService,
    /// JSON nesting or node count exceeds policy.
    JsonDepthExceeded,
    /// The target does not use HTTPS.
    HttpsRequired,
    /// Redirect handling violated policy.
    RedirectPolicyViolation,
    /// DNS returned no usable answer or failed.
    DnsResolutionFailed,
    /// Destination policy rejected an address.
    DestinationDenied,
    /// The connected peer was not in the approved DNS answer set.
    DnsRebindingDetected,
    /// Network I/O failed.
    NetworkFailure,
    /// TLS negotiation or validation failed.
    TlsFailure,
    /// A deadline expired.
    Timeout,
    /// The caller cancelled the operation.
    Cancelled,
    /// The response media type is not accepted.
    UnsupportedMediaType,
    /// The response exceeds the configured byte limit.
    ResponseTooLarge,
    /// The HTTP status is neither success nor an allowed redirect.
    HttpStatusRejected,
    /// No hosting provider was injected.
    ProviderUnavailable,
    /// The hosting provider is not authenticated.
    ProviderUnauthenticated,
    /// Hosting policy rejected the operation.
    ProviderPolicyViolation,
    /// The hosting adapter failed without exposing backend detail.
    ProviderFailure,
    /// The requested DID method is not implemented.
    UnsupportedMethod,
}

/// Typed did:web method error. It never contains identifiers, URLs, or bodies.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("did:web operation failed")]
#[non_exhaustive]
pub struct DidWebError {
    /// Stable, non-identifying failure reason.
    pub reason: DidWebErrorReason,
}

impl DidWebError {
    /// Construct a redacted method error from a stable reason.
    #[must_use]
    pub const fn new(reason: DidWebErrorReason) -> Self {
        Self { reason }
    }
}

/// Stable failures returned by an injected DNS/HTTPS implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DidWebTransportErrorReason {
    /// DNS lookup failure.
    Dns,
    /// Connection or response failure.
    Network,
    /// TLS negotiation, certificate, or hostname failure.
    Tls,
    /// Transport deadline expired.
    Timeout,
    /// Caller cancelled transport work.
    Cancelled,
}

/// Transport error that deliberately carries no backend text or target data.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("did:web transport failed")]
#[non_exhaustive]
pub struct DidWebTransportError {
    /// Stable, non-identifying transport reason.
    pub reason: DidWebTransportErrorReason,
}

/// Stable hosting-provider failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DidWebHostingErrorReason {
    /// The adapter has no valid authentication state.
    Unauthenticated,
    /// Provider policy denied the operation.
    Policy,
    /// Provider execution failed.
    Failure,
}

/// Hosting error that deliberately carries no backend text or target data.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("did:web hosting operation failed")]
#[non_exhaustive]
pub struct DidWebHostingError {
    /// Stable, non-identifying hosting reason.
    pub reason: DidWebHostingErrorReason,
}

impl DidWebHostingError {
    /// Construct a redacted hosting error.
    #[must_use]
    pub const fn new(reason: DidWebHostingErrorReason) -> Self {
        Self { reason }
    }
}

impl DidWebTransportError {
    /// Construct a redacted transport error.
    #[must_use]
    pub const fn new(reason: DidWebTransportErrorReason) -> Self {
        Self { reason }
    }
}

impl From<DidWebTransportError> for DidWebError {
    fn from(error: DidWebTransportError) -> Self {
        let reason = match error.reason {
            DidWebTransportErrorReason::Dns => DidWebErrorReason::DnsResolutionFailed,
            DidWebTransportErrorReason::Network => DidWebErrorReason::NetworkFailure,
            DidWebTransportErrorReason::Tls => DidWebErrorReason::TlsFailure,
            DidWebTransportErrorReason::Timeout => DidWebErrorReason::Timeout,
            DidWebTransportErrorReason::Cancelled => DidWebErrorReason::Cancelled,
        };
        Self::new(reason)
    }
}

impl From<DidWebHostingError> for DidWebError {
    fn from(error: DidWebHostingError) -> Self {
        let reason = match error.reason {
            DidWebHostingErrorReason::Unauthenticated => DidWebErrorReason::ProviderUnauthenticated,
            DidWebHostingErrorReason::Policy => DidWebErrorReason::ProviderPolicyViolation,
            DidWebHostingErrorReason::Failure => DidWebErrorReason::ProviderFailure,
        };
        Self::new(reason)
    }
}

impl From<DidWebErrorReason> for IdentityCoreErrorReason {
    fn from(reason: DidWebErrorReason) -> Self {
        match reason {
            DidWebErrorReason::InvalidPrefix => Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_PREFIX,
            DidWebErrorReason::UnsupportedMethod => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_UNSUPPORTED_METHOD
            }
            DidWebErrorReason::IdentifierTooLong => {
                Self::IDENTITY_CORE_ERROR_REASON_RESOURCE_LIMIT_EXCEEDED
            }
            DidWebErrorReason::InvalidDomain => Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOMAIN,
            DidWebErrorReason::InvalidPort => Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_PORT,
            DidWebErrorReason::InvalidPath | DidWebErrorReason::InvalidPercentEncoding => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_PATH
            }
            DidWebErrorReason::InvalidDidUrl => Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_URL,
            DidWebErrorReason::InvalidDocument => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOCUMENT
            }
            DidWebErrorReason::JsonLdProcessorUnavailable => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_JSON_LD_PROCESSOR_UNAVAILABLE
            }
            DidWebErrorReason::InvalidJsonLd => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_JSON_LD
            }
            DidWebErrorReason::DocumentIdentifierMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_DOCUMENT_IDENTIFIER_MISMATCH
            }
            DidWebErrorReason::InvalidVerificationMethod => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_VERIFICATION_METHOD
            }
            DidWebErrorReason::InvalidController => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_CONTROLLER_MISMATCH
            }
            DidWebErrorReason::UnresolvedRelationshipReference => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_RESOURCE_NOT_FOUND
            }
            DidWebErrorReason::InvalidService => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_SERVICE
            }
            DidWebErrorReason::JsonDepthExceeded => {
                Self::IDENTITY_CORE_ERROR_REASON_RESOURCE_LIMIT_EXCEEDED
            }
            DidWebErrorReason::HttpsRequired
            | DidWebErrorReason::DestinationDenied
            | DidWebErrorReason::DnsRebindingDetected
            | DidWebErrorReason::ProviderPolicyViolation => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_WEB_POLICY_VIOLATION
            }
            DidWebErrorReason::RedirectPolicyViolation => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_WEB_REDIRECT_REJECTED
            }
            DidWebErrorReason::DnsResolutionFailed | DidWebErrorReason::NetworkFailure => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_WEB_NETWORK_FAILURE
            }
            DidWebErrorReason::TlsFailure => Self::IDENTITY_CORE_ERROR_REASON_DID_WEB_TLS_FAILURE,
            DidWebErrorReason::Timeout => Self::IDENTITY_CORE_ERROR_REASON_DID_WEB_TIMEOUT,
            DidWebErrorReason::Cancelled => Self::IDENTITY_CORE_ERROR_REASON_DID_WEB_CANCELLED,
            DidWebErrorReason::UnsupportedMediaType => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_WEB_MEDIA_TYPE_REJECTED
            }
            DidWebErrorReason::ResponseTooLarge => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_WEB_RESPONSE_TOO_LARGE
            }
            DidWebErrorReason::HttpStatusRejected => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_WEB_HTTP_STATUS_REJECTED
            }
            DidWebErrorReason::ProviderUnavailable => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_WEB_PROVIDER_UNAVAILABLE
            }
            DidWebErrorReason::ProviderUnauthenticated => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_WEB_PROVIDER_UNAUTHENTICATED
            }
            DidWebErrorReason::ProviderFailure => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_WEB_PROVIDER_FAILURE
            }
        }
    }
}

/// Stable JSON-LD processing failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DidWebJsonLdErrorReason {
    /// JSON-LD expansion, context loading, or data-model conversion failed.
    InvalidDocument,
}

/// Typed, redacted failure returned by an injected JSON-LD processor.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("did:web JSON-LD processing failed")]
#[non_exhaustive]
pub struct DidWebJsonLdError {
    /// Stable failure reason without document or context data.
    pub reason: DidWebJsonLdErrorReason,
}

impl DidWebJsonLdError {
    /// Construct a redacted JSON-LD processing error.
    #[must_use]
    pub const fn new(reason: DidWebJsonLdErrorReason) -> Self {
        Self { reason }
    }
}

impl From<DidWebError> for IdentityCoreErrorReason {
    fn from(error: DidWebError) -> Self {
        error.reason.into()
    }
}

#[cfg(test)]
#[path = "lib_proto_error_tests.rs"]
mod proto_error_tests;
