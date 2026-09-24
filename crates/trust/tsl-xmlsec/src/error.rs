// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// Error returned by the TSL XMLDSig verifier.
#[derive(Debug, Error)]
pub enum XmlSecError {
    /// The native xmlsec backend was not compiled into this build.
    #[error("XMLDSig backend not available (enable feature `xmlsec-ffi`)")]
    BackendUnavailable,

    /// The XML input violates the TSL-specific verifier hardening policy.
    #[error("XMLDSig policy violation")]
    PolicyViolation(XmlSecPolicyViolationReason),

    /// The document signature was absent or failed cryptographic verification.
    #[error("invalid or missing XML signature")]
    InvalidSignature,

    /// The document failed the pinned ETSI TS 119 612 XSD.
    #[error("trusted-list XML schema validation failed")]
    SchemaValidationFailed,

    /// The verifier could not classify a parser, locking, or backend failure more narrowly.
    #[error("internal error")]
    Internal,
}

/// TSL-specific XMLDSig policy violation reason.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum XmlSecPolicyViolationReason {
    /// The document root is not an ETSI TrustServiceStatusList element.
    #[error("root element must be TrustServiceStatusList")]
    InvalidRootElement,

    /// The TSL root has no `xml:id` or `id` attribute for same-document reference binding.
    #[error("TSL root must have xml:id for same-document reference resolution")]
    MissingRootId,

    /// The XML parser reached EOF before finding a root element.
    #[error("TSL root element is missing")]
    MissingRootElement,

    /// RetrievalMethod indirection is not allowed by this verifier profile.
    #[error("RetrievalMethod is not allowed for TSL/LOTL verification")]
    RetrievalMethodNotAllowed,

    /// KeyInfoReference indirection is not allowed by this verifier profile.
    #[error("KeyInfoReference is not allowed for TSL/LOTL verification")]
    KeyInfoReferenceNotAllowed,

    /// A ds:Reference URI targeted anything other than a same-document fragment.
    #[error("Reference URI must be same-document")]
    NonSameDocumentReference,

    /// The signed structure is ambiguous, incomplete, or outside the strict TSL profile.
    #[error("XML signature structure is not the strict TSL profile")]
    InvalidSignatureProfile,

    /// An XML ID value is repeated and could enable wrapping ambiguity.
    #[error("XML ID values must be unique")]
    DuplicateId,

    /// A signature, digest, canonicalization, or transform algorithm is not allowed.
    #[error("XML signature algorithm is not allowed")]
    UnsupportedAlgorithm,

    /// The backend-selected verification certificate was not present in the verified KeyInfo.
    #[error("XML signature verification key is not bound to KeyInfo")]
    SignerBindingMismatch,

    /// The root reference did not use the mandated transforms in exact order.
    #[error("TSL root reference transforms do not match TS 119 612 Annex B.1")]
    RootTransformProfile,

    /// XAdES signed properties were absent, ambiguous, or not reference-bound.
    #[error("XAdES signed properties are invalid")]
    InvalidSignedProperties,

    /// SigningCertificateV2 was absent, ambiguous, or malformed.
    #[error("XAdES SigningCertificateV2 is invalid")]
    InvalidSigningCertificate,

    /// SigningTime was absent, ambiguous, malformed, or outside its signed container.
    #[error("XAdES SigningTime is invalid")]
    InvalidSigningTime,

    /// DataObjectFormat did not cover each signed data object exactly once.
    #[error("XAdES DataObjectFormat coverage is invalid")]
    InvalidDataObjectFormat,

    /// SigningCertificateV2 did not identify the backend-selected signer.
    #[error("XAdES signing-certificate digest does not match the signer")]
    SigningCertificateMismatch,

    /// KeyInfo did not carry exactly the one TLSO certificate allowed by TS 119 612.
    #[error("KeyInfo must carry exactly one TLSO certificate")]
    KeyInfoCertificateCount,
}

impl From<XmlSecPolicyViolationReason> for IdentityCoreErrorReason {
    fn from(reason: XmlSecPolicyViolationReason) -> Self {
        match reason {
            XmlSecPolicyViolationReason::InvalidRootElement => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_INVALID_ROOT_ELEMENT
            }
            XmlSecPolicyViolationReason::MissingRootId => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_MISSING_ROOT_ID
            }
            XmlSecPolicyViolationReason::MissingRootElement => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_MISSING_ROOT_ELEMENT
            }
            XmlSecPolicyViolationReason::RetrievalMethodNotAllowed => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_RETRIEVAL_METHOD_NOT_ALLOWED
            }
            XmlSecPolicyViolationReason::KeyInfoReferenceNotAllowed => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_KEY_INFO_REFERENCE_NOT_ALLOWED
            }
            XmlSecPolicyViolationReason::NonSameDocumentReference => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_NON_SAME_DOCUMENT_REFERENCE
            }
            XmlSecPolicyViolationReason::InvalidSignatureProfile => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_INVALID_SIGNATURE_PROFILE
            }
            XmlSecPolicyViolationReason::DuplicateId => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_DUPLICATE_ID
            }
            XmlSecPolicyViolationReason::UnsupportedAlgorithm => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_UNSUPPORTED_ALGORITHM
            }
            XmlSecPolicyViolationReason::SignerBindingMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_SIGNER_BINDING_MISMATCH
            }
            XmlSecPolicyViolationReason::RootTransformProfile => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_ROOT_TRANSFORMS
            }
            XmlSecPolicyViolationReason::InvalidSignedProperties => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XADES_SIGNED_PROPERTIES
            }
            XmlSecPolicyViolationReason::InvalidSigningCertificate => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XADES_SIGNING_CERTIFICATE
            }
            XmlSecPolicyViolationReason::InvalidSigningTime => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XADES_SIGNING_TIME
            }
            XmlSecPolicyViolationReason::InvalidDataObjectFormat => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XADES_DATA_OBJECT_FORMAT
            }
            XmlSecPolicyViolationReason::SigningCertificateMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XADES_CERTIFICATE_MISMATCH
            }
            XmlSecPolicyViolationReason::KeyInfoCertificateCount => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_KEY_INFO_CERTIFICATE_COUNT
            }
        }
    }
}

impl From<XmlSecError> for IdentityCoreErrorReason {
    fn from(reason: XmlSecError) -> Self {
        match reason {
            XmlSecError::BackendUnavailable => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_BACKEND_UNAVAILABLE
            }
            XmlSecError::PolicyViolation(reason) => reason.into(),
            XmlSecError::InvalidSignature => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_INVALID_SIGNATURE
            }
            XmlSecError::SchemaValidationFailed => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_SCHEMA_VALIDATION_FAILED
            }
            XmlSecError::Internal => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_INTERNAL
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
