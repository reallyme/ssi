// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// Typed failures for native TSL XMLDSig and signer trust verification.
#[derive(Debug, Error)]
pub enum TslOpenSslError {
    /// The authenticated document failed portable TS 119 612 projection.
    ///
    /// Retaining the core reason is intentional: callers must distinguish
    /// malformed provider and service identities from a generic XML failure,
    /// including through the protobuf error contract.
    #[error("trusted-list semantic validation failed")]
    TrustedList(identity_trust_tsl_core::TslError),

    /// XML parsing failed.
    #[error("invalid XML")]
    InvalidXml,

    /// The root tag is not the exact TS 119 612 TSLTag discriminator.
    #[error("invalid trusted-list tag")]
    InvalidTag,

    /// NextUpdate is not after issuance or exceeds six calendar months.
    #[error("invalid trusted-list update window")]
    InvalidUpdateWindow,

    /// XML signature was missing or invalid.
    #[error("invalid or missing XML signature")]
    InvalidSignature,

    /// The TSL signing certificate could not be extracted or parsed.
    #[error("unable to extract signing certificate")]
    InvalidSigner,

    /// The XMLDSig signer is not the exact externally authorized certificate.
    #[error("trusted-list signer does not match the externally authorized certificate")]
    ExternalSignerCertificateMismatch,

    /// Trust-root input failed validation before backend processing.
    #[error("invalid TSL trust-root input")]
    TrustRoots(TslTrustRootErrorReason),

    /// The TSL signer certificate failed trust evaluation.
    #[error("TSL signer is not trusted")]
    TrustFailure(TslSignerTrustFailureReason),

    /// The authenticated TLSO certificate violates TS 119 612 clause 5.7.1.
    #[error("TSL signer certificate profile is invalid")]
    SignerProfile(TslSignerProfileFailureReason),

    /// The XML signature violates the TS 119 612 XAdES/XMLDSig profile.
    #[error("TSL XAdES signature profile is invalid")]
    SignatureProfile(TslSignatureProfileFailureReason),

    /// The authenticated list's TS 119 612 re-issuance deadline elapsed.
    #[error("trusted list is expired")]
    ExpiredTrustedList,

    /// A critical TSL extension has semantics this verifier does not implement.
    #[error("unsupported critical TSL extension")]
    UnsupportedCriticalExtension,

    /// Native backend is unavailable on this target.
    #[error("TSL verification backend is unavailable on this platform/build")]
    BackendUnavailable,

    /// Internal verification failure.
    #[error("internal error")]
    Internal,
}

/// Fixed reason for rejecting the TS 119 612 XMLDSig/XAdES signature profile.
///
/// The reason remains typed across the native adapter so the protobuf contract
/// can preserve the exact ETSI EN 319 132-1 or TS 119 612 policy failure rather
/// than reducing every structural rejection to a generic signature error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslSignatureProfileFailureReason {
    /// The document root is not an ETSI `TrustServiceStatusList` element.
    #[error("root element must be TrustServiceStatusList")]
    InvalidRootElement,
    /// The TSL root has no ID for same-document reference binding.
    #[error("trusted-list root identifier is missing")]
    MissingRootId,
    /// The XML document contains no root element.
    #[error("trusted-list root element is missing")]
    MissingRootElement,
    /// XMLDSig `RetrievalMethod` indirection is outside the closed profile.
    #[error("RetrievalMethod is not allowed")]
    RetrievalMethodNotAllowed,
    /// XMLDSig `KeyInfoReference` indirection is outside the closed profile.
    #[error("KeyInfoReference is not allowed")]
    KeyInfoReferenceNotAllowed,
    /// A reference does not identify an element in the same XML document.
    #[error("reference is not same-document")]
    NonSameDocumentReference,
    /// The signature structure is ambiguous, incomplete, or outside the profile.
    #[error("XML signature structure is invalid")]
    InvalidSignatureProfile,
    /// An XML identifier is repeated and could enable wrapping ambiguity.
    #[error("XML identifier is duplicated")]
    DuplicateId,
    /// An XML signature, digest, canonicalization, or transform suite is disallowed.
    #[error("XML signature algorithm is not allowed")]
    UnsupportedAlgorithm,
    /// The backend-selected signer is not bound to authenticated `KeyInfo`.
    #[error("XML signature signer is not bound to KeyInfo")]
    SignerBindingMismatch,
    /// The TSL root reference transforms do not match TS 119 612 Annex B.1.
    #[error("trusted-list root transforms are invalid")]
    RootTransformProfile,
    /// EN 319 132-1 signed properties are missing, ambiguous, or unbound.
    #[error("XAdES signed properties are invalid")]
    InvalidSignedProperties,
    /// `SigningCertificateV2` is missing, ambiguous, or malformed.
    #[error("XAdES signing-certificate property is invalid")]
    InvalidSigningCertificate,
    /// `SigningTime` is missing, ambiguous, malformed, or not protected.
    #[error("XAdES signing time is invalid")]
    InvalidSigningTime,
    /// `DataObjectFormat` does not cover every signed data object exactly once.
    #[error("XAdES data-object format coverage is invalid")]
    InvalidDataObjectFormat,
    /// `SigningCertificateV2` does not identify the authenticated signer.
    #[error("XAdES signing certificate does not match the signer")]
    SigningCertificateMismatch,
    /// `KeyInfo` does not contain exactly the one TLSO certificate allowed.
    #[error("KeyInfo certificate count is invalid")]
    KeyInfoCertificateCount,
}

impl From<TslSignatureProfileFailureReason> for IdentityCoreErrorReason {
    fn from(reason: TslSignatureProfileFailureReason) -> Self {
        match reason {
            TslSignatureProfileFailureReason::InvalidRootElement => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_INVALID_ROOT_ELEMENT
            }
            TslSignatureProfileFailureReason::MissingRootId => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_MISSING_ROOT_ID
            }
            TslSignatureProfileFailureReason::MissingRootElement => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_MISSING_ROOT_ELEMENT
            }
            TslSignatureProfileFailureReason::RetrievalMethodNotAllowed => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_RETRIEVAL_METHOD_NOT_ALLOWED
            }
            TslSignatureProfileFailureReason::KeyInfoReferenceNotAllowed => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_KEY_INFO_REFERENCE_NOT_ALLOWED
            }
            TslSignatureProfileFailureReason::NonSameDocumentReference => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_NON_SAME_DOCUMENT_REFERENCE
            }
            TslSignatureProfileFailureReason::InvalidSignatureProfile => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_INVALID_SIGNATURE_PROFILE
            }
            TslSignatureProfileFailureReason::DuplicateId => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_DUPLICATE_ID
            }
            TslSignatureProfileFailureReason::UnsupportedAlgorithm => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_UNSUPPORTED_ALGORITHM
            }
            TslSignatureProfileFailureReason::SignerBindingMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_SIGNER_BINDING_MISMATCH
            }
            TslSignatureProfileFailureReason::RootTransformProfile => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_ROOT_TRANSFORMS
            }
            TslSignatureProfileFailureReason::InvalidSignedProperties => {
                Self::IDENTITY_CORE_ERROR_REASON_XADES_SIGNED_PROPERTIES
            }
            TslSignatureProfileFailureReason::InvalidSigningCertificate => {
                Self::IDENTITY_CORE_ERROR_REASON_XADES_SIGNING_CERTIFICATE
            }
            TslSignatureProfileFailureReason::InvalidSigningTime => {
                Self::IDENTITY_CORE_ERROR_REASON_XADES_SIGNING_TIME
            }
            TslSignatureProfileFailureReason::InvalidDataObjectFormat => {
                Self::IDENTITY_CORE_ERROR_REASON_XADES_DATA_OBJECT_FORMAT
            }
            TslSignatureProfileFailureReason::SigningCertificateMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_XADES_CERTIFICATE_MISMATCH
            }
            TslSignatureProfileFailureReason::KeyInfoCertificateCount => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_KEY_INFO_CERTIFICATE_COUNT
            }
        }
    }
}

/// Fixed, non-secret reason for rejecting TSL trust-root input.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslTrustRootErrorReason {
    /// At least one trust root is required.
    #[error("trust-root collection is empty")]
    Empty,

    /// The collection exceeds the trust core's public root-count bound.
    #[error("too many trust roots")]
    TooManyTrustRoots,

    /// One root exceeds the X.509 parser's DER input bound.
    #[error("trust-root DER exceeds its fixed bound")]
    CertificateDerTooLarge,

    /// The complete PEM bundle exceeds its fixed byte budget.
    #[error("trust-root PEM bundle exceeds its fixed bound")]
    PemBundleTooLarge,

    /// The bounded PEM allocation could not be reserved.
    #[error("trust-root PEM allocation failed")]
    AllocationFailed,

    /// A bounded trust-root DER value was not a certificate.
    #[error("trust-root DER is invalid")]
    InvalidCertificateDer,
}

impl From<TslTrustRootErrorReason> for IdentityCoreErrorReason {
    fn from(reason: TslTrustRootErrorReason) -> Self {
        match reason {
            TslTrustRootErrorReason::Empty => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_API_INVALID_INPUT
            }
            TslTrustRootErrorReason::TooManyTrustRoots => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_RESOURCE_TOO_MANY_ROOTS
            }
            TslTrustRootErrorReason::CertificateDerTooLarge => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_CERTIFICATE_DER_TOO_LARGE
            }
            TslTrustRootErrorReason::PemBundleTooLarge => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_CERTIFICATE_PEM_BUNDLE_TOO_LARGE
            }
            TslTrustRootErrorReason::AllocationFailed => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_RESOURCE_LIMIT_EXCEEDED
            }
            TslTrustRootErrorReason::InvalidCertificateDer => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_INVALID_DER
            }
        }
    }
}

/// Non-secret reason code for TSL signer trust failure.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslSignerTrustFailureReason {
    /// No trust path reached a configured root.
    #[error("no valid trust path")]
    NoValidPath,

    /// Signer certificate was outside its validity window.
    #[error("invalid signer validity time")]
    InvalidTime,

    /// Chain-link policy failed.
    #[error("chain linkage policy violation")]
    ChainLinkPolicy,

    /// Signer certificate signature failed verification.
    #[error("invalid signer signature")]
    InvalidSignature,

    /// Signer certificate was revoked.
    #[error("signer certificate revoked")]
    Revoked,

    /// Signer status check failed.
    #[error("signer status check failed")]
    StatusFailure,

    /// Internal trust evaluation failed.
    #[error("internal trust evaluation failure")]
    Internal,

    /// Signer trust configuration exceeded a fixed core resource bound.
    #[error("signer trust configuration resource limit exceeded")]
    ResourceLimit,

    /// Available evidence conclusively rejected the signer.
    #[error("TSL signer trust was rejected")]
    Rejected,

    /// Required signer trust evidence or capability was unavailable.
    #[error("TSL signer trust is indeterminate")]
    Indeterminate,
}

/// Fixed reason for a TS 119 612 TLSO certificate profile rejection.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslSignerProfileFailureReason {
    /// Issuer is neither the TLSO itself nor a service in the current or an
    /// authenticated same-community trusted list.
    #[error("certificate issuer is not an authorized trusted-list signer issuer")]
    UnauthorizedIssuer,
    /// Too many authenticated community lists were supplied for issuer policy.
    #[error("too many authenticated community lists")]
    CommunityListLimit,
    /// Subject country does not equal the authenticated scheme territory.
    #[error("certificate subject country does not match SchemeTerritory")]
    CountryMismatch,
    /// No textual Subject organization equals an authenticated operator name.
    #[error("certificate subject organization does not match SchemeOperatorName")]
    OrganizationMismatch,
    /// RFC 5280 KeyUsage is absent.
    #[error("certificate key usage is missing")]
    MissingKeyUsage,
    /// A usage other than signature/content commitment is asserted.
    #[error("certificate key usage is not exclusive to signature or content commitment")]
    InvalidKeyUsage,
    /// RFC 5280 SubjectKeyIdentifier is absent or empty.
    #[error("certificate subject key identifier is missing")]
    MissingSubjectKeyIdentifier,
    /// SubjectKeyIdentifier is not an RFC 5280 method (1) or method (2)
    /// identifier for the certificate's exact subjectPublicKey bits.
    #[error("certificate subject key identifier is not derived from the subject public key")]
    InvalidSubjectKeyIdentifier,
    /// BasicConstraints is absent or marks the signer as a CA.
    #[error("certificate basic constraints do not assert CA=false")]
    InvalidBasicConstraints,
    /// ExtendedKeyUsage is absent or not exclusive to trusted-list signing.
    #[error("certificate extended key usage is not restricted to trusted-list signing")]
    InvalidExtendedKeyUsage,
    /// The key or certificate signature suite fails the three-year horizon.
    #[error("certificate key or signature algorithm lacks the required usable lifetime")]
    AlgorithmLifetime,
}

impl From<TslSignerProfileFailureReason> for IdentityCoreErrorReason {
    fn from(reason: TslSignerProfileFailureReason) -> Self {
        match reason {
            TslSignerProfileFailureReason::UnauthorizedIssuer => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_UNAUTHORIZED_ISSUER
            }
            TslSignerProfileFailureReason::CommunityListLimit => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_COMMUNITY_LIST_LIMIT
            }
            TslSignerProfileFailureReason::CountryMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_COUNTRY_MISMATCH
            }
            TslSignerProfileFailureReason::OrganizationMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_ORGANIZATION_MISMATCH
            }
            TslSignerProfileFailureReason::MissingKeyUsage => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_MISSING_KEY_USAGE
            }
            TslSignerProfileFailureReason::InvalidKeyUsage => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_KEY_USAGE
            }
            TslSignerProfileFailureReason::MissingSubjectKeyIdentifier => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_SUBJECT_KEY_IDENTIFIER
            }
            TslSignerProfileFailureReason::InvalidSubjectKeyIdentifier => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_INVALID_SUBJECT_KEY_IDENTIFIER
            }
            TslSignerProfileFailureReason::InvalidBasicConstraints => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_BASIC_CONSTRAINTS
            }
            TslSignerProfileFailureReason::InvalidExtendedKeyUsage => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_EXTENDED_KEY_USAGE
            }
            TslSignerProfileFailureReason::AlgorithmLifetime => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_ALGORITHM_LIFETIME
            }
        }
    }
}

impl From<TslSignerTrustFailureReason> for IdentityCoreErrorReason {
    fn from(reason: TslSignerTrustFailureReason) -> Self {
        match reason {
            TslSignerTrustFailureReason::NoValidPath => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_NO_VALID_PATH
            }
            TslSignerTrustFailureReason::InvalidTime => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_INVALID_TIME
            }
            TslSignerTrustFailureReason::ChainLinkPolicy => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_CHAIN_LINK_POLICY
            }
            TslSignerTrustFailureReason::InvalidSignature => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_INVALID_SIGNATURE
            }
            TslSignerTrustFailureReason::Revoked => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_REVOKED
            }
            TslSignerTrustFailureReason::StatusFailure => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_STATUS_FAILURE
            }
            TslSignerTrustFailureReason::Internal => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_INTERNAL
            }
            TslSignerTrustFailureReason::ResourceLimit => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_RESOURCE_LIMIT
            }
            TslSignerTrustFailureReason::Rejected => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_REJECTED
            }
            TslSignerTrustFailureReason::Indeterminate => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_INDETERMINATE
            }
        }
    }
}

impl From<TslOpenSslError> for IdentityCoreErrorReason {
    fn from(reason: TslOpenSslError) -> Self {
        match reason {
            TslOpenSslError::TrustedList(reason) => reason.into(),
            TslOpenSslError::InvalidXml => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_OPENSSL_INVALID_XML
            }
            TslOpenSslError::InvalidTag => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_TAG
            }
            TslOpenSslError::InvalidUpdateWindow => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_UPDATE_WINDOW
            }
            TslOpenSslError::InvalidSignature => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_OPENSSL_INVALID_SIGNATURE
            }
            TslOpenSslError::InvalidSigner => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_OPENSSL_INVALID_SIGNER
            }
            TslOpenSslError::ExternalSignerCertificateMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_EXTERNAL_CERTIFICATE_MISMATCH
            }
            TslOpenSslError::TrustRoots(reason) => reason.into(),
            TslOpenSslError::TrustFailure(reason) => reason.into(),
            TslOpenSslError::SignerProfile(reason) => reason.into(),
            TslOpenSslError::SignatureProfile(reason) => reason.into(),
            TslOpenSslError::ExpiredTrustedList => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_EXPIRED
            }
            TslOpenSslError::UnsupportedCriticalExtension => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_UNSUPPORTED_CRITICAL_EXTENSION
            }
            TslOpenSslError::BackendUnavailable => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_OPENSSL_BACKEND_UNAVAILABLE
            }
            TslOpenSslError::Internal => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_OPENSSL_INTERNAL
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
