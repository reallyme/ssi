// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// Typed trust API failures.
#[derive(Debug, Error)]
pub enum TrustApiError {
    /// The trusted-list document failed typed TS 119 612 validation.
    #[error("trusted-list semantic validation failed")]
    TrustedList(identity_trust_tsl_core::TslError),

    /// Input shape or required field validation failed.
    #[error("invalid input")]
    InvalidInput,

    /// Certificate chain did not satisfy trust policy.
    #[error("certificate chain not trusted")]
    NotTrusted,

    /// Issuer is not authorized by the supplied trusted list.
    #[error("issuer not authorized by trusted list")]
    NotAuthorized,

    /// Trust service exists but is not active.
    #[error("trust service is not active")]
    ServiceNotActive,

    /// Trust service status was absent or unknown.
    #[error("trust service status unknown")]
    ServiceStatusUnknown,

    /// Trust service type was absent or unknown.
    #[error("trust service type unknown")]
    ServiceTypeUnknown,

    /// Trust service type does not authorize the requested purpose.
    #[error("trust service does not authorize requested purpose")]
    ServiceTypeMismatch,

    /// Certificate was revoked.
    #[error("certificate revoked")]
    Revoked,

    /// Certificate was suspended.
    #[error("certificate suspended")]
    Suspended,

    /// Signature verification failed.
    #[error("signature verification failed")]
    InvalidSignature,

    /// Trust policy failed for a fixed reason.
    #[error("policy violation")]
    Policy(TrustPolicyErrorReason),

    /// An authenticated trusted list violates its ETSI profile.
    #[error("trusted-list policy violation")]
    TrustedListPolicy(TrustedListPolicyErrorReason),

    /// A fixed trust-resource boundary was exceeded.
    #[error("trust resource limit exceeded")]
    ResourceLimit(TrustApiResourceLimitReason),

    /// Backend failed without exposing implementation details.
    #[error("backend verification failure")]
    BackendFailure,
}

/// Fixed, non-secret ETSI trusted-list profile failure reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TrustedListPolicyErrorReason {
    /// The root tag is not the exact TS 119 612 TSLTag discriminator.
    #[error("invalid trusted-list tag")]
    InvalidTag,
    /// NextUpdate is not after issuance or exceeds six calendar months.
    #[error("invalid trusted-list update window")]
    InvalidUpdateWindow,
    /// Issuer is neither the TLSO itself nor a TSP service in the current or
    /// an authenticated same-community trusted list.
    #[error("certificate issuer is not authorized by the trusted-list community")]
    UnauthorizedIssuer,
    /// Too many authenticated community lists were supplied.
    #[error("too many authenticated trusted-list community inputs")]
    CommunityListLimit,
    /// The XMLDSig signer differs from the certificate authenticated by the
    /// external LOTL bootstrap source.
    #[error("trusted-list signer does not match externally authorized certificate")]
    ExternalSignerCertificateMismatch,
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
    /// SubjectKeyIdentifier is not derived using an admitted RFC 5280 method.
    #[error("certificate subject key identifier is invalid")]
    InvalidSubjectKeyIdentifier,
    /// BasicConstraints is absent or marks the signer as a CA.
    #[error("certificate basic constraints do not assert CA=false")]
    InvalidBasicConstraints,
    /// ExtendedKeyUsage is absent or not exclusive to trusted-list signing.
    #[error("certificate extended key usage is not restricted to trusted-list signing")]
    InvalidExtendedKeyUsage,
    /// The key or certificate signature suite fails the required usable lifetime.
    #[error("certificate key or signature algorithm lacks the required usable lifetime")]
    AlgorithmLifetime,
    /// The XML signature violates the TS 119 612 XAdES/XMLDSig profile.
    #[error("trusted-list XAdES signature profile is invalid")]
    SignatureProfile(TrustedListSignatureProfileErrorReason),
    /// The authenticated list's TS 119 612 re-issuance deadline elapsed.
    #[error("trusted list is expired")]
    Expired,
    /// A critical TSL extension is not recognized by the shared verifier.
    #[error("unsupported critical trusted-list extension")]
    UnsupportedCriticalExtension,
}

/// Fixed XMLDSig/XAdES reason returned by trusted-list verification.
///
/// These values retain the protobuf-first error taxonomy across the native
/// adapter and public API. The distinctions correspond to the closed XMLDSig
/// profile in TS 119 612 Annex B and the XAdES baseline rules in EN 319 132-1.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TrustedListSignatureProfileErrorReason {
    /// The document root is not an ETSI `TrustServiceStatusList` element.
    #[error("root element must be TrustServiceStatusList")]
    InvalidRootElement,
    /// The TSL root has no identifier for same-document reference binding.
    #[error("trusted-list root identifier is missing")]
    MissingRootId,
    /// The XML document contains no root element.
    #[error("trusted-list root element is missing")]
    MissingRootElement,
    /// XMLDSig `RetrievalMethod` indirection is not allowed.
    #[error("RetrievalMethod is not allowed")]
    RetrievalMethodNotAllowed,
    /// XMLDSig `KeyInfoReference` indirection is not allowed.
    #[error("KeyInfoReference is not allowed")]
    KeyInfoReferenceNotAllowed,
    /// A signature reference does not target the same document.
    #[error("reference is not same-document")]
    NonSameDocumentReference,
    /// The XML signature structure is incomplete, ambiguous, or disallowed.
    #[error("XML signature structure is invalid")]
    InvalidSignatureProfile,
    /// An XML identifier is repeated.
    #[error("XML identifier is duplicated")]
    DuplicateId,
    /// A signature, digest, canonicalization, or transform suite is disallowed.
    #[error("XML signature algorithm is not allowed")]
    UnsupportedAlgorithm,
    /// The backend-selected signer is not bound to authenticated `KeyInfo`.
    #[error("XML signature signer is not bound to KeyInfo")]
    SignerBindingMismatch,
    /// The root-reference transforms do not match TS 119 612 Annex B.1.
    #[error("trusted-list root transforms are invalid")]
    RootTransformProfile,
    /// XAdES signed properties are missing, ambiguous, or not reference-bound.
    #[error("XAdES signed properties are invalid")]
    InvalidSignedProperties,
    /// `SigningCertificateV2` is missing, ambiguous, or malformed.
    #[error("XAdES signing-certificate property is invalid")]
    InvalidSigningCertificate,
    /// `SigningTime` is missing, ambiguous, malformed, or not protected.
    #[error("XAdES signing time is invalid")]
    InvalidSigningTime,
    /// `DataObjectFormat` does not cover every signed object exactly once.
    #[error("XAdES data-object format coverage is invalid")]
    InvalidDataObjectFormat,
    /// `SigningCertificateV2` does not identify the authenticated signer.
    #[error("XAdES signing certificate does not match the signer")]
    SigningCertificateMismatch,
    /// `KeyInfo` does not carry exactly one TLSO certificate.
    #[error("KeyInfo certificate count is invalid")]
    KeyInfoCertificateCount,
}

impl From<TrustedListSignatureProfileErrorReason> for IdentityCoreErrorReason {
    fn from(reason: TrustedListSignatureProfileErrorReason) -> Self {
        match reason {
            TrustedListSignatureProfileErrorReason::InvalidRootElement => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_INVALID_ROOT_ELEMENT
            }
            TrustedListSignatureProfileErrorReason::MissingRootId => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_MISSING_ROOT_ID
            }
            TrustedListSignatureProfileErrorReason::MissingRootElement => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_MISSING_ROOT_ELEMENT
            }
            TrustedListSignatureProfileErrorReason::RetrievalMethodNotAllowed => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_RETRIEVAL_METHOD_NOT_ALLOWED
            }
            TrustedListSignatureProfileErrorReason::KeyInfoReferenceNotAllowed => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_KEY_INFO_REFERENCE_NOT_ALLOWED
            }
            TrustedListSignatureProfileErrorReason::NonSameDocumentReference => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_NON_SAME_DOCUMENT_REFERENCE
            }
            TrustedListSignatureProfileErrorReason::InvalidSignatureProfile => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_INVALID_SIGNATURE_PROFILE
            }
            TrustedListSignatureProfileErrorReason::DuplicateId => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_DUPLICATE_ID
            }
            TrustedListSignatureProfileErrorReason::UnsupportedAlgorithm => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_UNSUPPORTED_ALGORITHM
            }
            TrustedListSignatureProfileErrorReason::SignerBindingMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_SIGNER_BINDING_MISMATCH
            }
            TrustedListSignatureProfileErrorReason::RootTransformProfile => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_ROOT_TRANSFORMS
            }
            TrustedListSignatureProfileErrorReason::InvalidSignedProperties => {
                Self::IDENTITY_CORE_ERROR_REASON_XADES_SIGNED_PROPERTIES
            }
            TrustedListSignatureProfileErrorReason::InvalidSigningCertificate => {
                Self::IDENTITY_CORE_ERROR_REASON_XADES_SIGNING_CERTIFICATE
            }
            TrustedListSignatureProfileErrorReason::InvalidSigningTime => {
                Self::IDENTITY_CORE_ERROR_REASON_XADES_SIGNING_TIME
            }
            TrustedListSignatureProfileErrorReason::InvalidDataObjectFormat => {
                Self::IDENTITY_CORE_ERROR_REASON_XADES_DATA_OBJECT_FORMAT
            }
            TrustedListSignatureProfileErrorReason::SigningCertificateMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_XADES_CERTIFICATE_MISMATCH
            }
            TrustedListSignatureProfileErrorReason::KeyInfoCertificateCount => {
                Self::IDENTITY_CORE_ERROR_REASON_XMLSEC_KEY_INFO_CERTIFICATE_COUNT
            }
        }
    }
}

impl From<TrustedListPolicyErrorReason> for IdentityCoreErrorReason {
    fn from(reason: TrustedListPolicyErrorReason) -> Self {
        match reason {
            TrustedListPolicyErrorReason::InvalidTag => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_TAG
            }
            TrustedListPolicyErrorReason::InvalidUpdateWindow => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_UPDATE_WINDOW
            }
            TrustedListPolicyErrorReason::UnauthorizedIssuer => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_UNAUTHORIZED_ISSUER
            }
            TrustedListPolicyErrorReason::CommunityListLimit => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_COMMUNITY_LIST_LIMIT
            }
            TrustedListPolicyErrorReason::ExternalSignerCertificateMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_EXTERNAL_CERTIFICATE_MISMATCH
            }
            TrustedListPolicyErrorReason::CountryMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_COUNTRY_MISMATCH
            }
            TrustedListPolicyErrorReason::OrganizationMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_ORGANIZATION_MISMATCH
            }
            TrustedListPolicyErrorReason::MissingKeyUsage => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_MISSING_KEY_USAGE
            }
            TrustedListPolicyErrorReason::InvalidKeyUsage => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_KEY_USAGE
            }
            TrustedListPolicyErrorReason::MissingSubjectKeyIdentifier => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_SUBJECT_KEY_IDENTIFIER
            }
            TrustedListPolicyErrorReason::InvalidSubjectKeyIdentifier => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_INVALID_SUBJECT_KEY_IDENTIFIER
            }
            TrustedListPolicyErrorReason::InvalidBasicConstraints => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_BASIC_CONSTRAINTS
            }
            TrustedListPolicyErrorReason::InvalidExtendedKeyUsage => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_EXTENDED_KEY_USAGE
            }
            TrustedListPolicyErrorReason::AlgorithmLifetime => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_ALGORITHM_LIFETIME
            }
            TrustedListPolicyErrorReason::SignatureProfile(reason) => reason.into(),
            TrustedListPolicyErrorReason::Expired => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_CORE_EXPIRED
            }
            TrustedListPolicyErrorReason::UnsupportedCriticalExtension => {
                Self::IDENTITY_CORE_ERROR_REASON_TSL_CORE_UNSUPPORTED_CRITICAL_EXTENSION
            }
        }
    }
}

/// Fixed, non-secret resource limits enforced by the trust API.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TrustApiResourceLimitReason {
    /// The caller supplied more trust roots than the trust core accepts.
    #[error("too many trust roots")]
    TooManyTrustRoots,

    /// One trust-root certificate exceeded the X.509 DER limit.
    #[error("trust-root DER exceeds its fixed bound")]
    CertificateDerTooLarge,

    /// The encoded XMLSec trust-root bundle exceeded its byte budget.
    #[error("trust-root PEM bundle exceeds its fixed bound")]
    PemBundleTooLarge,

    /// The bounded native trust-root allocation could not be reserved.
    #[error("trust-root allocation failed")]
    AllocationFailed,
}

impl From<TrustApiResourceLimitReason> for IdentityCoreErrorReason {
    fn from(reason: TrustApiResourceLimitReason) -> Self {
        match reason {
            TrustApiResourceLimitReason::TooManyTrustRoots => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_RESOURCE_TOO_MANY_ROOTS
            }
            TrustApiResourceLimitReason::CertificateDerTooLarge => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_CERTIFICATE_DER_TOO_LARGE
            }
            TrustApiResourceLimitReason::PemBundleTooLarge => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_CERTIFICATE_PEM_BUNDLE_TOO_LARGE
            }
            TrustApiResourceLimitReason::AllocationFailed => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_RESOURCE_LIMIT_EXCEEDED
            }
        }
    }
}

/// Fixed trust policy failure reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TrustPolicyErrorReason {
    /// Policy identifier is not registered.
    #[error("unknown trust policy")]
    UnknownTrustPolicy,

    /// Issuer and subject distinguished names do not chain.
    #[error("issuer distinguished name mismatch")]
    IssuerDistinguishedNameMismatch,

    /// Authority key identifier and subject key identifier do not match.
    #[error("authority key identifier mismatch")]
    AuthorityKeyIdentifierMismatch,

    /// Authority key identifier was required but absent.
    #[error("missing authority key identifier")]
    MissingAuthorityKeyIdentifier,

    /// Subject key identifier was required but absent.
    #[error("missing subject key identifier")]
    MissingSubjectKeyIdentifier,

    /// Key identifiers required for chain linking were absent.
    #[error("missing key identifiers")]
    MissingKeyIdentifiers,
}

impl From<TrustPolicyErrorReason> for IdentityCoreErrorReason {
    fn from(reason: TrustPolicyErrorReason) -> Self {
        match reason {
            TrustPolicyErrorReason::UnknownTrustPolicy => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_POLICY_UNKNOWN_TRUST_POLICY
            }
            TrustPolicyErrorReason::IssuerDistinguishedNameMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_POLICY_ISSUER_DISTINGUISHED_NAME_MISMATCH
            }
            TrustPolicyErrorReason::AuthorityKeyIdentifierMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_POLICY_AUTHORITY_KEY_IDENTIFIER_MISMATCH
            }
            TrustPolicyErrorReason::MissingAuthorityKeyIdentifier => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_POLICY_MISSING_AUTHORITY_KEY_IDENTIFIER
            }
            TrustPolicyErrorReason::MissingSubjectKeyIdentifier => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_POLICY_MISSING_SUBJECT_KEY_IDENTIFIER
            }
            TrustPolicyErrorReason::MissingKeyIdentifiers => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_POLICY_MISSING_KEY_IDENTIFIERS
            }
        }
    }
}

impl From<TrustApiError> for IdentityCoreErrorReason {
    fn from(reason: TrustApiError) -> Self {
        match reason {
            TrustApiError::TrustedList(reason) => reason.into(),
            TrustApiError::InvalidInput => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_API_INVALID_INPUT
            }
            TrustApiError::NotTrusted => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_API_NOT_TRUSTED
            }
            TrustApiError::NotAuthorized => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_API_NOT_AUTHORIZED
            }
            TrustApiError::ServiceNotActive => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_API_SERVICE_NOT_ACTIVE
            }
            TrustApiError::ServiceStatusUnknown => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_API_SERVICE_STATUS_UNKNOWN
            }
            TrustApiError::ServiceTypeUnknown => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_API_SERVICE_TYPE_UNKNOWN
            }
            TrustApiError::ServiceTypeMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_API_SERVICE_TYPE_MISMATCH
            }
            TrustApiError::Revoked => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_API_REVOKED
            }
            TrustApiError::Suspended => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_API_SUSPENDED
            }
            TrustApiError::InvalidSignature => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_API_INVALID_SIGNATURE
            }
            TrustApiError::Policy(reason) => reason.into(),
            TrustApiError::TrustedListPolicy(reason) => reason.into(),
            TrustApiError::ResourceLimit(reason) => reason.into(),
            TrustApiError::BackendFailure => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_API_BACKEND_FAILURE
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
