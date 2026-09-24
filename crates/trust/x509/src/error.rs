// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
pub enum X509Error {
    #[error("invalid DER")]
    InvalidDer,

    #[error("invalid PEM")]
    InvalidPem,

    #[error("unsupported PEM label")]
    UnsupportedPemLabel,

    #[error("x509 parse error")]
    ParseError,

    /// RFC 5280 Section 4.1.2.2 positive, bounded serial invariant failed.
    #[error("invalid certificate serial number")]
    InvalidSerialNumber,

    /// RFC 5280 Section 4.2 forbids repeated extension OIDs in one certificate.
    #[error("duplicate certificate extension")]
    DuplicateExtension,

    #[error("missing required field")]
    MissingField(X509MissingField),

    #[error("policy failed")]
    PolicyFailed(X509PolicyFailure),

    #[error("x509 signature verification failed")]
    SignatureFailed(X509SignatureFailure),

    #[error("x509 resource limit exceeded")]
    ResourceLimitExceeded(X509ResourceLimit),
}

#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
pub enum X509MissingField {
    #[error("leaf certificate")]
    Leaf,
}

#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
pub enum X509PolicyFailure {
    #[error("leaf certificate must use X.509 version 3")]
    LeafMustBeV3,
    #[error("unknown critical certificate extension")]
    UnknownCriticalExtension,
    #[error("certificate not valid at given time")]
    CertificateNotValidAtTime,
    #[error("leaf must not be a CA")]
    LeafMustNotBeCa,
    #[error("missing leaf key usage")]
    MissingLeafKeyUsage,
    #[error("leaf key usage missing digital signature")]
    LeafMissingDigitalSignature,
    #[error("missing leaf extended key usage")]
    MissingLeafExtendedKeyUsage,
    #[error("leaf extended key usage does not match policy")]
    LeafExtendedKeyUsageMismatch,
    #[error("leaf certificate policies do not match policy")]
    LeafCertificatePolicyMismatch,
    #[error("leaf qcStatements missing required statementId")]
    LeafMissingRequiredQcStatement,
    #[error("leaf qcStatements QcType does not match policy")]
    LeafQcTypeMismatch,
    #[error("leaf public key does not satisfy the policy strength floor")]
    WeakPublicKey,
    #[error("leaf public-key algorithm is not allowed by the profile")]
    PublicKeyAlgorithmNotAllowed,
    #[error("leaf certificate-signature algorithm is not allowed by the profile")]
    SignatureAlgorithmNotAllowed,
    #[error("leaf subject alternative name does not satisfy the application profile")]
    LeafNameRequirement,
    #[error("leaf key identifiers do not satisfy the application profile")]
    LeafKeyIdentifierRequirement,
    #[error("leaf authority information access does not satisfy the application profile")]
    LeafAuthorityInformationAccessRequirement,
    #[error("leaf QSCD policy is missing the QcSSCD statement")]
    LeafMissingQscdStatement,
    #[error("leaf certificate does not satisfy the revocation pointer policy")]
    RevocationPointerMissing,
    #[error("trusted list service territory does not match policy")]
    TslTerritoryMismatch,
    #[error("trusted list service type does not match policy")]
    TslServiceTypeMismatch,
    #[error("trusted list service status is not granted")]
    TslStatusNotGranted,
    #[error("trusted list service status is not effective")]
    TslStatusNotEffective,
    #[error("trusted list service status is too old")]
    TslStatusTooOld,
    #[error("trusted list service certificate binding is missing")]
    TslCertificateBindingMissing,
    #[error("trusted list service certificate binding does not match leaf")]
    TslCertificateBindingMismatch,
    #[error("intermediate missing basic constraints")]
    IntermediateMissingBasicConstraints,
    #[error("intermediate is not CA:true")]
    IntermediateNotCa,
    #[error("intermediate missing key usage")]
    IntermediateMissingKeyUsage,
    #[error("intermediate missing keyCertSign")]
    IntermediateMissingKeyCertSign,
    #[error("leaf is missing a required certificate extension")]
    MissingRequiredExtension,
    #[error("leaf certificate extension criticality does not match policy")]
    ExtensionCriticality,
    #[error("leaf key usage does not match the selected certificate profile")]
    LeafKeyUsageProfile,
    #[error("leaf subject distinguished name does not match the selected profile")]
    LeafSubjectNameProfile,
    #[error("leaf issuer distinguished name does not match the selected profile")]
    LeafIssuerNameProfile,
    #[error("leaf certificate must not be self-issued")]
    LeafSelfIssued,
    #[error("WRPAC certificate policy selection is missing or ambiguous")]
    WrpacPolicyAmbiguous,
    #[error("WRPAC qualified-certificate statements do not match its policy family")]
    WrpacQcStatements,
    #[error("trust anchor is missing basic constraints")]
    TrustAnchorMissingBasicConstraints,
    #[error("trust anchor is not a certificate authority")]
    TrustAnchorNotCa,
    #[error("trust anchor is missing key usage")]
    TrustAnchorMissingKeyUsage,
    #[error("trust anchor key usage is missing keyCertSign")]
    TrustAnchorMissingKeyCertSign,
    #[error("trust anchor is missing a certificate policy")]
    TrustAnchorMissingCertificatePolicy,
    #[error("leaf contains noRevAvail where revocation is required")]
    LeafForbiddenNoRevAvail,
    #[error("leaf certificate policy is missing a CPS URI")]
    LeafMissingPolicyCpsUri,
    #[error("certificate key parameters do not satisfy the ETSI algorithm policy")]
    AlgorithmParametersNotAllowed,
    #[error("certificate path length constraint exceeded")]
    PathLengthConstraintExceeded,
}

#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
pub enum X509SignatureFailure {
    #[error("certificate chain is too short")]
    ChainTooShort,
    #[error("certificate issuer continuity mismatch")]
    ChainIssuerMismatch,
    #[error("unsupported certificate signature algorithm")]
    UnsupportedAlgorithm,
    #[error("invalid certificate signature")]
    InvalidSignature,
    #[error("certificate signature backend failure")]
    BackendFailure,
    #[error("XMLDSig verification is unavailable in this trust lane")]
    XmlDsigUnavailable,
}

#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
pub enum X509ResourceLimit {
    #[error("certificate chain is too long")]
    CertificateChainTooLong,
    #[error("certificate DER input is too large")]
    CertificateDerTooLarge,
    #[error("certificate PEM input is too large")]
    CertificatePemTooLarge,
    #[error("certificate PEM bundle is too large")]
    CertificatePemBundleTooLarge,
    #[error("certificate contains too many extensions")]
    TooManyExtensions,
    #[error("certificate object identifier is too long")]
    ObjectIdentifierTooLong,
    #[error("certificate name contains too many attributes")]
    TooManyNameAttributes,
}

impl From<X509MissingField> for IdentityCoreErrorReason {
    fn from(reason: X509MissingField) -> Self {
        match reason {
            X509MissingField::Leaf => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_MISSING_FIELD_LEAF
            }
        }
    }
}

impl From<X509PolicyFailure> for IdentityCoreErrorReason {
    fn from(reason: X509PolicyFailure) -> Self {
        match reason {
            X509PolicyFailure::LeafMustBeV3 => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_MUST_BE_V3
            }
            X509PolicyFailure::UnknownCriticalExtension => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_UNKNOWN_CRITICAL_EXTENSION
            }
            X509PolicyFailure::CertificateNotValidAtTime => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_CERTIFICATE_NOT_VALID_AT_TIME
            }
            X509PolicyFailure::LeafMustNotBeCa => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_MUST_NOT_BE_CA
            }
            X509PolicyFailure::MissingLeafKeyUsage => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_MISSING_LEAF_KEY_USAGE
            }
            X509PolicyFailure::LeafMissingDigitalSignature => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_MISSING_DIGITAL_SIGNATURE
            }
            X509PolicyFailure::MissingLeafExtendedKeyUsage => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_MISSING_LEAF_EXTENDED_KEY_USAGE
            }
            X509PolicyFailure::LeafExtendedKeyUsageMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_EXTENDED_KEY_USAGE_MISMATCH
            }
            X509PolicyFailure::LeafCertificatePolicyMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_CERTIFICATE_POLICY_MISMATCH
            }
            X509PolicyFailure::LeafMissingRequiredQcStatement => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_MISSING_REQUIRED_QC_STATEMENT
            }
            X509PolicyFailure::LeafQcTypeMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_QC_TYPE_MISMATCH
            }
            X509PolicyFailure::WeakPublicKey => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_WEAK_PUBLIC_KEY
            }
            X509PolicyFailure::PublicKeyAlgorithmNotAllowed => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_PUBLIC_KEY_ALGORITHM_NOT_ALLOWED
            }
            X509PolicyFailure::SignatureAlgorithmNotAllowed => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_SIGNATURE_ALGORITHM_NOT_ALLOWED
            }
            X509PolicyFailure::LeafNameRequirement => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_NAME_REQUIREMENT
            }
            X509PolicyFailure::LeafKeyIdentifierRequirement => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_KEY_IDENTIFIER_REQUIREMENT
            }
            X509PolicyFailure::LeafAuthorityInformationAccessRequirement => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_AUTHORITY_INFORMATION_ACCESS_REQUIREMENT
            }
            X509PolicyFailure::LeafMissingQscdStatement => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_MISSING_QSCD_STATEMENT
            }
            X509PolicyFailure::RevocationPointerMissing => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_REVOCATION_POINTER_MISSING
            }
            X509PolicyFailure::TslTerritoryMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_TERRITORY_MISMATCH
            }
            X509PolicyFailure::TslServiceTypeMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_SERVICE_TYPE_MISMATCH
            }
            X509PolicyFailure::TslStatusNotGranted => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_STATUS_NOT_GRANTED
            }
            X509PolicyFailure::TslStatusNotEffective => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_STATUS_NOT_EFFECTIVE
            }
            X509PolicyFailure::TslStatusTooOld => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_STATUS_TOO_OLD
            }
            X509PolicyFailure::TslCertificateBindingMissing => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_CERTIFICATE_BINDING_MISSING
            }
            X509PolicyFailure::TslCertificateBindingMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_CERTIFICATE_BINDING_MISMATCH
            }
            X509PolicyFailure::IntermediateMissingBasicConstraints => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_INTERMEDIATE_MISSING_BASIC_CONSTRAINTS
            }
            X509PolicyFailure::IntermediateNotCa => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_INTERMEDIATE_NOT_CA
            }
            X509PolicyFailure::IntermediateMissingKeyUsage => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_INTERMEDIATE_MISSING_KEY_USAGE
            }
            X509PolicyFailure::IntermediateMissingKeyCertSign => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_INTERMEDIATE_MISSING_KEY_CERT_SIGN
            }
            X509PolicyFailure::MissingRequiredExtension => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_MISSING_REQUIRED_EXTENSION
            }
            X509PolicyFailure::ExtensionCriticality => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_EXTENSION_CRITICALITY
            }
            X509PolicyFailure::LeafKeyUsageProfile => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_KEY_USAGE_PROFILE
            }
            X509PolicyFailure::LeafSubjectNameProfile => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_SUBJECT_NAME_PROFILE
            }
            X509PolicyFailure::LeafIssuerNameProfile => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_ISSUER_NAME_PROFILE
            }
            X509PolicyFailure::LeafSelfIssued => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_SELF_ISSUED
            }
            X509PolicyFailure::WrpacPolicyAmbiguous => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_WRPAC_POLICY_AMBIGUOUS
            }
            X509PolicyFailure::WrpacQcStatements => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_WRPAC_QC_STATEMENTS
            }
            X509PolicyFailure::TrustAnchorMissingBasicConstraints => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TRUST_ANCHOR_MISSING_BASIC_CONSTRAINTS
            }
            X509PolicyFailure::TrustAnchorNotCa => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TRUST_ANCHOR_NOT_CA
            }
            X509PolicyFailure::TrustAnchorMissingKeyUsage => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TRUST_ANCHOR_MISSING_KEY_USAGE
            }
            X509PolicyFailure::TrustAnchorMissingKeyCertSign => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TRUST_ANCHOR_MISSING_KEY_CERT_SIGN
            }
            X509PolicyFailure::TrustAnchorMissingCertificatePolicy => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TRUST_ANCHOR_MISSING_CERTIFICATE_POLICY
            }
            X509PolicyFailure::LeafForbiddenNoRevAvail => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_FORBIDDEN_NO_REV_AVAIL
            }
            X509PolicyFailure::LeafMissingPolicyCpsUri => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_MISSING_POLICY_CPS_URI
            }
            X509PolicyFailure::AlgorithmParametersNotAllowed => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_ALGORITHM_PARAMETERS_NOT_ALLOWED
            }
            X509PolicyFailure::PathLengthConstraintExceeded => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_PATH_LENGTH_CONSTRAINT_EXCEEDED
            }
        }
    }
}

impl From<X509SignatureFailure> for IdentityCoreErrorReason {
    fn from(reason: X509SignatureFailure) -> Self {
        match reason {
            X509SignatureFailure::ChainTooShort => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_CHAIN_TOO_SHORT
            }
            X509SignatureFailure::ChainIssuerMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_CHAIN_ISSUER_MISMATCH
            }
            X509SignatureFailure::UnsupportedAlgorithm => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_UNSUPPORTED_ALGORITHM
            }
            X509SignatureFailure::InvalidSignature => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_INVALID_SIGNATURE
            }
            X509SignatureFailure::BackendFailure => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_BACKEND_FAILURE
            }
            X509SignatureFailure::XmlDsigUnavailable => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_XMLDSIG_UNAVAILABLE
            }
        }
    }
}

impl From<X509ResourceLimit> for IdentityCoreErrorReason {
    fn from(reason: X509ResourceLimit) -> Self {
        match reason {
            X509ResourceLimit::CertificateChainTooLong => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_CERTIFICATE_CHAIN_TOO_LONG
            }
            X509ResourceLimit::CertificateDerTooLarge => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_CERTIFICATE_DER_TOO_LARGE
            }
            X509ResourceLimit::CertificatePemTooLarge => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_CERTIFICATE_PEM_TOO_LARGE
            }
            X509ResourceLimit::CertificatePemBundleTooLarge => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_CERTIFICATE_PEM_BUNDLE_TOO_LARGE
            }
            X509ResourceLimit::TooManyExtensions => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_TOO_MANY_EXTENSIONS
            }
            X509ResourceLimit::ObjectIdentifierTooLong => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_OBJECT_IDENTIFIER_TOO_LONG
            }
            X509ResourceLimit::TooManyNameAttributes => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_TOO_MANY_NAME_ATTRIBUTES
            }
        }
    }
}

impl From<X509Error> for IdentityCoreErrorReason {
    fn from(reason: X509Error) -> Self {
        match reason {
            X509Error::InvalidDer => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_INVALID_DER
            }
            X509Error::InvalidPem => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_INVALID_PEM
            }
            X509Error::UnsupportedPemLabel => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_UNSUPPORTED_PEM_LABEL
            }
            X509Error::ParseError => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_PARSE_ERROR
            }
            X509Error::InvalidSerialNumber | X509Error::DuplicateExtension => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_INVALID_DER
            }
            X509Error::MissingField(reason) => reason.into(),
            X509Error::PolicyFailed(reason) => reason.into(),
            X509Error::SignatureFailed(reason) => reason.into(),
            X509Error::ResourceLimitExceeded(reason) => reason.into(),
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
