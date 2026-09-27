// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

/// Typed failures returned by X.509 operations.
#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum X509Error {
    /// Invalid DER.
    #[error("invalid DER")]
    InvalidDer,

    /// Invalid PEM.
    #[error("invalid PEM")]
    InvalidPem,

    /// Unsupported PEM label.
    #[error("unsupported PEM label")]
    UnsupportedPemLabel,

    /// X.509 parsing failed.
    #[error("x509 parse error")]
    ParseError,

    /// RFC 5280 Section 4.1.2.2 positive, bounded serial invariant failed.
    #[error("invalid certificate serial number")]
    InvalidSerialNumber,

    /// RFC 5280 Section 4.2 forbids repeated extension OIDs in one certificate.
    #[error("duplicate certificate extension")]
    DuplicateExtension,

    /// A required certificate or certificate field is absent.
    #[error("missing required field")]
    MissingField(X509MissingField),

    /// The certificate or path violates the selected policy.
    #[error("policy failed")]
    PolicyFailed(X509PolicyFailure),

    /// X.509 signature verification failed.
    #[error("x509 signature verification failed")]
    SignatureFailed(X509SignatureFailure),

    /// X.509 resource limit exceeded.
    #[error("x509 resource limit exceeded")]
    ResourceLimitExceeded(X509ResourceLimit),
}

/// Typed X.509 missing field reasons reported to callers.
#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum X509MissingField {
    /// The certificate chain has no leaf certificate.
    #[error("leaf certificate")]
    Leaf,
}

/// Typed X.509 policy failure reasons reported to callers.
#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum X509PolicyFailure {
    /// Leaf certificate must use X.509 version 3.
    #[error("leaf certificate must use X.509 version 3")]
    LeafMustBeV3,
    /// Unknown critical certificate extension.
    #[error("unknown critical certificate extension")]
    UnknownCriticalExtension,
    /// Certificate not valid at given time.
    #[error("certificate not valid at given time")]
    CertificateNotValidAtTime,
    /// Leaf must not be a CA.
    #[error("leaf must not be a CA")]
    LeafMustNotBeCa,
    /// Missing leaf key usage.
    #[error("missing leaf key usage")]
    MissingLeafKeyUsage,
    /// Leaf key usage missing digital signature.
    #[error("leaf key usage missing digital signature")]
    LeafMissingDigitalSignature,
    /// Missing leaf extended key usage.
    #[error("missing leaf extended key usage")]
    MissingLeafExtendedKeyUsage,
    /// Leaf extended key usage does not match policy.
    #[error("leaf extended key usage does not match policy")]
    LeafExtendedKeyUsageMismatch,
    /// Leaf certificate policies do not match policy.
    #[error("leaf certificate policies do not match policy")]
    LeafCertificatePolicyMismatch,
    /// Leaf `qcStatements` lacks a required `statementId`.
    #[error("leaf qcStatements missing required statementId")]
    LeafMissingRequiredQcStatement,
    /// Leaf `qcStatements` does not contain an accepted qualified-certificate type.
    #[error("leaf qcStatements QcType does not match policy")]
    LeafQcTypeMismatch,
    /// Leaf public key does not satisfy the policy strength floor.
    #[error("leaf public key does not satisfy the policy strength floor")]
    WeakPublicKey,
    /// Leaf public-key algorithm is not allowed by the profile.
    #[error("leaf public-key algorithm is not allowed by the profile")]
    PublicKeyAlgorithmNotAllowed,
    /// Leaf certificate-signature algorithm is not allowed by the profile.
    #[error("leaf certificate-signature algorithm is not allowed by the profile")]
    SignatureAlgorithmNotAllowed,
    /// Leaf subject alternative name does not satisfy the application profile.
    #[error("leaf subject alternative name does not satisfy the application profile")]
    LeafNameRequirement,
    /// Leaf key identifiers do not satisfy the application profile.
    #[error("leaf key identifiers do not satisfy the application profile")]
    LeafKeyIdentifierRequirement,
    /// Leaf authority information access does not satisfy the application profile.
    #[error("leaf authority information access does not satisfy the application profile")]
    LeafAuthorityInformationAccessRequirement,
    /// Leaf QSCD policy is missing the QcSSCD statement.
    #[error("leaf QSCD policy is missing the QcSSCD statement")]
    LeafMissingQscdStatement,
    /// Leaf certificate does not satisfy the revocation pointer policy.
    #[error("leaf certificate does not satisfy the revocation pointer policy")]
    RevocationPointerMissing,
    /// Trusted list service territory does not match policy.
    #[error("trusted list service territory does not match policy")]
    TslTerritoryMismatch,
    /// Trusted list service type does not match policy.
    #[error("trusted list service type does not match policy")]
    TslServiceTypeMismatch,
    /// Trusted list service status is not granted.
    #[error("trusted list service status is not granted")]
    TslStatusNotGranted,
    /// Trusted list service status is not effective.
    #[error("trusted list service status is not effective")]
    TslStatusNotEffective,
    /// Trusted list service status is too old.
    #[error("trusted list service status is too old")]
    TslStatusTooOld,
    /// Trusted list service certificate binding is missing.
    #[error("trusted list service certificate binding is missing")]
    TslCertificateBindingMissing,
    /// Trusted list service certificate binding does not match the service CA.
    #[error("trusted list service certificate binding does not match service CA")]
    TslCertificateBindingMismatch,
    /// Intermediate missing basic constraints.
    #[error("intermediate missing basic constraints")]
    IntermediateMissingBasicConstraints,
    /// Intermediate does not assert `CA:TRUE`.
    #[error("intermediate is not CA:true")]
    IntermediateNotCa,
    /// Intermediate missing key usage.
    #[error("intermediate missing key usage")]
    IntermediateMissingKeyUsage,
    /// Intermediate key usage does not include `keyCertSign`.
    #[error("intermediate missing keyCertSign")]
    IntermediateMissingKeyCertSign,
    /// Leaf is missing a required certificate extension.
    #[error("leaf is missing a required certificate extension")]
    MissingRequiredExtension,
    /// Leaf certificate extension criticality does not match policy.
    #[error("leaf certificate extension criticality does not match policy")]
    ExtensionCriticality,
    /// Leaf key usage does not match the selected certificate profile.
    #[error("leaf key usage does not match the selected certificate profile")]
    LeafKeyUsageProfile,
    /// Leaf subject distinguished name does not match the selected profile.
    #[error("leaf subject distinguished name does not match the selected profile")]
    LeafSubjectNameProfile,
    /// Leaf issuer distinguished name does not match the selected profile.
    #[error("leaf issuer distinguished name does not match the selected profile")]
    LeafIssuerNameProfile,
    /// Leaf certificate must not be self-issued.
    #[error("leaf certificate must not be self-issued")]
    LeafSelfIssued,
    /// WRPAC certificate policy selection is missing or ambiguous.
    #[error("WRPAC certificate policy selection is missing or ambiguous")]
    WrpacPolicyAmbiguous,
    /// WRPAC qualified-certificate statements do not match its policy family.
    #[error("WRPAC qualified-certificate statements do not match its policy family")]
    WrpacQcStatements,
    /// Trust anchor is missing basic constraints.
    #[error("trust anchor is missing basic constraints")]
    TrustAnchorMissingBasicConstraints,
    /// Trust anchor is not a certificate authority.
    #[error("trust anchor is not a certificate authority")]
    TrustAnchorNotCa,
    /// Trust anchor is missing key usage.
    #[error("trust anchor is missing key usage")]
    TrustAnchorMissingKeyUsage,
    /// Trust-anchor key usage does not include `keyCertSign`.
    #[error("trust anchor key usage is missing keyCertSign")]
    TrustAnchorMissingKeyCertSign,
    /// Trust anchor is missing a certificate policy.
    #[error("trust anchor is missing a certificate policy")]
    TrustAnchorMissingCertificatePolicy,
    /// Leaf contains `noRevAvail` although revocation evidence is required.
    #[error("leaf contains noRevAvail where revocation is required")]
    LeafForbiddenNoRevAvail,
    /// Leaf certificate policy is missing a CPS URI.
    #[error("leaf certificate policy is missing a CPS URI")]
    LeafMissingPolicyCpsUri,
    /// Certificate key parameters do not satisfy the ETSI algorithm policy.
    #[error("certificate key parameters do not satisfy the ETSI algorithm policy")]
    AlgorithmParametersNotAllowed,
    /// Certificate path length constraint exceeded.
    #[error("certificate path length constraint exceeded")]
    PathLengthConstraintExceeded,
}

/// Typed X.509 signature failure reasons reported to callers.
#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum X509SignatureFailure {
    /// Certificate chain is too short.
    #[error("certificate chain is too short")]
    ChainTooShort,
    /// Certificate issuer continuity mismatch.
    #[error("certificate issuer continuity mismatch")]
    ChainIssuerMismatch,
    /// Unsupported certificate signature algorithm.
    #[error("unsupported certificate signature algorithm")]
    UnsupportedAlgorithm,
    /// Invalid certificate signature.
    #[error("invalid certificate signature")]
    InvalidSignature,
    /// Certificate signature backend failure.
    #[error("certificate signature backend failure")]
    BackendFailure,
    /// XMLDSig verification is unavailable in this trust lane.
    #[error("XMLDSig verification is unavailable in this trust lane")]
    XmlDsigUnavailable,
    /// RFC 5280 Section 4.1.1.2: `tbsCertificate.signature` differs from
    /// the outer `signatureAlgorithm`.
    #[error("certificate signature algorithm identifiers do not match")]
    AlgorithmIdentifierMismatch,
    /// The certificate carries a path constraint (NameConstraints,
    /// PolicyConstraints, or InhibitAnyPolicy) this trust lane does not process.
    #[error("certificate path constraint is unsupported in this trust lane")]
    UnsupportedPathConstraint,
}

/// Typed X.509 resource limit reasons reported to callers.
#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum X509ResourceLimit {
    /// Certificate chain is too long.
    #[error("certificate chain is too long")]
    CertificateChainTooLong,
    /// Certificate DER input is too large.
    #[error("certificate DER input is too large")]
    CertificateDerTooLarge,
    /// Certificate PEM input is too large.
    #[error("certificate PEM input is too large")]
    CertificatePemTooLarge,
    /// Certificate PEM bundle is too large.
    #[error("certificate PEM bundle is too large")]
    CertificatePemBundleTooLarge,
    /// Certificate contains too many extensions.
    #[error("certificate contains too many extensions")]
    TooManyExtensions,
    /// Certificate object identifier is too long.
    #[error("certificate object identifier is too long")]
    ObjectIdentifierTooLong,
    /// Certificate name contains too many attributes.
    #[error("certificate name contains too many attributes")]
    TooManyNameAttributes,
}

include!("error/map_to_proto.rs");

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
