// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_credential_claims::ClaimsError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Stable reasons for canonical credential payload failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CredentialCanonicalReason {
    /// A timestamp, status index, or resource limit cannot fit the canonical CBOR profile.
    #[error("integer out of range")]
    IntegerOutOfRange,

    /// Deterministic hashing failed or returned an unexpected digest length.
    #[error("hash failed")]
    Hash,

    /// Deterministic canonical payload encoding failed.
    #[error("canonical encoding failed")]
    Encoding,
}

/// Stable reasons for credential issuer signature failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CredentialSignatureReason {
    /// The credential algorithm is not a supported signature algorithm.
    #[error("unsupported signature algorithm")]
    UnsupportedAlgorithm,

    /// The signer failed to produce a credential signature.
    #[error("credential signing failed")]
    SigningFailed,

    /// The verifier rejected the credential issuer signature.
    #[error("credential issuer signature invalid")]
    VerificationFailed,

    /// The supplied verification method does not match the envelope signature metadata.
    #[error("verification method mismatch")]
    VerificationMethodMismatch,
}

/// Stable reasons for credential status verification failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CredentialStatusReason {
    /// The supplied status list is not the list referenced by the credential.
    #[error("status pointer mismatch")]
    StatusPointerMismatch,

    /// The status list is malformed or cannot represent the requested index.
    #[error("invalid status evidence")]
    InvalidEvidence,

    /// The status list is stale at the verification time.
    #[error("status evidence expired")]
    Expired,

    /// The status list is not yet valid at the verification time.
    #[error("status evidence not yet valid")]
    NotYetValid,

    /// The status-list signature failed verification.
    #[error("status signature invalid")]
    InvalidSignature,

    /// The credential is revoked.
    #[error("credential revoked")]
    Revoked,

    /// The credential is suspended.
    #[error("credential suspended")]
    Suspended,

    /// No configured revocation source could provide a terminal answer.
    #[error("status unavailable")]
    Unavailable,
}

/// Stable fields used when mapping malformed protobuf inputs.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CredentialProtoField {
    /// The credential kind enum is absent or unspecified.
    #[error("kind")]
    Kind,

    /// The assurance enum is absent or unspecified.
    #[error("assurance")]
    Assurance,

    /// The valid-from timestamp is absent or malformed.
    #[error("valid_from")]
    ValidFrom,

    /// The valid-until timestamp is absent or malformed.
    #[error("valid_until")]
    ValidUntil,

    /// The status message is absent or malformed.
    #[error("status")]
    Status,

    /// The subject message is absent or malformed.
    #[error("subject")]
    Subject,

    /// The subject-key message is absent or malformed.
    #[error("subject_key")]
    SubjectKey,

    /// The claims commitment message is absent or malformed.
    #[error("claims_commitment")]
    ClaimsCommitment,

    /// The QEAA compliance message is absent or malformed.
    #[error("qeaa_compliance")]
    QeaaCompliance,

    /// The issuer signature message is absent or malformed.
    #[error("issuer_signature")]
    IssuerSignature,

    /// A public key enum is absent or unspecified.
    #[error("public_key_algorithm")]
    PublicKeyAlgorithm,

    /// A signature enum is absent or unspecified.
    #[error("signature_algorithm")]
    SignatureAlgorithm,

    /// A status purpose enum is absent or unspecified.
    #[error("status_purpose")]
    StatusPurpose,

    /// A QEAA enum is absent or unspecified.
    #[error("qeaa_enum")]
    QeaaEnum,

    /// A SHA-256 digest or identifier field has the wrong byte length.
    #[error("fixed_bytes")]
    FixedBytes,
}

/// Stable reasons for malformed protobuf credential boundaries.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CredentialProtoReason {
    /// A required message field is absent.
    #[error("missing field")]
    MissingField(CredentialProtoField),

    /// An enum field is unknown or unspecified for the semantic model.
    #[error("invalid enum")]
    InvalidEnum(CredentialProtoField),

    /// A timestamp contains unsupported nanos or is outside the model range.
    #[error("invalid timestamp")]
    InvalidTimestamp(CredentialProtoField),

    /// A fixed-size byte field has the wrong length.
    #[error("invalid fixed bytes")]
    InvalidFixedBytes(CredentialProtoField),
}

/// Stable reasons for invalid credential inputs.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CredentialInvalidReason {
    /// Credential profile identifier is absent or oversized.
    #[error("invalid profile id")]
    InvalidProfileId,

    /// Issuer identifier is absent or oversized.
    #[error("invalid issuer id")]
    InvalidIssuerId,

    /// Issuer country code is absent or oversized.
    #[error("invalid issuer country")]
    InvalidIssuerCountry,

    /// Validity timestamps are not ordered.
    #[error("invalid validity window")]
    InvalidValidityWindow,

    /// Status-list URL is absent or oversized.
    #[error("invalid status list url")]
    InvalidStatusListUrl,

    /// Status-list index cannot be represented by the canonical credential profile.
    #[error("invalid status list index")]
    InvalidStatusListIndex,

    /// Subject identifier is absent or oversized.
    #[error("invalid subject id")]
    InvalidSubjectId,

    /// Public key reference is absent or malformed.
    #[error("invalid public key reference")]
    InvalidPublicKeyRef,

    /// Issuer signature metadata or bytes are absent or malformed.
    #[error("invalid issuer signature")]
    InvalidIssuerSignature,

    /// The public credential profile does not match the committed claim set.
    #[error("profile claimset mismatch")]
    ProfileClaimsetMismatch,

    /// QEAA credentials must carry QEAA compliance evidence.
    #[error("missing qeaa compliance")]
    MissingQeaaCompliance,

    /// Non-QEAA credentials must not carry QEAA compliance evidence.
    #[error("unexpected qeaa compliance")]
    UnexpectedQeaaCompliance,

    /// The holder-private bundle does not match the public credential envelope.
    #[error("private bundle envelope mismatch")]
    PrivateBundleEnvelopeMismatch,
}

/// Credential model and boundary validation errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CredentialError {
    /// Credential model input is malformed.
    #[error("invalid credential")]
    InvalidInput(CredentialInvalidReason),

    /// Embedded claim commitment or holder-private bundle is malformed.
    #[error("invalid credential claims")]
    Claims(ClaimsError),

    /// Embedded QEAA compliance evidence is malformed.
    #[error("invalid qeaa compliance")]
    Qeaa,

    /// Credential signing payload or envelope hash could not be derived.
    #[error("invalid credential canonical payload")]
    Canonical(CredentialCanonicalReason),

    /// Credential issuer signature failed signing or verification.
    #[error("credential signature failed")]
    Signature(CredentialSignatureReason),

    /// Credential status-list verification failed.
    #[error("credential status failed")]
    Status(CredentialStatusReason),

    /// Generated protobuf boundary input is malformed.
    #[error("invalid credential protobuf")]
    Proto(CredentialProtoReason),
}

impl From<CredentialCanonicalReason> for IdentityCoreErrorReason {
    fn from(reason: CredentialCanonicalReason) -> Self {
        match reason {
            CredentialCanonicalReason::IntegerOutOfRange => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_CANONICAL_INTEGER_OUT_OF_RANGE
            }
            CredentialCanonicalReason::Hash => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_CANONICAL_HASH
            }
            CredentialCanonicalReason::Encoding => {
                Self::IDENTITY_CORE_ERROR_REASON_CANONICALIZATION_FAILED
            }
        }
    }
}

impl From<CredentialSignatureReason> for IdentityCoreErrorReason {
    fn from(reason: CredentialSignatureReason) -> Self {
        match reason {
            CredentialSignatureReason::UnsupportedAlgorithm => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_SIGNATURE_UNSUPPORTED_ALGORITHM
            }
            CredentialSignatureReason::SigningFailed => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_SIGNATURE_SIGNING_FAILED
            }
            CredentialSignatureReason::VerificationFailed => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_SIGNATURE_VERIFICATION_FAILED
            }
            CredentialSignatureReason::VerificationMethodMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_SIGNATURE_VERIFICATION_METHOD_MISMATCH
            }
        }
    }
}

impl From<CredentialStatusReason> for IdentityCoreErrorReason {
    fn from(reason: CredentialStatusReason) -> Self {
        match reason {
            CredentialStatusReason::StatusPointerMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_POINTER_MISMATCH
            }
            CredentialStatusReason::InvalidEvidence => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_EVIDENCE
            }
            CredentialStatusReason::Expired => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_EXPIRED
            }
            CredentialStatusReason::NotYetValid => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_NOT_YET_VALID
            }
            CredentialStatusReason::InvalidSignature => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_SIGNATURE
            }
            CredentialStatusReason::Revoked => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_REVOKED
            }
            CredentialStatusReason::Suspended => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_SUSPENDED
            }
            CredentialStatusReason::Unavailable => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_UNAVAILABLE
            }
        }
    }
}

impl From<CredentialProtoReason> for IdentityCoreErrorReason {
    fn from(reason: CredentialProtoReason) -> Self {
        match reason {
            CredentialProtoReason::MissingField(_)
            | CredentialProtoReason::InvalidEnum(_)
            | CredentialProtoReason::InvalidTimestamp(_)
            | CredentialProtoReason::InvalidFixedBytes(_) => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_INVALID_ENVELOPE
            }
        }
    }
}

impl From<CredentialInvalidReason> for IdentityCoreErrorReason {
    fn from(reason: CredentialInvalidReason) -> Self {
        match reason {
            CredentialInvalidReason::ProfileClaimsetMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_PROFILE_MISMATCH
            }
            CredentialInvalidReason::InvalidProfileId => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_INVALID_PROFILE_ID
            }
            CredentialInvalidReason::InvalidIssuerId => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_INVALID_ISSUER_ID
            }
            CredentialInvalidReason::InvalidIssuerCountry => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_INVALID_ISSUER_COUNTRY
            }
            CredentialInvalidReason::InvalidValidityWindow => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_INVALID_VALIDITY_WINDOW
            }
            CredentialInvalidReason::InvalidStatusListUrl => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_INVALID_STATUS_LIST_URL
            }
            CredentialInvalidReason::InvalidStatusListIndex => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_INVALID_STATUS_LIST_INDEX
            }
            CredentialInvalidReason::InvalidSubjectId => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_INVALID_SUBJECT_ID
            }
            CredentialInvalidReason::InvalidPublicKeyRef => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_INVALID_PUBLIC_KEY_REF
            }
            CredentialInvalidReason::InvalidIssuerSignature => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_INVALID_ISSUER_SIGNATURE
            }
            CredentialInvalidReason::MissingQeaaCompliance => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_MISSING_QEAA_COMPLIANCE
            }
            CredentialInvalidReason::UnexpectedQeaaCompliance => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_UNEXPECTED_QEAA_COMPLIANCE
            }
            CredentialInvalidReason::PrivateBundleEnvelopeMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_PRIVATE_BUNDLE_ENVELOPE_MISMATCH
            }
        }
    }
}

impl From<CredentialError> for IdentityCoreErrorReason {
    fn from(error: CredentialError) -> Self {
        match error {
            CredentialError::InvalidInput(reason) => reason.into(),
            CredentialError::Claims(error) => error.into(),
            CredentialError::Qeaa => Self::IDENTITY_CORE_ERROR_REASON_AUDIT_EVIDENCE_INVALID,
            CredentialError::Canonical(reason) => reason.into(),
            CredentialError::Signature(reason) => reason.into(),
            CredentialError::Status(reason) => reason.into(),
            CredentialError::Proto(reason) => reason.into(),
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
