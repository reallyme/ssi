// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Non-secret reason codes for invalid canonical DID core state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CanonicalStateViolation {
    /// The DID sequence number cannot be represented in canonical CBOR.
    #[error("sequence exceeds CBOR integer range")]
    SequenceOutOfRange,

    /// The update-policy threshold cannot be represented in canonical CBOR.
    #[error("update policy threshold exceeds CBOR integer range")]
    ThresholdOutOfRange,

    /// A service endpoint used a JSON number outside the supported integer profile.
    #[error("service endpoint number is not a supported integer")]
    ServiceEndpointNumber,

    /// The genesis nonce is absent or has an invalid length.
    #[error("invalid genesis nonce")]
    GenesisNonce,

    /// A Bech32 human-readable prefix failed validation.
    #[error("invalid bech32 human-readable prefix")]
    Bech32Hrp,

    /// Bech32 payload conversion produced an out-of-range character index.
    #[error("invalid bech32 data value")]
    Bech32DataValue,

    /// Canonical core CBOR unexpectedly encoded to an empty byte string.
    #[error("empty canonical core CBOR")]
    EmptyCoreCbor,

    /// Canonical DID core DAG-CBOR encoding failed.
    #[error("canonical core CBOR encoding failed")]
    CborEncoding,

    /// A decoded value uses a CBOR variant outside the DID canonical profile.
    #[error("unsupported canonical core CBOR value")]
    UnsupportedCborValue,

    /// DID creation options violate sequence, identifier, controller, nonce, or prev rules.
    #[error("invalid create preconditions")]
    InvalidCreatePreconditions,

    /// A controller DID did not use the did:me method.
    #[error("controller must use did:me")]
    InvalidControllerDid,

    /// A requested domain-verification binding is not supported by the engine.
    #[error("unsupported domain verification binding")]
    UnsupportedDomainVerification,

    /// A verification method omitted its required algorithm.
    #[error("verification method algorithm missing")]
    MissingVerificationMethodAlgorithm,

    /// A verification method algorithm is not supported by did:me.
    #[error("verification method algorithm unsupported")]
    UnsupportedVerificationMethodAlgorithm,

    /// An authentication relationship references a missing verification method.
    #[error("authentication verification method missing")]
    MissingAuthenticationMethod,

    /// An authentication verification method uses an algorithm outside the profile.
    #[error("authentication algorithm unsupported")]
    InvalidAuthenticationAlgorithm,

    /// An assertion relationship references a missing verification method.
    #[error("assertion verification method missing")]
    MissingAssertionMethod,

    /// An assertion verification method uses an algorithm outside the profile.
    #[error("assertion algorithm unsupported")]
    InvalidAssertionAlgorithm,

    /// A key-agreement relationship references a missing verification method.
    #[error("key agreement verification method missing")]
    MissingKeyAgreementMethod,

    /// A key-agreement verification method uses an algorithm outside the profile.
    #[error("key agreement algorithm unsupported")]
    InvalidKeyAgreementAlgorithm,

    /// A capability-invocation relationship references a missing verification method.
    #[error("capability invocation verification method missing")]
    MissingInvocationMethod,

    /// A supplied genesis DID does not match the deterministic binding.
    #[error("genesis identifier does not match binding")]
    GenesisIdentifierMismatch,

    /// A Data Integrity proof requires an explicit creation timestamp.
    #[error("proof creation timestamp missing")]
    MissingProofCreated,

    /// Backend keypair generation failed for the selected algorithm.
    #[error("keypair generation failed")]
    KeypairGeneration,

    /// Public-key multikey encoding failed for the selected algorithm.
    #[error("multikey encoding failed")]
    MultikeyEncoding,
}

/// Errors related to DID core construction, canonicalization, and CID handling.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DidCoreError {
    /// Canonical DID core construction failed for a typed, non-secret reason.
    #[error("invalid canonical DID core state: {0}")]
    InvalidCanonicalState(CanonicalStateViolation),

    /// CID hashing failed while building or verifying a canonical core.
    #[error("failed to compute CID for canonical DID core")]
    HashingFailed,

    /// A supplied CID does not match the canonical DID core bytes.
    #[error("CID does not match canonical DID core")]
    InvalidCid,

    /// An internal invariant was violated in code that should be unreachable by valid inputs.
    #[error("internal DID core invariant violated")]
    InternalInvariant,

    /// Required private key material was not available to the signing callback.
    #[error("missing private key for verification method")]
    MissingPrivateKey,

    /// The update policy rejects the requested operation.
    #[error("update policy violation")]
    PolicyViolation,
}

impl From<CanonicalStateViolation> for IdentityCoreErrorReason {
    fn from(violation: CanonicalStateViolation) -> Self {
        match violation {
            CanonicalStateViolation::SequenceOutOfRange
            | CanonicalStateViolation::ThresholdOutOfRange => {
                Self::IDENTITY_CORE_ERROR_REASON_ARITHMETIC_OVERFLOW
            }
            CanonicalStateViolation::UnsupportedVerificationMethodAlgorithm
            | CanonicalStateViolation::InvalidAuthenticationAlgorithm
            | CanonicalStateViolation::InvalidAssertionAlgorithm
            | CanonicalStateViolation::InvalidKeyAgreementAlgorithm => {
                Self::IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_ALGORITHM
            }
            CanonicalStateViolation::UnsupportedDomainVerification => {
                Self::IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_FORMAT
            }
            CanonicalStateViolation::MissingVerificationMethodAlgorithm
            | CanonicalStateViolation::MissingAuthenticationMethod
            | CanonicalStateViolation::MissingAssertionMethod
            | CanonicalStateViolation::MissingKeyAgreementMethod
            | CanonicalStateViolation::MissingInvocationMethod => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_VERIFICATION_METHOD
            }
            _ => Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOCUMENT,
        }
    }
}

impl From<DidCoreError> for IdentityCoreErrorReason {
    fn from(error: DidCoreError) -> Self {
        match error {
            DidCoreError::InvalidCanonicalState(violation) => violation.into(),
            DidCoreError::HashingFailed => Self::IDENTITY_CORE_ERROR_REASON_CANONICALIZATION_FAILED,
            DidCoreError::InvalidCid => Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOCUMENT,
            DidCoreError::InternalInvariant => Self::IDENTITY_CORE_ERROR_REASON_INVALID_STATE,
            DidCoreError::MissingPrivateKey => Self::IDENTITY_CORE_ERROR_REASON_INVALID_SIGNATURE,
            DidCoreError::PolicyViolation => Self::IDENTITY_CORE_ERROR_REASON_POLICY_VIOLATION,
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
