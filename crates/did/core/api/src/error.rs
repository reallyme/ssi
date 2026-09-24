// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// Public API errors with fixed, non-PII failure categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DidApiError {
    /// The supplied DID does not use the supported did:me method.
    #[error("unsupported DID method")]
    UnsupportedDidMethod,

    /// The supplied DID failed method-specific validation.
    #[error("invalid DID")]
    InvalidDid,

    /// The supplied DID URL failed syntax or method validation.
    #[error("invalid DID URL")]
    InvalidDidUrl,

    /// did:web resolution or publication violated destination policy.
    #[error("did:web policy violation")]
    DidWebPolicyViolation,

    /// did:web network resolution failed.
    #[error("did:web network failure")]
    DidWebNetworkFailure,

    /// did:web TLS negotiation or validation failed.
    #[error("did:web TLS failure")]
    DidWebTlsFailure,

    /// did:web redirect policy rejected the response chain.
    #[error("did:web redirect rejected")]
    DidWebRedirectRejected,

    /// did:web response media type was not accepted.
    #[error("did:web media type rejected")]
    DidWebMediaTypeRejected,

    /// did:web response exceeded the configured limit.
    #[error("did:web response too large")]
    DidWebResponseTooLarge,

    /// did:web document identifier did not match the request.
    #[error("did:web document mismatch")]
    DidWebDocumentMismatch,

    /// did:web operation exceeded its deadline.
    #[error("did:web timeout")]
    DidWebTimeout,

    /// did:web operation was cancelled.
    #[error("did:web cancelled")]
    DidWebCancelled,

    /// did:ebsi registry document id did not match the requested legal-entity DID.
    #[error("did:ebsi document mismatch")]
    DidEbsiDocumentMismatch,

    /// did:ebsi legal-entity document or public JWK validation failed.
    #[error("did:ebsi document invalid")]
    DidEbsiDocumentInvalid,

    /// did:ebsi registry timeline or issuance-time binding was invalid.
    #[error("did:ebsi timeline invalid")]
    DidEbsiTimelineInvalid,

    /// did:ebsi registry result regressed below a caller-observed sequence.
    #[error("did:ebsi registry rollback detected")]
    DidEbsiRollbackDetected,

    /// did:ebsi registry provider failed without exposing backend text.
    #[error("did:ebsi registry failure")]
    DidEbsiRegistryFailure,

    /// The supplied DID URL requires resolver-owned path or query dereferencing.
    #[error("unsupported DID URL")]
    UnsupportedDidUrl,

    /// The supplied DID URL fragment did not identify a local DID document resource.
    #[error("DID URL fragment not found")]
    DidUrlFragmentNotFound,

    /// A provider-supplied DID resolution result violated did:me resolution invariants.
    #[error("DID resolution result invalid")]
    ResolutionResultInvalid,

    /// A provider-supplied DID creation result violated did:me genesis invariants.
    #[error("DID creation result invalid")]
    CreationResultInvalid,

    /// A DID update request violated canonical update boundary policy.
    #[error("DID update request invalid")]
    UpdateRequestInvalid,

    /// A provider-supplied DID update result violated transition invariants.
    #[error("DID update result invalid")]
    UpdateResultInvalid,

    /// A DID deactivation request violated canonical terminal-transition policy.
    #[error("DID deactivation request invalid")]
    DeactivationRequestInvalid,

    /// A provider-supplied DID deactivation result violated terminal-transition invariants.
    #[error("DID deactivation result invalid")]
    DeactivationResultInvalid,

    /// A selected-key rotation request violated canonical boundary policy.
    #[error("DID key rotation request invalid")]
    KeyRotationRequestInvalid,

    /// A provider-supplied selected-key rotation result violated transition invariants.
    #[error("DID key rotation result invalid")]
    KeyRotationResultInvalid,

    /// A relationship-key rotation request violated canonical boundary policy.
    #[error("DID relationship key rotation request invalid")]
    RelationshipKeyRotationRequestInvalid,

    /// A provider-supplied relationship-key result violated transition invariants.
    #[error("DID relationship key rotation result invalid")]
    RelationshipKeyRotationResultInvalid,

    /// A compromised-key replacement request violated recovery boundary policy.
    #[error("DID compromised key replacement request invalid")]
    CompromisedKeyReplacementRequestInvalid,

    /// A provider-supplied recovery result violated transition or authorization invariants.
    #[error("DID compromised key replacement result invalid")]
    CompromisedKeyReplacementResultInvalid,

    /// An all-key rotation request violated canonical boundary policy.
    #[error("DID all-key rotation request invalid")]
    AllKeyRotationRequestInvalid,

    /// A provider-supplied all-key rotation result violated transition invariants.
    #[error("DID all-key rotation result invalid")]
    AllKeyRotationResultInvalid,

    /// A key-relationship assignment request violated canonical boundary policy.
    #[error("DID key relationship assignment request invalid")]
    KeyRelationshipAssignmentRequestInvalid,

    /// A provider-supplied relationship assignment result violated transition invariants.
    #[error("DID key relationship assignment result invalid")]
    KeyRelationshipAssignmentResultInvalid,

    /// Genesis identifier derivation was requested without a nonce.
    #[error("missing genesis nonce")]
    MissingGenesisNonce,

    /// A verification method lacks the algorithm needed for key generation or rotation.
    #[error("verification method missing algorithm")]
    MissingVerificationMethodAlgorithm,

    /// The requested algorithm is unsupported by the active provider policy.
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,

    /// The requested DID relationship is not supported by did:me v1.
    #[error("unsupported DID relationship")]
    UnsupportedDidRelationship,

    /// The injected DID provider does not support the requested command capability.
    #[error("provider capability unsupported")]
    ProviderCapabilityUnsupported,

    /// Manual creation mode requires explicit verification methods.
    #[error("verificationMethods required when no profile is used")]
    MissingVerificationMethods,

    /// A requested verification method reference was not present in the document.
    #[error("verification method not found")]
    VerificationMethodNotFound,

    /// A key operation was requested without at least one verification method target.
    #[error("verification method selection required")]
    VerificationMethodSelectionRequired,

    /// Rotation of a proof-bearing document requires a timestamp for the replacement proof.
    #[error("rotation requires created timestamp")]
    RotationRequiresCreated,

    /// The previous DID document is missing required identity state.
    #[error("invalid old DID document")]
    MissingOldDocumentId,

    /// The previous DID document does not carry an update policy.
    #[error("missing update policy")]
    MissingUpdatePolicy,

    /// The DID engine rejected the operation without exposing dynamic internal context.
    #[error("DID engine failure")]
    EngineFailure,

    /// The requested create or update operation violates the configured update policy.
    #[error("update policy violation")]
    PolicyViolation,

    /// The update engine rejected the requested transition.
    #[error("DID update rejected")]
    UpdateRejected,

    /// Relationship assignment was inconsistent with did:me projection rules.
    #[error("relationship assignment invalid")]
    RelationshipAssignmentInvalid,

    /// Messaging pre-key discovery failed DID method validation.
    #[error("messaging pre-key discovery invalid")]
    MessagingPreKeyDiscoveryInvalid,

    /// Messaging pre-key designation failed DID method validation.
    #[error("messaging pre-key designation invalid")]
    MessagingPreKeyDesignationInvalid,

    /// Messaging pre-key rotation failed request or exact-transition validation.
    #[error("messaging pre-key rotation invalid")]
    MessagingPreKeyRotationInvalid,

    /// JSON-to-protobuf or protobuf encoding failed.
    #[error("proto encode failed")]
    ProtoEncodeFailed,

    /// Protobuf decoding or protobuf-to-JSON conversion failed.
    #[error("proto decode failed")]
    ProtoDecodeFailed,

    /// Brotli compression failed.
    #[error("brotli encode failed")]
    BrotliEncodeFailed,

    /// Brotli decompression failed.
    #[error("brotli decode failed")]
    BrotliDecodeFailed,
}

impl From<DidApiError> for IdentityCoreErrorReason {
    fn from(error: DidApiError) -> Self {
        match error {
            DidApiError::UnsupportedDidMethod => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_UNSUPPORTED_METHOD
            }
            DidApiError::UnsupportedAlgorithm => {
                Self::IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_ALGORITHM
            }
            DidApiError::ProviderCapabilityUnsupported => {
                Self::IDENTITY_CORE_ERROR_REASON_BACKEND_UNAVAILABLE
            }
            DidApiError::InvalidDid
            | DidApiError::InvalidDidUrl
            | DidApiError::UnsupportedDidUrl
            | DidApiError::DidUrlFragmentNotFound
            | DidApiError::DidEbsiDocumentMismatch
            | DidApiError::DidEbsiDocumentInvalid
            | DidApiError::DidEbsiTimelineInvalid
            | DidApiError::DidEbsiRollbackDetected
            | DidApiError::DidEbsiRegistryFailure
            | DidApiError::ResolutionResultInvalid
            | DidApiError::CreationResultInvalid
            | DidApiError::UpdateRequestInvalid
            | DidApiError::UpdateResultInvalid
            | DidApiError::DeactivationRequestInvalid
            | DidApiError::DeactivationResultInvalid
            | DidApiError::KeyRotationRequestInvalid
            | DidApiError::KeyRotationResultInvalid
            | DidApiError::RelationshipKeyRotationRequestInvalid
            | DidApiError::RelationshipKeyRotationResultInvalid
            | DidApiError::CompromisedKeyReplacementRequestInvalid
            | DidApiError::CompromisedKeyReplacementResultInvalid
            | DidApiError::AllKeyRotationRequestInvalid
            | DidApiError::AllKeyRotationResultInvalid
            | DidApiError::UnsupportedDidRelationship => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOCUMENT
            }
            DidApiError::PolicyViolation => Self::IDENTITY_CORE_ERROR_REASON_POLICY_VIOLATION,
            DidApiError::DidWebPolicyViolation => Self::IDENTITY_CORE_ERROR_REASON_POLICY_VIOLATION,
            DidApiError::ProtoEncodeFailed | DidApiError::BrotliEncodeFailed => {
                Self::IDENTITY_CORE_ERROR_REASON_SERIALIZATION_FAILED
            }
            DidApiError::ProtoDecodeFailed | DidApiError::BrotliDecodeFailed => {
                Self::IDENTITY_CORE_ERROR_REASON_INVALID_ENCODING
            }
            DidApiError::UpdateRejected => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_UPDATE_POLICY
            }
            DidApiError::RelationshipAssignmentInvalid => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOCUMENT
            }
            DidApiError::VerificationMethodSelectionRequired
            | DidApiError::MessagingPreKeyDiscoveryInvalid
            | DidApiError::MessagingPreKeyDesignationInvalid
            | DidApiError::MessagingPreKeyRotationInvalid => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOCUMENT
            }
            _ => Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOCUMENT,
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
