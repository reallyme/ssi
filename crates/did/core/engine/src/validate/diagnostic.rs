// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};

/// Severity assigned to a DID validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DidValidationSeverity {
    /// The DID document is not valid unless this issue is resolved.
    Error,

    /// The DID document may be valid, but validation could not prove an optional external claim.
    Warning,
}

/// Stable machine-readable category for a DID validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DidValidationCode {
    /// Required DID document contexts are missing, reordered, or duplicated.
    ContextInvalid,
    /// The DID identifier or genesis binding is not valid.
    IdentifierInvalid,
    /// A controller field is absent, malformed, or inconsistent with canonical core.
    ControllerInvalid,
    /// An `alsoKnownAs` entry is malformed.
    AlsoKnownAsInvalid,
    /// The sequence, previous CID, nonce, or key history state is malformed.
    CoreStateInvalid,
    /// `coreCbor` is not base64url.
    CoreCborEncodingInvalid,
    /// `coreCbor` is not canonical DAG-CBOR.
    CoreCborCanonicalInvalid,
    /// `currentCore` does not match the canonical core bytes.
    CoreCidMismatch,
    /// The decoded canonical core does not have the expected map shape.
    CoreShapeInvalid,
    /// The decoded canonical core does not match the DID document projection.
    CoreProjectionMismatch,
    /// A verification method is missing, malformed, duplicated, or semantically inconsistent.
    VerificationMethodInvalid,
    /// A relationship array is malformed or inconsistent with canonical core.
    RelationshipInvalid,
    /// A service entry is missing, duplicated, malformed, or inconsistent with canonical core.
    ServiceInvalid,
    /// The update policy is missing, malformed, or references unknown verification methods.
    UpdatePolicyInvalid,
    /// An attestation is malformed or references unsupported material.
    AttestationInvalid,
    /// An attestation signature failed cryptographic verification.
    AttestationSignatureInvalid,
    /// The configured update policy is not satisfied by attestations.
    AttestationPolicyNotSatisfied,
    /// A Data Integrity proof is absent, malformed, or uses unsupported schema values.
    DataIntegrityProofInvalid,
    /// A domain verification binding is malformed or internally inconsistent.
    DomainBindingInvalid,
    /// Domain verification was not performed because caller-supplied resolvers were missing.
    DomainVerificationSkipped,
    /// Domain verification ran but did not validate the claimed binding.
    DomainVerificationFailed,
    /// Domain verification could not be evaluated because the supplied response was missing or malformed.
    DomainVerificationUnavailable,
    /// An internal invariant expected by the validator was violated.
    InternalInvariantViolation,
}

/// Stable location category for a DID validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DidValidationLocation {
    /// The top-level DID document.
    Document,
    /// The `@context` field.
    Context,
    /// The DID `id` field.
    Id,
    /// The `controller` field.
    Controller,
    /// The `alsoKnownAs` field.
    AlsoKnownAs,
    /// The canonical core state fields.
    Core,
    /// The `keyHistory` field.
    KeyHistory,
    /// The `nonce` field.
    Nonce,
    /// The `verificationMethod` array.
    VerificationMethod,
    /// A relationship array.
    Relationship,
    /// The `service` array.
    Service,
    /// The `updatePolicy` field.
    UpdatePolicy,
    /// The `attestations` field.
    Attestation,
    /// The Data Integrity `proof` field.
    DataIntegrityProof,
    /// The `domainVerification` field.
    DomainVerification,
}

/// Machine-readable DID validation issue.
///
/// The validator deliberately reports stable codes and coarse locations instead
/// of embedding DIDs, CIDs, domains, parser text, or raw credential material in
/// diagnostics. That keeps logs and FFI/JSON responses deterministic and safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DidValidationIssue {
    /// Stable reason code for the issue.
    pub code: DidValidationCode,

    /// Stable location category for the issue.
    pub location: DidValidationLocation,

    /// Optional zero-based index for repeated fields.
    pub index: Option<u32>,
}

impl DidValidationIssue {
    /// Construct an issue without a repeated-field index.
    #[must_use]
    pub const fn new(code: DidValidationCode, location: DidValidationLocation) -> Self {
        Self {
            code,
            location,
            index: None,
        }
    }

    /// Construct an issue for a repeated-field entry.
    #[must_use]
    pub const fn indexed(
        code: DidValidationCode,
        location: DidValidationLocation,
        index: u32,
    ) -> Self {
        Self {
            code,
            location,
            index: Some(index),
        }
    }
}
