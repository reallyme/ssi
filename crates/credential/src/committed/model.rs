// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical credential-domain types used by VC protocol adapters.
//!
//! This module intentionally re-exports the package-owned identity model. VC,
//! JWT, SD-JWT, ZK, and delivery adapters must not grow a second credential
//! graph with different enum, key, signature, or status semantics.

pub use crate::{
    AssuranceLevel, CredentialEnvelope, CredentialKind, CredentialStatus, CredentialSubject,
    HolderBinding, PartyReference, PublicKeyIdentity, X509SubjectReference,
};
pub use reallyme_credential_claims::{
    ClaimOpening, ClaimsCommitment, CommitmentLimits, CredentialAlgorithm, DomainTags,
    KeyAssurance, KeyReference, MerkleTreeInfo, PublicKeyRef, PublicKeyRepresentation,
    RawPublicKeySerialization, Signature, SubjectPrivateBundle,
};
pub use reallyme_credential_status::StatusPurpose;
