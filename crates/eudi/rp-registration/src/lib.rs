// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict, bounded EUDI Wallet Relying Party registration profiles.
//!
//! Authentication receipts in this crate prove format and signature processing
//! only. They deliberately do not assert that a registrar, WRPRC signer, or
//! WRPAC certification path is trusted.

mod digest;
mod document;
mod error;
mod json;
mod model;
mod registry;
mod wrpac;
mod wrprc;

pub use digest::ArtifactDigest;
pub use document::{prepare_registration_document, PreparedRegistrarRegistrationDocument};
pub use error::{RegistrationError, RegistrationErrorReason};
pub use model::{
    BoundedText, ClaimPath, CredentialMetadata, CredentialRequest, DcSdJwtMetadata, IntendedUse,
    LocalizedText, MsoMdocMetadata, PolicyReference, ProtocolProfile, ProvidedAttestation,
    RegistryPagination, RegistryPayload, RegistryPayloadShape, SupervisoryAuthority,
    WalletRelyingParty, WalletRelyingPartyService, WrpEntitlement,
};
pub use registry::{
    authenticate_registry_record, AuthenticatedJws, AuthenticatedRegistryRecord,
    JoseRegistryJwsVerifier, RegistrarCertificateChain, RegistryAuthenticationInput,
    RegistryIntendedUseQuery, RegistryJwsVerifier, RegistryMetadata, ValidatedJwks,
};
pub use wrpac::{
    authenticate_access_certificate_association, AccessCertificateBinding,
    AuthenticatedAccessCertificateAssociation,
};
pub use wrprc::{
    authenticate_registration_certificate, parse_registration_certificate,
    AuthenticatedRegistrationCertificate, AuthenticatedRepresentation,
    ParsedRegistrationCertificate, RegisteredCredentialFormat, RegistrationCertificateBinding,
    RegistrationCertificateFormat, RegistrationCertificatePolicy, RegistrationCertificateProof,
};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use wrprc::{
    authenticate_wrprc_cose_sign1, authenticate_wrprc_jades, RegistrationCertificateCoseAlgorithm,
    RegistrationCertificateCoseAuthenticationInput,
    RegistrationCertificateJadesAuthenticationInput, RegistrationCertificateJadesPolicy,
};
