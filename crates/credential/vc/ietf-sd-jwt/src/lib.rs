// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// This source-only support crate is consumed through the root identity facade.
// Keep workspace missing-docs enforcement active by default while avoiding
// filler rustdoc on RFC 9901 helper structs that are still being shaped.
#![allow(missing_docs)]

//! IETF SD-JWT VC issuance and verification helpers.
//!
//! This crate emits the SD-JWT wire format as defined by the IETF SD-JWT family:
//! `issuer-signed-jwt~disclosure~...~[kb-jwt]`
//!
//! Me Profile extension:
//! - Optional `me_zk` claim can carry a Merkle commitment binding used by
//!   Me Protocol ZK proof flows.
//! - This extension is additive and namespaced so standard SD-JWT verifiers
//!   can ignore it while Me verifiers can enforce it.
//! - The commitment root is stable for the lifetime of one issued credential.
//!   Revealing it directly in multiple presentations is correlatable. Wallets
//!   that require unlinkability must keep `me_zk` issuer-bound and present only
//!   circuit outputs that use verifier-specific freshness and context binding.

pub mod error;
pub mod issue;
pub mod me_profile;
pub mod payload;
mod process_disclosures;
mod registered_claims;
pub mod rfc9901;
mod sensitive;
mod validate_temporal_claims;
pub mod verify;

pub use error::IetfSdJwtVcError;
pub use issue::{
    issue_ietf_sd_jwt_vc, issue_ietf_sd_jwt_vc_with_signer, IetfSdJwtHashAlgorithm,
    IetfSdJwtIssueInput, IetfSdJwtIssueOutput, IetfSdJwtJwtType,
};
#[cfg(feature = "conformance-vectors")]
pub use issue::{
    issue_ietf_sd_jwt_vc_deterministic, issue_ietf_sd_jwt_vc_with_signer_deterministic,
};
pub use me_profile::{
    extract_me_profile_merkle_binding, insert_me_profile_merkle_binding,
    verify_me_profile_merkle_binding, MeProfileMerkleBinding, ME_PROFILE_EXTENSION_CLAIM,
};
pub use payload::SdJwtDisclosure;
#[cfg(feature = "conformance-vectors")]
pub use rfc9901::issue_rfc9901_sd_jwt_deterministic;
pub use rfc9901::{
    issue_rfc9901_sd_jwt, verify_rfc9901_sd_jwt, DecoyPolicy, DisclosureRecord, KbJwtBuildParams,
    KbJwtVerifyParams, Rfc9901IssueInput, SdJwtArtifact, SelectiveDisclosureStrategy,
    VerifiedRfc9901,
};
pub use validate_temporal_claims::{
    IetfSdJwtTemporalPolicy, DEFAULT_IETF_SD_JWT_CLOCK_SKEW_SECONDS,
    MAX_IETF_SD_JWT_CLOCK_SKEW_SECONDS,
};
pub use verify::{verify_ietf_sd_jwt_vc, VerifiedIetfSdJwtVc};
