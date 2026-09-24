// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical ReallyMe identity protobuf bindings.
//!
//! This crate is message-only. Domain validation, bounded decoding, provider
//! policy, dispatch, and platform adapters belong to separate layers.

/// Generated protobuf boundary.
pub mod generated;

#[cfg(feature = "generated")]
mod zeroize_credential;
#[cfg(feature = "generated")]
mod zeroize_did;
#[cfg(feature = "generated")]
mod zeroize_eudi_pid;
#[cfg(feature = "generated")]
mod zeroize_status;

/// Stack-error adapters for identity-core-owned reason codes.
#[cfg(feature = "generated")]
pub mod stack_error;

#[cfg(feature = "generated")]
pub use zeroize_credential::{
    zeroize_credential_envelope, zeroize_credential_status, zeroize_holder_binding,
    zeroize_party_reference, zeroize_public_key_ref, zeroize_qeaa_compliance,
    zeroize_subject_private_bundle,
};
#[cfg(feature = "generated")]
pub use zeroize_eudi_pid::{
    zeroize_eudi_catalogue_document, zeroize_eudi_legal_person_pid,
    zeroize_eudi_natural_person_pid, zeroize_eudi_pid_allocation,
    zeroize_eudi_pid_issuance_authorization, zeroize_eudi_pid_revocation,
};
#[cfg(feature = "generated")]
pub use zeroize_status::zeroize_status_list;
