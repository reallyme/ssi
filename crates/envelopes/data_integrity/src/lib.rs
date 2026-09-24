// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! W3C Data Integrity identity envelope support.
//!
//! This crate owns VC proof semantics. Generic JWS/JWT mechanics stay in
//! `reallyme-jose`; DID document projection types are imported from the
//! identity DID model.

/// Data Integrity proof dispatch types.
pub mod proof;
/// Data Integrity signing entry points.
pub mod sign;
pub mod suites;
/// Data Integrity verification entry points.
pub mod verify;

pub use proof::{
    data_integrity_proof_status, DataIntegrityCryptosuite, DataIntegrityProofError,
    DataIntegrityProofStatus,
};
pub use sign::{sign_data_integrity_proof, DataIntegritySignInput};
pub use suites::es256_jws_cid_2025::{
    Es256JwsCid2025Status, ES256_JWS_CID_2025_CRYPTOSUITE, ES256_JWS_CID_2025_STATUS,
};
pub use verify::{verify_data_integrity_proof, DataIntegrityVerifyInput};
