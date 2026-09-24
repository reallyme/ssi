// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Key-set utilities for identity document construction.
//!
//! This crate owns validation and storage for verification-method identifiers,
//! public multikey material, and private signing material while the DID types
//! are still being introduced. Private bytes are stored in zeroizing wrappers
//! and are redacted from debug output by construction.

mod copy_keys;
mod error;
mod export_key_set;
mod exported_key_set;
mod import_key_set;
mod insert_key;
mod key_set;
mod private_key_material;
mod public_key_multibase;
mod read_key;
mod trim_keys;
mod verification_method_id;

pub use error::KeySetError;
pub use exported_key_set::{ExportedKeySet, ExportedPrivateKey};
pub use key_set::KeySet;
pub use private_key_material::PrivateKeyMaterial;
pub use public_key_multibase::PublicKeyMultibase;
pub use verification_method_id::VerificationMethodId;
