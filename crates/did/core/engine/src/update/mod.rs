// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
/// High-level DID update orchestration.
pub mod engine;

/// Typed update error codes.
pub mod error;

/// DID update chain invariants.
pub mod invariants;

/// Merge logic for updateable DID Document collections.
pub mod merge;

/// Update-policy validation helpers.
pub mod policy;

/// Verification-method rotation logic.
pub mod rotation;

pub use engine::{update_engine, UpdateMetadata, UpdateOptions, UpdateRelationships};
pub use error::UpdateError;
