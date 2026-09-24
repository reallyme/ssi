// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared identity primitives for DID, envelope, and credential crates.
//!
//! This crate owns semantic algorithm names, canonical-object boundaries, and the algorithm
//! registry used by higher-level DID and credential code.

/// Semantic algorithm identifiers.
pub mod algorithm;
/// Namespace-specific algorithm string mappings.
pub mod algorithm_map;
/// Canonical object traits for deterministic identity state.
pub mod canonical;
/// Typed errors for shared identity primitives.
pub mod error;
/// Algorithm metadata registry.
pub mod registry;

pub use algorithm::Algorithm;

pub use algorithm_map::{alg_str_to_alg, alg_to_did_alg_str, alg_to_vc_alg_str, vc_alg_str_to_alg};

pub use registry::{
    lookup_by_algorithm, lookup_by_multicodec_name, lookup_by_profile_type, AlgorithmSpec, KeyRole,
    ALGORITHM_REGISTRY,
};

pub use canonical::CanonicalObject;
pub use error::IdentityCoreError;
