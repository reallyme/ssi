// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use reallyme_did_core::CreateOptions;

/// Public DID profile identifiers (developer-facing).
///
/// This enum exists to provide a stable, developer-facing profile selector.
/// All actual profile semantics live in `identity-did-core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidProfile {
    /// Minimal did:me core identity profile.
    CoreIdentity,

    /// Public profile for human-readable identity documents.
    PublicProfile,

    /// Public profile with issuer-oriented assertion capabilities.
    PublicProfileIssuer,

    /// Credential issuer profile.
    Issuer,

    /// Messaging-oriented profile with key agreement support.
    Messaging,

    /// Payment-oriented profile.
    Payment,
}

impl DidProfile {
    /// Canonical string form (useful for logging, configs, CLI, etc.)
    pub fn as_str(&self) -> &'static str {
        match self {
            DidProfile::CoreIdentity => "core-identity",
            DidProfile::PublicProfile => "public-profile",
            DidProfile::PublicProfileIssuer => "public-profile-issuer",
            DidProfile::Issuer => "issuer",
            DidProfile::Messaging => "messaging",
            DidProfile::Payment => "payment",
        }
    }
}

/// Build a DID profile → partial CreateOptions.
///
/// This is a **thin delegation layer** over `identity-did-core`.
/// There is **zero business logic here by design**.
///
/// All guarantees:
/// - key relationships
/// - allowed / required algorithms
/// - VM structure
///
/// are enforced in `identity-did-core::profile::build_profile`.
pub fn build_profile(profile: DidProfile, did: &str) -> CreateOptions {
    use reallyme_did_core::profile::{build_profile as core_build, DidProfile as CoreProfile};

    let core_profile = match profile {
        DidProfile::CoreIdentity => CoreProfile::CoreIdentity,
        DidProfile::PublicProfile => CoreProfile::PublicProfile,
        DidProfile::PublicProfileIssuer => CoreProfile::PublicProfileIssuer,
        DidProfile::Issuer => CoreProfile::Issuer,
        DidProfile::Messaging => CoreProfile::Messaging,
        DidProfile::Payment => CoreProfile::Payment,
    };

    core_build(core_profile, did)
}
