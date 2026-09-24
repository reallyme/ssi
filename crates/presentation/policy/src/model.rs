// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_core_primitives::Algorithm;
use identity_credential_claims_core::DisclosureMode;

/// Verifier policy definition.
///
/// This structure is intentionally explicit:
/// every field corresponds to a potential accept/reject decision.
/// No implicit defaults, no hidden assumptions.

#[derive(Debug, Clone)]
pub struct VpPolicy {
    // ---------------------------------------------------------------------
    // Cryptography
    // ---------------------------------------------------------------------
    /// Allowed issuer signature algorithms.
    ///
    /// This applies to:
    /// - SD-JWT issuer signatures
    /// - ZK public inputs that bind to an issuer signature
    pub allowed_issuer_algorithms: Vec<Algorithm>,

    /// Allowed holder signature algorithms.
    ///
    /// Applies to:
    /// - SD-JWT holder binding JWT (kb_jwt)
    /// - ZK freshness / liveness signatures
    pub allowed_holder_algorithms: Vec<Algorithm>,

    // ---------------------------------------------------------------------
    // Presentation formats
    // ---------------------------------------------------------------------
    /// Allow SD-JWT based presentations.
    pub allow_sd_jwt: bool,

    /// Allow ZK-based presentations.
    pub allow_zk: bool,

    // ---------------------------------------------------------------------
    // Claims & disclosure semantics
    // ---------------------------------------------------------------------
    /// Required claims and their disclosure modes.
    ///
    /// These are *semantic requirements*, not cryptographic ones.
    /// Mapping to actual disclosures is done during evaluation.
    pub required_claims: Vec<RequiredClaim>,

    /// Optional allow-list of claimset identifiers.
    ///
    /// If present, credentials whose `claimset_id` is not in this list
    /// are rejected.
    pub allowed_claimsets: Option<Vec<String>>,

    // ---------------------------------------------------------------------
    // Status / revocation
    // ---------------------------------------------------------------------
    /// Require credential status to be checked.
    pub require_status: bool,

    /// minimum QEAA profile identifier
    pub min_qeaa_profile: Option<String>,

    /// Maximum allowed age (in seconds) of the status list.
    ///
    /// If `None`, freshness is not enforced beyond `next_update`.
    pub max_status_age_seconds: Option<u64>,

    // ---------------------------------------------------------------------
    // QEAA / audit
    // ---------------------------------------------------------------------
    /// Require QEAA compliance metadata to be present.
    pub require_qeaa: bool,

    /// Minimum required identity proofing level (LOIP).
    ///
    /// Interpreted according to ETSI / QEAA semantics.
    pub min_identity_proofing_level: Option<u32>,
}

/// A single required claim constraint.
///
/// `claim_path` must match the canonical claim path
/// (e.g. "/claims/age").
///
/// `mode` specifies *how* the claim must be disclosed
/// (reveal, predicate, range, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredClaim {
    /// Canonical claim path required by the verifier.
    pub claim_path: String,

    /// Disclosure mode required for the claim.
    pub mode: DisclosureMode,
}
