// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Registered SD-JWT VC claim names with fixed issuance and disclosure rules.

use crate::me_profile::ME_PROFILE_EXTENSION_CLAIM;

/// Top-level claims that SD-JWT VC forbids from being selectively disclosed.
///
/// A holder could otherwise drop them from a presentation, for example
/// turning a holder-bound credential into a bearer credential by omitting
/// the `cnf` disclosure.
const NON_SELECTIVELY_DISCLOSABLE_CLAIMS: [&str; 7] =
    ["iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "status"];

/// Registered claims populated only from dedicated issuance input fields.
///
/// Caller-supplied claim maps must not collide with these names, otherwise a
/// generic claim could silently override the issuer, subject, validity,
/// type, or holder binding chosen through the typed fields.
const ISSUER_OWNED_CLAIMS: [&str; 7] = ["iss", "sub", "iat", "nbf", "exp", "vct", "cnf"];

/// SD-JWT structural member names that caller claims must never use.
pub(crate) const SD_JWT_STRUCTURAL_CLAIMS: [&str; 3] = ["_sd", "_sd_alg", "..."];

/// Return whether a top-level claim name must remain in the issuer payload.
pub(crate) fn is_non_selectively_disclosable_claim(claim_name: &str) -> bool {
    NON_SELECTIVELY_DISCLOSABLE_CLAIMS.contains(&claim_name)
}

/// Return whether a claim name is owned by a dedicated RFC 9901 input field.
pub(crate) fn is_issuer_owned_claim(claim_name: &str) -> bool {
    ISSUER_OWNED_CLAIMS.contains(&claim_name)
}

/// Return whether a claim name is owned by a dedicated IETF SD-JWT VC input
/// field, including the Me profile extension claim.
pub(crate) fn is_ietf_issuer_owned_claim(claim_name: &str) -> bool {
    is_issuer_owned_claim(claim_name) || claim_name == ME_PROFILE_EXTENSION_CLAIM
}
