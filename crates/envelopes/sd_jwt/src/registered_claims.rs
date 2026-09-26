// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Registered top-level claims that must stay in the issuer-signed payload.

/// Top-level claims that SD-JWT VC forbids from being selectively disclosed.
///
/// These claims carry issuer identity, validity, type, status, and holder
/// binding. Making any of them disclosable would let a holder silently drop
/// them from a presentation, for example turning a holder-bound credential
/// into a bearer credential by omitting the `cnf` disclosure.
const NON_SELECTIVELY_DISCLOSABLE_CLAIMS: [&str; 7] =
    ["iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "status"];

/// Return whether a top-level claim name must remain in the issuer payload.
pub(crate) fn is_non_selectively_disclosable_claim(claim_name: &str) -> bool {
    NON_SELECTIVELY_DISCLOSABLE_CLAIMS.contains(&claim_name)
}
