// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Test vectors use direct time arithmetic and fixed-position assertions to
// keep the standards examples readable; production code remains linted.
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
//! OAuth substrate tests for PAR, DPoP, PKCE, metadata, and attestation auth.

include!("oauth_substrate_tests/section_01.rs");
include!("oauth_substrate_tests/dpop_thumbprints.rs");
include!("oauth_substrate_tests/validate_attestation_trust_receipts.rs");
include!("oauth_substrate_tests/section_02.rs");
include!("oauth_substrate_tests/section_03.rs");
