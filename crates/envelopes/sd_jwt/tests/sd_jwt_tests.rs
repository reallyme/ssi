// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::panic)]
//! Test coverage for this crate.

/// Verifier clock shared by generic SD-JWT verification tests.
const VERIFY_NOW_UNIX: u64 = 1_683_000_002;

include!("sd_jwt_tests/section_01.rs");
include!("sd_jwt_tests/section_02.rs");
include!("sd_jwt_tests/section_03.rs");
include!("sd_jwt_tests/section_04.rs");
