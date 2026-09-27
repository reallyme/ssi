// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Platform-dispatched OCSP response parsing.

mod checker;
mod dispatch;
mod model;

pub use checker::OcspChecker;
pub use dispatch::{parse_ocsp_response_der, parse_ocsp_response_der_with_nonce};
pub use model::ParsedOcspResponse;

#[cfg(test)]
#[path = "checker_tests.rs"]
mod checker_tests;
