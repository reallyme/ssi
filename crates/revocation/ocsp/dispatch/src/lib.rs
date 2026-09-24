// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Platform-dispatched OCSP response parsing.

mod dispatch;

pub use dispatch::parse_ocsp_response_der;
