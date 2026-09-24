// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(feature = "mdoc-crypto")]
mod mso_status;

include!("cbor/section_01.rs");
include!("cbor/section_02.rs");
include!("cbor/value_limits.rs");
include!("cbor/section_03.rs");

#[cfg(test)]
#[path = "mso_status_cbor_tests.rs"]
mod mso_status_cbor_tests;
