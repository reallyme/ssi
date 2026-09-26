// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use identity_trust_tsl_xmlsec::verify_tsl_xmldsig_xmlsec;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1_048_576 {
        return;
    }
    let Ok(xml) = core::str::from_utf8(data) else {
        return;
    };
    // Roots are checked for size before the structural pass. No native backend
    // is enabled: this target isolates parsing before signature authentication.
    let root = include_bytes!("../../crates/trust/tsl-xmlsec/tests/fixtures/unrelated_root.der");
    let _ = verify_tsl_xmldsig_xmlsec(xml, &[root], time::OffsetDateTime::UNIX_EPOCH);
});
