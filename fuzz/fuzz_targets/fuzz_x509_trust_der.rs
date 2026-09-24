// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_trust_x509::{parse_cert_der, parse_qc_statements};

const MAX_FUZZ_INPUT_BYTES: usize = 16_384;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }

    let _ = parse_qc_statements(data);
    let _ = parse_cert_der(data);
});
