// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_credential_claims::{
    claim_id_from_path, claim_path, escape_field_segment, parse_claim_path,
};

const MAX_FUZZ_INPUT_BYTES: usize = 2048;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }

    let Ok(input) = core::str::from_utf8(data) else {
        return;
    };

    let parsed = parse_claim_path(input);
    let _ = claim_id_from_path(input);

    if let Ok(path) = parsed {
        if let Some(claim_id) = path.claim_id() {
            let _ = claim_path(claim_id.as_str());
        }
    }

    let escaped = escape_field_segment(input);
    let _ = claim_path(escaped.as_str());
});
