// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_sd_jwt::{
    decode_disclosure, parse_sd_jwt_json_serialization, parse_sd_jwt_or_kb_compact,
    process_sd_jwt_payload, SdJwtProcessingPolicy,
};

const MAX_FUZZ_INPUT_BYTES: usize = 65_536;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }
    let Ok(input) = core::str::from_utf8(data) else {
        return;
    };

    // Compact and JSON serializations are parsed before any signature work.
    let _ = parse_sd_jwt_or_kb_compact(input);
    let _ = parse_sd_jwt_json_serialization(input);

    // Disclosure resolution: the first line is an issuer payload and every
    // following line is an encoded disclosure.
    let mut lines = input.lines();
    let Some(payload_line) = lines.next() else {
        return;
    };
    let disclosures: Vec<String> = lines.map(str::to_owned).collect();
    for disclosure in &disclosures {
        let _ = decode_disclosure(disclosure);
    }
    let Ok(payload) = serde_json::from_str(payload_line) else {
        return;
    };
    let _ = process_sd_jwt_payload(payload, &disclosures, SdJwtProcessingPolicy::default());
});
