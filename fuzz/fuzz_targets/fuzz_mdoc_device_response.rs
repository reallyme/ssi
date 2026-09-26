// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_mdoc::{decode_mdoc_device_response_cbor, encode_mdoc_device_response_cbor};

const MAX_FUZZ_INPUT_BYTES: usize = 16_384;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }

    let Ok(response) = decode_mdoc_device_response_cbor(data) else {
        return;
    };

    let _ = encode_mdoc_device_response_cbor(&response);
});
