// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use identity_trust_tsl_core::{parse_tsl_xml, MAX_TSL_XML_BYTES};
use libfuzzer_sys::fuzz_target;

// Keep individual executions responsive while still reaching all parser
// branches. The production parser independently enforces its larger protocol
// limit, so this harness limit is only a fuzzing resource budget.
const MAX_FUZZ_INPUT_BYTES: usize = 1_048_576;
const OVERSIZED_TRIGGER: &[u8] = b"generate:oversized";
const RECURSIVE_TRIGGER: &[u8] = b"generate:recursive";

fn exercise_oversized_boundary() {
    let Some(oversized_length) = MAX_TSL_XML_BYTES.checked_add(1) else {
        return;
    };
    let mut oversized = String::new();
    if oversized.try_reserve_exact(oversized_length).is_err() {
        return;
    }
    oversized.extend(core::iter::repeat_n('x', oversized_length));
    let _ = parse_tsl_xml(&oversized);
}

fn exercise_recursive_boundary() {
    const RECURSIVE_DEPTH: usize = 129;
    const OPEN_ELEMENT: &str = "<a>";
    const CLOSE_ELEMENT: &str = "</a>";

    let Some(element_bytes) = OPEN_ELEMENT
        .len()
        .checked_add(CLOSE_ELEMENT.len())
        .and_then(|bytes| bytes.checked_mul(RECURSIVE_DEPTH))
    else {
        return;
    };
    let mut recursive = String::new();
    if recursive.try_reserve_exact(element_bytes).is_err() {
        return;
    }
    for _ in 0..RECURSIVE_DEPTH {
        recursive.push_str(OPEN_ELEMENT);
    }
    for _ in 0..RECURSIVE_DEPTH {
        recursive.push_str(CLOSE_ELEMENT);
    }
    let _ = parse_tsl_xml(&recursive);
}

fuzz_target!(|data: &[u8]| {
    let control = data.strip_suffix(b"\n").unwrap_or(data);
    if control == OVERSIZED_TRIGGER {
        exercise_oversized_boundary();
        return;
    }
    if control == RECURSIVE_TRIGGER {
        exercise_recursive_boundary();
        return;
    }
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }

    if let Ok(xml) = core::str::from_utf8(data) {
        let _ = parse_tsl_xml(xml);
    }
});
