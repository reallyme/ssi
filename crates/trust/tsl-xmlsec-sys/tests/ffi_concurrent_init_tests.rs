// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Process-wide initialization of the XMLSec C shim under concurrent first use.
//!
//! This file is its own test binary so that the concurrent calls below are the
//! first native calls in the process and race on library initialization.
#![cfg(feature = "xmlsec-ffi")]
// The raw extern surface is only reachable through `unsafe`; the single call
// site documents its pointer, length, lifetime, aliasing, and ownership.
#![allow(unsafe_code)]

use std::sync::Barrier;

use identity_trust_tsl_xmlsec_sys::{meid_xmlsec_verify_tsl, MEID_XMLSEC_STATUS_XML_PARSE_FAILED};

const THREADS: usize = 16;
const ROOT: &[u8] = &[0x30];
const MALFORMED_XML: &[u8] = b"<unterminated";

fn verify_malformed_document() -> i32 {
    let root_pointers = [ROOT.as_ptr()];
    let root_lengths = [ROOT.len()];
    let mut output = vec![0_u8; 1024];
    let mut output_len = 0_usize;
    // SAFETY:
    // - Pointers: all inputs are borrowed from live statics or locals and all
    //   outputs point to locals owned by this frame.
    // - Lengths: each length equals its buffer's length; the root arrays hold
    //   exactly one element, matching the count of 1.
    // - Lifetime: every buffer outlives the call; the shim retains nothing.
    // - Aliasing: `output` and `output_len` are thread-local allocations
    //   distinct from every input.
    // - Ownership: the shim only reads inputs and writes within `output`.
    unsafe {
        meid_xmlsec_verify_tsl(
            MALFORMED_XML.as_ptr().cast(),
            MALFORMED_XML.len(),
            root_pointers.as_ptr(),
            root_lengths.as_ptr(),
            1,
            1_800_000_000,
            0,
            output.as_mut_ptr(),
            output.len(),
            &mut output_len,
        )
    }
}

#[test]
fn concurrent_first_use_initializes_once_and_reports_stable_status() {
    let barrier = Barrier::new(THREADS);
    let statuses: Vec<i32> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    verify_malformed_document()
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap_or(i32::MIN))
            .collect()
    });

    // Every caller observes completed initialization and then reaches the
    // parser; none observes a partially initialized library.
    assert!(statuses
        .iter()
        .all(|status| *status == MEID_XMLSEC_STATUS_XML_PARSE_FAILED));
    assert_eq!(
        verify_malformed_document(),
        MEID_XMLSEC_STATUS_XML_PARSE_FAILED
    );
}
