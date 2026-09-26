// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Boundary validation tests for the raw XMLSec C shim.
#![cfg(feature = "xmlsec-ffi")]
// These tests exercise the raw extern surface directly, which is only
// reachable through `unsafe`. Each call documents why its arguments are sound
// or which precondition it deliberately violates to assert rejection.
#![allow(unsafe_code)]

use std::os::raw::{c_char, c_uchar};

use identity_trust_tsl_xmlsec_sys::{
    meid_xmlsec_verify_tsl, MEID_XMLSEC_MAX_SIGNER_DER_BYTES, MEID_XMLSEC_MAX_TRUSTED_ROOTS,
    MEID_XMLSEC_MAX_TRUSTED_ROOT_DER_BYTES, MEID_XMLSEC_MAX_XML_BYTES,
    MEID_XMLSEC_STATUS_INVALID_ARGUMENT, MEID_XMLSEC_STATUS_XML_PARSE_FAILED,
};

const XML: &[u8] = b"<";
const ROOT: &[u8] = &[0x30];
const VERIFICATION_TIME: i64 = 1_800_000_000;

struct Call<'a> {
    xml: *const c_char,
    xml_len: usize,
    roots: *const *const c_uchar,
    root_lens: *const usize,
    root_count: usize,
    output: *mut c_uchar,
    output_capacity: usize,
    output_len: *mut usize,
    _borrow: core::marker::PhantomData<&'a ()>,
}

fn call(arguments: &Call<'_>) -> i32 {
    // SAFETY: every pointer in `Call` is either null (a deliberate violation
    // the shim must reject before dereferencing) or borrowed from a live
    // buffer in the calling test whose length is described by the paired
    // length field. The shim validates null pointers, lengths, counts, and
    // aliasing before any access and retains no pointer after returning.
    unsafe {
        meid_xmlsec_verify_tsl(
            arguments.xml,
            arguments.xml_len,
            arguments.roots,
            arguments.root_lens,
            arguments.root_count,
            VERIFICATION_TIME,
            0,
            arguments.output,
            arguments.output_capacity,
            arguments.output_len,
        )
    }
}

struct Buffers {
    root_pointers: [*const c_uchar; 1],
    root_lengths: [usize; 1],
    output: Vec<u8>,
    output_len: usize,
}

impl Buffers {
    fn new() -> Self {
        Self {
            root_pointers: [ROOT.as_ptr()],
            root_lengths: [ROOT.len()],
            output: vec![0_u8; 4096],
            output_len: 0,
        }
    }

    fn valid_call(&mut self) -> Call<'_> {
        Call {
            xml: XML.as_ptr().cast(),
            xml_len: XML.len(),
            roots: self.root_pointers.as_ptr(),
            root_lens: self.root_lengths.as_ptr(),
            root_count: 1,
            output: self.output.as_mut_ptr(),
            output_capacity: self.output.len(),
            output_len: &mut self.output_len,
            _borrow: core::marker::PhantomData,
        }
    }
}

#[test]
fn well_formed_arguments_reach_the_xml_parser() {
    let mut buffers = Buffers::new();
    let arguments = buffers.valid_call();
    assert_eq!(call(&arguments), MEID_XMLSEC_STATUS_XML_PARSE_FAILED);
}

#[test]
fn rejects_null_and_empty_xml() {
    let mut buffers = Buffers::new();
    let mut arguments = buffers.valid_call();
    arguments.xml = core::ptr::null();
    assert_eq!(call(&arguments), MEID_XMLSEC_STATUS_INVALID_ARGUMENT);

    let mut arguments = buffers.valid_call();
    arguments.xml_len = 0;
    assert_eq!(call(&arguments), MEID_XMLSEC_STATUS_INVALID_ARGUMENT);

    let mut arguments = buffers.valid_call();
    arguments.xml_len = MEID_XMLSEC_MAX_XML_BYTES + 1;
    assert_eq!(call(&arguments), MEID_XMLSEC_STATUS_INVALID_ARGUMENT);
}

#[test]
fn rejects_missing_zero_and_excess_trust_roots() {
    let mut buffers = Buffers::new();
    let mut arguments = buffers.valid_call();
    arguments.roots = core::ptr::null();
    assert_eq!(call(&arguments), MEID_XMLSEC_STATUS_INVALID_ARGUMENT);

    let mut arguments = buffers.valid_call();
    arguments.root_lens = core::ptr::null();
    assert_eq!(call(&arguments), MEID_XMLSEC_STATUS_INVALID_ARGUMENT);

    let mut arguments = buffers.valid_call();
    arguments.root_count = 0;
    assert_eq!(call(&arguments), MEID_XMLSEC_STATUS_INVALID_ARGUMENT);

    // The count check precedes any read of the arrays, so an excess count is
    // rejected without touching the single-element arrays.
    let mut arguments = buffers.valid_call();
    arguments.root_count = MEID_XMLSEC_MAX_TRUSTED_ROOTS + 1;
    assert_eq!(call(&arguments), MEID_XMLSEC_STATUS_INVALID_ARGUMENT);
}

#[test]
fn rejects_null_empty_and_oversized_root_entries() {
    let mut buffers = Buffers::new();
    buffers.root_pointers[0] = core::ptr::null();
    let arguments = buffers.valid_call();
    assert_eq!(call(&arguments), MEID_XMLSEC_STATUS_INVALID_ARGUMENT);

    let mut buffers = Buffers::new();
    buffers.root_lengths[0] = 0;
    let arguments = buffers.valid_call();
    assert_eq!(call(&arguments), MEID_XMLSEC_STATUS_INVALID_ARGUMENT);

    // The length check precedes any read of the root bytes.
    let mut buffers = Buffers::new();
    buffers.root_lengths[0] = MEID_XMLSEC_MAX_TRUSTED_ROOT_DER_BYTES + 1;
    let arguments = buffers.valid_call();
    assert_eq!(call(&arguments), MEID_XMLSEC_STATUS_INVALID_ARGUMENT);
}

#[test]
fn rejects_invalid_output_buffers() {
    let mut buffers = Buffers::new();
    let mut arguments = buffers.valid_call();
    arguments.output = core::ptr::null_mut();
    assert_eq!(call(&arguments), MEID_XMLSEC_STATUS_INVALID_ARGUMENT);

    let mut arguments = buffers.valid_call();
    arguments.output_capacity = 0;
    assert_eq!(call(&arguments), MEID_XMLSEC_STATUS_INVALID_ARGUMENT);

    let mut arguments = buffers.valid_call();
    arguments.output_capacity = MEID_XMLSEC_MAX_SIGNER_DER_BYTES + 1;
    assert_eq!(call(&arguments), MEID_XMLSEC_STATUS_INVALID_ARGUMENT);

    let mut arguments = buffers.valid_call();
    arguments.output_len = core::ptr::null_mut();
    assert_eq!(call(&arguments), MEID_XMLSEC_STATUS_INVALID_ARGUMENT);
}

#[test]
fn rejects_output_aliasing_any_input() {
    // Output overlapping the XML input.
    let mut shared = vec![b'<'; 64];
    let mut buffers = Buffers::new();
    let mut arguments = buffers.valid_call();
    arguments.xml = shared.as_ptr().cast();
    arguments.xml_len = shared.len();
    arguments.output = shared.as_mut_ptr();
    arguments.output_capacity = shared.len();
    assert_eq!(call(&arguments), MEID_XMLSEC_STATUS_INVALID_ARGUMENT);

    // Output overlapping a trust root.
    let mut shared_root = vec![0x30_u8; 64];
    let mut buffers = Buffers::new();
    buffers.root_pointers[0] = shared_root.as_ptr();
    buffers.root_lengths[0] = shared_root.len();
    let mut arguments = buffers.valid_call();
    arguments.output = shared_root.as_mut_ptr();
    arguments.output_capacity = shared_root.len();
    assert_eq!(call(&arguments), MEID_XMLSEC_STATUS_INVALID_ARGUMENT);
}
