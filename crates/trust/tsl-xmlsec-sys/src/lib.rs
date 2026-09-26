// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal native bindings for XMLDSig verification using libxmlsec1.
//!
//! This crate intentionally exposes a tiny C shim API (not full xmlsec).
//!
//! # Threading model
//!
//! libxml2, libxslt, and xmlsec hold process-wide state (parser globals, the
//! external entity loader, default XSLT security preferences, the error
//! callback, and crypto backend registration). The shim initializes that state
//! exactly once per process through `pthread_once`, records the resulting
//! status, and returns the same status to every later call. A failed
//! initialization therefore fails closed deterministically and is never
//! retried against partially initialized library state.
//!
//! Per-call objects are owned by the calling thread for the duration of one
//! call. The safe wrapper in `identity-trust-tsl-xmlsec` additionally
//! serializes verification calls behind a process-wide lock, so callers of the
//! safe API need no further synchronization. Other code in the same process
//! that reconfigures libxml2 globals concurrently is outside this contract.
//!
//! # ABI limits and status codes
//!
//! The constants in this crate are the single source of truth for the shim's
//! buffer limits and status codes; the build script renders the same values
//! into the generated C wrapper.

mod abi;
mod bindings;

pub use abi::{
    MEID_XMLSEC_MAX_SIGNER_DER_BYTES, MEID_XMLSEC_MAX_TRUSTED_ROOTS,
    MEID_XMLSEC_MAX_TRUSTED_ROOT_DER_BYTES, MEID_XMLSEC_MAX_XML_BYTES,
    MEID_XMLSEC_STATUS_CONTEXT_SETUP_FAILED, MEID_XMLSEC_STATUS_INIT_FAILED,
    MEID_XMLSEC_STATUS_INVALID_ARGUMENT, MEID_XMLSEC_STATUS_KEYS_MANAGER_CREATE_FAILED,
    MEID_XMLSEC_STATUS_KEYS_MANAGER_INIT_FAILED, MEID_XMLSEC_STATUS_MISSING_ROOT,
    MEID_XMLSEC_STATUS_MISSING_SIGNATURE, MEID_XMLSEC_STATUS_OK,
    MEID_XMLSEC_STATUS_POLICY_SETUP_FAILED, MEID_XMLSEC_STATUS_SCHEMA_INIT_FAILED,
    MEID_XMLSEC_STATUS_SCHEMA_INVALID, MEID_XMLSEC_STATUS_SIGNATURE_INVALID,
    MEID_XMLSEC_STATUS_TRUSTED_ROOT_LOAD_FAILED,
    MEID_XMLSEC_STATUS_VERIFICATION_TIME_UNREPRESENTABLE, MEID_XMLSEC_STATUS_XML_PARSE_FAILED,
};
pub use bindings::meid_xmlsec_verify_tsl;
