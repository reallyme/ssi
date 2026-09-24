// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal native bindings for XMLDSig verification using libxmlsec1.
//!
//! This crate intentionally exposes a tiny C shim API (not full xmlsec).

mod bindings;

pub use bindings::meid_xmlsec_verify_tsl;
