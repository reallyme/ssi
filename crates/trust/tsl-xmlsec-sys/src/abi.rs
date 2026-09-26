// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Single source of truth for the C shim ABI limits and status codes.
//
// This file is compiled into the crate as the `abi` module and is also
// textually included by `build.rs`, which renders every constant below into
// the generated C wrapper. Rust and C therefore cannot disagree on a limit or
// status value. The file must stay free of inner attributes and inner doc
// comments so that both inclusion paths accept it.

/// Maximum XML document bytes accepted by the shim.
pub const MEID_XMLSEC_MAX_XML_BYTES: usize = 16 * 1024 * 1024;
/// Maximum number of DER trust roots accepted in one verification call.
pub const MEID_XMLSEC_MAX_TRUSTED_ROOTS: usize = 32;
/// Maximum DER bytes accepted for one trust root.
pub const MEID_XMLSEC_MAX_TRUSTED_ROOT_DER_BYTES: usize = 65_536;
/// Maximum DER bytes the shim may write for the backend-selected signer.
pub const MEID_XMLSEC_MAX_SIGNER_DER_BYTES: usize = 1024 * 1024;

/// Verification succeeded and the signer certificate was written.
pub const MEID_XMLSEC_STATUS_OK: i32 = 0;
/// A pointer, length, count, capacity, or aliasing precondition failed.
pub const MEID_XMLSEC_STATUS_INVALID_ARGUMENT: i32 = -1;
/// Process-wide libxml2, libxslt, or xmlsec initialization failed.
pub const MEID_XMLSEC_STATUS_INIT_FAILED: i32 = -2;
/// libxml2 rejected the document.
pub const MEID_XMLSEC_STATUS_XML_PARSE_FAILED: i32 = -3;
/// The parsed document has no root element.
pub const MEID_XMLSEC_STATUS_MISSING_ROOT: i32 = -4;
/// The document contains no XMLDSig `Signature` element.
pub const MEID_XMLSEC_STATUS_MISSING_SIGNATURE: i32 = -5;
/// The xmlsec keys manager could not be created.
pub const MEID_XMLSEC_STATUS_KEYS_MANAGER_CREATE_FAILED: i32 = -6;
/// The xmlsec keys manager could not be initialized.
pub const MEID_XMLSEC_STATUS_KEYS_MANAGER_INIT_FAILED: i32 = -7;
/// A trust root was rejected by the backend certificate loader.
pub const MEID_XMLSEC_STATUS_TRUSTED_ROOT_LOAD_FAILED: i32 = -8;
/// The xmlsec signature context could not be created or configured.
pub const MEID_XMLSEC_STATUS_CONTEXT_SETUP_FAILED: i32 = -9;
/// The signature failed cryptographic or certificate-path verification.
pub const MEID_XMLSEC_STATUS_SIGNATURE_INVALID: i32 = -10;
/// The pinned trusted-list schema could not be compiled.
pub const MEID_XMLSEC_STATUS_SCHEMA_INIT_FAILED: i32 = -11;
/// The document failed pinned trusted-list schema validation.
pub const MEID_XMLSEC_STATUS_SCHEMA_INVALID: i32 = -12;
/// The verification time does not fit the platform `time_t`.
pub const MEID_XMLSEC_STATUS_VERIFICATION_TIME_UNREPRESENTABLE: i32 = -13;
/// The reference URI or transform allowlist could not be installed.
pub const MEID_XMLSEC_STATUS_POLICY_SETUP_FAILED: i32 = -14;
