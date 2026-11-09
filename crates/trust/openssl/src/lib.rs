// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OpenSSL-backed certificate signature verification.

mod verifier;

pub use verifier::OpenSslSignatureVerifier;
