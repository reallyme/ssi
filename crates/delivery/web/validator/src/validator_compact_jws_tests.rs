// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{extract_jws_algorithm, MAX_COMPACT_JWS_BYTES};

#[test]
fn rejects_oversized_compact_jws_before_header_decoding() {
    let token = "a".repeat(MAX_COMPACT_JWS_BYTES + 1);
    assert!(extract_jws_algorithm(&token).is_err());
}

#[test]
fn rejects_compact_jws_with_extra_segments() {
    let header = codec_base64url::bytes_to_base64url(br#"{"alg":"ES256"}"#);
    let token = format!("{header}.payload.signature.extra");
    assert!(extract_jws_algorithm(&token).is_err());
}
