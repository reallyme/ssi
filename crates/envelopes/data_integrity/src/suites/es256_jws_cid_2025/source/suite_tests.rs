// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use super::proof_payload;
use reallyme_codec::base64url::bytes_to_base64url;

const VECTORS: &str = include_str!("../../../../tests/fixtures/protocol-wire-formats.json");

#[test]
fn proof_payload_matches_portable_wire_vector() {
    let vectors: serde_json::Value =
        serde_json::from_str(VECTORS).expect("portable vector JSON must parse");
    let vector = vectors
        .get("did_me_data_integrity")
        .expect("did:me data-integrity vector must exist");
    let current_core = vector
        .get("current_core")
        .expect("current core must exist")
        .as_str()
        .expect("current core must be text");
    let created = vector
        .get("created")
        .expect("created must exist")
        .as_str()
        .expect("created must be text");
    let payload = proof_payload(current_core, created).expect("vector payload must encode");

    assert_eq!(
        payload,
        vector
            .get("payload_utf8")
            .expect("payload must exist")
            .as_str()
            .expect("payload must be text")
            .as_bytes()
    );
    assert_eq!(
        bytes_to_base64url(&payload),
        vector
            .get("payload_base64url")
            .expect("encoded payload must exist")
            .as_str()
            .expect("encoded payload must be text")
    );
}
