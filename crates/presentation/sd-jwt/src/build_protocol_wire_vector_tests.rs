// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use super::{bytes_to_base64url, canonical_disclosure_set_hash};

const VECTORS: &str = include_str!("../tests/fixtures/protocol-wire-formats.json");

#[test]
fn disclosure_set_hash_matches_portable_wire_vector() {
    let vectors: serde_json::Value =
        serde_json::from_str(VECTORS).expect("portable vector JSON must parse");
    let vector = vectors
        .get("sd_jwt_key_binding")
        .expect("SD-JWT key-binding vector must exist");
    let disclosures = vector
        .get("input_disclosures")
        .expect("input disclosures must exist")
        .as_array()
        .expect("input disclosures must be an array")
        .iter()
        .map(|value| value.as_str().expect("disclosure must be text").to_owned())
        .collect::<Vec<_>>();

    let digest =
        canonical_disclosure_set_hash(&disclosures).expect("wire-vector disclosure set must hash");
    assert_eq!(
        bytes_to_base64url(digest.as_bytes()),
        vector
            .get("disclosure_set_hash_base64url")
            .expect("expected hash must exist")
            .as_str()
            .expect("expected hash must be text")
    );
    assert_eq!(
        vector
            .get("required_claim")
            .and_then(serde_json::Value::as_str),
        Some("disclosure_set_hash")
    );
}
