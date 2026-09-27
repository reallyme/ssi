// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::parse_did_document_json;

#[test]
fn did_document_json_rejects_duplicate_members_and_oversized_input() {
    assert!(parse_did_document_json(br#"{"id":"did:me:a","id":"did:me:b"}"#).is_err());
    assert!(parse_did_document_json(&vec![b' '; 1_048_577]).is_err());
}
