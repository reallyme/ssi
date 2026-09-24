// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::SensitiveDidDocument;
use reallyme_did_types::DIDDocument;
use zeroize::Zeroize;

#[test]
fn debug_is_redacted_and_manual_cleanup_clears_document() {
    let mut document = DIDDocument::default();
    document.id = "did:me:sensitive".to_owned();
    document.core_cbor = "sensitive-core".to_owned();
    let mut owner = SensitiveDidDocument::from_document(document);

    assert_eq!(format!("{owner:?}"), "SensitiveDidDocument(<redacted>)");
    owner.zeroize();
    assert!(owner.as_document().id.is_empty());
    assert!(owner.as_document().core_cbor.is_empty());
}
