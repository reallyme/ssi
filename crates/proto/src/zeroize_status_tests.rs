// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::MessageField;

use super::zeroize_status_list;
use crate::generated::proto::identity::status::v1 as pb;
#[test]
fn status_cleanup_clears_payload_and_signature_material() {
    let mut list = pb::StatusList {
        issuer_did: "did:example:issuer".to_owned(),
        encoded_list: vec![1, 2, 3],
        length: 24,
        list_id: vec![4; 32],
        signature: MessageField::some(pb::StatusListSignature {
            sig_bytes: vec![5; 64],
            ..Default::default()
        }),
        ..Default::default()
    };

    zeroize_status_list(&mut list);

    assert!(list.issuer_did.is_empty());
    assert!(list.encoded_list.is_empty());
    assert_eq!(list.length, 0);
    assert!(list.list_id.is_empty());
    assert!(list.signature.as_option().is_none());
}
