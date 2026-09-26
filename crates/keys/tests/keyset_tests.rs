// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
//! Test coverage for this crate.

use std::collections::BTreeMap;

use reallyme_codec::multikey::encode_multikey;
use reallyme_keys::{ExportedKeySet, ExportedPrivateKey, KeySet, KeySetError};

fn public_key(seed: u8) -> String {
    encode_multikey("ed25519-pub", &[seed; 32]).expect("test public key should encode")
}

#[test]
fn insert_and_retrieve_keys() {
    let mut key_set = KeySet::new();
    let public = public_key(1);

    key_set
        .put_key("#k1", vec![1, 2, 3], public.clone())
        .expect("valid key pair should insert");

    assert_eq!(
        key_set
            .private_key("#k1")
            .expect("private key should exist")
            .expose_secret(),
        &[1, 2, 3]
    );
    assert_eq!(
        key_set
            .get_private("#k1")
            .expect("private key copy should succeed")
            .as_slice(),
        [1, 2, 3].as_slice()
    );
    assert_eq!(
        key_set.get_public("#k1").expect("public key should exist"),
        public
    );
}

#[test]
fn missing_keys_return_typed_errors() {
    let key_set = KeySet::new();

    assert_eq!(
        key_set
            .get_private("#missing")
            .expect_err("missing private key should fail"),
        KeySetError::MissingPrivateKey
    );
    assert_eq!(
        key_set
            .get_public("#missing")
            .expect_err("missing public key should fail"),
        KeySetError::MissingPublicKey
    );
}

#[test]
fn invalid_inputs_are_rejected() {
    let mut key_set = KeySet::new();
    let public = public_key(1);

    assert_eq!(
        key_set
            .put_key("", vec![1], public.clone())
            .expect_err("empty verification method id should fail"),
        KeySetError::InvalidVerificationMethodId
    );
    assert_eq!(
        key_set
            .put_key("#bad", Vec::new(), public.clone())
            .expect_err("empty private key should fail"),
        KeySetError::InvalidPrivateKeyMaterial
    );
    assert_eq!(
        key_set
            .put_key("#bad", vec![1], "not-multibase")
            .expect_err("non-multibase public key should fail"),
        KeySetError::InvalidPublicKeyMultibase
    );
    assert_eq!(
        key_set
            .put_public("#bad\n", public.clone())
            .expect_err("control characters in ids should fail"),
        KeySetError::InvalidVerificationMethodId
    );
    assert_eq!(
        key_set
            .put_public("#bidi\u{202e}", public)
            .expect_err("format controls in ids should fail"),
        KeySetError::InvalidVerificationMethodId
    );
    assert_eq!(
        key_set
            .put_public("#bad-public", "zzzz")
            .expect_err("invalid base58/multikey public key should fail"),
        KeySetError::InvalidPublicKeyMultibase
    );
}

#[test]
fn oversized_inputs_are_rejected() {
    let mut key_set = KeySet::new();
    let public = public_key(1);

    let oversized_id = "#".repeat(1_025);
    let oversized_private_key = vec![1; (16 * 1024) + 1];
    let oversized_public_key = format!("z{}", "a".repeat(32 * 1024));

    assert_eq!(
        key_set
            .put_key(oversized_id, vec![1], public.clone())
            .expect_err("oversized verification method id should fail"),
        KeySetError::InvalidVerificationMethodId
    );
    assert_eq!(
        key_set
            .put_key("#large-private", oversized_private_key, public)
            .expect_err("oversized private key should fail"),
        KeySetError::InvalidPrivateKeyMaterial
    );
    assert_eq!(
        key_set
            .put_public("#large-public", oversized_public_key)
            .expect_err("oversized public key should fail"),
        KeySetError::InvalidPublicKeyMultibase
    );
}

#[test]
fn put_public_only_stores_public_key() {
    let mut key_set = KeySet::new();
    let public = public_key(1);

    key_set
        .put_public("#k1", public.clone())
        .expect("valid public key should insert");

    assert_eq!(
        key_set
            .get_private("#k1")
            .expect_err("public-only entry should not have private material"),
        KeySetError::MissingPrivateKey
    );
    assert_eq!(
        key_set.get_public("#k1").expect("public key should exist"),
        public
    );
}

#[test]
fn copy_into_is_deep_copy() {
    let mut source = KeySet::new();
    let public_a = public_key(10);
    let public_b = public_key(11);
    source
        .put_key("#k1", vec![9], public_a.clone())
        .expect("valid source key should insert");

    let mut target = KeySet::new();
    source.copy_into(&mut target);

    assert_eq!(
        target
            .get_private("#k1")
            .expect("copied private key should exist")
            .as_slice(),
        [9].as_slice()
    );
    assert_eq!(
        target
            .get_public("#k1")
            .expect("copied public key should exist"),
        public_a
    );

    source
        .put_key("#k1", vec![7], public_b)
        .expect("valid overwrite should succeed");

    assert_eq!(
        target
            .get_private("#k1")
            .expect("target private key should remain unchanged")
            .as_slice(),
        [9].as_slice()
    );
    assert_eq!(
        target
            .get_public("#k1")
            .expect("target public key should remain unchanged"),
        public_a
    );
}

#[test]
fn trim_to_vms_removes_unlisted_keys() {
    let mut key_set = KeySet::new();
    let public_1 = public_key(1);
    let public_2 = public_key(2);
    let public_3 = public_key(3);

    key_set
        .put_key("#k1", vec![1], public_1)
        .expect("valid key should insert");
    key_set
        .put_key("#k2", vec![2], public_2)
        .expect("valid key should insert");
    key_set
        .put_key("#k3", vec![3], public_3)
        .expect("valid key should insert");

    key_set
        .trim_to_vms(&["#k1".to_owned(), "#k3".to_owned()])
        .expect("valid trim ids should succeed");

    assert_eq!(
        key_set
            .get_private("#k1")
            .expect("kept private key should exist")
            .as_slice(),
        [1].as_slice()
    );
    assert_eq!(
        key_set
            .get_private("#k3")
            .expect("kept private key should exist")
            .as_slice(),
        [3].as_slice()
    );

    assert_eq!(
        key_set
            .get_private("#k2")
            .expect_err("trimmed private key should be missing"),
        KeySetError::MissingPrivateKey
    );
    assert_eq!(
        key_set
            .get_public("#k2")
            .expect_err("trimmed public key should be missing"),
        KeySetError::MissingPublicKey
    );
}

#[test]
fn export_and_import_roundtrip() {
    let mut original = KeySet::new();
    let public_1 = public_key(1);
    let public_2 = public_key(2);
    original
        .put_key("#k1", vec![0, 1, 2], public_1.clone())
        .expect("valid key should insert");
    original
        .put_public("#k2", public_2.clone())
        .expect("valid public key should insert");

    let exported = original.export();
    let imported = KeySet::import(exported).expect("valid export should import");

    assert_eq!(
        imported
            .get_private("#k1")
            .expect("imported private key should exist")
            .as_slice(),
        [0, 1, 2].as_slice()
    );
    assert_eq!(
        imported
            .get_public("#k1")
            .expect("imported public key should exist"),
        public_1
    );

    assert_eq!(
        imported
            .get_private("#k2")
            .expect_err("public-only key should not gain private material"),
        KeySetError::MissingPrivateKey
    );
    assert_eq!(
        imported
            .get_public("#k2")
            .expect("imported public-only key should exist"),
        public_2
    );
}

#[test]
fn import_rejects_invalid_private_base64() {
    let mut private = BTreeMap::new();
    private.insert(
        "#k1".to_owned(),
        ExportedPrivateKey::new("not base64".to_owned()),
    );

    let exported = ExportedKeySet {
        private,
        public: BTreeMap::new(),
    };

    assert_eq!(
        KeySet::import(exported).expect_err("malformed base64 should fail import"),
        KeySetError::InvalidPrivateKeyEncoding
    );
}

#[test]
fn export_serializes_deterministically() {
    let mut first = KeySet::new();
    first
        .put_key("#b", vec![2], public_key(2))
        .expect("valid key should insert");
    first
        .put_key("#a", vec![1], public_key(1))
        .expect("valid key should insert");

    let mut second = KeySet::new();
    second
        .put_key("#a", vec![1], public_key(1))
        .expect("valid key should insert");
    second
        .put_key("#b", vec![2], public_key(2))
        .expect("valid key should insert");

    let first_json =
        serde_json::to_string(&first.export()).expect("exported key set should serialize");
    let second_json =
        serde_json::to_string(&second.export()).expect("exported key set should serialize");

    assert_eq!(first_json, second_json);
}

#[test]
fn debug_output_redacts_private_material() {
    let mut key_set = KeySet::new();
    let public = public_key(7);
    key_set
        .put_key("#k1", vec![7, 8, 9], public.clone())
        .expect("valid key should insert");

    let key_set_debug = format!("{key_set:?}");
    let exported_debug = format!("{:?}", key_set.export());

    assert!(key_set_debug.contains("private_key_count"));
    assert!(!key_set_debug.contains("7"));
    assert!(!key_set_debug.contains(&public));
    assert!(exported_debug.contains("private_key_count"));
    assert!(!exported_debug.contains("BwgJ"));
}

#[test]
fn rejected_put_key_leaves_no_private_material_behind() {
    let mut key_set = KeySet::new();

    assert_eq!(
        key_set.put_key("bad id\n", vec![1, 2, 3], public_key(40)),
        Err(KeySetError::InvalidVerificationMethodId)
    );
    assert_eq!(
        key_set.put_key("#k1", vec![1, 2, 3], "not-a-multikey"),
        Err(KeySetError::InvalidPublicKeyMultibase)
    );
    assert_eq!(
        key_set.private_key("#k1").map(|_| ()),
        Err(KeySetError::MissingPrivateKey)
    );
    assert_eq!(
        key_set.public_key("#k1").map(|_| ()),
        Err(KeySetError::MissingPublicKey)
    );
}
