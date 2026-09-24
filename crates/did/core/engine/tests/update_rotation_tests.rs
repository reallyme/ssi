// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_core::update::error::UpdateError;
use reallyme_did_core::update::rotation::apply_rotations;
use reallyme_did_types::VerificationMethod;
use std::collections::HashMap;

fn vm(id: &str, pk: &str) -> VerificationMethod {
    VerificationMethod {
        id: id.into(),
        vm_type: "Multikey".into(),
        controller: "did:me:test".into(),
        public_key_multibase: pk.into(),
        algorithm: Some("Ed25519".into()),
    }
}

#[test]
fn no_rotation_keeps_keys() {
    let vms = vec![vm("#k1", "zOld")];
    let rotate = HashMap::new();

    let out = apply_rotations(&vms, &rotate, |_| None).unwrap();
    assert_eq!(out[0].public_key_multibase, "zOld");
}

#[test]
fn rotation_replaces_public_key() {
    let vms = vec![vm("#k1", "zOld")];

    let mut rotate = HashMap::new();
    rotate.insert("#k1".into(), true);

    let out = apply_rotations(&vms, &rotate, |_| Some("zNew".into())).unwrap();
    assert_eq!(out[0].public_key_multibase, "zNew");
}

#[test]
fn rotation_missing_key_fails() {
    let vms = vec![vm("#k1", "zOld")];

    let mut rotate = HashMap::new();
    rotate.insert("#k1".into(), true);

    let err = apply_rotations(&vms, &rotate, |_| None).unwrap_err();
    assert!(matches!(err, UpdateError::MissingRotatedKey));
}
