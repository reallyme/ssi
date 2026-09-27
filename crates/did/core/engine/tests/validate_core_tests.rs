// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_core::validate::core::{validate_core_snapshot, DidMeDocCoreView};
use reallyme_did_core::validate::{DidValidationCode, DidValidationIssue};

use identity_core_primitives::Algorithm;
use reallyme_did_core::{
    generate_did_me, Canonical, CoreVerificationMethod, DidCore, UpdatePolicy,
};

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_did_types::Controller;

fn has_code(errors: &[DidValidationIssue], code: DidValidationCode) -> bool {
    errors.iter().any(|issue| issue.code == code)
}

/// Helper: build a valid DidCore + matching CID
fn make_valid_core(sequence: u64, prev: Option<&str>) -> (DidCore, String) {
    let genesis_nonce = [0_u8; 16];
    let nonce = if sequence == 1 {
        Some(genesis_nonce.to_vec())
    } else {
        None
    };
    let controller_keys = vec![CoreVerificationMethod {
        id: "#ed25519".into(),
        vm_type: "Multikey".into(),
        algorithm: Algorithm::Ed25519,
        public_key_multibase: "zDummyKey".into(),
    }];
    let update_policy = UpdatePolicy {
        allowed_verification_methods: vec!["#ed25519".into()],
        threshold: None,
    };
    let id = generate_did_me(&genesis_nonce, &update_policy, &controller_keys).unwrap();

    let core = DidCore {
        id: id.clone(),
        sequence,
        nonce,
        controller: vec![id],
        controller_keys,
        authentication: vec!["#ed25519".into()],
        assertion: vec!["#ed25519".into()],
        key_agreement: vec![],
        services: vec![],
        projection_hash: [0_u8; 32],
        update_policy,
        prev: prev.map(|s| s.into()),
    };

    let cid = reallyme_did_core::compute_core_cid(&core).unwrap();
    (core, cid)
}

#[test]
fn valid_core_snapshot_passes() {
    let (core, cid) = make_valid_core(1, None);
    let cbor_b64 = bytes_to_base64url(&core.canonical_cbor().unwrap());

    let view = DidMeDocCoreView {
        id: &core.id,
        controller: &Controller::Single(core.id.clone()),
        sequence: 1,
        prev: None,
        current_core: &cid,
        core_cbor: &cbor_b64,
    };

    let res = validate_core_snapshot(view);

    assert!(res.ok, "{:?}", res.errors);
    assert!(res.errors.is_empty());
    assert!(res.core.is_some());
    assert!(res.cbor_bytes.is_some());
}

#[test]
fn genesis_core_rejects_a_different_well_formed_method_identifier() {
    let (core, cid) = make_valid_core(1, None);
    let alternate_nonce = [1_u8; 16];
    let alternate_id =
        generate_did_me(&alternate_nonce, &core.update_policy, &core.controller_keys).unwrap();
    let cbor_b64 = bytes_to_base64url(&core.canonical_cbor().unwrap());

    let result = validate_core_snapshot(DidMeDocCoreView {
        id: &alternate_id,
        controller: &Controller::Single(alternate_id.clone()),
        sequence: 1,
        prev: None,
        current_core: &cid,
        core_cbor: &cbor_b64,
    });

    assert!(!result.ok);
    assert!(has_code(
        &result.errors,
        DidValidationCode::IdentifierInvalid
    ));
}

#[test]
fn invalid_base64_corecbor_fails() {
    let view = DidMeDocCoreView {
        id: "did:me:test",
        controller: &Controller::Single("did:me:test".into()),
        sequence: 1,
        prev: None,
        current_core: "bafyinvalid",
        core_cbor: "!!!not-base64url!!!",
    };

    let res = validate_core_snapshot(view);

    assert!(!res.ok);
    assert!(has_code(
        &res.errors,
        DidValidationCode::CoreCborEncodingInvalid
    ));
}

#[test]
fn invalid_cbor_fails() {
    let bad_bytes = vec![0xde, 0xad, 0xbe, 0xef];
    let bad_b64 = bytes_to_base64url(&bad_bytes);

    let view = DidMeDocCoreView {
        id: "did:me:test",
        controller: &Controller::Single("did:me:test".into()),
        sequence: 1,
        prev: None,
        current_core: "bafyinvalid",
        core_cbor: &bad_b64,
    };

    let res = validate_core_snapshot(view);

    assert!(!res.ok);
    assert!(has_code(
        &res.errors,
        DidValidationCode::CoreCborCanonicalInvalid
    ));
}

#[test]
fn cid_mismatch_is_detected() {
    let (core, _) = make_valid_core(1, None);
    let cbor_b64 = bytes_to_base64url(&core.canonical_cbor().unwrap());

    let view = DidMeDocCoreView {
        id: &core.id,
        controller: &Controller::Single(core.id.clone()),
        sequence: 1,
        prev: None,
        current_core: "bafyWRONGCID",
        core_cbor: &cbor_b64,
    };

    let res = validate_core_snapshot(view);

    assert!(!res.ok);
    assert!(has_code(&res.errors, DidValidationCode::CoreCidMismatch));
}

#[test]
fn sequence_mismatch_is_detected() {
    let (core, cid) = make_valid_core(1, None);
    let cbor_b64 = bytes_to_base64url(&core.canonical_cbor().unwrap());

    let view = DidMeDocCoreView {
        id: &core.id,
        controller: &Controller::Single(core.id.clone()),
        sequence: 2,
        prev: None,
        current_core: &cid,
        core_cbor: &cbor_b64,
    };

    let res = validate_core_snapshot(view);

    assert!(!res.ok);
    assert!(has_code(
        &res.errors,
        DidValidationCode::CoreProjectionMismatch
    ));
}

#[test]
fn prev_mismatch_is_detected() {
    let (core, cid) = make_valid_core(2, Some("bafyOLD"));
    let cbor_b64 = bytes_to_base64url(&core.canonical_cbor().unwrap());

    let view = DidMeDocCoreView {
        id: &core.id,
        controller: &Controller::Single(core.id.clone()),
        sequence: 2,
        prev: Some("bafyDIFFERENT"),
        current_core: &cid,
        core_cbor: &cbor_b64,
    };

    let res = validate_core_snapshot(view);

    assert!(!res.ok);
    assert!(has_code(
        &res.errors,
        DidValidationCode::CoreProjectionMismatch
    ));
}

#[test]
fn controller_mismatch_with_signed_core_is_an_error() {
    let (core, cid) = make_valid_core(1, None);
    let cbor_b64 = bytes_to_base64url(&core.canonical_cbor().unwrap());

    let view = DidMeDocCoreView {
        id: &core.id,
        controller: &Controller::Single("did:me:delegate".into()),
        sequence: 1,
        prev: None,
        current_core: &cid,
        core_cbor: &cbor_b64,
    };

    let res = validate_core_snapshot(view);

    assert!(!res.ok);
    assert!(has_code(&res.errors, DidValidationCode::ControllerInvalid));
    assert!(res.warnings.is_empty());
}
