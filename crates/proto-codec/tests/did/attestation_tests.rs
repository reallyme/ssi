// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_did_types::Attestation as JsonAtt;
use reallyme_ssi_proto::generated::proto::reallyme::crypto::v1::SignatureAlgorithm;
use reallyme_ssi_proto_codec::did::mapping::{attestation_from_proto, attestation_to_proto};
use reallyme_ssi_proto_codec::did::DidProtoCodecError;

#[test]
fn json_to_proto_and_back_roundtrip() {
    let sig_bytes = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
    let sig_b64u = bytes_to_base64url(&sig_bytes);

    let json = JsonAtt {
        alg: "Ed25519".to_string(),
        vm: "#ed25519".to_string(),
        sig: sig_b64u.clone(),
    };

    let proto = attestation_to_proto(&json).expect("json to proto");

    assert_eq!(proto.alg, SignatureAlgorithm::Ed25519);
    assert_eq!(proto.vm, "#ed25519");
    assert_eq!(proto.sig, sig_bytes);

    let json2 = attestation_from_proto(&proto).expect("proto to json");

    assert_eq!(json2.alg, json.alg);
    assert_eq!(json2.vm, json.vm);
    assert_eq!(json2.sig, json.sig);
}

#[test]
fn rejects_invalid_base64url_signature() {
    let json = JsonAtt {
        alg: "Ed25519".to_string(),
        vm: "#vm".to_string(),
        sig: "!!!notbase64!!!".to_string(),
    };

    let err = attestation_to_proto(&json).unwrap_err();
    assert_eq!(err, DidProtoCodecError::InvalidBase64Url);
}
