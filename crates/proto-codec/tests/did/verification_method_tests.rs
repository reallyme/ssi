// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use buffa::{EnumValue, MessageField};
use reallyme_did_types::VerificationMethod;
use reallyme_ssi_proto::generated::proto::meid::did::v1::VerificationMethod as PbVM;
use reallyme_ssi_proto::generated::proto::reallyme::crypto::v1::{
    crypto_algorithm_identifier, CryptoAlgorithmIdentifier, SignatureAlgorithm,
};
use reallyme_ssi_proto_codec::did::mapping::verification_method::{vm_from_proto, vm_to_proto};
use reallyme_ssi_proto_codec::did::DidProtoCodecError;

#[test]
fn json_to_proto_ed25519() {
    let vm = VerificationMethod {
        id: "#key-1".to_string(),
        vm_type: "Multikey".to_string(),
        controller: "did:example:123".to_string(),
        public_key_multibase: "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3s8C7W5f".to_string(),
        algorithm: Some("Ed25519".to_string()),
    };

    let pb = vm_to_proto(&vm).unwrap();

    assert_eq!(pb.id, "#key-1");
    assert_eq!(pb.r#type, "Multikey");
    assert_eq!(pb.controller, "did:example:123");
    assert_eq!(pb.public_key_multibase, vm.public_key_multibase);
    let back = vm_from_proto(&pb).unwrap();
    assert_eq!(back.algorithm.as_deref(), Some("Ed25519"));
}

#[test]
fn proto_to_json_p256() {
    let algorithm = CryptoAlgorithmIdentifier {
        algorithm: Some(crypto_algorithm_identifier::Algorithm::Signature(
            EnumValue::from(SignatureAlgorithm::EcdsaP256Sha256),
        )),
        ..CryptoAlgorithmIdentifier::default()
    };

    let pb = PbVM {
        id: "#key-1".to_string(),
        r#type: "Multikey".to_string(),
        controller: "did:example:123".to_string(),
        public_key_multibase: "zP256ExampleMultikeyValue".to_string(),
        algorithm: MessageField::some(algorithm),
        ..PbVM::default()
    };

    let vm = vm_from_proto(&pb).unwrap();

    assert_eq!(vm.id, "#key-1");
    assert_eq!(vm.vm_type, "Multikey");
    assert_eq!(vm.controller, "did:example:123");
    assert_eq!(vm.public_key_multibase, "zP256ExampleMultikeyValue");
    assert_eq!(vm.algorithm.as_deref(), Some("P-256"));
}

#[test]
fn json_to_proto_missing_algorithm_fails() {
    let vm = VerificationMethod {
        id: "#key-1".to_string(),
        vm_type: "Multikey".to_string(),
        controller: "did:example:123".to_string(),
        public_key_multibase: "zBadKey".to_string(),
        algorithm: None,
    };

    let err = vm_to_proto(&vm).unwrap_err();
    assert_eq!(err, DidProtoCodecError::MissingRequiredField);
}

#[test]
fn roundtrip_json_proto_json() {
    let original = VerificationMethod {
        id: "#key-1".to_string(),
        vm_type: "Multikey".to_string(),
        controller: "did:example:123".to_string(),
        public_key_multibase: "z6Mkf9wZs2cT8wzKp".to_string(),
        algorithm: Some("Ed25519".to_string()),
    };

    let pb = vm_to_proto(&original).unwrap();
    let back = vm_from_proto(&pb).unwrap();

    assert_eq!(original.id, back.id);
    assert_eq!(original.controller, back.controller);
    assert_eq!(original.public_key_multibase, back.public_key_multibase);
    assert_eq!(back.algorithm.as_deref(), Some("Ed25519"));
    assert_eq!(back.vm_type, "Multikey");
}
