// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    generate_did_me, genesis_binding_cbor, is_valid_did_me, parse_did_me,
    verify_genesis_core_identifier, DidMeErrorReason,
};
use identity_core_primitives::Algorithm;
use reallyme_did_core::Canonical;
use reallyme_did_core::DidCore;
use reallyme_did_core::{CoreVerificationMethod, UpdatePolicy};

fn sample_key() -> CoreVerificationMethod {
    CoreVerificationMethod {
        id: "#ed25519".to_owned(),
        vm_type: "Multikey".to_owned(),
        algorithm: Algorithm::Ed25519,
        public_key_multibase: "z6MkkRtoB8oeJhJGp6WT8PAzmNmcAA4UDCmMiHHnPKDo9jJ3".to_owned(),
    }
}

fn sample_key_with_id(id: &str) -> CoreVerificationMethod {
    CoreVerificationMethod {
        id: id.to_owned(),
        vm_type: "Multikey".to_owned(),
        algorithm: Algorithm::Ed25519,
        public_key_multibase: "z6MkkRtoB8oeJhJGp6WT8PAzmNmcAA4UDCmMiHHnPKDo9jJ3".to_owned(),
    }
}

fn sample_policy() -> UpdatePolicy {
    UpdatePolicy {
        allowed_verification_methods: vec!["#ed25519".to_owned()],
        threshold: Some(1),
    }
}

#[test]
fn generated_did_me_has_bech32_payload_and_valid_checksum() -> Result<(), Box<dyn std::error::Error>>
{
    let nonce = [0xA5u8; 16];
    let policy = sample_policy();
    let did = generate_did_me(&nonce, &policy, &[sample_key()])?;

    assert!(did.starts_with("did:me:me1"));
    let parsed = parse_did_me(&did)?;
    assert_eq!(parsed.payload.len(), 16);
    assert!(is_valid_did_me(&did));
    Ok(())
}

#[test]
fn known_did_me_vector_decodes_to_expected_payload() -> Result<(), Box<dyn std::error::Error>> {
    let parsed = parse_did_me("did:me:me1072e0a7myhee5da50wt3tu2a9sds44xv")?;
    assert_eq!(
        parsed.payload,
        [
            0x7f, 0x95, 0x97, 0xf7, 0xdb, 0x25, 0xf3, 0x9a, 0x37, 0xb4, 0x7b, 0x97, 0x15, 0xf1,
            0x5d, 0x2c,
        ]
    );
    Ok(())
}

#[test]
fn did_me_rejects_uppercase_identifier() {
    let err = parse_did_me("did:me:ME1072E0A7MYHEE5DA50WT3TU2A9SDS44XV")
        .err()
        .map(|error| error.reason);
    assert_eq!(err, Some(DidMeErrorReason::InvalidHrp));
}

#[test]
fn did_me_rejects_tampered_checksum() {
    let err = parse_did_me("did:me:me1072e0a7myhee5da50wt3tu2a9sds44xu")
        .err()
        .map(|error| error.reason);
    assert_eq!(err, Some(DidMeErrorReason::InvalidChecksum));
}

#[test]
fn genesis_binding_verification_uses_core_fields_from_spec_section_2_6(
) -> Result<(), Box<dyn std::error::Error>> {
    let nonce = [0xA5u8; 16];
    let controller_keys = vec![sample_key()];
    let update_policy = sample_policy();
    let did = generate_did_me(&nonce, &update_policy, &controller_keys)?;
    let core = DidCore {
        id: did.clone(),
        sequence: 1,
        nonce: Some(nonce.to_vec()),
        controller: vec![did.clone()],
        controller_keys,
        authentication: vec!["#ed25519".to_owned()],
        assertion: vec!["#ed25519".to_owned()],
        key_agreement: vec![],
        services: vec![],
        update_policy,
        prev: None,
    };
    let core_cbor = core.canonical_cbor()?;
    let core_value = reallyme_codec::cbor::decode_dag_cbor(&core_cbor)?;

    verify_genesis_core_identifier(&did, &core_value)?;
    assert!(genesis_binding_cbor(&[0xA5u8; 15], &sample_policy(), &[sample_key()]).is_err());
    Ok(())
}

#[test]
fn genesis_identifier_verification_rejects_unsorted_controller_keys(
) -> Result<(), Box<dyn std::error::Error>> {
    let nonce = [0xA5u8; 16];
    let controller_keys = vec![sample_key_with_id("#z"), sample_key_with_id("#a")];
    let update_policy = UpdatePolicy {
        allowed_verification_methods: vec!["#a".to_owned()],
        threshold: Some(1),
    };
    let did = generate_did_me(&nonce, &update_policy, &controller_keys)?;
    let core = DidCore {
        id: did.clone(),
        sequence: 1,
        nonce: Some(nonce.to_vec()),
        controller: vec![did],
        controller_keys,
        authentication: vec!["#a".to_owned()],
        assertion: vec!["#a".to_owned()],
        key_agreement: vec![],
        services: vec![],
        update_policy,
        prev: None,
    };
    let core_cbor = core.canonical_cbor()?;
    let core_value = reallyme_codec::cbor::decode_dag_cbor(&core_cbor)?;

    let err = verify_genesis_core_identifier(&core.id, &core_value)
        .err()
        .map(|error| error.reason);
    assert_eq!(err, Some(DidMeErrorReason::InvalidControllerKeys));
    Ok(())
}
