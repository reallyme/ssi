// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
//! Test coverage for this crate.

use reallyme_credential_status::{
    status_bit, status_list_signing_payload, verify_status, CredentialStatusError,
    CredentialStatusInvalidReason, StatusList, StatusListAlgorithm, StatusListSignature,
    StatusListVerifier, StatusPurpose, MAX_STATUS_LIST_ENTRIES,
};
use serde_json::Value;
use zeroize::Zeroize;

const STATUS_LIST_VECTORS: &str = include_str!("../../../vectors/status-list.json");

struct AcceptVerifier;

impl StatusListVerifier for AcceptVerifier {
    fn verify_status_list(
        &self,
        issuer: &str,
        alg: StatusListAlgorithm,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CredentialStatusError> {
        if issuer == "did:example:issuer"
            && matches!(alg, StatusListAlgorithm::Ed25519)
            && !payload.is_empty()
            && signature == b"sig"
        {
            Ok(())
        } else {
            Err(CredentialStatusError::InvalidSignature)
        }
    }
}

struct VectorVerifier {
    expected_issuer: String,
    expected_payload_hex: String,
    expected_signature: Vec<u8>,
}

impl StatusListVerifier for VectorVerifier {
    fn verify_status_list(
        &self,
        issuer: &str,
        alg: StatusListAlgorithm,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CredentialStatusError> {
        if issuer == self.expected_issuer
            && alg == StatusListAlgorithm::Ed25519
            && to_hex(payload) == self.expected_payload_hex
            && signature == self.expected_signature.as_slice()
        {
            Ok(())
        } else {
            Err(CredentialStatusError::InvalidSignature)
        }
    }
}

fn list(purpose: StatusPurpose, encoded_list: Vec<u8>) -> StatusList {
    StatusList {
        issuer: "did:example:issuer".to_owned(),
        purpose,
        issued_at: 1_700_000_000,
        next_update: 1_800_000_000,
        encoded_list,
        length: 16,
        list_id: Some([7_u8; 32]),
        signature: StatusListSignature {
            alg: StatusListAlgorithm::Ed25519,
            sig_bytes: b"sig".to_vec(),
        },
    }
}

#[test]
fn status_list_debug_is_privacy_safe_and_owned_material_can_be_zeroized() {
    let mut status = list(StatusPurpose::Revocation, vec![0xA5, 0x5A]);

    let debug = format!("{status:?}");
    assert!(!debug.contains("did:example:issuer"));
    assert!(!debug.contains("115, 105, 103"));
    assert!(!debug.contains("165, 90"));

    status.zeroize();

    assert!(status.issuer.is_empty());
    assert_eq!(status.issued_at, 0);
    assert_eq!(status.next_update, 0);
    assert!(status.encoded_list.is_empty());
    assert_eq!(status.length, 0);
    assert_eq!(status.list_id, Some([0; 32]));
    assert!(status.signature.sig_bytes.is_empty());
}

#[test]
fn status_list_vectors_verify_or_fail_closed() {
    let suite: Value = serde_json::from_str(STATUS_LIST_VECTORS).unwrap();
    assert_eq!(
        suite["schema"].as_str().unwrap(),
        "reallyme.identity.conformance.status_list.v2"
    );

    for case in suite["cases"].as_array().unwrap() {
        let status = status_list_from_vector(&case["status_list"]);
        let index = case["credential_status_index"].as_u64().unwrap();
        let now_unix = case["now_unix"].as_u64().unwrap();
        let payload = status_list_signing_payload(&status).unwrap();
        let payload_hex = to_hex(payload.as_slice());
        let expected = &case["expected"];

        if let Some(expected_payload_hex) = expected["status_signing_payload_hex"].as_str() {
            assert_eq!(payload_hex, expected_payload_hex);
        }
        if let Some(expected_bit) = expected["status_bit"].as_bool() {
            assert_eq!(status_bit(&status, index).unwrap(), expected_bit);
        }

        let verifier = VectorVerifier {
            expected_issuer: status.issuer.clone(),
            expected_payload_hex: payload_hex,
            expected_signature: hex_to_bytes(case["verifier_signature_hex"].as_str().unwrap()),
        };
        let actual = verify_status(&status, index, now_unix, &verifier);
        match expected["result"].as_str().unwrap() {
            "ok" => actual.unwrap(),
            code => assert_eq!(actual.unwrap_err(), expected_error(code).unwrap()),
        }
    }
}

#[test]
fn verifies_clear_revocation_status() {
    let status = list(StatusPurpose::Revocation, vec![0b0000_0000, 0b0000_0000]);

    verify_status(&status, 3, 1_700_000_001, &AcceptVerifier).unwrap();
}

#[test]
fn rejects_revoked_status_bit() {
    let status = list(StatusPurpose::Revocation, vec![0b0000_1000, 0b0000_0000]);

    let err = verify_status(&status, 3, 1_700_000_001, &AcceptVerifier).unwrap_err();

    assert_eq!(err, CredentialStatusError::Revoked);
}

#[test]
fn rejects_suspended_status_bit() {
    let status = list(StatusPurpose::Suspension, vec![0b0000_0100, 0b0000_0000]);

    let err = verify_status(&status, 2, 1_700_000_001, &AcceptVerifier).unwrap_err();

    assert_eq!(err, CredentialStatusError::Suspended);
}

#[test]
fn rejects_expired_status_list() {
    let status = list(StatusPurpose::Revocation, vec![0, 0]);

    let err = verify_status(&status, 2, 1_800_000_001, &AcceptVerifier).unwrap_err();

    assert_eq!(err, CredentialStatusError::Expired);
}

#[test]
fn rejects_status_list_before_issued_time() {
    let status = list(StatusPurpose::Revocation, vec![0, 0]);

    let err = verify_status(&status, 2, 1_699_999_999, &AcceptVerifier).unwrap_err();

    assert_eq!(err, CredentialStatusError::NotYetValid);
}

#[test]
fn rejects_invalid_status_list_signature() {
    let mut status = list(StatusPurpose::Revocation, vec![0, 0]);
    status.signature.sig_bytes = b"wrong-signature".to_vec();

    let err = verify_status(&status, 2, 1_700_000_001, &AcceptVerifier).unwrap_err();

    assert_eq!(err, CredentialStatusError::InvalidSignature);
}

#[test]
fn rejects_empty_status_list_signature_metadata() {
    let mut status = list(StatusPurpose::Revocation, vec![0, 0]);
    status.signature.sig_bytes.clear();

    let err = verify_status(&status, 2, 1_700_000_001, &AcceptVerifier).unwrap_err();

    assert_eq!(
        err,
        CredentialStatusError::InvalidInput(
            CredentialStatusInvalidReason::InvalidSignatureMetadata
        )
    );
}

#[test]
fn rejects_out_of_bounds_index() {
    let status = list(StatusPurpose::Revocation, vec![0, 0]);

    let err = verify_status(&status, 16, 1_700_000_001, &AcceptVerifier).unwrap_err();

    assert_eq!(
        err,
        CredentialStatusError::InvalidInput(CredentialStatusInvalidReason::InvalidIndex)
    );
}

#[test]
fn rejects_empty_status_list_issuer() {
    let mut status = list(StatusPurpose::Revocation, vec![0, 0]);
    status.issuer.clear();

    let err = verify_status(&status, 2, 1_700_000_001, &AcceptVerifier).unwrap_err();

    assert_eq!(
        err,
        CredentialStatusError::InvalidInput(CredentialStatusInvalidReason::EmptyIssuer)
    );
}

#[test]
fn rejects_invalid_status_list_time_window() {
    let mut status = list(StatusPurpose::Revocation, vec![0, 0]);
    status.issued_at = status.next_update;

    let err = verify_status(&status, 2, 1_700_000_001, &AcceptVerifier).unwrap_err();

    assert_eq!(
        err,
        CredentialStatusError::InvalidInput(CredentialStatusInvalidReason::InvalidTimeWindow)
    );
}

#[test]
fn rejects_short_status_list_encoded_bytes() {
    let mut status = list(StatusPurpose::Revocation, vec![0]);
    status.length = 16;

    let err = verify_status(&status, 2, 1_700_000_001, &AcceptVerifier).unwrap_err();

    assert_eq!(
        err,
        CredentialStatusError::InvalidInput(CredentialStatusInvalidReason::InvalidEncodedList)
    );
}

#[test]
fn rejects_overlong_status_list_encoded_bytes() {
    let status = list(StatusPurpose::Revocation, vec![0, 0, 0]);

    let err = verify_status(&status, 2, 1_700_000_001, &AcceptVerifier).unwrap_err();

    assert_eq!(
        err,
        CredentialStatusError::InvalidInput(CredentialStatusInvalidReason::InvalidEncodedList)
    );
}

#[test]
fn signing_payload_changes_when_status_bytes_change() {
    let clean = status_list_signing_payload(&list(StatusPurpose::Revocation, vec![0, 0])).unwrap();
    let revoked =
        status_list_signing_payload(&list(StatusPurpose::Revocation, vec![1, 0])).unwrap();

    assert_ne!(clean, revoked);
}

#[test]
fn rejects_status_list_over_entry_limit() {
    let mut status = list(StatusPurpose::Revocation, vec![0, 0]);
    status.length = MAX_STATUS_LIST_ENTRIES + 1;

    let err = verify_status(&status, 0, 1_700_000_001, &AcceptVerifier).unwrap_err();

    assert_eq!(
        err,
        CredentialStatusError::InvalidInput(CredentialStatusInvalidReason::TooLarge)
    );
}

fn status_list_from_vector(value: &Value) -> StatusList {
    let list_id = value["list_id_hex"]
        .as_str()
        .map(|hex| <[u8; 32]>::try_from(hex_to_bytes(hex).as_slice()).unwrap());
    StatusList {
        issuer: value["issuer"].as_str().unwrap().to_owned(),
        purpose: purpose_from_str(value["purpose"].as_str().unwrap()).unwrap(),
        issued_at: value["issued_at"].as_u64().unwrap(),
        next_update: value["next_update"].as_u64().unwrap(),
        encoded_list: hex_to_bytes(value["encoded_list_hex"].as_str().unwrap()),
        length: value["length"].as_u64().unwrap(),
        list_id,
        signature: StatusListSignature {
            alg: algorithm_from_str(value["signature"]["alg"].as_str().unwrap()).unwrap(),
            sig_bytes: hex_to_bytes(value["signature"]["sig_bytes_hex"].as_str().unwrap()),
        },
    }
}

fn purpose_from_str(value: &str) -> Option<StatusPurpose> {
    match value {
        "Revocation" => Some(StatusPurpose::Revocation),
        "Suspension" => Some(StatusPurpose::Suspension),
        _ => None,
    }
}

fn algorithm_from_str(value: &str) -> Option<StatusListAlgorithm> {
    match value {
        "Ed25519" => Some(StatusListAlgorithm::Ed25519),
        "P256" => Some(StatusListAlgorithm::P256),
        "Secp256k1" => Some(StatusListAlgorithm::Secp256k1),
        _ => None,
    }
}

fn expected_error(code: &str) -> Option<CredentialStatusError> {
    match code {
        "Revoked" => Some(CredentialStatusError::Revoked),
        "Suspended" => Some(CredentialStatusError::Suspended),
        "Expired" => Some(CredentialStatusError::Expired),
        "NotYetValid" => Some(CredentialStatusError::NotYetValid),
        "InvalidSignature" => Some(CredentialStatusError::InvalidSignature),
        "InvalidIndex" => Some(CredentialStatusError::InvalidInput(
            CredentialStatusInvalidReason::InvalidIndex,
        )),
        _ => None,
    }
}

fn hex_to_bytes(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex strings must have even length");
    let mut out = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks(2) {
        let hex = core::str::from_utf8(chunk).unwrap();
        out.push(u8::from_str_radix(hex, 16).unwrap());
    }
    out
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[test]
fn signing_payload_authenticates_algorithm_metadata() {
    let mut status = list(StatusPurpose::Revocation, vec![0, 0]);
    let original = status_list_signing_payload(&status).unwrap();
    let verifier = PayloadVerifier(original);
    verify_status(&status, 0, 1_700_000_001, &verifier).unwrap();
    for algorithm in [StatusListAlgorithm::P256, StatusListAlgorithm::Secp256k1] {
        status.signature.alg = algorithm;
        assert_eq!(
            verify_status(&status, 0, 1_700_000_001, &verifier),
            Err(CredentialStatusError::InvalidSignature)
        );
    }
}

struct PayloadVerifier(Vec<u8>);

impl StatusListVerifier for PayloadVerifier {
    fn verify_status_list(
        &self,
        _: &str,
        _: StatusListAlgorithm,
        payload: &[u8],
        _: &[u8],
    ) -> Result<(), CredentialStatusError> {
        if payload == self.0 {
            Ok(())
        } else {
            Err(CredentialStatusError::InvalidSignature)
        }
    }
}
