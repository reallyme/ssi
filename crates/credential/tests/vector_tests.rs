// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
//! Test coverage for this crate.

use reallyme_credential::{
    credential_envelope_hash, credential_signing_payload, sign_credential_envelope,
    verify_credential, verify_credential_status, AssuranceLevel, CredentialEnvelope,
    CredentialError, CredentialIssuerSigner, CredentialIssuerVerifier, CredentialKind,
    CredentialSignatureReason, CredentialStatus, CredentialStatusReason, CredentialSubject,
    CredentialVerificationInput, HolderBinding, PartyReference,
};
use reallyme_credential_claims::{
    ClaimsCommitment, CommitmentLimits, CredentialAlgorithm, DomainTags, KeyAssurance,
    KeyReference, PublicKeyRef, PublicKeyRepresentation, RawPublicKeySerialization, Signature,
};
use reallyme_credential_status::{
    status_list_signing_payload, CredentialStatusError, StatusList, StatusListAlgorithm,
    StatusListSignature, StatusListVerifier, StatusPurpose,
};
use serde_json::Value;

const CREDENTIAL_CANONICAL_VECTORS: &str =
    include_str!("../../../vectors/credential/canonical.json");

struct VectorCredentialSigner {
    expected_payload_hash_hex: String,
    signature: Vec<u8>,
    verification_key: PublicKeyRef,
}

impl CredentialIssuerSigner for VectorCredentialSigner {
    fn verification_key(&self) -> &PublicKeyRef {
        &self.verification_key
    }

    fn sign_credential_payload(&self, payload: &[u8]) -> Result<Vec<u8>, CredentialError> {
        if sha256_hex(payload) != self.expected_payload_hash_hex {
            return Err(CredentialError::Signature(
                CredentialSignatureReason::SigningFailed,
            ));
        }
        Ok(self.signature.clone())
    }
}

struct VectorCredentialVerifier {
    expected_payload_hash_hex: String,
    expected_signature: Vec<u8>,
    verification_key: PublicKeyRef,
}

impl CredentialIssuerVerifier for VectorCredentialVerifier {
    fn verify_credential_payload(
        &self,
        _issuer_reference: &PartyReference,
        verification_key: &PublicKeyRef,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CredentialError> {
        if verification_key != &self.verification_key {
            return Err(CredentialError::Signature(
                CredentialSignatureReason::VerificationMethodMismatch,
            ));
        }
        if verification_key.alg == CredentialAlgorithm::Ed25519
            && sha256_hex(payload) == self.expected_payload_hash_hex
            && signature == self.expected_signature.as_slice()
        {
            Ok(())
        } else {
            Err(CredentialError::Signature(
                CredentialSignatureReason::VerificationFailed,
            ))
        }
    }
}

struct VectorStatusVerifier {
    expected_payload_hex: String,
    expected_signature: Vec<u8>,
}

impl StatusListVerifier for VectorStatusVerifier {
    fn verify_status_list(
        &self,
        issuer: &str,
        alg: StatusListAlgorithm,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CredentialStatusError> {
        if issuer == "did:web:issuer.example"
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

#[test]
fn credential_canonical_conformance_vectors_match_or_fail_closed() {
    let suite: Value = serde_json::from_str(CREDENTIAL_CANONICAL_VECTORS).unwrap();
    for case in suite["cases"].as_array().unwrap() {
        let envelope = envelope_from_vector(&case["envelope"]);
        let status_list = status_list_from_vector(&case["status_list"]);
        let expected = &case["expected"];

        let payload = credential_signing_payload(&envelope).unwrap();
        let payload_hex = to_hex(payload.as_slice());
        let credential_hash = credential_envelope_hash(&envelope).unwrap();
        let credential_hash_hex = to_hex(credential_hash.as_slice());
        let status_payload = status_list_signing_payload(&status_list).unwrap();
        let status_payload_hex = to_hex(status_payload.as_slice());
        let vector_signature = vector_signature(payload.as_slice());
        let vector_signature_hex = to_hex(vector_signature.as_slice());

        assert_eq!(
            payload_hex,
            expected["canonical_payload_hex"].as_str().unwrap()
        );
        assert_eq!(
            credential_hash_hex,
            expected["credential_hash_hex"].as_str().unwrap()
        );
        assert_eq!(
            vector_signature_hex,
            expected["vector_signature_hex"].as_str().unwrap()
        );
        assert_eq!(
            status_payload_hex,
            expected["status_signing_payload_hex"].as_str().unwrap()
        );

        let mut signed_envelope = envelope_from_vector(&case["envelope"]);
        signed_envelope.issuer_signature.raw_rs.clear();
        let signer = VectorCredentialSigner {
            expected_payload_hash_hex: credential_hash_hex.clone(),
            signature: vector_signature.clone(),
            verification_key: signed_envelope.issuer_signature.verification_key.clone(),
        };
        sign_credential_envelope(&mut signed_envelope, &signer).unwrap();
        assert_eq!(signed_envelope.issuer_signature.raw_rs, vector_signature);

        let credential_verifier = VectorCredentialVerifier {
            expected_payload_hash_hex: credential_hash_hex,
            expected_signature: vector_signature,
            verification_key: signed_envelope.issuer_signature.verification_key.clone(),
        };
        let status_verifier = VectorStatusVerifier {
            expected_payload_hex: status_payload_hex,
            expected_signature: status_list.signature.sig_bytes.clone(),
        };

        let clear_result = verify_credential(&CredentialVerificationInput {
            envelope: &signed_envelope,
            issuer_verifier: &credential_verifier,
            status_list: &status_list,
            status_verifier: &status_verifier,
            now_unix: 1_750_000_000,
        });
        if expected["status_clear_result"].as_str().unwrap() == "ok" {
            clear_result.unwrap();
        } else {
            clear_result.unwrap_err();
        }

        let mut revoked_status = status_list_from_vector(&case["status_list"]);
        revoked_status.encoded_list[0] = 0b1000_0000;
        let revoked_payload_hex = to_hex(
            status_list_signing_payload(&revoked_status)
                .unwrap()
                .as_slice(),
        );
        let revoked_verifier = VectorStatusVerifier {
            expected_payload_hex: revoked_payload_hex,
            expected_signature: revoked_status.signature.sig_bytes.clone(),
        };
        assert_eq!(
            verify_credential_status(
                &signed_envelope,
                &revoked_status,
                1_750_000_000,
                &revoked_verifier
            )
            .unwrap_err(),
            expected_credential_status_error(expected["status_revoked_error"].as_str().unwrap())
        );

        assert_eq!(
            verify_credential_status(
                &signed_envelope,
                &status_list,
                1_780_000_000,
                &status_verifier
            )
            .unwrap_err(),
            expected_credential_status_error(expected["status_expired_error"].as_str().unwrap())
        );

        let mut mismatched_status = status_list_from_vector(&case["status_list"]);
        mismatched_status.list_id = Some([5; 32]);
        assert_eq!(
            verify_credential_status(
                &signed_envelope,
                &mismatched_status,
                1_750_000_000,
                &status_verifier
            )
            .unwrap_err(),
            expected_credential_status_error(
                expected["status_pointer_mismatch_error"].as_str().unwrap()
            )
        );
    }
}

#[test]
fn credential_canonical_positive_vectors_match() {
    let suite: Value = serde_json::from_str(CREDENTIAL_CANONICAL_VECTORS).unwrap();
    for case in suite["cases"].as_array().unwrap() {
        let envelope = envelope_from_vector(&case["envelope"]);
        let status_list = status_list_from_vector(&case["status_list"]);
        let expected = &case["expected"];

        let payload = credential_signing_payload(&envelope).unwrap();
        let payload_hex = to_hex(payload.as_slice());
        let credential_hash = credential_envelope_hash(&envelope).unwrap();
        let credential_hash_hex = to_hex(credential_hash.as_slice());
        let status_payload = status_list_signing_payload(&status_list).unwrap();
        let status_payload_hex = to_hex(status_payload.as_slice());
        let vector_signature = vector_signature(payload.as_slice());
        let vector_signature_hex = to_hex(vector_signature.as_slice());

        assert_eq!(
            payload_hex,
            expected["canonical_payload_hex"].as_str().unwrap()
        );
        assert_eq!(
            credential_hash_hex,
            expected["credential_hash_hex"].as_str().unwrap()
        );
        assert_eq!(
            vector_signature_hex,
            expected["vector_signature_hex"].as_str().unwrap()
        );
        assert_eq!(
            status_payload_hex,
            expected["status_signing_payload_hex"].as_str().unwrap()
        );

        let mut signed_envelope = envelope_from_vector(&case["envelope"]);
        signed_envelope.issuer_signature.raw_rs.clear();
        let signer = VectorCredentialSigner {
            expected_payload_hash_hex: credential_hash_hex.clone(),
            signature: vector_signature.clone(),
            verification_key: signed_envelope.issuer_signature.verification_key.clone(),
        };
        sign_credential_envelope(&mut signed_envelope, &signer).unwrap();
        assert_eq!(signed_envelope.issuer_signature.raw_rs, vector_signature);

        let credential_verifier = VectorCredentialVerifier {
            expected_payload_hash_hex: credential_hash_hex,
            expected_signature: vector_signature,
            verification_key: signed_envelope.issuer_signature.verification_key.clone(),
        };
        let status_verifier = VectorStatusVerifier {
            expected_payload_hex: status_payload_hex,
            expected_signature: status_list.signature.sig_bytes.clone(),
        };

        verify_credential(&CredentialVerificationInput {
            envelope: &signed_envelope,
            issuer_verifier: &credential_verifier,
            status_list: &status_list,
            status_verifier: &status_verifier,
            now_unix: 1_750_000_000,
        })
        .unwrap();
    }
}

#[test]
fn credential_canonical_negative_vectors_fail_closed() {
    let suite: Value = serde_json::from_str(CREDENTIAL_CANONICAL_VECTORS).unwrap();
    for case in suite["cases"].as_array().unwrap() {
        let envelope = envelope_from_vector(&case["envelope"]);
        let status_list = status_list_from_vector(&case["status_list"]);
        let expected = &case["expected"];
        let payload = credential_signing_payload(&envelope).unwrap();
        let credential_hash = credential_envelope_hash(&envelope).unwrap();
        let credential_hash_hex = to_hex(credential_hash.as_slice());
        let vector_signature = vector_signature(payload.as_slice());
        let mut signed_envelope = envelope_from_vector(&case["envelope"]);
        signed_envelope.issuer_signature.raw_rs = vector_signature;

        let status_payload = status_list_signing_payload(&status_list).unwrap();
        let status_verifier = VectorStatusVerifier {
            expected_payload_hex: to_hex(status_payload.as_slice()),
            expected_signature: status_list.signature.sig_bytes.clone(),
        };
        let credential_verifier = VectorCredentialVerifier {
            expected_payload_hash_hex: credential_hash_hex,
            expected_signature: signed_envelope.issuer_signature.raw_rs.clone(),
            verification_key: signed_envelope.issuer_signature.verification_key.clone(),
        };
        verify_credential(&CredentialVerificationInput {
            envelope: &signed_envelope,
            issuer_verifier: &credential_verifier,
            status_list: &status_list,
            status_verifier: &status_verifier,
            now_unix: 1_750_000_000,
        })
        .unwrap();

        let mut revoked_status = status_list_from_vector(&case["status_list"]);
        revoked_status.encoded_list[0] = 0b1000_0000;
        let revoked_payload_hex = to_hex(
            status_list_signing_payload(&revoked_status)
                .unwrap()
                .as_slice(),
        );
        let revoked_verifier = VectorStatusVerifier {
            expected_payload_hex: revoked_payload_hex,
            expected_signature: revoked_status.signature.sig_bytes.clone(),
        };
        assert_eq!(
            verify_credential_status(
                &signed_envelope,
                &revoked_status,
                1_750_000_000,
                &revoked_verifier
            )
            .unwrap_err(),
            expected_credential_status_error(expected["status_revoked_error"].as_str().unwrap())
        );

        assert_eq!(
            verify_credential_status(
                &signed_envelope,
                &status_list,
                1_780_000_000,
                &status_verifier
            )
            .unwrap_err(),
            expected_credential_status_error(expected["status_expired_error"].as_str().unwrap())
        );

        let mut mismatched_status = status_list_from_vector(&case["status_list"]);
        mismatched_status.list_id = Some([5; 32]);
        assert_eq!(
            verify_credential_status(
                &signed_envelope,
                &mismatched_status,
                1_750_000_000,
                &status_verifier
            )
            .unwrap_err(),
            expected_credential_status_error(
                expected["status_pointer_mismatch_error"].as_str().unwrap()
            )
        );
    }
}

fn envelope_from_vector(value: &Value) -> CredentialEnvelope {
    CredentialEnvelope {
        kind: credential_kind(value["kind"].as_str().unwrap()),
        profile_id: value["profile_id"].as_str().unwrap().to_owned(),
        assurance: assurance(value["assurance"].as_str().unwrap()),
        issuer_reference: PartyReference::Did(value["issuer_id"].as_str().unwrap().to_owned()),
        issuer_country: value["issuer_country"].as_str().unwrap().to_owned(),
        valid_from: value["valid_from"].as_i64().unwrap(),
        valid_until: value["valid_until"].as_i64().unwrap(),
        status: credential_status_from_vector(&value["status"]),
        subject: credential_subject_from_vector(&value["subject"]),
        claims_commitment: claims_commitment_from_vector(&value["claims_commitment"]),
        qeaa_compliance: None,
        issuer_signature: signature_from_vector(&value["issuer_signature"]),
    }
}

fn credential_status_from_vector(value: &Value) -> CredentialStatus {
    CredentialStatus {
        status_list_url: value["status_list_url"].as_str().unwrap().to_owned(),
        status_list_id: array32_from_hex(value["status_list_id_hex"].as_str().unwrap()),
        status_list_index: value["status_list_index"].as_u64().unwrap(),
        purpose: status_purpose(value["purpose"].as_str().unwrap()),
    }
}

fn credential_subject_from_vector(value: &Value) -> CredentialSubject {
    let subject_id = value["subject_id"].as_str().unwrap().to_owned();
    CredentialSubject {
        subject_reference: if subject_id.starts_with("did:") {
            PartyReference::Did(subject_id)
        } else {
            PartyReference::OpaqueIdentifier(subject_id)
        },
        holder_binding: HolderBinding::CryptographicKey(public_key_ref_from_vector(
            &value["subject_key"],
        )),
    }
}

fn claims_commitment_from_vector(value: &Value) -> ClaimsCommitment {
    ClaimsCommitment {
        merkle_root: bytes_from_hex(value["merkle_root_hex"].as_str().unwrap()),
        claimset_id: value["claimset_id"].as_str().unwrap().to_owned(),
        hash_alg: value["hash_alg"].as_str().unwrap().to_owned(),
        value_encoding: value["value_encoding"].as_str().unwrap().to_owned(),
        domain_tags: DomainTags {
            clm: value["domain_tags"]["clm"].as_str().unwrap().to_owned(),
            leaf: value["domain_tags"]["leaf"].as_str().unwrap().to_owned(),
            node: value["domain_tags"]["node"].as_str().unwrap().to_owned(),
        },
        limits: CommitmentLimits {
            max_value_len: u32::try_from(value["limits"]["max_value_len"].as_u64().unwrap())
                .unwrap(),
            salt_len: u32::try_from(value["limits"]["salt_len"].as_u64().unwrap()).unwrap(),
        },
    }
}

fn public_key_ref_from_vector(value: &Value) -> PublicKeyRef {
    PublicKeyRef {
        alg: credential_algorithm(value["alg"].as_str().unwrap()),
        reference: KeyReference::DidVerificationMethod(
            value["did_url"].as_str().unwrap().to_owned(),
        ),
        public_key: PublicKeyRepresentation::Raw {
            serialization: RawPublicKeySerialization::FixedWidth,
            bytes: bytes_from_hex(value["multikey_hex"].as_str().unwrap()),
        },
        assurance: KeyAssurance::None,
    }
}

fn signature_from_vector(value: &Value) -> Signature {
    Signature {
        verification_key: PublicKeyRef {
            alg: credential_algorithm(value["alg"].as_str().unwrap()),
            reference: KeyReference::DidVerificationMethod(
                value["verification_method"].as_str().unwrap().to_owned(),
            ),
            public_key: PublicKeyRepresentation::Raw {
                serialization: RawPublicKeySerialization::FixedWidth,
                bytes: vec![0x11; 32],
            },
            assurance: KeyAssurance::None,
        },
        raw_rs: bytes_from_hex(value["raw_hex"].as_str().unwrap()),
    }
}

fn status_list_from_vector(value: &Value) -> StatusList {
    StatusList {
        issuer: value["issuer"].as_str().unwrap().to_owned(),
        purpose: status_purpose(value["purpose"].as_str().unwrap()),
        issued_at: value["issued_at"].as_u64().unwrap(),
        next_update: value["next_update"].as_u64().unwrap(),
        encoded_list: bytes_from_hex(value["encoded_list_hex"].as_str().unwrap()),
        length: value["length"].as_u64().unwrap(),
        list_id: Some(array32_from_hex(value["list_id_hex"].as_str().unwrap())),
        signature: StatusListSignature {
            alg: status_algorithm(value["signature"]["alg"].as_str().unwrap()),
            sig_bytes: bytes_from_hex(value["signature"]["sig_bytes_hex"].as_str().unwrap()),
        },
    }
}

fn vector_signature(payload: &[u8]) -> Vec<u8> {
    let first = sha256_prefixed(b"RM-CREDENTIAL-VECTOR-SIG-V1", payload, b"0");
    let second = sha256_prefixed(b"RM-CREDENTIAL-VECTOR-SIG-V1", payload, b"1");
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(first.as_slice());
    out.extend_from_slice(second.as_slice());
    out
}

fn expected_credential_status_error(value: &str) -> CredentialError {
    match value {
        "Revoked" => CredentialError::Status(CredentialStatusReason::Revoked),
        "Expired" => CredentialError::Status(CredentialStatusReason::Expired),
        "StatusPointerMismatch" => {
            CredentialError::Status(CredentialStatusReason::StatusPointerMismatch)
        }
        _ => CredentialError::Status(CredentialStatusReason::InvalidEvidence),
    }
}

fn sha256_prefixed(prefix: &[u8], payload: &[u8], suffix: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(prefix.len() + payload.len() + suffix.len());
    data.extend_from_slice(prefix);
    data.extend_from_slice(payload);
    data.extend_from_slice(suffix);
    reallyme_crypto::dispatch::hash_digest(reallyme_crypto::core::HashAlgorithm::Sha2_256, &data)
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap()
}

fn sha256_hex(payload: &[u8]) -> String {
    let digest = reallyme_crypto::dispatch::hash_digest(
        reallyme_crypto::core::HashAlgorithm::Sha2_256,
        payload,
    )
    .unwrap();
    to_hex(digest.as_slice())
}

fn credential_kind(value: &str) -> CredentialKind {
    match value {
        "Pid" => CredentialKind::Pid,
        "Qeaa" => CredentialKind::Qeaa,
        _ => CredentialKind::Eaa,
    }
}

fn assurance(value: &str) -> AssuranceLevel {
    match value {
        "Substantial" => AssuranceLevel::Substantial,
        _ => AssuranceLevel::High,
    }
}

fn credential_algorithm(value: &str) -> CredentialAlgorithm {
    match value {
        "Ed25519" => CredentialAlgorithm::Ed25519,
        "P256" => CredentialAlgorithm::P256,
        "Secp256k1" => CredentialAlgorithm::Secp256k1,
        _ => CredentialAlgorithm::Unspecified,
    }
}

fn status_algorithm(value: &str) -> StatusListAlgorithm {
    match value {
        "P256" => StatusListAlgorithm::P256,
        "Secp256k1" => StatusListAlgorithm::Secp256k1,
        _ => StatusListAlgorithm::Ed25519,
    }
}

fn status_purpose(value: &str) -> StatusPurpose {
    match value {
        "Suspension" => StatusPurpose::Suspension,
        _ => StatusPurpose::Revocation,
    }
}

fn array32_from_hex(value: &str) -> [u8; 32] {
    let bytes = bytes_from_hex(value);
    <[u8; 32]>::try_from(bytes.as_slice()).unwrap()
}

fn bytes_from_hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    let mut out = Vec::with_capacity(value.len() / 2);
    let mut index = 0;
    while index < value.len() {
        let end = index + 2;
        let byte = u8::from_str_radix(&value[index..end], 16).unwrap();
        out.push(byte);
        index = end;
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
