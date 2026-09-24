// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.

#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use envelopes_data_integrity::{
    data_integrity_proof_status, sign_data_integrity_proof,
    suites::es256_jws_cid_2025::{verify_es256_jws_cid_2025, Es256JwsCid2025Error},
    verify_data_integrity_proof, DataIntegrityCryptosuite, DataIntegrityProofError,
    DataIntegrityProofStatus, DataIntegritySignInput, DataIntegrityVerifyInput,
};
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::generate_multikey_keypair;
use reallyme_did_types::{Controller, DIDDocument, VerificationMethod};

const CURRENT_CORE: &str = "bafyreib6examplecurrentcorecid";
const VERIFICATION_METHOD: &str = "did:me:issuer#assertion-1";
const CREATED: &str = "2026-01-01T00:00:00Z";

#[test]
fn data_integrity_status_is_active() {
    assert_eq!(
        data_integrity_proof_status(),
        DataIntegrityProofStatus::Active
    );
}

#[test]
fn generic_dispatch_signs_and_verifies_es256_jws_cid_2025() {
    let keypair = generate_multikey_keypair(Algorithm::P256).expect("P-256 keypair");
    let proof = sign_data_integrity_proof(&DataIntegritySignInput {
        cryptosuite: DataIntegrityCryptosuite::Es256JwsCid2025,
        current_core: CURRENT_CORE,
        secret_key: keypair.secret_key.as_ref(),
        verification_method: VERIFICATION_METHOD,
        created: CREATED,
    })
    .expect("proof signs");
    let document = did_document(keypair.public_key_multikey, Some(proof));

    assert_eq!(
        verify_data_integrity_proof(&DataIntegrityVerifyInput {
            cryptosuite: DataIntegrityCryptosuite::Es256JwsCid2025,
            document: &document,
        }),
        Ok(())
    );
}

#[test]
fn generic_dispatch_rejects_empty_signing_input() {
    let keypair = generate_multikey_keypair(Algorithm::P256).expect("P-256 keypair");

    assert!(matches!(
        sign_data_integrity_proof(&DataIntegritySignInput {
            cryptosuite: DataIntegrityCryptosuite::Es256JwsCid2025,
            current_core: "",
            secret_key: keypair.secret_key.as_ref(),
            verification_method: VERIFICATION_METHOD,
            created: CREATED,
        }),
        Err(DataIntegrityProofError::InvalidInput)
    ));
}

#[test]
fn generic_dispatch_rejects_tampered_current_core() {
    let keypair = generate_multikey_keypair(Algorithm::P256).expect("P-256 keypair");
    let proof = sign_data_integrity_proof(&DataIntegritySignInput {
        cryptosuite: DataIntegrityCryptosuite::Es256JwsCid2025,
        current_core: CURRENT_CORE,
        secret_key: keypair.secret_key.as_ref(),
        verification_method: VERIFICATION_METHOD,
        created: CREATED,
    })
    .expect("proof signs");
    let mut document = did_document(keypair.public_key_multikey, Some(proof));
    document.current_core = "bafyreib6tamperedcurrentcorecid".to_owned();

    assert_eq!(
        verify_data_integrity_proof(&DataIntegrityVerifyInput {
            cryptosuite: DataIntegrityCryptosuite::Es256JwsCid2025,
            document: &document,
        }),
        Err(DataIntegrityProofError::CryptosuiteFailed)
    );
}

#[test]
fn es256_jws_cid_2025_rejects_extra_protected_header_members() {
    let keypair = generate_multikey_keypair(Algorithm::P256).expect("P-256 keypair");
    let mut proof = sign_data_integrity_proof(&DataIntegritySignInput {
        cryptosuite: DataIntegrityCryptosuite::Es256JwsCid2025,
        current_core: CURRENT_CORE,
        secret_key: keypair.secret_key.as_ref(),
        verification_method: VERIFICATION_METHOD,
        created: CREATED,
    })
    .expect("proof signs");

    let original_jws = proof.jws.as_deref().expect("proof jws");
    let mut parts = original_jws.split('.');
    let _header = parts.next().expect("jws header");
    let payload = parts.next().expect("jws payload");
    let signature = parts.next().expect("jws signature");
    assert!(parts.next().is_none());

    let extra_header = bytes_to_base64url(br#"{"alg":"ES256","typ":"JWT"}"#);
    proof.jws = Some(format!("{extra_header}.{payload}.{signature}"));

    let document = did_document(keypair.public_key_multikey, Some(proof));

    assert_eq!(
        verify_es256_jws_cid_2025(&document),
        Err(Es256JwsCid2025Error::BadJwsHeader)
    );
}

fn did_document(
    public_key_multibase: String,
    proof: Option<reallyme_did_types::DataIntegrityProof>,
) -> DIDDocument {
    let mut document = DIDDocument::default();
    document.context = vec!["https://www.w3.org/ns/did/v1".to_owned()];
    document.id = "did:me:issuer".to_owned();
    document.controller = Controller::Single("did:me:issuer".to_owned());
    document.current_core = CURRENT_CORE.to_owned();
    document.verification_method = vec![VerificationMethod {
        id: VERIFICATION_METHOD.to_owned(),
        vm_type: "Multikey".to_owned(),
        controller: "did:me:issuer".to_owned(),
        public_key_multibase,
        algorithm: Some("P-256".to_owned()),
    }];
    document.assertion_method = vec![VERIFICATION_METHOD.to_owned()];
    document.data_integrity_proof = proof;
    document
}
