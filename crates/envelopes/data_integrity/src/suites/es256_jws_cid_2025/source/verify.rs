// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::base64url_bytes_to_bytes;
use reallyme_codec::multikey::parse_multikey;
use reallyme_crypto::core::Algorithm as CryptoAlgorithm;
use reallyme_crypto::dispatch::verify as dispatch_verify;
use reallyme_crypto::p256::p256_ecdsa_jose_signature_to_der;
use reallyme_did_types::DIDDocument;

use super::{Es256JwsCid2025Error, CRYPTOSUITE};

/// Verify an es256-jws-cid-2025 DataIntegrityProof on a DIDDocument.
pub fn verify_es256_jws_cid_2025(doc: &DIDDocument) -> Result<(), Es256JwsCid2025Error> {
    let proof = doc
        .data_integrity_proof
        .as_ref()
        .ok_or(Es256JwsCid2025Error::InvalidInput)?;

    if proof.proof_type != "DataIntegrityProof" {
        return Err(Es256JwsCid2025Error::BadProofType);
    }
    if proof.cryptosuite.as_deref() != Some(CRYPTOSUITE) {
        return Err(Es256JwsCid2025Error::BadCryptosuite);
    }
    if proof.proof_purpose.as_deref() != Some("assertionMethod") {
        return Err(Es256JwsCid2025Error::InvalidInput);
    }

    let vm_ref = proof
        .verification_method
        .as_deref()
        .ok_or(Es256JwsCid2025Error::MissingVerificationMethod)?;

    let jws = proof
        .jws
        .as_deref()
        .ok_or(Es256JwsCid2025Error::MissingJws)?;

    if !doc.assertion_method.iter().any(|s| s == vm_ref) {
        return Err(Es256JwsCid2025Error::VerificationMethodNotAllowed);
    }

    let vm = doc
        .verification_method
        .iter()
        .find(|v| v.id == vm_ref)
        .ok_or(Es256JwsCid2025Error::VerificationMethodNotFound)?;

    let parsed = parse_multikey(&vm.public_key_multibase)
        .map_err(|_| Es256JwsCid2025Error::InvalidMultikey)?;

    if parsed.alg != "P-256" {
        return Err(Es256JwsCid2025Error::WrongAlgorithm);
    }

    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(Es256JwsCid2025Error::MalformedJws);
    }
    let (h, p, s) = (parts[0], parts[1], parts[2]);

    let header_bytes =
        base64url_bytes_to_bytes(h.as_bytes()).map_err(|_| Es256JwsCid2025Error::BadJwsHeader)?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| Es256JwsCid2025Error::BadJwsHeader)?;

    let Some(header_object) = header.as_object() else {
        return Err(Es256JwsCid2025Error::BadJwsHeader);
    };

    if header_object.len() != 1
        || header_object.get("alg").and_then(|v| v.as_str()) != Some("ES256")
    {
        return Err(Es256JwsCid2025Error::BadJwsHeader);
    }

    let payload_bytes =
        base64url_bytes_to_bytes(p.as_bytes()).map_err(|_| Es256JwsCid2025Error::BadJwsHeader)?;
    let payload =
        core::str::from_utf8(&payload_bytes).map_err(|_| Es256JwsCid2025Error::BadJwsHeader)?;

    if payload != doc.current_core {
        return Err(Es256JwsCid2025Error::PayloadMismatch);
    }

    let raw_sig = base64url_bytes_to_bytes(s.as_bytes())
        .map_err(|_| Es256JwsCid2025Error::BadSignatureEncoding)?;
    let der_sig = p256_ecdsa_jose_signature_to_der(&raw_sig)
        .map_err(|_| Es256JwsCid2025Error::BadSignatureEncoding)?;

    let signing_input = format!("{h}.{p}");

    dispatch_verify(
        CryptoAlgorithm::P256,
        &parsed.public_key,
        signing_input.as_bytes(),
        &der_sig,
    )
    .map_err(|_| Es256JwsCid2025Error::VerifyFailed)?;

    Ok(())
}
