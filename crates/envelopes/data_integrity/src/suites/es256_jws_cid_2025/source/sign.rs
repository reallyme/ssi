// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::core::Algorithm as CryptoAlgorithm;
use reallyme_crypto::dispatch::sign as dispatch_sign;
use reallyme_crypto::p256::p256_ecdsa_der_to_jose_signature;
use reallyme_did_types::DataIntegrityProof;

use super::{Es256JwsCid2025Error, CRYPTOSUITE};

fn jws_header_b64() -> String {
    bytes_to_base64url(br#"{"alg":"ES256"}"#)
}

/// Create a DataIntegrityProof using es256-jws-cid-2025.
///
/// Payload is EXACT UTF-8 bytes of currentCore (CID string).
pub fn sign_es256_jws_cid_2025(
    current_core: &str,
    secret_key: &[u8],
    verification_method: &str,
    created: &str,
) -> Result<DataIntegrityProof, Es256JwsCid2025Error> {
    if current_core.is_empty() {
        return Err(Es256JwsCid2025Error::InvalidInput);
    }

    let header_b64 = jws_header_b64();
    let payload_b64 = bytes_to_base64url(current_core.as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");

    let der_sig = dispatch_sign(CryptoAlgorithm::P256, secret_key, signing_input.as_bytes())
        .map_err(|_| Es256JwsCid2025Error::VerifyFailed)?;

    let raw64 = p256_ecdsa_der_to_jose_signature(&der_sig)
        .map_err(|_| Es256JwsCid2025Error::BadSignatureEncoding)?;
    let sig_b64 = bytes_to_base64url(&raw64);

    let jws = format!("{header_b64}.{payload_b64}.{sig_b64}");

    Ok(DataIntegrityProof {
        proof_type: "DataIntegrityProof".into(),
        cryptosuite: Some(CRYPTOSUITE.into()),
        verification_method: Some(verification_method.into()),
        created: Some(created.into()),
        proof_purpose: Some("assertionMethod".into()),
        jws: Some(jws),
    })
}
