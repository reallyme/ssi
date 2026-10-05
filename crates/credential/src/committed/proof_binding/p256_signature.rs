// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! P-256 signature canonicalization for SSI proof-bound credentials.

use super::P256_SIGNATURE_BYTES;
use crate::committed::error::VcError;
use reallyme_crypto::{
    p256::{
        normalize_p256_ecdsa_jose_signature_low_s, p256_ecdsa_jose_signature_to_der,
        verify_p256_digest_der,
    },
    sha2::digest as sha2_256_digest,
};

pub(crate) fn normalize_p256_zk_signature_low_s(
    signature: [u8; P256_SIGNATURE_BYTES],
) -> Result<[u8; P256_SIGNATURE_BYTES], VcError> {
    normalize_p256_ecdsa_jose_signature_low_s(&signature)
        .map_err(|_| VcError::ProofBindingSignatureInvalid)
}

pub(crate) fn require_p256_zk_signature_low_s(
    signature: &[u8; P256_SIGNATURE_BYTES],
) -> Result<(), VcError> {
    // The proof transcript binds raw signature bytes. Crypto validates both
    // scalars; equality with its canonical form is the profile's low-S gate.
    let normalized = normalize_p256_zk_signature_low_s(*signature)?;
    if normalized != *signature {
        return Err(VcError::ProofBindingSignatureInvalid);
    }
    Ok(())
}

pub(super) fn verify_p256_zk_signature(
    signature: &[u8; P256_SIGNATURE_BYTES],
    payload: &[u8],
    issuer_public_key: &[u8],
) -> Result<(), VcError> {
    require_p256_zk_signature_low_s(signature)?;
    let der = p256_ecdsa_jose_signature_to_der(signature)
        .map_err(|_| VcError::ProofBindingSignatureInvalid)?;
    let digest = sha2_256_digest(payload).into_bytes();
    verify_p256_digest_der(der.as_slice(), &digest, issuer_public_key)
        .map_err(|_| VcError::ProofBindingSignatureInvalid)
}
