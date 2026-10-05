// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Test-only P-256 high-S twins for profile canonicalization checks.

use crypto_core::Algorithm as CryptoAlgorithm;
use crypto_dispatch::sign;
use reallyme_credential::committed::error::VcError;
use reallyme_credential::committed::issue::CredentialPayloadSigner;
use reallyme_credential::committed::model::PublicKeyRef;
use reallyme_credential::{CredentialError, CredentialIssuerSigner, CredentialSignatureReason};

const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
const P256_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];
const P256_SIGNATURE_BYTE_RADIX: u16 = 256;

pub(super) struct HighSP256IssuerSigner<'a> {
    pub(super) private_key: &'a [u8],
    pub(super) verification_key: &'a PublicKeyRef,
}

impl CredentialPayloadSigner for HighSP256IssuerSigner<'_> {
    fn algorithm(&self) -> CryptoAlgorithm {
        CryptoAlgorithm::P256
    }

    fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, VcError> {
        high_s_p256_signature(self.private_key, payload).map_err(|_| VcError::InvalidCredential)
    }
}

impl CredentialIssuerSigner for HighSP256IssuerSigner<'_> {
    fn verification_key(&self) -> &PublicKeyRef {
        self.verification_key
    }

    fn sign_credential_payload(&self, payload: &[u8]) -> Result<Vec<u8>, CredentialError> {
        high_s_p256_signature(self.private_key, payload)
            .map_err(|_| CredentialError::Signature(CredentialSignatureReason::SigningFailed))
    }
}

fn high_s_p256_signature(private_key: &[u8], payload: &[u8]) -> Result<Vec<u8>, ()> {
    let signature = sign(CryptoAlgorithm::P256, private_key, payload).map_err(|_| ())?;
    let raw =
        reallyme_crypto::p256::p256_ecdsa_der_to_jose_signature(&signature).map_err(|_| ())?;
    Ok(high_s_twin(raw).to_vec())
}

pub(super) fn high_s_twin(mut signature: [u8; 64]) -> [u8; 64] {
    if is_high_s(&signature) {
        return signature;
    }
    let mut borrow = 0_u16;
    let s = signature
        .get_mut(P256_ORDER.len()..)
        .expect("P-256 signature has a scalar-sized S component");
    for (output_byte, order_byte) in s.iter_mut().rev().zip(P256_ORDER.iter().rev()) {
        let minuend = u16::from(*order_byte);
        let subtrahend = u16::from(*output_byte)
            .checked_add(borrow)
            .expect("P-256 byte subtraction fits u16");
        if minuend >= subtrahend {
            let difference = minuend
                .checked_sub(subtrahend)
                .expect("P-256 subtraction does not underflow");
            *output_byte = u8::try_from(difference).expect("difference fits a byte");
            borrow = 0;
        } else {
            let difference = minuend
                .checked_add(P256_SIGNATURE_BYTE_RADIX)
                .and_then(|value| value.checked_sub(subtrahend))
                .expect("P-256 borrowed subtraction fits u16");
            *output_byte = u8::try_from(difference).expect("difference fits a byte");
            borrow = 1;
        }
    }
    assert_eq!(borrow, 0, "P-256 order exceeds a valid signature scalar");
    signature
}

fn is_high_s(signature: &[u8; 64]) -> bool {
    for (left, right) in signature[32..].iter().zip(P256_HALF_ORDER) {
        if *left > right {
            return true;
        }
        if *left < right {
            return false;
        }
    }
    false
}

pub(super) fn assert_low_s(signature: &[u8; 64]) {
    for (left, right) in signature[32..].iter().zip(P256_HALF_ORDER) {
        if *left < right {
            return;
        }
        if *left > right {
            panic!("signature S scalar must be low-S");
        }
    }
}
