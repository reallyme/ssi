// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::unwrap_used)]

use super::resolve_device_key_algorithm;
use crate::cbor::cbor_value_to_bytes;
use crate::{MdocEnvelopeError, MdocInvalidInputReason};
use ciborium::value::Value;
use reallyme_cose::{cose_key_from_public_bytes, cose_key_to_vec, Algorithm};
use reallyme_crypto::dispatch::generate_keypair;

fn cose_key_for(algorithm: Algorithm) -> Vec<u8> {
    let (public_key, _) = generate_keypair(algorithm).unwrap();
    let key = cose_key_from_public_bytes(algorithm, &public_key).unwrap();
    cose_key_to_vec(&key).unwrap().to_vec()
}

#[test]
fn binds_signature_algorithm_to_key_type_and_curve() {
    for algorithm in [
        Algorithm::Ed25519,
        Algorithm::P256,
        Algorithm::P384,
        Algorithm::P521,
        Algorithm::Secp256k1,
    ] {
        assert_eq!(
            resolve_device_key_algorithm(&cose_key_for(algorithm)),
            Ok(algorithm)
        );
    }
}

#[test]
fn rejects_non_signature_device_key() {
    // OKP / X25519 public key: usable for key agreement, never for DeviceAuth.
    let x25519_key = cbor_value_to_bytes(&Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(1.into())),
        (Value::Integer((-1).into()), Value::Integer(4.into())),
        (Value::Integer((-2).into()), Value::Bytes(vec![9_u8; 32])),
    ]))
    .unwrap();

    assert_eq!(
        resolve_device_key_algorithm(&x25519_key),
        Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::DeviceKeyAlgorithmMismatch
        ))
    );
}

#[test]
fn rejects_malformed_device_key() {
    assert_eq!(
        resolve_device_key_algorithm(&[0xa0]),
        Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::InvalidDeviceAuthentication
        ))
    );
}
