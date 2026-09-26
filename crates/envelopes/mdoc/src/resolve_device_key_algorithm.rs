// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Binding between an MSO device COSE_Key and its DeviceAuth signature algorithm.
//!
//! DeviceAuth signatures must be verified only under the algorithm implied by
//! the authenticated device key's type and curve (for example ES256 with
//! EC2/P-256, EdDSA with OKP/Ed25519). Raw public-key bytes alone do not carry
//! that binding, so it is derived here from the COSE_Key parameters.

use ciborium::value::{Integer, Value};
use reallyme_cose::{cose_key_from_slice, cose_key_signature_algorithm, Algorithm};

use crate::cbor::{cbor_bytes_to_value, expect_map};
use crate::{MdocEnvelopeError, MdocInvalidInputReason};

/// RFC 9052 §7.1 COSE_Key `kty` label.
const COSE_KEY_LABEL_KTY: i64 = 1;
/// RFC 9053 §7 COSE_Key `crv` label for EC2 and OKP keys.
const COSE_KEY_LABEL_CRV: i64 = -1;

/// IANA COSE Key Type `OKP`.
const COSE_KTY_OKP: i64 = 1;
/// IANA COSE Key Type `EC2`.
const COSE_KTY_EC2: i64 = 2;

/// IANA COSE Elliptic Curve `P-256`.
const COSE_CRV_P256: i64 = 1;
/// IANA COSE Elliptic Curve `P-384`.
const COSE_CRV_P384: i64 = 2;
/// IANA COSE Elliptic Curve `P-521`.
const COSE_CRV_P521: i64 = 3;
/// IANA COSE Elliptic Curve `Ed25519`.
const COSE_CRV_ED25519: i64 = 6;
/// IANA COSE Elliptic Curve `secp256k1`.
const COSE_CRV_SECP256K1: i64 = 8;

/// Return the signature algorithm bound to an MSO device COSE_Key.
///
/// The curve-derived algorithm and any explicit COSE_Key `alg` parameter must
/// agree. Keys that cannot produce signatures, such as X25519, are rejected.
pub(crate) fn resolve_device_key_algorithm(
    device_key_cose_key_cbor: &[u8],
) -> Result<Algorithm, MdocEnvelopeError> {
    let key = cose_key_from_slice(device_key_cose_key_cbor).map_err(|_| invalid_device_key())?;
    let declared = cose_key_signature_algorithm(&key)
        .map_err(|_| invalid_device_key())?
        .map(|algorithm| algorithm.crypto_algorithm());
    let curve = curve_algorithm(device_key_cose_key_cbor)?;

    match (curve, declared) {
        (Some(curve), Some(declared)) if curve == declared => Ok(curve),
        (Some(curve), None) => Ok(curve),
        // Key types without a curve parameter (for example ML-DSA AKP keys)
        // carry their signature algorithm in the validated `alg` parameter.
        (None, Some(declared)) => Ok(declared),
        (Some(_), Some(_)) | (None, None) => Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::DeviceKeyAlgorithmMismatch,
        )),
    }
}

fn curve_algorithm(
    device_key_cose_key_cbor: &[u8],
) -> Result<Option<Algorithm>, MdocEnvelopeError> {
    let value = cbor_bytes_to_value(device_key_cose_key_cbor).map_err(|_| invalid_device_key())?;
    let entries = expect_map(&value, MdocInvalidInputReason::InvalidDeviceAuthentication)?;
    let kty = integer_parameter(entries, COSE_KEY_LABEL_KTY);
    let crv = integer_parameter(entries, COSE_KEY_LABEL_CRV);

    Ok(match (kty, crv) {
        (Some(COSE_KTY_OKP), Some(COSE_CRV_ED25519)) => Some(Algorithm::Ed25519),
        (Some(COSE_KTY_EC2), Some(COSE_CRV_P256)) => Some(Algorithm::P256),
        (Some(COSE_KTY_EC2), Some(COSE_CRV_P384)) => Some(Algorithm::P384),
        (Some(COSE_KTY_EC2), Some(COSE_CRV_P521)) => Some(Algorithm::P521),
        (Some(COSE_KTY_EC2), Some(COSE_CRV_SECP256K1)) => Some(Algorithm::Secp256k1),
        _ => None,
    })
}

fn integer_parameter(entries: &[(Value, Value)], label: i64) -> Option<i64> {
    entries.iter().find_map(|(key, value)| match (key, value) {
        (Value::Integer(key), Value::Integer(value)) if integer_equals(*key, label) => {
            i64::try_from(*value).ok()
        }
        _ => None,
    })
}

fn integer_equals(integer: Integer, expected: i64) -> bool {
    i64::try_from(integer).is_ok_and(|value| value == expected)
}

const fn invalid_device_key() -> MdocEnvelopeError {
    MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidDeviceAuthentication)
}

#[cfg(test)]
#[path = "resolve_device_key_algorithm_tests.rs"]
mod tests;
