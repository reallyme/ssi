// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use buffa::Message;
use codec_cbor::{encode_dag_cbor, CborValue};

use crate::committed::{
    canonical::canonical_credential_bytes,
    error::VcError,
    model::{CredentialEnvelope, Signature},
};
use reallyme_credential_claims::{
    public_key_ref_from_proto, public_key_ref_to_proto, validate_public_key_ref,
    CredentialAlgorithm,
};
use reallyme_ssi_proto::generated::proto::identity::credential::v1 as credential_pb;

use ciborium::de::from_reader;
use ciborium::value::Value;
use std::io::Cursor;

const MAX_SIGNED_ENVELOPE_BYTES: usize = 1024 * 1024;
const MAX_VERIFICATION_KEY_BYTES: usize = 64 * 1024;
const MAX_SIGNATURE_BYTES: usize = 8192;

/// A self-contained “signed envelope” wrapper.
///
/// Encoded as canonical DAG-CBOR map:
/// {
/// "vc_canon": bstr, // canonical bytes (signature excluded)
/// "verification_key": bstr, // canonical credential PublicKeyRef protobuf
/// "sig": bstr // raw signature bytes
/// }
///
/// Serialized envelope bytes suitable for VC-JWT embedding, storage, or transport.
/// Verification is: verify(sig, vc_canon).
pub fn encode_signed_envelope_cbor(envelope: &CredentialEnvelope) -> Result<Vec<u8>, VcError> {
    let vc_canon = canonical_credential_bytes(envelope).map_err(|_| VcError::Canonicalization)?;
    if vc_canon.is_empty() || vc_canon.len() > MAX_SIGNED_ENVELOPE_BYTES {
        return Err(VcError::InvalidCredential);
    }

    let sig = &envelope.issuer_signature;
    if sig.raw_rs.is_empty()
        || sig.raw_rs.len() > MAX_SIGNATURE_BYTES
        || validate_public_key_ref(&sig.verification_key).is_err()
        || !matches!(
            sig.verification_key.alg,
            CredentialAlgorithm::Ed25519
                | CredentialAlgorithm::P256
                | CredentialAlgorithm::Secp256k1
                | CredentialAlgorithm::MlDsa44
                | CredentialAlgorithm::MlDsa65
                | CredentialAlgorithm::MlDsa87
        )
    {
        return Err(VcError::InvalidCredential);
    }
    let verification_key = public_key_ref_to_proto(&sig.verification_key).encode_to_vec();
    if verification_key.is_empty() || verification_key.len() > MAX_VERIFICATION_KEY_BYTES {
        return Err(VcError::InvalidCredential);
    }

    let value = CborValue::Map(vec![
        ("vc_canon".into(), CborValue::Bytes(vc_canon)),
        (
            "verification_key".into(),
            CborValue::Bytes(verification_key),
        ),
        ("sig".into(), CborValue::Bytes(sig.raw_rs.clone())),
    ]);

    encode_dag_cbor(&value).map_err(|_| VcError::Canonicalization)
}

/// Extract (canonical bytes, signature) from the signed envelope wrapper.
///
/// This is **interop CBOR decoding**:
/// - accepts valid CBOR
/// - does NOT enforce canonical ordering
/// - does NOT re-encode
///
/// Canonicality is guaranteed by the encoder side.
pub fn decode_signed_envelope_cbor(bytes: &[u8]) -> Result<(Vec<u8>, Signature), VcError> {
    if bytes.is_empty() || bytes.len() > MAX_SIGNED_ENVELOPE_BYTES {
        return Err(VcError::InvalidCredential);
    }
    let mut reader = Cursor::new(bytes);
    let v: Value = from_reader(&mut reader).map_err(|_| VcError::InvalidCredential)?;
    let consumed = usize::try_from(reader.position()).map_err(|_| VcError::InvalidCredential)?;
    if consumed != bytes.len() {
        return Err(VcError::InvalidCredential);
    }

    let m = match v {
        Value::Map(m) => m,
        _ => return Err(VcError::InvalidCredential),
    };

    let mut vc_canon: Option<Vec<u8>> = None;
    let mut verification_key: Option<Vec<u8>> = None;
    let mut sig_bytes: Option<Vec<u8>> = None;

    for (k, val) in m {
        let key = match k {
            Value::Text(s) => s,
            _ => return Err(VcError::InvalidCredential),
        };

        match (key.as_str(), val) {
            ("vc_canon", Value::Bytes(value)) if vc_canon.is_none() => {
                if value.is_empty() || value.len() > MAX_SIGNED_ENVELOPE_BYTES {
                    return Err(VcError::InvalidCredential);
                }
                vc_canon = Some(value);
            }
            ("verification_key", Value::Bytes(value)) if verification_key.is_none() => {
                if value.is_empty() || value.len() > MAX_VERIFICATION_KEY_BYTES {
                    return Err(VcError::InvalidCredential);
                }
                verification_key = Some(value);
            }
            ("sig", Value::Bytes(value)) if sig_bytes.is_none() => {
                if value.is_empty() || value.len() > MAX_SIGNATURE_BYTES {
                    return Err(VcError::InvalidCredential);
                }
                sig_bytes = Some(value);
            }
            _ => return Err(VcError::InvalidCredential),
        }
    }

    let vc_canon = vc_canon.ok_or(VcError::InvalidCredential)?;
    let verification_key = verification_key.ok_or(VcError::InvalidCredential)?;
    let verification_key_proto =
        credential_pb::PublicKeyRef::decode(&mut verification_key.as_slice())
            .map_err(|_| VcError::InvalidCredential)?;
    let verification_key = public_key_ref_from_proto(&verification_key_proto)
        .map_err(|_| VcError::InvalidCredential)?;
    let sig_bytes = sig_bytes.ok_or(VcError::InvalidCredential)?;

    Ok((
        vc_canon,
        Signature {
            verification_key,
            raw_rs: sig_bytes,
        },
    ))
}
