// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::EnumValue;
use identity_core_primitives::algorithm_map::alg_str_to_alg;
use identity_core_primitives::Algorithm;
use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_did_types::Attestation as JsonAtt;
use reallyme_ssi_proto::generated::proto::meid::did::v1::Attestation as PbAtt;
use reallyme_ssi_proto::generated::proto::reallyme::crypto::v1::SignatureAlgorithm;

use crate::did::DidProtoCodecError;

/// JSON-domain attestation to did:me protobuf.
pub fn attestation_to_proto(a: &JsonAtt) -> Result<PbAtt, DidProtoCodecError> {
    Ok(PbAtt {
        alg: EnumValue::from(signature_algorithm_to_proto(&a.alg)?),
        vm: a.vm.clone(),
        sig: base64url_to_bytes(&a.sig).map_err(|_| DidProtoCodecError::InvalidBase64Url)?,
        ..PbAtt::default()
    })
}

/// did:me protobuf attestation to JSON-domain model.
pub fn attestation_from_proto(p: &PbAtt) -> Result<JsonAtt, DidProtoCodecError> {
    Ok(JsonAtt {
        alg: signature_algorithm_from_proto(
            p.alg
                .as_known()
                .ok_or(DidProtoCodecError::UnsupportedAlgorithm)?,
        )
        .ok_or(DidProtoCodecError::UnsupportedAlgorithm)?
        .to_owned(),
        vm: p.vm.clone(),
        sig: bytes_to_base64url(&p.sig),
    })
}

fn signature_algorithm_to_proto(value: &str) -> Result<SignatureAlgorithm, DidProtoCodecError> {
    let semantic = alg_str_to_alg(value).map_err(|_| DidProtoCodecError::UnsupportedAlgorithm)?;

    match semantic {
        Algorithm::Ed25519 => Ok(SignatureAlgorithm::Ed25519),
        Algorithm::P256 => Ok(SignatureAlgorithm::EcdsaP256Sha256),
        Algorithm::Secp256k1 => Ok(SignatureAlgorithm::EcdsaSecp256k1Sha256),
        Algorithm::MlDsa87 => Ok(SignatureAlgorithm::MlDsa87),
        Algorithm::X25519 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
            Err(DidProtoCodecError::UnsupportedAlgorithm)
        }
    }
}

fn signature_algorithm_from_proto(value: SignatureAlgorithm) -> Option<&'static str> {
    match value {
        SignatureAlgorithm::Ed25519 => Some("Ed25519"),
        SignatureAlgorithm::EcdsaP256Sha256 => Some("P-256"),
        SignatureAlgorithm::EcdsaSecp256k1Sha256 => Some("secp256k1"),
        SignatureAlgorithm::MlDsa87 => Some("ML-DSA-87"),
        _ => None,
    }
}
