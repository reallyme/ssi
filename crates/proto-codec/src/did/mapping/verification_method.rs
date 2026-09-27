// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{EnumValue, MessageField};
use identity_core_primitives::algorithm_map::{alg_str_to_alg, alg_to_did_alg_str};
use identity_core_primitives::Algorithm;
use reallyme_did_types::VerificationMethod as JsonVM;
use reallyme_ssi_proto::generated::proto::meid::did::v1::VerificationMethod as PbVM;
use reallyme_ssi_proto::generated::proto::reallyme::crypto::v1::{
    crypto_algorithm_identifier, CryptoAlgorithmIdentifier, KemAlgorithm, KeyAgreementAlgorithm,
    MulticodecKeyAlgorithm, SignatureAlgorithm,
};

use crate::did::DidProtoCodecError;

/// JSON-domain verification method to did:me protobuf.
pub fn vm_to_proto(vm: &JsonVM) -> Result<PbVM, DidProtoCodecError> {
    let alg = vm
        .algorithm
        .as_deref()
        .ok_or(DidProtoCodecError::MissingRequiredField)?;

    Ok(PbVM {
        id: vm.id.clone(),
        r#type: vm.vm_type.clone(),
        controller: vm.controller.clone(),
        public_key_multibase: vm.public_key_multibase.clone(),
        algorithm: MessageField::some(algorithm_to_proto(alg)?),
        ..PbVM::default()
    })
}

/// did:me protobuf verification method to JSON-domain model.
pub fn vm_from_proto(p: &PbVM) -> Result<JsonVM, DidProtoCodecError> {
    let algorithm = p
        .algorithm
        .as_option()
        .ok_or(DidProtoCodecError::MissingRequiredField)
        .and_then(algorithm_from_proto)?;
    Ok(JsonVM {
        id: p.id.clone(),
        vm_type: p.r#type.clone(),
        controller: p.controller.clone(),
        public_key_multibase: p.public_key_multibase.clone(),
        algorithm: Some(algorithm),
    })
}

pub(crate) fn algorithm_to_proto(
    value: &str,
) -> Result<CryptoAlgorithmIdentifier, DidProtoCodecError> {
    let semantic = alg_str_to_alg(value).map_err(|_| DidProtoCodecError::UnsupportedAlgorithm)?;
    let algorithm = match semantic {
        Algorithm::Ed25519 => crypto_algorithm_identifier::Algorithm::Signature(EnumValue::from(
            SignatureAlgorithm::Ed25519,
        )),
        Algorithm::P256 => crypto_algorithm_identifier::Algorithm::Signature(EnumValue::from(
            SignatureAlgorithm::EcdsaP256Sha256,
        )),
        Algorithm::Secp256k1 => crypto_algorithm_identifier::Algorithm::Signature(EnumValue::from(
            SignatureAlgorithm::EcdsaSecp256k1Sha256,
        )),
        Algorithm::MlDsa87 => crypto_algorithm_identifier::Algorithm::Signature(EnumValue::from(
            SignatureAlgorithm::MlDsa87,
        )),
        Algorithm::X25519 => crypto_algorithm_identifier::Algorithm::KeyAgreement(EnumValue::from(
            KeyAgreementAlgorithm::X25519,
        )),
        Algorithm::MlKem768 => {
            crypto_algorithm_identifier::Algorithm::Kem(EnumValue::from(KemAlgorithm::MlKem768))
        }
        Algorithm::MlKem1024 => {
            crypto_algorithm_identifier::Algorithm::Kem(EnumValue::from(KemAlgorithm::MlKem1024))
        }
        _ => return Err(DidProtoCodecError::UnsupportedAlgorithm),
    };

    Ok(CryptoAlgorithmIdentifier {
        algorithm: Some(algorithm),
        ..CryptoAlgorithmIdentifier::default()
    })
}

fn algorithm_from_proto(value: &CryptoAlgorithmIdentifier) -> Result<String, DidProtoCodecError> {
    let algorithm = value
        .algorithm
        .as_ref()
        .ok_or(DidProtoCodecError::MissingRequiredField)?;
    let semantic = match algorithm {
        crypto_algorithm_identifier::Algorithm::Signature(sig) => match sig.as_known() {
            Some(SignatureAlgorithm::Ed25519) => Algorithm::Ed25519,
            Some(SignatureAlgorithm::EcdsaP256Sha256) => Algorithm::P256,
            Some(SignatureAlgorithm::EcdsaSecp256k1Sha256) => Algorithm::Secp256k1,
            Some(SignatureAlgorithm::MlDsa87) => Algorithm::MlDsa87,
            _ => return Err(DidProtoCodecError::UnsupportedAlgorithm),
        },
        crypto_algorithm_identifier::Algorithm::KeyAgreement(agreement) => {
            match agreement.as_known() {
                Some(KeyAgreementAlgorithm::X25519) => Algorithm::X25519,
                _ => return Err(DidProtoCodecError::UnsupportedAlgorithm),
            }
        }
        crypto_algorithm_identifier::Algorithm::Kem(kem) => match kem.as_known() {
            Some(KemAlgorithm::MlKem768) => Algorithm::MlKem768,
            Some(KemAlgorithm::MlKem1024) => Algorithm::MlKem1024,
            _ => return Err(DidProtoCodecError::UnsupportedAlgorithm),
        },
        crypto_algorithm_identifier::Algorithm::MulticodecKey(multicodec) => {
            match multicodec.as_known() {
                Some(MulticodecKeyAlgorithm::Ed25519Pub) => Algorithm::Ed25519,
                Some(MulticodecKeyAlgorithm::X25519Pub) => Algorithm::X25519,
                Some(MulticodecKeyAlgorithm::Secp256k1Pub) => Algorithm::Secp256k1,
                Some(MulticodecKeyAlgorithm::P256Pub) => Algorithm::P256,
                Some(MulticodecKeyAlgorithm::MlKem768Pub) => Algorithm::MlKem768,
                Some(MulticodecKeyAlgorithm::MlKem1024Pub) => Algorithm::MlKem1024,
                Some(MulticodecKeyAlgorithm::MlDsa87Pub) => Algorithm::MlDsa87,
                _ => return Err(DidProtoCodecError::UnsupportedAlgorithm),
            }
        }
        _ => return Err(DidProtoCodecError::UnsupportedAlgorithm),
    };

    Ok(alg_to_did_alg_str(semantic).to_owned())
}
