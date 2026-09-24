// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn decode_public_key_bytes(
    representation: &PublicKeyRepresentation,
) -> Result<Vec<u8>, ClaimsError> {
    match representation {
        PublicKeyRepresentation::JwkJson(value) => {
            let jwk = serde_json::from_slice::<reallyme_crypto::jwk::Jwk>(value).map_err(|_| {
                ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidCommitmentMaterial)
            })?;
            jwk.public_key_bytes().map_err(|_| {
                ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidCommitmentMaterial)
            })
        }
        PublicKeyRepresentation::CoseKey(value) => {
            let key = cose_key_from_slice(value).map_err(|_| {
                ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidCommitmentMaterial)
            })?;
            cose_key_to_public_bytes(&key).map_err(|_| {
                ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidCommitmentMaterial)
            })
        }
        PublicKeyRepresentation::Multikey(value) => reallyme_codec::multikey::parse_multikey(value)
            .map(|parsed| parsed.public_key)
            .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidCommitmentMaterial)),
        PublicKeyRepresentation::SubjectPublicKeyInfoDer(value) => {
            parse_subject_public_key_info_der(value)
                .map(|spki| spki.public_key)
                .map_err(|_| {
                    ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidCommitmentMaterial)
                })
        }
        PublicKeyRepresentation::Raw { bytes, .. } => Ok(bytes.clone()),
    }
}

/// Validate that a representation contains supported public key material and
/// does not smuggle private or symmetric key bytes across a public boundary.
pub fn validate_public_key_representation(
    algorithm: CredentialAlgorithm,
    representation: &PublicKeyRepresentation,
) -> Result<(), ClaimsError> {
    if matches!(algorithm, CredentialAlgorithm::Unspecified)
        || !valid_public_key_representation(algorithm, representation)
    {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidCommitmentMaterial,
        ));
    }
    Ok(())
}

fn validate_signature(signature: &Signature) -> Result<(), ClaimsError> {
    if signature.raw_rs.is_empty() || validate_public_key_ref(&signature.verification_key).is_err()
    {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidCommitmentMaterial,
        ));
    }
    Ok(())
}

fn valid_key_reference(reference: &KeyReference) -> bool {
    match reference {
        KeyReference::DidVerificationMethod(value) => {
            !value.trim().is_empty() && value.len() <= MAX_PUBLIC_KEY_MATERIAL_BYTES
        }
        KeyReference::X509Certificate(value) => valid_x509_certificate(value),
        KeyReference::DirectPublicKey => true,
    }
}

fn valid_public_key_representation(
    algorithm: CredentialAlgorithm,
    representation: &PublicKeyRepresentation,
) -> bool {
    match representation {
        PublicKeyRepresentation::JwkJson(value) => valid_public_jwk(algorithm, value),
        PublicKeyRepresentation::CoseKey(value) => valid_public_cose_key(algorithm, value),
        PublicKeyRepresentation::Multikey(value) => {
            if value.is_empty() || value.len() > MAX_PUBLIC_KEY_MATERIAL_BYTES {
                return false;
            }
            let Ok(parsed) = reallyme_codec::multikey::parse_multikey(value) else {
                return false;
            };
            multikey_algorithm_matches(algorithm, parsed.alg)
                && public_key_shape_matches(algorithm, parsed.public_key.as_slice())
        }
        PublicKeyRepresentation::SubjectPublicKeyInfoDer(value) => {
            valid_subject_public_key_info(algorithm, value)
        }
        PublicKeyRepresentation::Raw {
            serialization,
            bytes,
        } => {
            if bytes.is_empty() || bytes.len() > MAX_PUBLIC_KEY_MATERIAL_BYTES {
                return false;
            }
            match (algorithm, serialization) {
                (
                    CredentialAlgorithm::Ed25519 | CredentialAlgorithm::X25519,
                    RawPublicKeySerialization::FixedWidth,
                ) => bytes.len() == 32,
                (
                    CredentialAlgorithm::P256 | CredentialAlgorithm::Secp256k1,
                    RawPublicKeySerialization::Sec1Compressed,
                ) => bytes.len() == 33,
                (
                    CredentialAlgorithm::P256 | CredentialAlgorithm::Secp256k1,
                    RawPublicKeySerialization::Sec1Uncompressed,
                ) => bytes.len() == 65,
                (
                    CredentialAlgorithm::Es256kRecovery,
                    RawPublicKeySerialization::Sec1Compressed,
                ) => bytes.len() == 33,
                (
                    CredentialAlgorithm::Es256kRecovery,
                    RawPublicKeySerialization::Sec1Uncompressed,
                ) => bytes.len() == 65,
                (CredentialAlgorithm::MlDsa44, RawPublicKeySerialization::FixedWidth) => {
                    bytes.len() == 1_312
                }
                (CredentialAlgorithm::MlDsa65, RawPublicKeySerialization::FixedWidth) => {
                    bytes.len() == 1_952
                }
                (CredentialAlgorithm::MlDsa87, RawPublicKeySerialization::FixedWidth) => {
                    bytes.len() == 2_592
                }
                (CredentialAlgorithm::MlKem768, RawPublicKeySerialization::FixedWidth) => {
                    bytes.len() == 1_184
                }
                (CredentialAlgorithm::MlKem1024, RawPublicKeySerialization::FixedWidth) => {
                    bytes.len() == 1_568
                }
                _ => false,
            }
        }
    }
}

fn valid_public_jwk(algorithm: CredentialAlgorithm, value: &[u8]) -> bool {
    if value.is_empty() || value.len() > MAX_PUBLIC_KEY_MATERIAL_BYTES {
        return false;
    }
    let Ok(parsed) = parse_public_jwk(value) else {
        return false;
    };
    let Ok(sanitized) = serde_json::to_vec(&parsed.members) else {
        return false;
    };
    let Ok(jwk) = serde_json::from_slice::<reallyme_crypto::jwk::Jwk>(&sanitized) else {
        return false;
    };
    // The shared JWK parser rejects private and symmetric members before their
    // values are materialized. Extracting bytes also validates the supported
    // public-key profile rather than accepting an object with only a `kty`.
    let exact_algorithm_matches = match (&jwk, algorithm) {
        (reallyme_crypto::jwk::Jwk::Ec(value), CredentialAlgorithm::P256) => value.crv == "P-256",
        (reallyme_crypto::jwk::Jwk::Ec(value), CredentialAlgorithm::Secp256k1) => {
            value.crv == "secp256k1"
        }
        (reallyme_crypto::jwk::Jwk::Okp(value), CredentialAlgorithm::Ed25519) => {
            value.crv == "Ed25519"
        }
        (reallyme_crypto::jwk::Jwk::Okp(value), CredentialAlgorithm::X25519) => {
            value.crv == "X25519"
        }
        (reallyme_crypto::jwk::Jwk::Akp(value), CredentialAlgorithm::MlDsa44) => {
            value.alg == "ML-DSA-44"
        }
        (reallyme_crypto::jwk::Jwk::Akp(value), CredentialAlgorithm::MlDsa65) => {
            value.alg == "ML-DSA-65"
        }
        (reallyme_crypto::jwk::Jwk::Akp(value), CredentialAlgorithm::MlDsa87) => {
            value.alg == "ML-DSA-87"
        }
        (reallyme_crypto::jwk::Jwk::Akp(value), CredentialAlgorithm::MlKem768) => {
            value.alg == "ML-KEM-768"
        }
        (reallyme_crypto::jwk::Jwk::Akp(value), CredentialAlgorithm::MlKem1024) => {
            value.alg == "ML-KEM-1024"
        }
        _ => false,
    };
    exact_algorithm_matches
        && valid_jwk_key_operations(algorithm, parsed.key_operations.as_deref())
        && jwk
            .public_key_bytes()
            .is_ok_and(|bytes| public_key_shape_matches(algorithm, bytes.as_slice()))
}

fn valid_public_cose_key(algorithm: CredentialAlgorithm, value: &[u8]) -> bool {
    if value.is_empty() || value.len() > MAX_PUBLIC_KEY_MATERIAL_BYTES {
        return false;
    }
    let Ok(key) = cose_key_from_slice(value) else {
        return false;
    };
    let Ok(public_key) = cose_key_to_public_bytes(&key) else {
        return false;
    };
    let signature_algorithm_matches = match cose_key_signature_algorithm(&key) {
        Ok(Some(value)) => cose_signature_algorithm_matches(algorithm, value),
        Ok(None) => matches!(
            algorithm,
            CredentialAlgorithm::MlKem768 | CredentialAlgorithm::MlKem1024
        ),
        Err(_) => false,
    };
    // `CoseKey` owns all byte parameters behind a zeroize-on-drop boundary.
    // A valid public key is precisely one for which public extraction succeeds
    // and private extraction reports absence rather than yielding key bytes.
    signature_algorithm_matches
        && public_key_shape_matches(algorithm, public_key.as_slice())
        && matches!(
            cose_key_to_private_bytes(&key),
            Err(CoseError::MissingKeyMaterial)
        )
}

fn cose_signature_algorithm_matches(
    algorithm: CredentialAlgorithm,
    cose_algorithm: CoseSignatureAlgorithm,
) -> bool {
    matches!(
        (algorithm, cose_algorithm),
        (
            CredentialAlgorithm::Ed25519,
            CoseSignatureAlgorithm::Ed25519
        ) | (CredentialAlgorithm::P256, CoseSignatureAlgorithm::Es256)
            | (CredentialAlgorithm::P256, CoseSignatureAlgorithm::Esp256)
            | (
                CredentialAlgorithm::Secp256k1,
                CoseSignatureAlgorithm::Es256K
            )
            | (
                CredentialAlgorithm::Es256kRecovery,
                CoseSignatureAlgorithm::Es256K
            )
            | (
                CredentialAlgorithm::MlDsa44,
                CoseSignatureAlgorithm::MlDsa44
            )
            | (
                CredentialAlgorithm::MlDsa65,
                CoseSignatureAlgorithm::MlDsa65
            )
            | (
                CredentialAlgorithm::MlDsa87,
                CoseSignatureAlgorithm::MlDsa87
            )
    )
}

fn multikey_algorithm_matches(algorithm: CredentialAlgorithm, value: &str) -> bool {
    matches!(
        (algorithm, value),
        (CredentialAlgorithm::Ed25519, "Ed25519")
            | (CredentialAlgorithm::X25519, "X25519")
            | (CredentialAlgorithm::P256, "P-256")
            | (CredentialAlgorithm::Secp256k1, "secp256k1")
            | (CredentialAlgorithm::Es256kRecovery, "secp256k1")
            | (CredentialAlgorithm::MlDsa44, "ML-DSA-44")
            | (CredentialAlgorithm::MlDsa65, "ML-DSA-65")
            | (CredentialAlgorithm::MlDsa87, "ML-DSA-87")
            | (CredentialAlgorithm::MlKem768, "ML-KEM-768")
            | (CredentialAlgorithm::MlKem1024, "ML-KEM-1024")
    )
}

fn public_key_shape_matches(algorithm: CredentialAlgorithm, value: &[u8]) -> bool {
    match algorithm {
        CredentialAlgorithm::Ed25519 | CredentialAlgorithm::X25519 => value.len() == 32,
        CredentialAlgorithm::P256
        | CredentialAlgorithm::Secp256k1
        | CredentialAlgorithm::Es256kRecovery => value.len() == 33 || value.len() == 65,
        CredentialAlgorithm::MlDsa44 => value.len() == 1_312,
        CredentialAlgorithm::MlDsa65 => value.len() == 1_952,
        CredentialAlgorithm::MlDsa87 => value.len() == 2_592,
        CredentialAlgorithm::MlKem768 => value.len() == 1_184,
        CredentialAlgorithm::MlKem1024 => value.len() == 1_568,
        CredentialAlgorithm::Unspecified => false,
    }
}

fn valid_x509_certificate(value: &[u8]) -> bool {
    if value.is_empty() || value.len() > MAX_PUBLIC_KEY_MATERIAL_BYTES {
        return false;
    }
    validate_certificate_der(value)
}

fn valid_subject_public_key_info(algorithm: CredentialAlgorithm, value: &[u8]) -> bool {
    if value.is_empty() || value.len() > MAX_PUBLIC_KEY_MATERIAL_BYTES {
        return false;
    }
    let Ok(spki) = parse_subject_public_key_info_der(value) else {
        return false;
    };
    subject_public_key_algorithm_matches(algorithm, spki.algorithm)
        && public_key_shape_matches(algorithm, spki.public_key.as_slice())
}

fn subject_public_key_algorithm_matches(
    algorithm: CredentialAlgorithm,
    parsed: SubjectPublicKeyAlgorithm,
) -> bool {
    match algorithm {
        CredentialAlgorithm::Ed25519 => parsed == SubjectPublicKeyAlgorithm::Ed25519,
        CredentialAlgorithm::X25519 => parsed == SubjectPublicKeyAlgorithm::X25519,
        CredentialAlgorithm::P256 => parsed == SubjectPublicKeyAlgorithm::P256,
        CredentialAlgorithm::Secp256k1 | CredentialAlgorithm::Es256kRecovery => {
            parsed == SubjectPublicKeyAlgorithm::Secp256k1
        }
        CredentialAlgorithm::MlDsa44 => parsed == SubjectPublicKeyAlgorithm::MlDsa44,
        CredentialAlgorithm::MlDsa65 => parsed == SubjectPublicKeyAlgorithm::MlDsa65,
        CredentialAlgorithm::MlDsa87 => parsed == SubjectPublicKeyAlgorithm::MlDsa87,
        CredentialAlgorithm::MlKem768 => parsed == SubjectPublicKeyAlgorithm::MlKem768,
        CredentialAlgorithm::MlKem1024 => parsed == SubjectPublicKeyAlgorithm::MlKem1024,
        CredentialAlgorithm::Unspecified => false,
    }
}

fn valid_key_assurance(assurance: &KeyAssurance) -> bool {
    match assurance {
        KeyAssurance::None => true,
        KeyAssurance::KeyAttestation(value) | KeyAssurance::HardwareAttestation(value) => {
            !value.is_empty() && value.len() <= MAX_PUBLIC_KEY_MATERIAL_BYTES
        }
        KeyAssurance::X509Chain(values) => {
            !values.is_empty()
                && values.len() <= MAX_KEY_ASSURANCE_CERTIFICATES
                && values.iter().all(|value| valid_x509_certificate(value))
        }
    }
}

/// Validate one holder-private claim opening against commitment limits.
pub fn validate_claim_opening(
    commitment: &ClaimsCommitment,
    opening: &ClaimOpening,
) -> Result<(), ClaimsError> {
    parse_claim_path(opening.claim_path.as_str())?;
    let max_value_len = usize::try_from(commitment.limits.max_value_len)
        .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidCommitmentMaterial))?;
    let salt_len = usize::try_from(commitment.limits.salt_len)
        .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidCommitmentMaterial))?;
    if opening.value.len() > max_value_len || opening.salt.len() != salt_len {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidCommitmentMaterial,
        ));
    }
    if opening.merkle_path.len() > MAX_CLAIM_OPENING_MERKLE_DEPTH {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidPrivateBundleTree,
        ));
    }
    for sibling in &opening.merkle_path {
        validate_hash(sibling.as_slice())?;
    }

    Ok(())
}

fn validate_supported_commitment(commitment: &ClaimsCommitment) -> Result<(), ClaimsError> {
    if commitment.hash_alg != CLAIM_COMMITMENT_HASH_ALG_SHA256 {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::UnsupportedCommitmentHash,
        ));
    }
    if commitment.value_encoding != CLAIM_COMMITMENT_VALUE_ENCODING {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::UnsupportedCommitmentEncoding,
        ));
    }
    Ok(())
}

fn validate_hash(value: &[u8]) -> Result<(), ClaimsError> {
    if value.len() == CLAIM_COMMITMENT_HASH_BYTES {
        Ok(())
    } else {
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidCommitmentMaterial,
        ))
    }
}

fn canonical_claim_value_bytes(value: &ClaimValue) -> Result<Vec<u8>, ClaimsError> {
    let mut out = Vec::new();
    write_canonical_claim_value(value, &mut out)?;
    Ok(out)
}
