// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cryptographic proof-only tests for WRPRC JAdES and COSE representations.

use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{extension::KeyUsage, X509Builder, X509NameBuilder},
};
use reallyme_eudi_rp_registration::{
    authenticate_registration_certificate, authenticate_wrprc_cose_sign1, authenticate_wrprc_jades,
    ArtifactDigest, RegistrationCertificateBinding, RegistrationCertificateCoseAlgorithm,
    RegistrationCertificateCoseAuthenticationInput,
    RegistrationCertificateJadesAuthenticationInput, RegistrationCertificateJadesPolicy,
    RegistrationError, RegistrationErrorReason,
};
use zeroize::Zeroizing;

fn proof_signing_identity() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), RegistrationError> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|_error| {
        RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
    })?;
    let ec_key = EcKey::generate(&group).map_err(|_error| {
        RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
    })?;
    let private_key = ec_key.private_key().to_vec_padded(32).map_err(|_error| {
        RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
    })?;
    let key = PKey::from_ec_key(ec_key).map_err(|_error| {
        RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
    })?;
    build_signing_identity(&key, private_key, MessageDigest::sha256())
}

fn proof_ed25519_signing_identity() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), RegistrationError> {
    let key = PKey::generate_ed25519().map_err(|_error| {
        RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
    })?;
    let private_key = key.raw_private_key().map_err(|_error| {
        RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
    })?;
    build_signing_identity(&key, private_key, MessageDigest::null())
}

fn build_signing_identity(
    key: &PKey<Private>,
    private_key: Vec<u8>,
    digest: MessageDigest,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), RegistrationError> {
    let mut builder = X509Builder::new().map_err(|_error| {
        RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
    })?;
    builder.set_version(2).map_err(|_error| {
        RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
    })?;
    let serial = BigNum::from_u32(1)
        .and_then(|value| value.to_asn1_integer())
        .map_err(|_error| {
            RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
        })?;
    builder.set_serial_number(&serial).map_err(|_error| {
        RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
    })?;
    let mut name = X509NameBuilder::new().map_err(|_error| {
        RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
    })?;
    name.append_entry_by_nid(Nid::COMMONNAME, "WRPRC Proof Signer")
        .map_err(|_error| {
            RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
        })?;
    let name = name.build();
    builder.set_subject_name(&name).map_err(|_error| {
        RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
    })?;
    builder.set_issuer_name(&name).map_err(|_error| {
        RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
    })?;
    builder.set_pubkey(key).map_err(|_error| {
        RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
    })?;
    let not_before = Asn1Time::from_unix(0).map_err(|_error| {
        RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
    })?;
    let not_after = Asn1Time::from_unix(1_000_000_000).map_err(|_error| {
        RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
    })?;
    builder.set_not_before(&not_before).map_err(|_error| {
        RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
    })?;
    builder.set_not_after(&not_after).map_err(|_error| {
        RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
    })?;
    let key_usage = KeyUsage::new()
        .critical()
        .digital_signature()
        .build()
        .map_err(|_error| {
            RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
        })?;
    builder.append_extension(key_usage).map_err(|_error| {
        RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
    })?;
    builder.sign(key, digest).map_err(|_error| {
        RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
    })?;
    let certificate = builder.build().to_der().map_err(|_error| {
        RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate)
    })?;
    Ok((certificate, Zeroizing::new(private_key)))
}

fn sign_wrprc_jades(
    payload: &[u8],
    certificate_der: &[u8],
    private_key: &[u8],
) -> Result<Vec<u8>, RegistrationError> {
    sign_wrprc_jades_profile(
        payload,
        certificate_der,
        private_key,
        "rc-wrp+jwt",
        TestJadesAlgorithm::Es256,
    )
}

fn sign_wrprc_jades_ed25519(
    payload: &[u8],
    certificate_der: &[u8],
    private_key: &[u8],
) -> Result<Vec<u8>, RegistrationError> {
    sign_wrprc_jades_profile(
        payload,
        certificate_der,
        private_key,
        "rc-wrp+jwt",
        TestJadesAlgorithm::Ed25519,
    )
}

fn sign_wrprc_jades_with_type(
    payload: &[u8],
    certificate_der: &[u8],
    private_key: &[u8],
    type_value: &str,
) -> Result<Vec<u8>, RegistrationError> {
    sign_wrprc_jades_profile(
        payload,
        certificate_der,
        private_key,
        type_value,
        TestJadesAlgorithm::Es256,
    )
}

#[derive(Clone, Copy)]
enum TestJadesAlgorithm {
    Es256,
    Ed25519,
}

fn sign_wrprc_jades_profile(
    payload: &[u8],
    certificate_der: &[u8],
    private_key: &[u8],
    type_value: &str,
    algorithm: TestJadesAlgorithm,
) -> Result<Vec<u8>, RegistrationError> {
    let certificate = reallyme_codec::base64::bytes_to_base64(certificate_der);
    let algorithm_name = match algorithm {
        TestJadesAlgorithm::Es256 => "ES256",
        TestJadesAlgorithm::Ed25519 => "EdDSA",
    };
    let header = format!(
        r#"{{"alg":"{algorithm_name}","typ":"{type_value}","iat":100,"x5c":["{certificate}"]}}"#
    );
    sign_wrprc_jades_header(payload, private_key, &header, algorithm)
}

fn sign_wrprc_jades_without_x5c(
    payload: &[u8],
    certificate_der: &[u8],
    private_key: &[u8],
) -> Result<Vec<u8>, RegistrationError> {
    let certificate_digest = ArtifactDigest::sha256(certificate_der);
    let thumbprint = reallyme_codec::base64url::bytes_to_base64url(certificate_digest.as_bytes());
    let header =
        format!(r#"{{"alg":"ES256","typ":"rc-wrp+jwt","iat":100,"x5t#S256":"{thumbprint}"}}"#);
    sign_wrprc_jades_header(payload, private_key, &header, TestJadesAlgorithm::Es256)
}

fn sign_wrprc_jades_header(
    payload: &[u8],
    private_key: &[u8],
    header: &str,
    algorithm: TestJadesAlgorithm,
) -> Result<Vec<u8>, RegistrationError> {
    let protected = reallyme_codec::base64url::bytes_to_base64url(header.as_bytes());
    let encoded_payload = reallyme_codec::base64url::bytes_to_base64url(payload);
    let signing_input = format!("{protected}.{encoded_payload}");
    let signature = match algorithm {
        TestJadesAlgorithm::Es256 => reallyme_jose::jws::suites::es256::sign_p256_jose_prehash(
            private_key,
            signing_input.as_bytes(),
        )
        .map(Vec::from)
        .map_err(|_error| {
            RegistrationError::Invalid(RegistrationErrorReason::SignatureVerificationFailed)
        })?,
        TestJadesAlgorithm::Ed25519 => {
            reallyme_crypto::ed25519::sign_ed25519(private_key, signing_input.as_bytes()).map_err(
                |_error| {
                    RegistrationError::Invalid(RegistrationErrorReason::SignatureVerificationFailed)
                },
            )?
        }
    };
    let encoded_signature = reallyme_codec::base64url::bytes_to_base64url(&signature);
    Ok(format!("{signing_input}.{encoded_signature}").into_bytes())
}

#[derive(Clone, Copy)]
enum TestCoseAlgorithm {
    Es256,
    Ed25519,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TestX5ChainPlacement {
    Protected,
    Unprotected,
    Missing,
}

fn sign_wrprc_cose(
    payload: &[u8],
    certificate_der: &[u8],
    private_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, RegistrationError> {
    sign_wrprc_cose_profile(
        payload,
        certificate_der,
        private_key,
        "rc-wrp+cwt",
        TestX5ChainPlacement::Protected,
        TestCoseAlgorithm::Es256,
    )
}

fn sign_wrprc_cose_ed25519(
    payload: &[u8],
    certificate_der: &[u8],
    private_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, RegistrationError> {
    sign_wrprc_cose_profile(
        payload,
        certificate_der,
        private_key,
        "rc-wrp+cwt",
        TestX5ChainPlacement::Protected,
        TestCoseAlgorithm::Ed25519,
    )
}

fn sign_wrprc_cose_profile(
    payload: &[u8],
    certificate_der: &[u8],
    private_key: &[u8],
    type_value: &str,
    x5chain_placement: TestX5ChainPlacement,
    algorithm: TestCoseAlgorithm,
) -> Result<Zeroizing<Vec<u8>>, RegistrationError> {
    let mut protected = Zeroizing::new(Vec::new());
    protected.push(if x5chain_placement == TestX5ChainPlacement::Protected {
        0xa3
    } else {
        0xa2
    });
    protected.extend_from_slice(&[
        0x01,
        match algorithm {
            TestCoseAlgorithm::Es256 => 0x26,
            TestCoseAlgorithm::Ed25519 => 0x27,
        },
    ]);
    protected.push(0x10);
    append_cbor_text(&mut protected, type_value)?;
    if x5chain_placement == TestX5ChainPlacement::Protected {
        protected.extend_from_slice(&[0x18, 0x21]);
        append_cbor_bytes(&mut protected, certificate_der)?;
    }

    let signing_input = cose_signature_structure(&protected, payload)?;
    let signature = match algorithm {
        TestCoseAlgorithm::Es256 => reallyme_jose::jws::suites::es256::sign_p256_jose_prehash(
            private_key,
            signing_input.as_slice(),
        )
        .map(Vec::from)
        .map_err(|_error| {
            RegistrationError::Invalid(RegistrationErrorReason::SignatureVerificationFailed)
        })?,
        TestCoseAlgorithm::Ed25519 => {
            reallyme_crypto::ed25519::sign_ed25519(private_key, signing_input.as_slice()).map_err(
                |_error| {
                    RegistrationError::Invalid(RegistrationErrorReason::SignatureVerificationFailed)
                },
            )?
        }
    };

    let mut cose = Zeroizing::new(Vec::new());
    cose.push(0x84);
    append_cbor_bytes(&mut cose, &protected)?;
    if x5chain_placement == TestX5ChainPlacement::Unprotected {
        cose.extend_from_slice(&[0xa1, 0x18, 0x21]);
        append_cbor_bytes(&mut cose, certificate_der)?;
    } else {
        cose.push(0xa0);
    }
    append_cbor_bytes(&mut cose, payload)?;
    append_cbor_bytes(&mut cose, &signature)?;
    Ok(cose)
}

fn cose_signature_structure(
    protected: &[u8],
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, RegistrationError> {
    let mut encoded = Zeroizing::new(Vec::new());
    encoded.push(0x84);
    encoded.push(0x6a);
    encoded.extend_from_slice(b"Signature1");
    append_cbor_bytes(&mut encoded, protected)?;
    encoded.push(0x40);
    append_cbor_bytes(&mut encoded, payload)?;
    Ok(encoded)
}

fn append_cbor_text(output: &mut Vec<u8>, value: &str) -> Result<(), RegistrationError> {
    append_cbor_major_length(output, 3, value.len())?;
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn append_cbor_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), RegistrationError> {
    append_cbor_major_length(output, 2, value.len())?;
    output.extend_from_slice(value);
    Ok(())
}

fn append_cbor_major_length(
    output: &mut Vec<u8>,
    major: u8,
    length: usize,
) -> Result<(), RegistrationError> {
    let prefix = major.checked_shl(5).ok_or(RegistrationError::Invalid(
        RegistrationErrorReason::SerializationFailed,
    ))?;
    if length <= 23 {
        output.push(
            prefix
                | u8::try_from(length).map_err(|_error| {
                    RegistrationError::Invalid(RegistrationErrorReason::SerializationFailed)
                })?,
        );
    } else if length <= usize::from(u8::MAX) {
        output.push(prefix | 24);
        output.push(u8::try_from(length).map_err(|_error| {
            RegistrationError::Invalid(RegistrationErrorReason::SerializationFailed)
        })?);
    } else if length <= usize::from(u16::MAX) {
        output.push(prefix | 25);
        output.extend_from_slice(
            &u16::try_from(length)
                .map_err(|_error| {
                    RegistrationError::Invalid(RegistrationErrorReason::SerializationFailed)
                })?
                .to_be_bytes(),
        );
    } else {
        output.push(prefix | 26);
        output.extend_from_slice(
            &u32::try_from(length)
                .map_err(|_error| {
                    RegistrationError::Invalid(RegistrationErrorReason::SerializationFailed)
                })?
                .to_be_bytes(),
        );
    }
    Ok(())
}

#[test]
fn wrprc_proof_rejects_non_certificate_signer_bytes() {
    let policy = RegistrationCertificateJadesPolicy::default();
    let error = authenticate_wrprc_jades(RegistrationCertificateJadesAuthenticationInput {
        compact_jws: b"header.payload.signature",
        expected_signer_certificate_der: b"not-a-certificate",
        binding_digest: ArtifactDigest::from_bytes([0_u8; 32]),
        evaluation_time: time::OffsetDateTime::UNIX_EPOCH,
        policy: &policy,
    })
    .err();
    assert_eq!(
        error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::InvalidCertificate)
    );
}

#[test]
fn wrprc_receipt_binds_authenticated_representation_and_local_issuance_state(
) -> Result<(), RegistrationError> {
    let payload = include_bytes!("vectors/valid-wrprc-payload.json");
    let binding = RegistrationCertificateBinding::try_new(
        "NTRCH-123",
        "service-1",
        "age-check",
        None,
        ArtifactDigest::sha256(b"https://registry.example/entry/123"),
        ArtifactDigest::sha256(b"reviewed-registration-snapshot"),
    )?;
    let binding_digest = binding.digest()?;
    let (signer_certificate, private_key) = proof_signing_identity()?;
    let compact_jades = sign_wrprc_jades(payload, &signer_certificate, &private_key)?;
    let jades_policy = RegistrationCertificateJadesPolicy::default();
    let jades_result = authenticate_wrprc_jades(RegistrationCertificateJadesAuthenticationInput {
        compact_jws: &compact_jades,
        expected_signer_certificate_der: &signer_certificate,
        binding_digest,
        evaluation_time: time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(150),
        policy: &jades_policy,
    });
    assert_eq!(
        jades_result
            .as_ref()
            .err()
            .copied()
            .map(RegistrationError::reason),
        None
    );
    let jades_proof = jades_result?;
    let cose_sign1 = sign_wrprc_cose(payload, &signer_certificate, &private_key)?;
    let cose_result =
        authenticate_wrprc_cose_sign1(RegistrationCertificateCoseAuthenticationInput {
            cose_sign1: &cose_sign1,
            expected_signer_certificate_der: &signer_certificate,
            binding_digest,
            allowed_algorithms: &[RegistrationCertificateCoseAlgorithm::Es256],
        });
    assert_eq!(
        cose_result
            .as_ref()
            .err()
            .copied()
            .map(RegistrationError::reason),
        None
    );
    let cose_proof = cose_result?;
    let mut tagged_cose = Vec::new();
    tagged_cose
        .try_reserve_exact(
            cose_sign1
                .len()
                .checked_add(1)
                .ok_or(RegistrationError::Invalid(
                    RegistrationErrorReason::CapacityUnavailable,
                ))?,
        )
        .map_err(|_error| {
            RegistrationError::Invalid(RegistrationErrorReason::CapacityUnavailable)
        })?;
    tagged_cose.push(0xd2);
    tagged_cose.extend_from_slice(&cose_sign1);
    let tagged_result =
        authenticate_wrprc_cose_sign1(RegistrationCertificateCoseAuthenticationInput {
            cose_sign1: &tagged_cose,
            expected_signer_certificate_der: &signer_certificate,
            binding_digest,
            allowed_algorithms: &[RegistrationCertificateCoseAlgorithm::Es256],
        });
    assert_eq!(
        tagged_result
            .as_ref()
            .err()
            .copied()
            .map(RegistrationError::reason),
        None
    );
    drop(tagged_result?);
    let unprotected_chain_cose = sign_wrprc_cose_profile(
        payload,
        &signer_certificate,
        &private_key,
        "rc-wrp+cwt",
        TestX5ChainPlacement::Unprotected,
        TestCoseAlgorithm::Es256,
    )?;
    drop(authenticate_wrprc_cose_sign1(
        RegistrationCertificateCoseAuthenticationInput {
            cose_sign1: &unprotected_chain_cose,
            expected_signer_certificate_der: &signer_certificate,
            binding_digest,
            allowed_algorithms: &[RegistrationCertificateCoseAlgorithm::Es256],
        },
    )?);
    let (ed25519_certificate, ed25519_private_key) = proof_ed25519_signing_identity()?;
    let ed25519_jades =
        sign_wrprc_jades_ed25519(payload, &ed25519_certificate, &ed25519_private_key)?;
    let ed25519_jades_result =
        authenticate_wrprc_jades(RegistrationCertificateJadesAuthenticationInput {
            compact_jws: &ed25519_jades,
            expected_signer_certificate_der: &ed25519_certificate,
            binding_digest,
            evaluation_time: time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(150),
            policy: &jades_policy,
        });
    assert_eq!(
        ed25519_jades_result
            .as_ref()
            .err()
            .copied()
            .map(RegistrationError::reason),
        None
    );
    drop(ed25519_jades_result?);
    let ed25519_cose =
        sign_wrprc_cose_ed25519(payload, &ed25519_certificate, &ed25519_private_key)?;
    let ed25519_result =
        authenticate_wrprc_cose_sign1(RegistrationCertificateCoseAuthenticationInput {
            cose_sign1: &ed25519_cose,
            expected_signer_certificate_der: &ed25519_certificate,
            binding_digest,
            allowed_algorithms: &[RegistrationCertificateCoseAlgorithm::Ed25519],
        });
    assert_eq!(
        ed25519_result
            .as_ref()
            .err()
            .copied()
            .map(RegistrationError::reason),
        None
    );
    drop(ed25519_result?);
    let authenticated =
        authenticate_registration_certificate(vec![jades_proof, cose_proof], binding)?;
    assert_eq!(authenticated.representations().len(), 2);
    assert_eq!(authenticated.parsed().relying_party_id(), "NTRCH-123");
    assert_eq!(authenticated.binding().service_id(), "service-1");
    assert_eq!(authenticated.binding().intended_use_id(), "age-check");
    Ok(())
}

#[test]
fn wrprc_proof_verifiers_reject_tampering_wrong_leaf_and_algorithm_substitution(
) -> Result<(), RegistrationError> {
    let payload = include_bytes!("vectors/valid-wrprc-payload.json");
    let (certificate, private_key) = proof_signing_identity()?;
    let (wrong_certificate, _wrong_private_key) = proof_signing_identity()?;
    let compact = sign_wrprc_jades(payload, &certificate, &private_key)?;
    let policy = RegistrationCertificateJadesPolicy::default();

    let wrong_type_compact =
        sign_wrprc_jades_with_type(payload, &certificate, &private_key, "JWT")?;
    let wrong_jades_type =
        authenticate_wrprc_jades(RegistrationCertificateJadesAuthenticationInput {
            compact_jws: &wrong_type_compact,
            expected_signer_certificate_der: &certificate,
            binding_digest: ArtifactDigest::from_bytes([7_u8; 32]),
            evaluation_time: time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(150),
            policy: &policy,
        })
        .err();
    assert_eq!(
        wrong_jades_type.map(RegistrationError::reason),
        Some(RegistrationErrorReason::UnsupportedProfile)
    );

    let missing_x5c_compact = sign_wrprc_jades_without_x5c(payload, &certificate, &private_key)?;
    let missing_jades_chain =
        authenticate_wrprc_jades(RegistrationCertificateJadesAuthenticationInput {
            compact_jws: &missing_x5c_compact,
            expected_signer_certificate_der: &certificate,
            binding_digest: ArtifactDigest::from_bytes([7_u8; 32]),
            evaluation_time: time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(150),
            policy: &policy,
        })
        .err();
    assert_eq!(
        missing_jades_chain.map(RegistrationError::reason),
        Some(RegistrationErrorReason::MissingSignerCertificate)
    );

    let mut tampered_compact = compact.clone();
    let last = tampered_compact
        .last_mut()
        .ok_or(RegistrationError::Invalid(
            RegistrationErrorReason::InvalidCompactJws,
        ))?;
    *last = if *last == b'A' { b'B' } else { b'A' };
    let tampered_jades =
        authenticate_wrprc_jades(RegistrationCertificateJadesAuthenticationInput {
            compact_jws: &tampered_compact,
            expected_signer_certificate_der: &certificate,
            binding_digest: ArtifactDigest::from_bytes([7_u8; 32]),
            evaluation_time: time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(150),
            policy: &policy,
        })
        .err();
    assert_eq!(
        tampered_jades.map(RegistrationError::reason),
        Some(RegistrationErrorReason::SignatureVerificationFailed)
    );

    let wrong_leaf = authenticate_wrprc_jades(RegistrationCertificateJadesAuthenticationInput {
        compact_jws: &compact,
        expected_signer_certificate_der: &wrong_certificate,
        binding_digest: ArtifactDigest::from_bytes([7_u8; 32]),
        evaluation_time: time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(150),
        policy: &policy,
    })
    .err();
    assert!(matches!(
        wrong_leaf.map(RegistrationError::reason),
        Some(
            RegistrationErrorReason::AuthenticationReceiptMismatch
                | RegistrationErrorReason::SignatureVerificationFailed
        )
    ));

    let cose = sign_wrprc_cose(payload, &certificate, &private_key)?;
    let wrong_cose_leaf =
        authenticate_wrprc_cose_sign1(RegistrationCertificateCoseAuthenticationInput {
            cose_sign1: &cose,
            expected_signer_certificate_der: &wrong_certificate,
            binding_digest: ArtifactDigest::from_bytes([7_u8; 32]),
            allowed_algorithms: &[RegistrationCertificateCoseAlgorithm::Es256],
        })
        .err();
    assert_eq!(
        wrong_cose_leaf.map(RegistrationError::reason),
        Some(RegistrationErrorReason::AuthenticationReceiptMismatch)
    );

    let wrong_type_cose = sign_wrprc_cose_profile(
        payload,
        &certificate,
        &private_key,
        "CWT",
        TestX5ChainPlacement::Protected,
        TestCoseAlgorithm::Es256,
    )?;
    let wrong_cose_type =
        authenticate_wrprc_cose_sign1(RegistrationCertificateCoseAuthenticationInput {
            cose_sign1: &wrong_type_cose,
            expected_signer_certificate_der: &certificate,
            binding_digest: ArtifactDigest::from_bytes([7_u8; 32]),
            allowed_algorithms: &[RegistrationCertificateCoseAlgorithm::Es256],
        })
        .err();
    assert_eq!(
        wrong_cose_type.map(RegistrationError::reason),
        Some(RegistrationErrorReason::UnsupportedProfile)
    );

    let missing_chain_cose = sign_wrprc_cose_profile(
        payload,
        &certificate,
        &private_key,
        "rc-wrp+cwt",
        TestX5ChainPlacement::Missing,
        TestCoseAlgorithm::Es256,
    )?;
    let missing_cose_chain =
        authenticate_wrprc_cose_sign1(RegistrationCertificateCoseAuthenticationInput {
            cose_sign1: &missing_chain_cose,
            expected_signer_certificate_der: &certificate,
            binding_digest: ArtifactDigest::from_bytes([7_u8; 32]),
            allowed_algorithms: &[RegistrationCertificateCoseAlgorithm::Es256],
        })
        .err();
    assert_eq!(
        missing_cose_chain.map(RegistrationError::reason),
        Some(RegistrationErrorReason::MissingSignerCertificate)
    );

    let disallowed =
        authenticate_wrprc_cose_sign1(RegistrationCertificateCoseAuthenticationInput {
            cose_sign1: &cose,
            expected_signer_certificate_der: &certificate,
            binding_digest: ArtifactDigest::from_bytes([7_u8; 32]),
            allowed_algorithms: &[RegistrationCertificateCoseAlgorithm::Ed25519],
        })
        .err();
    assert_eq!(
        disallowed.map(RegistrationError::reason),
        Some(RegistrationErrorReason::UnsupportedProfile)
    );

    for invalid_allowlist in [
        &[][..],
        &[
            RegistrationCertificateCoseAlgorithm::Es256,
            RegistrationCertificateCoseAlgorithm::Es256,
        ][..],
    ] {
        let invalid_policy =
            authenticate_wrprc_cose_sign1(RegistrationCertificateCoseAuthenticationInput {
                cose_sign1: &cose,
                expected_signer_certificate_der: &certificate,
                binding_digest: ArtifactDigest::from_bytes([7_u8; 32]),
                allowed_algorithms: invalid_allowlist,
            })
            .err();
        assert_eq!(
            invalid_policy.map(RegistrationError::reason),
            Some(RegistrationErrorReason::UnsupportedProfile)
        );
    }

    let mut trailing_cose = cose.to_vec();
    trailing_cose.push(0);
    let mut unexpected_tag_cose = Vec::new();
    unexpected_tag_cose.push(0xd1);
    unexpected_tag_cose.extend_from_slice(&cose);
    let mut noncanonical_cose = Vec::new();
    noncanonical_cose.extend_from_slice(&[0x98, 0x04]);
    noncanonical_cose.extend_from_slice(&cose[1..]);
    for malformed in [&trailing_cose, &unexpected_tag_cose, &noncanonical_cose] {
        let malformed_error =
            authenticate_wrprc_cose_sign1(RegistrationCertificateCoseAuthenticationInput {
                cose_sign1: malformed,
                expected_signer_certificate_der: &certificate,
                binding_digest: ArtifactDigest::from_bytes([7_u8; 32]),
                allowed_algorithms: &[RegistrationCertificateCoseAlgorithm::Es256],
            })
            .err();
        assert_eq!(
            malformed_error.map(RegistrationError::reason),
            Some(RegistrationErrorReason::InvalidField)
        );
    }

    let oversized_cose = vec![0_u8; 2 * 1_024 * 1_024 + 1];
    let oversized_error =
        authenticate_wrprc_cose_sign1(RegistrationCertificateCoseAuthenticationInput {
            cose_sign1: &oversized_cose,
            expected_signer_certificate_der: &certificate,
            binding_digest: ArtifactDigest::from_bytes([7_u8; 32]),
            allowed_algorithms: &[RegistrationCertificateCoseAlgorithm::Es256],
        })
        .err();
    assert_eq!(
        oversized_error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::InputTooLarge)
    );

    let mut tampered = cose.to_vec();
    let last = tampered.last_mut().ok_or(RegistrationError::Invalid(
        RegistrationErrorReason::InvalidField,
    ))?;
    *last ^= 1;
    let tampered_error =
        authenticate_wrprc_cose_sign1(RegistrationCertificateCoseAuthenticationInput {
            cose_sign1: &tampered,
            expected_signer_certificate_der: &certificate,
            binding_digest: ArtifactDigest::from_bytes([7_u8; 32]),
            allowed_algorithms: &[RegistrationCertificateCoseAlgorithm::Es256],
        })
        .err();
    assert_eq!(
        tampered_error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::SignatureVerificationFailed)
    );
    Ok(())
}
