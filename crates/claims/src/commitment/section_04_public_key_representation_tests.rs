// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

    use super::{
        certificate_subject_public_key_info, validate_public_key_ref,
        validate_public_key_representation, CredentialAlgorithm, KeyAssurance, KeyReference,
        PublicKeyRef, PublicKeyRepresentation, RawPublicKeySerialization,
    };
    use reallyme_codec::base64::base64_to_bytes;
    use reallyme_cose::{
        cose_key_from_private_bytes, cose_key_from_public_bytes, cose_key_to_vec, Algorithm,
    };
    use reallyme_crypto::dispatch::generate_keypair;

    const ED25519_PUBLIC_JWK: &[u8] =
        br#"{"kty":"OKP","crv":"Ed25519","x":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}"#;
    const ED25519_PUBLIC_JWK_WITH_POLICY: &[u8] =
        br#"{"kty":"OKP","crv":"Ed25519","x":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","alg":"EdDSA","use":"sig","key_ops":["verify"]}"#;
    const ED25519_PRIVATE_JWK: &[u8] = br#"{"kty":"OKP","crv":"Ed25519","x":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","d":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"}"#;
    const P256_CERTIFICATE_DER_BASE64: &str = "MIIBnDCCAUGgAwIBAgIUHstvLWZAfP1dCyMfk9cf9nvPlj0wCgYIKoZIzj0EAwIwIzEhMB8GA1UEAwwYUmVhbGx5TWUgQ3JlZGVudGlhbCBUZXN0MB4XDTI2MDkxNDAxNDIzNFoXDTM2MDkxMTAxNDIzNFowIzEhMB8GA1UEAwwYUmVhbGx5TWUgQ3JlZGVudGlhbCBUZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh/SHT3HbaNx+yYl7xZWFeVHiNIsaD6UKp0CqKxUumSUMeDJMnRvXdMI+crBu+4jKBGXEbetjaETVXXddCg+C0KNTMFEwHQYDVR0OBBYEFOJff9WjvL5fmtCxmv1g++4bMt7CMB8GA1UdIwQYMBaAFOJff9WjvL5fmtCxmv1g++4bMt7CMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhALr9eh/oRwRIl3N9KVADHhuUVGH8DRR8neWJG5bB2G8yAiEAy8Flw2k5LB++moO9pX+mT8nn5TCnbTkJPfaeX+EHvJM=";

    #[test]
    fn public_jwk_is_accepted_and_private_jwk_is_rejected() {
        assert!(validate_public_key_representation(
            CredentialAlgorithm::Ed25519,
            &PublicKeyRepresentation::JwkJson(ED25519_PUBLIC_JWK.to_vec()),
        )
        .is_ok());
        assert!(validate_public_key_representation(
            CredentialAlgorithm::Ed25519,
            &PublicKeyRepresentation::JwkJson(ED25519_PRIVATE_JWK.to_vec()),
        )
        .is_err());
    }

    #[test]
    fn jwk_policy_members_are_consistent_and_duplicate_members_fail_closed() {
        assert!(validate_public_key_representation(
            CredentialAlgorithm::Ed25519,
            &PublicKeyRepresentation::JwkJson(ED25519_PUBLIC_JWK_WITH_POLICY.to_vec()),
        )
        .is_ok());

        for invalid in [
            br#"{"kty":"OKP","kty":"OKP","crv":"Ed25519","x":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}"#.as_slice(),
            br#"{"kty":"OKP","crv":"Ed25519","x":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","alg":"ES256"}"#.as_slice(),
            br#"{"kty":"OKP","crv":"Ed25519","x":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","use":"enc"}"#.as_slice(),
            br#"{"kty":"OKP","crv":"Ed25519","x":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","key_ops":["sign"]}"#.as_slice(),
            br#"{"kty":"OKP","crv":"Ed25519","x":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","key_ops":["verify","verify"]}"#.as_slice(),
            br#"{"kty":"oct","k":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}"#.as_slice(),
            br#"{"kty":"OKP","crv":"Ed25519","x":"Bw"}"#.as_slice(),
        ] {
            assert!(validate_public_key_representation(
                CredentialAlgorithm::Ed25519,
                &PublicKeyRepresentation::JwkJson(invalid.to_vec()),
            )
            .is_err());
        }
    }

    #[test]
    fn jwk_resource_limits_reject_oversized_and_nested_extension_input() {
        let oversized = vec![b' '; super::MAX_PUBLIC_KEY_MATERIAL_BYTES + 1];
        assert!(validate_public_key_representation(
            CredentialAlgorithm::Ed25519,
            &PublicKeyRepresentation::JwkJson(oversized),
        )
        .is_err());

        let nested = format!(
            "{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\",\"x-extra\":{}{}}}",
            "[".repeat(40),
            "]".repeat(40),
        );
        assert!(validate_public_key_representation(
            CredentialAlgorithm::Ed25519,
            &PublicKeyRepresentation::JwkJson(nested.into_bytes()),
        )
        .is_err());
    }

    #[test]
    fn public_cose_key_is_accepted_and_private_cose_key_is_rejected() {
        let (public_key, private_key) =
            generate_keypair(Algorithm::Ed25519).expect("test key generation must succeed");
        let public_cose = cose_key_from_public_bytes(Algorithm::Ed25519, &public_key)
            .and_then(|key| cose_key_to_vec(&key))
            .expect("test public COSE_Key construction must succeed");
        let private_cose =
            cose_key_from_private_bytes(Algorithm::Ed25519, &private_key, Some(&public_key))
                .and_then(|key| cose_key_to_vec(&key))
                .expect("test private COSE_Key construction must succeed");

        assert!(validate_public_key_representation(
            CredentialAlgorithm::Ed25519,
            &PublicKeyRepresentation::CoseKey(public_cose.to_vec()),
        )
        .is_ok());
        assert!(validate_public_key_representation(
            CredentialAlgorithm::Ed25519,
            &PublicKeyRepresentation::CoseKey(private_cose.to_vec()),
        )
        .is_err());
    }

    #[test]
    fn cose_key_rejects_duplicate_labels_policy_mismatches_and_wrong_lengths() {
        let (public_key, _private_key) =
            generate_keypair(Algorithm::Ed25519).expect("test key generation must succeed");
        let mut valid_with_verify = vec![
            0xa5, 0x01, 0x01, 0x03, 0x32, 0x04, 0x81, 0x02, 0x20, 0x06, 0x21, 0x58,
            0x20,
        ];
        valid_with_verify.extend_from_slice(&public_key);
        assert!(validate_public_key_representation(
            CredentialAlgorithm::Ed25519,
            &PublicKeyRepresentation::CoseKey(valid_with_verify),
        )
        .is_ok());

        let mut duplicate_label = vec![
            0xa5, 0x01, 0x01, 0x01, 0x01, 0x03, 0x32, 0x20, 0x06, 0x21, 0x58, 0x20,
        ];
        duplicate_label.extend_from_slice(&public_key);

        let mut signing_operation_without_private_key = vec![
            0xa5, 0x01, 0x01, 0x03, 0x32, 0x04, 0x81, 0x01, 0x20, 0x06, 0x21, 0x58,
            0x20,
        ];
        signing_operation_without_private_key.extend_from_slice(&public_key);

        let mut wrong_algorithm = vec![
            0xa4, 0x01, 0x01, 0x03, 0x26, 0x20, 0x06, 0x21, 0x58, 0x20,
        ];
        wrong_algorithm.extend_from_slice(&public_key);

        let mut wrong_curve = vec![
            0xa4, 0x01, 0x01, 0x03, 0x32, 0x20, 0x04, 0x21, 0x58, 0x20,
        ];
        wrong_curve.extend_from_slice(&public_key);

        let mut wrong_length = vec![
            0xa4, 0x01, 0x01, 0x03, 0x32, 0x20, 0x06, 0x21, 0x58, 0x1f,
        ];
        wrong_length.extend_from_slice(&public_key[..31]);

        for invalid in [
            duplicate_label,
            signing_operation_without_private_key,
            wrong_algorithm,
            wrong_curve,
            wrong_length,
        ] {
            assert!(validate_public_key_representation(
                CredentialAlgorithm::Ed25519,
                &PublicKeyRepresentation::CoseKey(invalid),
            )
            .is_err());
        }
    }

    #[test]
    fn cose_key_resource_limits_reject_oversized_and_deeply_nested_input() {
        let oversized = vec![0_u8; super::MAX_PUBLIC_KEY_MATERIAL_BYTES + 1];
        assert!(validate_public_key_representation(
            CredentialAlgorithm::Ed25519,
            &PublicKeyRepresentation::CoseKey(oversized),
        )
        .is_err());

        let mut nested = vec![0xa5, 0x01, 0x01, 0x03, 0x32, 0x18, 0x63];
        nested.extend(core::iter::repeat_n(0x81, 40));
        nested.push(0x00);
        nested.extend_from_slice(&[0x20, 0x06, 0x21, 0x58, 0x20]);
        nested.extend_from_slice(&[7_u8; 32]);
        assert!(validate_public_key_representation(
            CredentialAlgorithm::Ed25519,
            &PublicKeyRepresentation::CoseKey(nested),
        )
        .is_err());
    }

    #[test]
    fn x509_reference_requires_the_declared_algorithm_and_same_public_key() {
        let certificate_der =
            base64_to_bytes(P256_CERTIFICATE_DER_BASE64).expect("test certificate must decode");
        let certificate_key = certificate_subject_public_key_info(&certificate_der)
            .expect("test certificate must contain a supported public key");
        let valid = PublicKeyRef {
            alg: CredentialAlgorithm::P256,
            reference: KeyReference::X509Certificate(certificate_der.clone()),
            public_key: PublicKeyRepresentation::Raw {
                serialization: RawPublicKeySerialization::Sec1Uncompressed,
                bytes: certificate_key.public_key.clone(),
            },
            assurance: KeyAssurance::None,
        };
        assert!(validate_public_key_ref(&valid).is_ok());

        let mut wrong_key = certificate_key.public_key;
        wrong_key[1] ^= 0x01;
        let mismatched = PublicKeyRef {
            alg: CredentialAlgorithm::P256,
            reference: KeyReference::X509Certificate(certificate_der.clone()),
            public_key: PublicKeyRepresentation::Raw {
                serialization: RawPublicKeySerialization::Sec1Uncompressed,
                bytes: wrong_key,
            },
            assurance: KeyAssurance::None,
        };
        assert!(validate_public_key_ref(&mismatched).is_err());

        let wrong_algorithm = PublicKeyRef {
            alg: CredentialAlgorithm::Secp256k1,
            reference: KeyReference::X509Certificate(certificate_der),
            public_key: valid.public_key.clone(),
            assurance: KeyAssurance::None,
        };
        assert!(validate_public_key_ref(&wrong_algorithm).is_err());
    }
