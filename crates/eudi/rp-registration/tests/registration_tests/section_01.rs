// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_eudi_rp_registration::{
    authenticate_access_certificate_association, authenticate_registry_record,
    parse_registration_certificate, prepare_registration_document, AccessCertificateBinding,
    ArtifactDigest, AuthenticatedJws, CredentialMetadata, ProtocolProfile,
    RegistrationCertificatePolicy, RegistrationError, RegistrationErrorReason,
    RegistryAuthenticationInput, RegistryIntendedUseQuery, RegistryJwsVerifier, RegistryMetadata,
    RegistryPayload, RegistryPayloadShape, ValidatedJwks, WalletRelyingParty, WrpEntitlement,
};

const WRP: &str = include_str!("../vectors/valid-ts5-wrp.json");
const ALTERNATE_CERTIFICATE_B64: &str =
    include_str!("../../../../trust/x509/tests/fixtures/qwac_server_auth_cert.der.b64");
const P256_PUBLIC_X: &str = "zovuXfZo2sBrLwEy_9yuyzmsnqAmSz9e7kMWaPUtlPU";
const P256_PUBLIC_Y: &str = "y_n6M-ozBp7M4eq5rAx52ghP-a8dgbtXMkQCNRGgvHE";
const P256_LEAF_CERTIFICATE_B64: &str = "MIIB6jCCAZGgAwIBAgIUcE7RmpSme/eHZaGfCzWjNjtsiHYwCgYIKoZIzj0EAwIwQzELMAkGA1UEBhMCQ0gxFjAUBgNVBAoMDVJlYWxseU1lIFRlc3QxHDAaBgNVBAMME1JlZ2lzdHJhciBUZXN0IFJvb3QwHhcNMjYwOTE3MDMwMzAzWhcNMzYwOTE0MDMwMzAzWjBGMQswCQYDVQQGEwJDSDEWMBQGA1UECgwNUmVhbGx5TWUgVGVzdDEfMB0GA1UEAwwWUmVnaXN0cmFyIFNpZ25pbmcgTGVhZjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABM6L7l32aNrAay8BMv/crss5rJ6gJks/Xu5DFmj1LZT1y/n6M+ozBp7M4eq5rAx52ghP+a8dgbtXMkQCNRGgvHGjYDBeMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBQQ5eNWwS359uWZOUcjTI/BCZXTETAfBgNVHSMEGDAWgBS7GhUOGTtG3XD7Dp/zpjQWZO9nSTAKBggqhkjOPQQDAgNHADBEAiBjp76nIMdHH4LUSJYoi9yO0eglrwAqE4TgPpCMhsV9jwIgfASVYeMgtDM4sTYyPZpiOfKI6umX7hVL9mMdV91Kpzs=";
const P256_ROOT_CERTIFICATE_B64: &str = "MIIB6zCCAZGgAwIBAgIUemVPne1k4/3qcrcjMcNx6D62RrEwCgYIKoZIzj0EAwIwQzELMAkGA1UEBhMCQ0gxFjAUBgNVBAoMDVJlYWxseU1lIFRlc3QxHDAaBgNVBAMME1JlZ2lzdHJhciBUZXN0IFJvb3QwHhcNMjYwOTE3MDMwMjU0WhcNMzYwOTE0MDMwMjU0WjBDMQswCQYDVQQGEwJDSDEWMBQGA1UECgwNUmVhbGx5TWUgVGVzdDEcMBoGA1UEAwwTUmVnaXN0cmFyIFRlc3QgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJV8XcdAPnFxP4zSDH+eUVmzhSCeJ5vjQC6BnuDMbnkAzoZgoHelrqt3yvkSz1h/xHJyEExBba88G9v1pSscXx+jYzBhMB8GA1UdIwQYMBaAFLsaFQ4ZO0bdcPsOn/OmNBZk72dJMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBS7GhUOGTtG3XD7Dp/zpjQWZO9nSTAKBggqhkjOPQQDAgNIADBFAiBktIl2JNdRgnUXFzZnQAVY3Yj6sjpjt0jL5sqa3nfFOAIhAJy9JRFFD24q9UdeYxKbIW9/ftuTygrDFzYSREE5Xp4Y";

/// Signed `iat` used by the current-envelope fixtures.
const FIXTURE_ISSUED_AT: i64 = 42;
/// Freshness bound applied by the fixtures, in seconds.
const MAX_RESPONSE_AGE_SECONDS: u64 = 300;

fn evaluation_time() -> time::OffsetDateTime {
    time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(FIXTURE_ISSUED_AT + 10)
}

struct AcceptingVerifier;

impl RegistryJwsVerifier for AcceptingVerifier {
    fn verify(
        &self,
        compact_jws: &[u8],
        _jwks: &ValidatedJwks,
    ) -> Result<AuthenticatedJws, RegistrationError> {
        let encoded =
            compact_jws
                .split(|byte| *byte == b'.')
                .nth(1)
                .ok_or(RegistrationError::Invalid(
                    RegistrationErrorReason::InvalidCompactJws,
                ))?;
        let payload =
            reallyme_codec::base64url::base64url_bytes_to_bytes(encoded).map_err(|_error| {
                RegistrationError::Invalid(RegistrationErrorReason::InvalidCompactJws)
            })?;
        AuthenticatedJws::try_new(compact_jws, &payload, signer_certificate_chain()?)
    }
}

struct ChainVerifier {
    certificates_der: Vec<Vec<u8>>,
}

impl RegistryJwsVerifier for ChainVerifier {
    fn verify(
        &self,
        compact_jws: &[u8],
        _jwks: &ValidatedJwks,
    ) -> Result<AuthenticatedJws, RegistrationError> {
        let encoded =
            compact_jws
                .split(|byte| *byte == b'.')
                .nth(1)
                .ok_or(RegistrationError::Invalid(
                    RegistrationErrorReason::InvalidCompactJws,
                ))?;
        let payload =
            reallyme_codec::base64url::base64url_bytes_to_bytes(encoded).map_err(|_error| {
                RegistrationError::Invalid(RegistrationErrorReason::InvalidCompactJws)
            })?;
        AuthenticatedJws::try_new(compact_jws, &payload, self.certificates_der.clone())
    }
}

#[test]
fn current_array_preserves_pagination_and_current_intended_use_fields(
) -> Result<(), RegistrationError> {
    let payload = format!(
        r#"{{"iss":"registry-1","iat":42,"data":[{WRP}],"pagination":{{"next_cursor":"cursor-2","has_next_page":true}}}}"#
    );
    let compact = compact(payload.as_bytes());
    let jwks = jwks()?;
    let authenticated = authenticate_registry_record(
        RegistryAuthenticationInput {
            profile: ProtocolProfile::Ts5V1_5,
            payload_shape: RegistryPayloadShape::Ts5SignedWrpArray,
            compact_jws: &compact,
            jwks: &jwks,
            evaluation_time: evaluation_time(),
            max_response_age_seconds: MAX_RESPONSE_AGE_SECONDS,
            expected_intended_use: None,
        },
        &AcceptingVerifier,
    )?;
    let RegistryPayload::WrpArray {
        records,
        pagination,
    } = authenticated.payload()
    else {
        return Err(RegistrationError::Invalid(
            RegistrationErrorReason::PayloadShapeMismatch,
        ));
    };
    assert_eq!(records.len(), 1);
    let service = &records[0].services()[0];
    let intended_use = &service.intended_uses()[0];
    assert_eq!(intended_use.created_at(), Some("2026-09-17T00:00:00Z"));
    assert_eq!(intended_use.purpose()[0].content(), "Verify age");
    assert_eq!(
        intended_use.privacy_policy()[0].policy_uri(),
        "https://rp.example/privacy"
    );
    assert_eq!(service.entitlements(), &[WrpEntitlement::ServiceProvider]);
    assert!(matches!(
        intended_use.credentials()[0].metadata(),
        CredentialMetadata::DcSdJwt(metadata)
            if metadata.vct_values()[0].expose() == "urn:example:pid"
    ));
    assert_eq!(
        pagination.as_ref().and_then(|value| value.next_cursor()),
        Some("cursor-2")
    );
    assert!(pagination
        .as_ref()
        .is_some_and(|value| value.has_next_page()));
    Ok(())
}

#[test]
fn duplicate_entitlements_are_rejected() {
    let duplicated = WRP.replace(
        r#""entitlements": ["https://uri.etsi.org/19475/Entitlement/Service_Provider"]"#,
        r#""entitlements": ["https://uri.etsi.org/19475/Entitlement/Service_Provider", "https://uri.etsi.org/19475/Entitlement/Service_Provider"]"#,
    );
    assert_eq!(
        WalletRelyingParty::from_json(duplicated.as_bytes())
            .err()
            .map(RegistrationError::reason),
        Some(RegistrationErrorReason::InvalidField)
    );
}

#[test]
fn intended_use_timestamps_are_parsed_and_ordered() {
    let malformed = WRP.replace("2026-09-17T00:00:00Z", "not-a-time");
    assert_eq!(
        WalletRelyingParty::from_json(malformed.as_bytes())
            .err()
            .map(RegistrationError::reason),
        Some(RegistrationErrorReason::InvalidValidityInterval)
    );

    let reversed = WRP.replace(
        r#""createdAt": "2026-09-17T00:00:00Z""#,
        r#""createdAt": "2026-09-17T00:00:00Z", "revokedAt": "2026-09-16T00:00:00Z""#,
    );
    assert_eq!(
        WalletRelyingParty::from_json(reversed.as_bytes())
            .err()
            .map(RegistrationError::reason),
        Some(RegistrationErrorReason::InvalidValidityInterval)
    );
}

fn jwks() -> Result<ValidatedJwks, RegistrationError> {
    jwks_with_x5c(&[P256_LEAF_CERTIFICATE_B64, P256_ROOT_CERTIFICATE_B64])
}

fn jwks_with_x5c(certificates: &[&str]) -> Result<ValidatedJwks, RegistrationError> {
    let x5c = certificates
        .iter()
        .map(|value| format!(r#""{}""#, value.trim()))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!(
        r#"{{"keys":[{{"kty":"EC","crv":"P-256","x":"{P256_PUBLIC_X}","y":"{P256_PUBLIC_Y}","alg":"ES256","use":"sig","key_ops":["verify"],"kid":"registrar-key-1","x5c":[{x5c}]}}]}}"#
    );
    ValidatedJwks::try_new(
        "https://registry.example/jwks",
        "https://registry.example/jwks",
        1,
        "application/jwk-set+json; charset=utf-8",
        body.as_bytes(),
    )
}

fn wrpac_leaf() -> Result<Vec<u8>, RegistrationError> {
    reallyme_codec::base64::base64_to_bytes(include_str!("../vectors/wrpac-ncp-legal.der.b64").trim())
        .map_err(|_error| RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate))
}

fn signer_certificate() -> Result<Vec<u8>, RegistrationError> {
    reallyme_codec::base64::base64_to_bytes(P256_LEAF_CERTIFICATE_B64)
        .map_err(|_error| RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate))
}

fn root_certificate() -> Result<Vec<u8>, RegistrationError> {
    reallyme_codec::base64::base64_to_bytes(P256_ROOT_CERTIFICATE_B64)
        .map_err(|_error| RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate))
}

fn signer_certificate_chain() -> Result<Vec<Vec<u8>>, RegistrationError> {
    Ok(vec![signer_certificate()?, root_certificate()?])
}

fn alternate_certificate() -> Result<Vec<u8>, RegistrationError> {
    reallyme_codec::base64::base64_to_bytes(ALTERNATE_CERTIFICATE_B64.trim())
        .map_err(|_error| RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate))
}

fn compact(payload: &[u8]) -> Vec<u8> {
    let header = reallyme_codec::base64url::bytes_to_base64url(
        br#"{"alg":"ES256","kid":"registrar-key-1"}"#,
    );
    let payload = reallyme_codec::base64url::bytes_to_base64url(payload);
    format!("{header}.{payload}.c2ln").into_bytes()
}

#[test]
fn current_envelope_preserves_profile_and_metadata() -> Result<(), RegistrationError> {
    let payload = format!(r#"{{"iss":"registry-1","iat":42,"data":{WRP}}}"#);
    let compact = compact(payload.as_bytes());
    let jwks = jwks()?;
    let mut authenticated = authenticate_registry_record(
        RegistryAuthenticationInput {
            profile: ProtocolProfile::Ts5V1_5,
            payload_shape: RegistryPayloadShape::Ts5SignedWrp,
            compact_jws: &compact,
            jwks: &jwks,
            evaluation_time: evaluation_time(),
            max_response_age_seconds: MAX_RESPONSE_AGE_SECONDS,
            expected_intended_use: None,
        },
        &AcceptingVerifier,
    )?;
    assert_eq!(authenticated.profile(), ProtocolProfile::Ts5V1_5);
    assert!(matches!(
        authenticated.metadata(),
        RegistryMetadata::Current { issued_at: 42, .. }
    ));
    let expected_leaf = signer_certificate()?;
    let expected_root = root_certificate()?;
    assert_eq!(
        authenticated.signer_certificate_digest(),
        ArtifactDigest::sha256(&expected_leaf)
    );
    let chain = authenticated
        .take_signer_certificate_chain()
        .ok_or(RegistrationError::Invalid(
            RegistrationErrorReason::MissingSignerCertificate,
        ))?;
    assert_eq!(chain.len(), 2);
    assert_eq!(
        chain.leaf_certificate_digest(),
        ArtifactDigest::sha256(&expected_leaf)
    );
    let retained_der = chain.into_der_certificates();
    assert_eq!(retained_der.as_slice(), &[expected_leaf, expected_root]);
    assert!(authenticated.take_signer_certificate_chain().is_none());
    Ok(())
}

#[test]
fn authentication_receipt_must_preserve_the_exact_jwks_chain() -> Result<(), RegistrationError> {
    let payload = format!(r#"{{"iss":"registry-1","iat":42,"data":{WRP}}}"#);
    let compact = compact(payload.as_bytes());
    let leaf = signer_certificate()?;
    let root = root_certificate()?;
    let alternate = alternate_certificate()?;
    let jwks = jwks()?;

    let matching_verifier = ChainVerifier {
        certificates_der: vec![leaf.clone(), root.clone()],
    };
    let mut authenticated = authenticate_registry_record(
        RegistryAuthenticationInput {
            profile: ProtocolProfile::Ts5V1_5,
            payload_shape: RegistryPayloadShape::Ts5SignedWrp,
            compact_jws: &compact,
            jwks: &jwks,
            evaluation_time: evaluation_time(),
            max_response_age_seconds: MAX_RESPONSE_AGE_SECONDS,
            expected_intended_use: None,
        },
        &matching_verifier,
    )?;
    let retained =
        authenticated
            .take_signer_certificate_chain()
            .ok_or(RegistrationError::Invalid(
                RegistrationErrorReason::MissingSignerCertificate,
            ))?;
    let retained_der = retained.into_der_certificates();
    assert_eq!(retained_der.as_slice(), &[leaf.clone(), root.clone()]);

    for substituted_chain in [vec![leaf.clone()], vec![alternate]] {
        let verifier = ChainVerifier {
            certificates_der: substituted_chain,
        };
        let error = authenticate_registry_record(
            RegistryAuthenticationInput {
                profile: ProtocolProfile::Ts5V1_5,
                payload_shape: RegistryPayloadShape::Ts5SignedWrp,
                compact_jws: &compact,
                jwks: &jwks,
                evaluation_time: evaluation_time(),
                max_response_age_seconds: MAX_RESPONSE_AGE_SECONDS,
                expected_intended_use: None,
            },
            &verifier,
        )
        .err();
        assert_eq!(
            error.map(RegistrationError::reason),
            Some(RegistrationErrorReason::AuthenticationReceiptMismatch)
        );
    }

    let reordered_error =
        AuthenticatedJws::try_new(&compact, payload.as_bytes(), vec![root, leaf.clone()]).err();
    assert_eq!(
        reordered_error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::CertificateProfileMismatch)
    );
    let duplicate_error =
        AuthenticatedJws::try_new(&compact, payload.as_bytes(), vec![leaf.clone(), leaf]).err();
    assert_eq!(
        duplicate_error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::CertificateProfileMismatch)
    );
    Ok(())
}

#[test]
fn authentication_receipt_rejects_empty_and_oversized_chains() -> Result<(), RegistrationError> {
    let compact = compact(br#"{"iss":"registry-1","iat":42,"data":true}"#);
    let empty_error = AuthenticatedJws::try_new(&compact, b"{}", Vec::new()).err();
    assert_eq!(
        empty_error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::MissingSignerCertificate)
    );

    let certificate = signer_certificate()?;
    let oversized_count = vec![certificate; 11];
    let oversized_error = AuthenticatedJws::try_new(&compact, b"{}", oversized_count).err();
    assert_eq!(
        oversized_error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::ResourceLimitExceeded)
    );

    let oversized_der = vec![0_u8; 65_537];
    let oversized_der_error = AuthenticatedJws::try_new(&compact, b"{}", vec![oversized_der]).err();
    assert_eq!(
        oversized_der_error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::ResourceLimitExceeded)
    );

    let leaf = signer_certificate()?;
    for malformed_chain in [vec![leaf.clone(), Vec::new()], vec![leaf, vec![0x30, 0x00]]] {
        let malformed_error = AuthenticatedJws::try_new(&compact, b"{}", malformed_chain).err();
        assert_eq!(
            malformed_error.map(RegistrationError::reason),
            Some(RegistrationErrorReason::InvalidCertificate)
        );
    }
    Ok(())
}

#[test]
fn jwks_rejects_same_algorithm_certificate_key_substitution() -> Result<(), RegistrationError> {
    let payload = format!(r#"{{"iss":"registry-1","iat":42,"data":{WRP}}}"#);
    let compact = compact(payload.as_bytes());
    let substituted_jwks = jwks_with_x5c(&[P256_ROOT_CERTIFICATE_B64])?;
    let error = authenticate_registry_record(
        RegistryAuthenticationInput {
            profile: ProtocolProfile::Ts5V1_5,
            payload_shape: RegistryPayloadShape::Ts5SignedWrp,
            compact_jws: &compact,
            jwks: &substituted_jwks,
            evaluation_time: evaluation_time(),
            max_response_age_seconds: MAX_RESPONSE_AGE_SECONDS,
            expected_intended_use: None,
        },
        &AcceptingVerifier,
    )
    .err();
    assert_eq!(
        error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::AuthenticationReceiptMismatch)
    );
    Ok(())
}

#[test]
fn duplicate_member_is_rejected_before_semantic_parsing() {
    let duplicate = include_bytes!("../vectors/invalid-duplicate-ts5-wrp.json");
    let error = WalletRelyingParty::from_json(duplicate).err();
    assert_eq!(
        error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::DuplicateJsonMember)
    );
}

#[test]
fn oversized_and_recursively_nested_json_are_rejected_before_model_allocation() {
    let oversized = vec![b' '; (4 * 1_024 * 1_024) + 1];
    let oversized_error = WalletRelyingParty::from_json(&oversized).err();
    assert_eq!(
        oversized_error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::InputTooLarge)
    );

    let nested = format!("{}null{}", "[".repeat(25), "]".repeat(25));
    let nested_error = WalletRelyingParty::from_json(nested.as_bytes()).err();
    assert_eq!(
        nested_error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::ResourceLimitExceeded)
    );
}

#[test]
fn credential_format_cannot_be_substituted_across_metadata_profiles() {
    let substituted = WRP.replace(r#""format": "dc+sd-jwt""#, r#""format": "mso_mdoc""#);
    let error = WalletRelyingParty::from_json(substituted.as_bytes()).err();
    assert_eq!(
        error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::SemanticBindingMismatch)
    );
}

#[test]
fn service_requires_one_contact_channel_but_not_support_uri_specifically(
) -> Result<(), RegistrationError> {
    let without_support_uri = WRP.replace(
        "      \"supportURI\": \"https://rp.example/support\",\n",
        "",
    );
    let relying_party = WalletRelyingParty::from_json(without_support_uri.as_bytes())?;
    assert_eq!(relying_party.services()[0].support_uri(), None);
    assert_eq!(
        relying_party.services()[0].email(),
        Some("support@rp.example")
    );

    let without_contact =
        without_support_uri.replace("      \"email\": \"support@rp.example\",\n", "");
    let error = WalletRelyingParty::from_json(without_contact.as_bytes()).err();
    assert_eq!(
        error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::MissingField)
    );
    Ok(())
}

#[test]
fn entitlement_uris_and_attestation_provider_semantics_are_enforced() {
    const SERVICE_PROVIDER_URI: &str = "https://uri.etsi.org/19475/Entitlement/Service_Provider";
    const QEAA_PROVIDER_URI: &str = "https://uri.etsi.org/19475/Entitlement/QEAA_Provider";

    let short_label = WRP.replace(SERVICE_PROVIDER_URI, "Service_Provider");
    let short_label_error = WalletRelyingParty::from_json(short_label.as_bytes()).err();
    assert_eq!(
        short_label_error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::InvalidField)
    );

    let missing_provided_attestations = WRP.replace(SERVICE_PROVIDER_URI, QEAA_PROVIDER_URI);
    let missing_error =
        WalletRelyingParty::from_json(missing_provided_attestations.as_bytes()).err();
    assert_eq!(
        missing_error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::SemanticBindingMismatch)
    );
}

#[test]
fn incoherent_current_pagination_is_rejected() -> Result<(), RegistrationError> {
    let payload = format!(
        r#"{{"iss":"registry-1","iat":42,"data":[{WRP}],"pagination":{{"has_next_page":true}}}}"#
    );
    let compact = compact(payload.as_bytes());
    let jwks = jwks()?;
    let error = authenticate_registry_record(
        RegistryAuthenticationInput {
            profile: ProtocolProfile::Ts5V1_5,
            payload_shape: RegistryPayloadShape::Ts5SignedWrpArray,
            compact_jws: &compact,
            jwks: &jwks,
            evaluation_time: evaluation_time(),
            max_response_age_seconds: MAX_RESPONSE_AGE_SECONDS,
            expected_intended_use: None,
        },
        &AcceptingVerifier,
    )
    .err();
    assert_eq!(
        error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::SemanticBindingMismatch)
    );
    Ok(())
}

#[test]
fn profile_shape_downgrade_is_rejected() -> Result<(), RegistrationError> {
    let compact = compact(WRP.as_bytes());
    let jwks = jwks()?;
    let error = authenticate_registry_record(
        RegistryAuthenticationInput {
            profile: ProtocolProfile::Ts5V1_5,
            payload_shape: RegistryPayloadShape::LegacyRawWrp,
            compact_jws: &compact,
            jwks: &jwks,
            evaluation_time: evaluation_time(),
            max_response_age_seconds: MAX_RESPONSE_AGE_SECONDS,
            expected_intended_use: None,
        },
        &AcceptingVerifier,
    )
    .err();
    assert_eq!(
        error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::PayloadShapeMismatch)
    );
    Ok(())
}

#[test]
fn legacy_encoder_is_exactly_one_element_and_has_no_secret_field() -> Result<(), RegistrationError>
{
    let relying_party = WalletRelyingParty::from_json(WRP.as_bytes())?;
    let prepared = prepare_registration_document(
        ProtocolProfile::EuReferenceLegacyV0_2_2,
        "internal-rp-1",
        7,
        &relying_party,
    )?;
    let value: serde_json::Value = serde_json::from_slice(prepared.expose_encoded_document())
        .map_err(|_error| RegistrationError::Invalid(RegistrationErrorReason::InvalidJson))?;
    assert_eq!(value.as_array().map(Vec::len), Some(1));
    assert!(!prepared
        .expose_encoded_document()
        .windows(b"hash_pid".len())
        .any(|window| window == b"hash_pid"));
    Ok(())
}

#[test]
fn cross_origin_jwks_redirect_is_rejected() {
    let error = ValidatedJwks::try_new(
        "https://registry.example/jwks",
        "https://attacker.example/jwks",
        1,
        "application/json",
        br#"{"keys":[{"kty":"EC"}]}"#,
    )
    .err();
    assert_eq!(
        error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::SemanticBindingMismatch)
    );
}

fn authenticate_with(
    profile: ProtocolProfile,
    payload_shape: RegistryPayloadShape,
    payload: &[u8],
    evaluation_time: time::OffsetDateTime,
    max_response_age_seconds: u64,
    expected_intended_use: Option<RegistryIntendedUseQuery<'_>>,
) -> Result<(), RegistrationError> {
    let compact = compact(payload);
    let jwks = jwks()?;
    authenticate_registry_record(
        RegistryAuthenticationInput {
            profile,
            payload_shape,
            compact_jws: &compact,
            jwks: &jwks,
            evaluation_time,
            max_response_age_seconds,
            expected_intended_use,
        },
        &AcceptingVerifier,
    )
    .map(drop)
}

#[test]
fn stale_or_future_dated_registry_answer_is_rejected() -> Result<(), RegistrationError> {
    let payload = format!(
        r#"{{"iss":"registry-1","iat":{FIXTURE_ISSUED_AT},"data":{{"isRegistered":true}}}}"#
    );
    authenticate_with(
        ProtocolProfile::Ts5V1_5,
        RegistryPayloadShape::Ts5SignedIntendedUseCheck,
        payload.as_bytes(),
        evaluation_time(),
        MAX_RESPONSE_AGE_SECONDS,
        None,
    )?;
    let max_age = i64::try_from(MAX_RESPONSE_AGE_SECONDS)
        .map_err(|_error| RegistrationError::Invalid(RegistrationErrorReason::InvalidField))?;
    let stale =
        time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(FIXTURE_ISSUED_AT + max_age + 1);
    let future_payload =
        br#"{"iss":"registry-1","iat":100000,"data":{"isRegistered":true}}"#.as_slice();
    let future = time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(100_000 - 61);
    for (payload, at) in [(payload.as_bytes(), stale), (future_payload, future)] {
        let error = authenticate_with(
            ProtocolProfile::Ts5V1_5,
            RegistryPayloadShape::Ts5SignedIntendedUseCheck,
            payload,
            at,
            MAX_RESPONSE_AGE_SECONDS,
            None,
        )
        .err();
        assert_eq!(
            error.map(RegistrationError::reason),
            Some(RegistrationErrorReason::ResponseNotFresh)
        );
    }
    for invalid_max_age in [0, 86_401] {
        let error = authenticate_with(
            ProtocolProfile::Ts5V1_5,
            RegistryPayloadShape::Ts5SignedIntendedUseCheck,
            payload.as_bytes(),
            evaluation_time(),
            invalid_max_age,
            None,
        )
        .err();
        assert_eq!(
            error.map(RegistrationError::reason),
            Some(RegistrationErrorReason::InvalidField)
        );
    }
    Ok(())
}

#[test]
fn legacy_raw_boolean_answer_fails_closed() {
    for answer in [b"true".as_slice(), b"false".as_slice()] {
        let error = authenticate_with(
            ProtocolProfile::EuReferenceLegacyV0_2_2,
            RegistryPayloadShape::LegacyRawBoolean,
            answer,
            evaluation_time(),
            MAX_RESPONSE_AGE_SECONDS,
            None,
        )
        .err();
        assert_eq!(
            error.map(RegistrationError::reason),
            Some(RegistrationErrorReason::UnboundLegacyAnswer)
        );
    }
    let malformed = authenticate_with(
        ProtocolProfile::EuReferenceLegacyV0_2_2,
        RegistryPayloadShape::LegacyRawBoolean,
        b"\"true\"",
        evaluation_time(),
        MAX_RESPONSE_AGE_SECONDS,
        None,
    )
    .err();
    assert_eq!(
        malformed.map(RegistrationError::reason),
        Some(RegistrationErrorReason::InvalidField)
    );
}

#[test]
fn single_wrp_answer_must_register_the_queried_intended_use() -> Result<(), RegistrationError> {
    let payload = format!(r#"{{"iss":"registry-1","iat":{FIXTURE_ISSUED_AT},"data":{WRP}}}"#);
    authenticate_with(
        ProtocolProfile::Ts5V1_5,
        RegistryPayloadShape::Ts5SignedWrp,
        payload.as_bytes(),
        evaluation_time(),
        MAX_RESPONSE_AGE_SECONDS,
        Some(RegistryIntendedUseQuery {
            service_id: "service-1",
            intended_use_id: "age-check",
        }),
    )?;
    for (service_id, intended_use_id) in
        [("service-1", "address-check"), ("service-2", "age-check")]
    {
        let error = authenticate_with(
            ProtocolProfile::Ts5V1_5,
            RegistryPayloadShape::Ts5SignedWrp,
            payload.as_bytes(),
            evaluation_time(),
            MAX_RESPONSE_AGE_SECONDS,
            Some(RegistryIntendedUseQuery {
                service_id,
                intended_use_id,
            }),
        )
        .err();
        assert_eq!(
            error.map(RegistrationError::reason),
            Some(RegistrationErrorReason::SemanticBindingMismatch)
        );
    }
    let check_payload = format!(
        r#"{{"iss":"registry-1","iat":{FIXTURE_ISSUED_AT},"data":{{"isRegistered":true}}}}"#
    );
    let unbindable = authenticate_with(
        ProtocolProfile::Ts5V1_5,
        RegistryPayloadShape::Ts5SignedIntendedUseCheck,
        check_payload.as_bytes(),
        evaluation_time(),
        MAX_RESPONSE_AGE_SECONDS,
        Some(RegistryIntendedUseQuery {
            service_id: "service-1",
            intended_use_id: "age-check",
        }),
    )
    .err();
    assert_eq!(
        unbindable.map(RegistrationError::reason),
        Some(RegistrationErrorReason::PayloadShapeMismatch)
    );
    Ok(())
}

#[test]
fn same_origin_jwks_redirect_to_another_location_is_rejected() {
    for final_url in [
        "https://registry.example/keys/jwks",
        "https://registry.example/jwks?tenant=other",
        "https://registry.example:8443/jwks",
    ] {
        let error = ValidatedJwks::try_new(
            "https://registry.example/jwks",
            final_url,
            1,
            "application/json",
            br#"{"keys":[{"kty":"EC"}]}"#,
        )
        .err();
        assert_eq!(
            error.map(RegistrationError::reason),
            Some(RegistrationErrorReason::SemanticBindingMismatch)
        );
    }
}
