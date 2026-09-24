// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Security and interoperability tests for EUDI registration artifacts.

use reallyme_eudi_rp_registration::{
    authenticate_access_certificate_association, authenticate_registry_record,
    parse_registration_certificate, prepare_registration_document, AccessCertificateBinding,
    ArtifactDigest, AuthenticatedJws, CredentialMetadata, ProtocolProfile,
    RegistrationCertificatePolicy, RegistrationError, RegistrationErrorReason,
    RegistryAuthenticationInput, RegistryJwsVerifier, RegistryMetadata, RegistryPayload,
    RegistryPayloadShape, ValidatedJwks, WalletRelyingParty, WrpEntitlement,
};

const WRP: &str = include_str!("vectors/valid-ts5-wrp.json");
const ALTERNATE_CERTIFICATE_B64: &str =
    include_str!("../../../trust/x509/tests/fixtures/qwac_server_auth_cert.der.b64");
const P256_PUBLIC_X: &str = "zovuXfZo2sBrLwEy_9yuyzmsnqAmSz9e7kMWaPUtlPU";
const P256_PUBLIC_Y: &str = "y_n6M-ozBp7M4eq5rAx52ghP-a8dgbtXMkQCNRGgvHE";
const P256_LEAF_CERTIFICATE_B64: &str = "MIIB6jCCAZGgAwIBAgIUcE7RmpSme/eHZaGfCzWjNjtsiHYwCgYIKoZIzj0EAwIwQzELMAkGA1UEBhMCQ0gxFjAUBgNVBAoMDVJlYWxseU1lIFRlc3QxHDAaBgNVBAMME1JlZ2lzdHJhciBUZXN0IFJvb3QwHhcNMjYwOTE3MDMwMzAzWhcNMzYwOTE0MDMwMzAzWjBGMQswCQYDVQQGEwJDSDEWMBQGA1UECgwNUmVhbGx5TWUgVGVzdDEfMB0GA1UEAwwWUmVnaXN0cmFyIFNpZ25pbmcgTGVhZjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABM6L7l32aNrAay8BMv/crss5rJ6gJks/Xu5DFmj1LZT1y/n6M+ozBp7M4eq5rAx52ghP+a8dgbtXMkQCNRGgvHGjYDBeMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBQQ5eNWwS359uWZOUcjTI/BCZXTETAfBgNVHSMEGDAWgBS7GhUOGTtG3XD7Dp/zpjQWZO9nSTAKBggqhkjOPQQDAgNHADBEAiBjp76nIMdHH4LUSJYoi9yO0eglrwAqE4TgPpCMhsV9jwIgfASVYeMgtDM4sTYyPZpiOfKI6umX7hVL9mMdV91Kpzs=";
const P256_ROOT_CERTIFICATE_B64: &str = "MIIB6zCCAZGgAwIBAgIUemVPne1k4/3qcrcjMcNx6D62RrEwCgYIKoZIzj0EAwIwQzELMAkGA1UEBhMCQ0gxFjAUBgNVBAoMDVJlYWxseU1lIFRlc3QxHDAaBgNVBAMME1JlZ2lzdHJhciBUZXN0IFJvb3QwHhcNMjYwOTE3MDMwMjU0WhcNMzYwOTE0MDMwMjU0WjBDMQswCQYDVQQGEwJDSDEWMBQGA1UECgwNUmVhbGx5TWUgVGVzdDEcMBoGA1UEAwwTUmVnaXN0cmFyIFRlc3QgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJV8XcdAPnFxP4zSDH+eUVmzhSCeJ5vjQC6BnuDMbnkAzoZgoHelrqt3yvkSz1h/xHJyEExBba88G9v1pSscXx+jYzBhMB8GA1UdIwQYMBaAFLsaFQ4ZO0bdcPsOn/OmNBZk72dJMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBS7GhUOGTtG3XD7Dp/zpjQWZO9nSTAKBggqhkjOPQQDAgNIADBFAiBktIl2JNdRgnUXFzZnQAVY3Yj6sjpjt0jL5sqa3nfFOAIhAJy9JRFFD24q9UdeYxKbIW9/ftuTygrDFzYSREE5Xp4Y";

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
        "https://registry.example/keys/jwks",
        1,
        "application/jwk-set+json; charset=utf-8",
        body.as_bytes(),
    )
}

fn wrpac_leaf() -> Result<Vec<u8>, RegistrationError> {
    reallyme_codec::base64::base64_to_bytes(include_str!("vectors/wrpac-ncp-legal.der.b64").trim())
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
    let duplicate = include_bytes!("vectors/invalid-duplicate-ts5-wrp.json");
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

#[test]
fn wrprc_status_and_validity_are_parsed_strictly() -> Result<(), RegistrationError> {
    let payload = include_bytes!("vectors/valid-wrprc-payload.json");
    let parsed = parse_registration_certificate(payload)?;
    assert_eq!(parsed.relying_party_id(), "NTRCH-123");
    assert_eq!(parsed.status_list_index(), 9);
    assert_eq!(parsed.issued_at(), 100);
    assert_eq!(parsed.expires_at(), 200);
    assert_eq!(
        parsed.certificate_policy(),
        RegistrationCertificatePolicy::EtsiTs119475Wrprc
    );
    Ok(())
}

#[test]
fn wrprc_requires_the_normative_policy_oid_and_https_cp_cps_location() {
    let wrong_policy = include_str!("vectors/valid-wrprc-payload.json")
        .replace("0.4.0.19475.3.1", "0.4.0.19475.3.2");
    let policy_error = parse_registration_certificate(wrong_policy.as_bytes()).err();
    assert_eq!(
        policy_error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::CertificateProfileMismatch)
    );

    let insecure_location = include_str!("vectors/valid-wrprc-payload.json").replace(
        "https://registrar.example/certificate-policy",
        "http://registrar.example/certificate-policy",
    );
    let location_error = parse_registration_certificate(insecure_location.as_bytes()).err();
    assert_eq!(
        location_error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::InvalidUri)
    );
}

#[test]
fn wrprc_rejects_non_normative_entitlement_identifiers() {
    let payload = include_str!("vectors/valid-wrprc-payload.json").replace(
        "https://uri.etsi.org/19475/Entitlement/Service_Provider",
        "Service_Provider",
    );
    let error = parse_registration_certificate(payload.as_bytes()).err();
    assert_eq!(
        error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::InvalidField)
    );
}

#[test]
fn digest_constructor_retains_fixed_width() {
    let digest = ArtifactDigest::from_bytes([7_u8; 32]);
    assert_eq!(digest.as_bytes(), &[7_u8; 32]);
}

#[test]
fn wrpac_association_projects_standard_holder_and_exact_local_bindings(
) -> Result<(), RegistrationError> {
    let leaf_der = wrpac_leaf()?;
    let leaf_digest = ArtifactDigest::sha256(&leaf_der);
    let registry_reference_digest = ArtifactDigest::sha256(b"registry-reference");
    let binding = AccessCertificateBinding::try_new(
        leaf_digest,
        "VATMT-1",
        "service-1",
        Some("customer-association-1"),
        registry_reference_digest,
    )?;
    let evaluation_time = time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1_800_000_000);
    let authenticated =
        authenticate_access_certificate_association(&leaf_der, evaluation_time, binding)?;
    assert_eq!(authenticated.leaf_certificate_digest(), leaf_digest);
    assert_eq!(authenticated.holder_relying_party_id(), "VATMT-1");
    assert_eq!(authenticated.holder_service_id(), "service-1");
    assert_eq!(
        authenticated.intermediary_association_id(),
        Some("customer-association-1")
    );
    assert_eq!(
        authenticated.national_register_reference_digest(),
        registry_reference_digest
    );
    assert!(authenticated.valid_from_unix_seconds() < authenticated.valid_until_unix_seconds());
    Ok(())
}

#[test]
fn wrpac_association_rejects_substituted_holder() -> Result<(), RegistrationError> {
    let leaf_der = wrpac_leaf()?;
    let binding = AccessCertificateBinding::try_new(
        ArtifactDigest::sha256(&leaf_der),
        "VATMT-substituted",
        "service-1",
        None,
        ArtifactDigest::sha256(b"registry-reference"),
    )?;
    let evaluation_time = time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1_800_000_000);
    let error =
        authenticate_access_certificate_association(&leaf_der, evaluation_time, binding).err();
    assert_eq!(
        error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::SemanticBindingMismatch)
    );
    Ok(())
}
