// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn wrprc_proof_verifiers_reject_tampering_wrong_leaf_and_algorithm_substitution(
) -> Result<(), RegistrationError> {
    let payload = include_bytes!("../vectors/valid-wrprc-payload.json");
    let cwt = wrprc_cwt_claims(payload)?;
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
            evaluation_time: evaluation_time(),
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
            evaluation_time: evaluation_time(),
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
            evaluation_time: evaluation_time(),
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
        evaluation_time: evaluation_time(),
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

    let cose = sign_wrprc_cose(&cwt, &certificate, &private_key)?;
    let wrong_cose_leaf =
        authenticate_wrprc_cose_sign1(RegistrationCertificateCoseAuthenticationInput {
            cose_sign1: &cose,
            expected_signer_certificate_der: &wrong_certificate,
            evaluation_time: evaluation_time(),
            allowed_algorithms: &[RegistrationCertificateCoseAlgorithm::Es256],
        })
        .err();
    assert_eq!(
        wrong_cose_leaf.map(RegistrationError::reason),
        Some(RegistrationErrorReason::AuthenticationReceiptMismatch)
    );

    let wrong_type_cose = sign_wrprc_cose_profile(
        &cwt,
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
            evaluation_time: evaluation_time(),
            allowed_algorithms: &[RegistrationCertificateCoseAlgorithm::Es256],
        })
        .err();
    assert_eq!(
        wrong_cose_type.map(RegistrationError::reason),
        Some(RegistrationErrorReason::UnsupportedProfile)
    );

    let missing_chain_cose = sign_wrprc_cose_profile(
        &cwt,
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
            evaluation_time: evaluation_time(),
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
            evaluation_time: evaluation_time(),
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
                evaluation_time: evaluation_time(),
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
                evaluation_time: evaluation_time(),
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
            evaluation_time: evaluation_time(),
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
            evaluation_time: evaluation_time(),
            allowed_algorithms: &[RegistrationCertificateCoseAlgorithm::Es256],
        })
        .err();
    assert_eq!(
        tampered_error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::SignatureVerificationFailed)
    );
    Ok(())
}

fn authenticate_cose_at(
    cwt: &[u8],
    certificate: &[u8],
    private_key: &[u8],
    evaluation_time: time::OffsetDateTime,
) -> Result<reallyme_eudi_rp_registration::RegistrationCertificateProof, RegistrationError> {
    let cose_sign1 = sign_wrprc_cose(cwt, certificate, private_key)?;
    authenticate_wrprc_cose_sign1(RegistrationCertificateCoseAuthenticationInput {
        cose_sign1: &cose_sign1,
        expected_signer_certificate_der: certificate,
        evaluation_time,
        allowed_algorithms: &[RegistrationCertificateCoseAlgorithm::Es256],
    })
}

fn fixture_binding(
    intermediary_association_id: Option<&str>,
) -> Result<RegistrationCertificateBinding, RegistrationError> {
    RegistrationCertificateBinding::try_new(
        "NTRCH-123",
        "service-1",
        "age-check",
        intermediary_association_id,
        ArtifactDigest::sha256(b"https://registry.example/entry/123"),
        ArtifactDigest::sha256(b"reviewed-registration-snapshot"),
    )
}

fn with_extra_claim(cwt: &[u8], entry: &[u8]) -> Result<Vec<u8>, RegistrationError> {
    const MAX_DIRECT_MAP_HEADER: u8 = 0xb6;
    let (header, claims) = cwt.split_first().ok_or(RegistrationError::Invalid(
        RegistrationErrorReason::SerializationFailed,
    ))?;
    if !(0xa0..MAX_DIRECT_MAP_HEADER).contains(header) {
        return Err(RegistrationError::Invalid(
            RegistrationErrorReason::SerializationFailed,
        ));
    }
    let mut output = vec![header.checked_add(1).ok_or(RegistrationError::Invalid(
        RegistrationErrorReason::SerializationFailed,
    ))?];
    output.extend_from_slice(claims);
    output.extend_from_slice(entry);
    Ok(output)
}

#[test]
fn wrprc_proof_rejects_evaluation_outside_signed_validity_period() -> Result<(), RegistrationError>
{
    let payload = include_bytes!("../vectors/valid-wrprc-payload.json");
    let cwt = wrprc_cwt_claims(payload)?;
    let (certificate, private_key) = proof_signing_identity()?;

    for accepted in [40, 100, 199] {
        drop(authenticate_cose_at(
            &cwt,
            &certificate,
            &private_key,
            at(accepted),
        )?);
    }
    for rejected in [39, 200, 10_000] {
        let error = authenticate_cose_at(&cwt, &certificate, &private_key, at(rejected)).err();
        assert_eq!(
            error.map(RegistrationError::reason),
            Some(RegistrationErrorReason::OutsideValidityPeriod)
        );
    }

    let compact = sign_wrprc_jades(payload, &certificate, &private_key)?;
    let policy = RegistrationCertificateJadesPolicy::default();
    let expired = authenticate_wrprc_jades(RegistrationCertificateJadesAuthenticationInput {
        compact_jws: &compact,
        expected_signer_certificate_der: &certificate,
        evaluation_time: at(200),
        policy: &policy,
    })
    .err();
    assert_eq!(
        expired.map(RegistrationError::reason),
        Some(RegistrationErrorReason::OutsideValidityPeriod)
    );
    Ok(())
}

#[test]
fn wrprc_binding_must_match_signed_intermediary() -> Result<(), RegistrationError> {
    let payload = include_bytes!("../vectors/valid-wrprc-payload.json");
    let mut claims: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|_error| RegistrationError::Invalid(RegistrationErrorReason::InvalidJson))?;
    let direct_cwt = wrprc_cwt_claims(payload)?;
    let members = claims.as_object_mut().ok_or(RegistrationError::Invalid(
        RegistrationErrorReason::InvalidJson,
    ))?;
    members.insert(
        "intermediary".to_owned(),
        serde_json::json!({"sub": "INT-1", "name": "Example Intermediary"}),
    );
    let intermediated_json = serde_json::to_vec(&claims)
        .map_err(|_error| RegistrationError::Invalid(RegistrationErrorReason::InvalidJson))?;
    let intermediated_cwt = wrprc_cwt_claims(&intermediated_json)?;
    let (certificate, private_key) = proof_signing_identity()?;

    let accepted = authenticate_registration_certificate(
        vec![authenticate_cose_at(
            &intermediated_cwt,
            &certificate,
            &private_key,
            evaluation_time(),
        )?],
        fixture_binding(Some("INT-1"))?,
    )?;
    assert_eq!(accepted.parsed().intermediary_id(), Some("INT-1"));

    for (cwt, intermediary) in [
        (&intermediated_cwt, None),
        (&intermediated_cwt, Some("INT-2")),
        (&direct_cwt, Some("INT-1")),
    ] {
        let proof = authenticate_cose_at(cwt, &certificate, &private_key, evaluation_time())?;
        let error =
            authenticate_registration_certificate(vec![proof], fixture_binding(intermediary)?)
                .err();
        assert_eq!(
            error.map(RegistrationError::reason),
            Some(RegistrationErrorReason::SemanticBindingMismatch)
        );
    }
    Ok(())
}

#[test]
fn wrprc_cose_payload_must_be_a_strict_cwt_claims_set() -> Result<(), RegistrationError> {
    let payload = include_bytes!("../vectors/valid-wrprc-payload.json");
    let cwt = wrprc_cwt_claims(payload)?;
    let (certificate, private_key) = proof_signing_identity()?;

    let mut too_deep = Vec::new();
    append_cbor_text(&mut too_deep, "nested")?;
    too_deep.extend_from_slice(&[0x81_u8; 24]);
    too_deep.push(0xf6);
    let mut trailing = cwt.clone();
    trailing.push(0xf6);

    let cases: [(Vec<u8>, RegistrationErrorReason); 9] = [
        // A JSON claims set is not an RFC 8392 CWT.
        (payload.to_vec(), RegistrationErrorReason::InvalidField),
        // Repeated registered claim key (`sub`).
        (
            with_extra_claim(&cwt, b"\x02\x69NTRCH-999")?,
            RegistrationErrorReason::DuplicateJsonMember,
        ),
        // Registered claim carried under a text key.
        (
            with_extra_claim(&cwt, b"\x63sub\x69NTRCH-123")?,
            RegistrationErrorReason::InvalidField,
        ),
        // Unassigned integer claim key.
        (
            with_extra_claim(&cwt, b"\x18\x2a\xf6")?,
            RegistrationErrorReason::UnknownField,
        ),
        // Negative integer claim key.
        (
            with_extra_claim(&cwt, b"\x20\xf6")?,
            RegistrationErrorReason::UnknownField,
        ),
        // Floating-point value.
        (
            with_extra_claim(&cwt, b"\x61x\xf9\x3c\x00")?,
            RegistrationErrorReason::InvalidField,
        ),
        // Tagged value.
        (
            with_extra_claim(&cwt, b"\x61x\xc1\x01")?,
            RegistrationErrorReason::InvalidField,
        ),
        // Nesting beyond the shared depth bound.
        (
            with_extra_claim(&cwt, &too_deep)?,
            RegistrationErrorReason::ResourceLimitExceeded,
        ),
        // Trailing data after the claims map.
        (trailing, RegistrationErrorReason::InvalidField),
    ];
    for (claims, expected) in cases {
        let error =
            authenticate_cose_at(&claims, &certificate, &private_key, evaluation_time()).err();
        assert_eq!(error.map(RegistrationError::reason), Some(expected));
    }

    // A byte-string claim value has no counterpart in the claim model.
    let byte_value = with_extra_claim(&cwt, b"\x61x\x41\x00")?;
    let error =
        authenticate_cose_at(&byte_value, &certificate, &private_key, evaluation_time()).err();
    assert_eq!(
        error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::InvalidField)
    );
    Ok(())
}
