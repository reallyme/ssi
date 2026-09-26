// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn sd_jwt_vp_rejects_valid_sd_jwt_paired_with_swapped_envelope() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).unwrap();
    let (holder_pub, holder_priv) = generate_keypair(Algorithm::Ed25519).unwrap();
    let issuer_jwk = ed25519_issuer_jwk(&issuer_pub);
    let holder_jwk = ed25519_issuer_jwk(&holder_pub);

    let presented = issue_age_credential(holder_pub.clone(), &issuer_priv, 42);
    // A second, genuinely issuer-signed envelope for the same holder. Its
    // signature verifies, but the issuer SD-JWT never committed to it.
    let swapped = issue_age_credential(holder_pub.clone(), &issuer_priv, 17);

    let issuer_sd_jwt = issuer_sd_jwt_for_issued(&presented, &issuer_jwk, &issuer_priv);
    let vp = build_sd_jwt_presentation_with_kb_binding(
        &presented.subject_bundle,
        issuer_sd_jwt,
        &["/claims/age".into()],
        &holder_jwk,
        &holder_priv,
        KbJwtBindingInput {
            nonce: "nonce-123",
            aud: "verifier.example",
            iat_unix: TEST_NOW_UNIX,
        },
    )
    .unwrap();

    verify_sd_jwt_vp_with_binding(
        &vp,
        &presented.envelope,
        &issuer_jwk,
        &issuer_pub,
        Some(&holder_pub),
        holder_binding_for_nonce("nonce-123"),
    )
    .unwrap();

    let swapped_error = verify_sd_jwt_vp_with_binding(
        &vp,
        &swapped.envelope,
        &issuer_jwk,
        &issuer_pub,
        Some(&holder_pub),
        holder_binding_for_nonce("nonce-123"),
    )
    .unwrap_err();
    assert!(matches!(
        swapped_error,
        SdJwtVpError::EnvelopeBindingMismatch
    ));

    // Omitting the holder-supplied envelope hash must not skip the binding.
    let mut without_holder_hash = vp.clone();
    without_holder_hash.envelope_hash = None;
    let unhinted_error = verify_sd_jwt_vp_with_binding(
        &without_holder_hash,
        &swapped.envelope,
        &issuer_jwk,
        &issuer_pub,
        Some(&holder_pub),
        holder_binding_for_nonce("nonce-123"),
    )
    .unwrap_err();
    assert!(matches!(
        unhinted_error,
        SdJwtVpError::EnvelopeBindingMismatch
    ));
}

#[test]
fn sd_jwt_vp_rejects_holder_envelope_hash_that_differs_from_sd_hash() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).unwrap();
    let (holder_pub, holder_priv) = generate_keypair(Algorithm::Ed25519).unwrap();
    let issuer_jwk = ed25519_issuer_jwk(&issuer_pub);
    let holder_jwk = ed25519_issuer_jwk(&holder_pub);
    let issued = issue_age_credential(holder_pub.clone(), &issuer_priv, 42);
    let issuer_sd_jwt = issuer_sd_jwt_for_issued(&issued, &issuer_jwk, &issuer_priv);
    let mut vp = build_sd_jwt_presentation_with_kb_binding(
        &issued.subject_bundle,
        issuer_sd_jwt,
        &["/claims/age".into()],
        &holder_jwk,
        &holder_priv,
        KbJwtBindingInput {
            nonce: "nonce-123",
            aud: "verifier.example",
            iat_unix: TEST_NOW_UNIX,
        },
    )
    .unwrap();
    vp.envelope_hash = Some([0x5a; 32]);

    let error = verify_sd_jwt_vp_with_binding(
        &vp,
        &issued.envelope,
        &issuer_jwk,
        &issuer_pub,
        Some(&holder_pub),
        holder_binding_for_nonce("nonce-123"),
    )
    .unwrap_err();
    assert!(matches!(error, SdJwtVpError::EnvelopeBindingMismatch));
}

#[test]
fn sd_jwt_vp_rejects_envelope_signed_by_another_issuer() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).unwrap();
    let (_, other_issuer_priv) = generate_keypair(Algorithm::Ed25519).unwrap();
    let (holder_pub, holder_priv) = generate_keypair(Algorithm::Ed25519).unwrap();
    let issuer_jwk = ed25519_issuer_jwk(&issuer_pub);
    let holder_jwk = ed25519_issuer_jwk(&holder_pub);

    // The trusted issuer signs an SD-JWT over the envelope hash of an envelope
    // it did not sign itself; the envelope signature must still be verified.
    let foreign = issue_age_credential(holder_pub.clone(), &other_issuer_priv, 42);
    let issuer_sd_jwt = issuer_sd_jwt_for_issued(&foreign, &issuer_jwk, &issuer_priv);
    let vp = build_sd_jwt_presentation_with_kb_binding(
        &foreign.subject_bundle,
        issuer_sd_jwt,
        &["/claims/age".into()],
        &holder_jwk,
        &holder_priv,
        KbJwtBindingInput {
            nonce: "nonce-123",
            aud: "verifier.example",
            iat_unix: TEST_NOW_UNIX,
        },
    )
    .unwrap();

    let error = verify_sd_jwt_vp_with_binding(
        &vp,
        &foreign.envelope,
        &issuer_jwk,
        &issuer_pub,
        Some(&holder_pub),
        holder_binding_for_nonce("nonce-123"),
    )
    .unwrap_err();
    assert!(matches!(error, SdJwtVpError::Crypto));
}

#[test]
fn sd_jwt_vp_accepts_only_the_hashed_nonce_encoding() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).unwrap();
    let (holder_pub, holder_priv) = generate_keypair(Algorithm::Ed25519).unwrap();
    let issuer_jwk = ed25519_issuer_jwk(&issuer_pub);
    let holder_jwk = ed25519_issuer_jwk(&holder_pub);
    let issued = issue_age_credential(holder_pub.clone(), &issuer_priv, 42);
    let issuer_sd_jwt = issuer_sd_jwt_for_issued(&issued, &issuer_jwk, &issuer_priv);

    // A nonce string that is also valid base64url for exactly 32 bytes.
    let raw_challenge = [0x11_u8; 32];
    let encoded_nonce = bytes_to_base64url(&raw_challenge);
    let vp = build_sd_jwt_presentation_with_kb_binding(
        &issued.subject_bundle,
        issuer_sd_jwt,
        &["/claims/age".into()],
        &holder_jwk,
        &holder_priv,
        KbJwtBindingInput {
            nonce: &encoded_nonce,
            aud: "verifier.example",
            iat_unix: TEST_NOW_UNIX,
        },
    )
    .unwrap();

    let mut decoded_binding = holder_binding_for_nonce(&encoded_nonce);
    decoded_binding.expected_nonce_32 = raw_challenge;
    let error = verify_sd_jwt_vp_with_binding(
        &vp,
        &issued.envelope,
        &issuer_jwk,
        &issuer_pub,
        Some(&holder_pub),
        decoded_binding,
    )
    .unwrap_err();
    assert!(matches!(error, SdJwtVpError::Crypto));

    verify_sd_jwt_vp_with_binding(
        &vp,
        &issued.envelope,
        &issuer_jwk,
        &issuer_pub,
        Some(&holder_pub),
        holder_binding_for_nonce(&encoded_nonce),
    )
    .unwrap();
}

#[test]
fn sd_jwt_vp_rejects_zero_verifier_time() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).unwrap();
    let (holder_pub, _) = generate_keypair(Algorithm::Ed25519).unwrap();
    let issuer_jwk = ed25519_issuer_jwk(&issuer_pub);
    let issued = issue_age_credential(holder_pub, &issuer_priv, 42);
    let issuer_sd_jwt = issuer_sd_jwt_for_issued(&issued, &issuer_jwk, &issuer_priv);
    let vp = build_sd_jwt_presentation(
        &issued.subject_bundle,
        issuer_sd_jwt,
        &["/claims/age".into()],
    )
    .unwrap();

    let error =
        verify_sd_jwt_vp(&vp, &issued.envelope, &issuer_jwk, &issuer_pub, None, 0).unwrap_err();
    assert!(matches!(error, SdJwtVpError::Crypto));
}
