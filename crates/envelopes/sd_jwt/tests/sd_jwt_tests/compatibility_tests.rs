// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn jws_json_serialization_keeps_sd_parameters_on_the_first_signature() {
    let input = json!({
        "payload": "e30",
        "signatures": [
            {
                "protected": "e30",
                "signature": "AA",
                "header": { "kid": "issuer-key-1" }
            },
            {
                "protected": "e30",
                "signature": "AA",
                "header": {
                    "kid": "issuer-key-2",
                    "disclosures": []
                }
            }
        ]
    });

    assert_eq!(
        parse_sd_jwt_json_serialization(&input.to_string()).err(),
        Some(SdJwtEnvelopeError::InvalidJsonSerialization)
    );
}

#[test]
fn issue_sd_jwt_vc_media_types_require_vct() {
    let issuer = gen_ed25519();

    for issuer_type in [
        SdJwtIssuerType::DigitalCredentialSdJwt,
        SdJwtIssuerType::VerifiableCredentialSdJwt,
    ] {
        let mut salts = DeterministicSaltSource::new();
        let error = issue_sd_jwt(
            SdJwtIssuanceInput {
                claims: json!({
                    "iss": "https://example.com/issuer",
                    "given_name": "Max",
                }),
                issuer_jwk: &issuer.jwk,
                issuer_private_key: &issuer.private,
                policy: SdJwtIssuancePolicy {
                    issuer_type,
                    ..SdJwtIssuancePolicy::default()
                },
            },
            &mut salts,
        )
        .expect_err("SD-JWT VC issuance without vct must fail");

        assert_eq!(error, SdJwtEnvelopeError::InvalidIssuanceInput);
    }
}
