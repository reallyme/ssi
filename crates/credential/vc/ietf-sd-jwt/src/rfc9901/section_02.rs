// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

const MAX_KB_JWT_FUTURE_IAT_SKEW_SECONDS: u64 = 300;
// This is a defense-in-depth ceiling; OpenID4VP deployments should normally
// select a substantially shorter request-scoped freshness window.
const MAX_KB_JWT_AGE_SECONDS: u64 = 86_400;

pub fn issue_rfc9901_sd_jwt(
    input: &Rfc9901IssueInput,
    issuer_jwk: &Jwk,
    issuer_private_key: &[u8],
) -> Result<SdJwtArtifact, IetfSdJwtVcError> {
    let mut salt_rng = Rfc9901OsSaltRng;
    issue_rfc9901_sd_jwt_with_rng(input, issuer_jwk, issuer_private_key, &mut salt_rng)
}

/// Issue an RFC 9901 SD-JWT with a deterministic salt stream.
///
/// This entry point exists only for conformance vectors and golden fixtures.
/// It is excluded from normal builds so production callers cannot select the
/// reproducible stream accidentally.
#[cfg(feature = "conformance-vectors")]
pub fn issue_rfc9901_sd_jwt_deterministic(
    input: &Rfc9901IssueInput,
    issuer_jwk: &Jwk,
    issuer_private_key: &[u8],
    salt_seed: u64,
) -> Result<SdJwtArtifact, IetfSdJwtVcError> {
    let mut salt_rng = Rfc9901DeterministicSaltRng::new(salt_seed);
    issue_rfc9901_sd_jwt_with_rng(input, issuer_jwk, issuer_private_key, &mut salt_rng)
}

fn issue_rfc9901_sd_jwt_with_rng(
    input: &Rfc9901IssueInput,
    issuer_jwk: &Jwk,
    issuer_private_key: &[u8],
    salt_rng: &mut dyn Rfc9901SaltRng,
) -> Result<SdJwtArtifact, IetfSdJwtVcError> {
    if input.issuer.trim().is_empty()
        || input.issuer.len() > MAX_SD_JWT_ISSUER_BYTES
        || !input.user_claims.is_object()
        || !json_value_within_limits(&input.user_claims)
        || input.custom_json_paths.len() > MAX_SD_JWT_DISCLOSURES
        || input
            .custom_json_paths
            .iter()
            .any(|path| path.is_empty() || path.len() > MAX_SD_JWT_STRING_BYTES)
    {
        return Err(IetfSdJwtVcError::InvalidInput);
    }

    let mut ctx = TransformCtx {
        strategy: input.strategy,
        json_paths: input.custom_json_paths.iter().cloned().collect(),
        salt_rng,
        object_decoys: input.decoys.object_decoys,
        array_decoys: input.decoys.array_decoys,
        disclosures: Vec::new(),
    };

    let transformed_claims = transform_value(&input.user_claims, "$", &mut ctx, true)?;

    let mut payload = Map::new();
    payload.insert("iss".to_string(), Value::String(input.issuer.clone()));

    if let Some(sub) = &input.subject {
        payload.insert("sub".to_string(), Value::String(sub.clone()));
    }
    if let Some(iat) = input.issued_at_unix {
        payload.insert("iat".to_string(), Value::Number(iat.into()));
    }
    if let Some(nbf) = input.not_before_unix {
        payload.insert("nbf".to_string(), Value::Number(nbf.into()));
    }
    if let Some(exp) = input.expires_at_unix {
        payload.insert("exp".to_string(), Value::Number(exp.into()));
    }
    if let Some(vct) = &input.vct {
        payload.insert("vct".to_string(), Value::String(vct.clone()));
    }
    if let Some(cnf) = &input.confirmation_jwk {
        payload.insert("cnf".to_string(), serde_json::json!({"jwk": cnf}));
    }

    if let Value::Object(m) = transformed_claims {
        for (k, v) in m {
            payload.insert(k, v);
        }
    } else {
        return Err(IetfSdJwtVcError::InvalidInput);
    }

    let issuer_signed_jwt = encode_signed_jwt_with_header_options(
        &Value::Object(payload),
        issuer_jwk,
        issuer_private_key,
        &JwtHeaderEncodeOptions::new(Some("dc+sd-jwt".to_string())),
    )
    .map_err(|_| IetfSdJwtVcError::Signature)?;

    let disclosures = ctx.disclosures.iter().map(|r| r.encoded.clone()).collect();

    let artifact = SdJwtArtifact {
        issuer_signed_jwt,
        disclosures,
        kb_jwt: None,
        records: ctx.disclosures,
    };
    validate_artifact(&artifact, IetfSdJwtVcError::InvalidCompactFormat)?;
    Ok(artifact)
}

pub fn verify_rfc9901_sd_jwt(
    artifact: &SdJwtArtifact,
    issuer_jwk: &Jwk,
    issuer_public_key: &[u8],
    kb_verify: Option<KbJwtVerifyParams<'_>>,
) -> Result<VerifiedRfc9901, IetfSdJwtVcError> {
    validate_artifact(artifact, IetfSdJwtVcError::InvalidCompactFormat)?;
    let payload: Value = decode_verify_jwt_signature_only_with_header_validation(
        &artifact.issuer_signed_jwt,
        issuer_jwk,
        issuer_public_key,
        &JwtHeaderValidationOptions::new(false, false, &["dc+sd-jwt"]),
    )
    .map_err(|_| IetfSdJwtVcError::Verification)?;

    let payload_obj = payload.as_object().ok_or(IetfSdJwtVcError::InvalidInput)?;

    // RFC 9901 §§3.3, 4.1.2, 4.3, and 7.3 require an SD-JWT+KB when
    // key binding is required. The issuer-signed `cnf` claim is an immutable
    // signal that this credential is holder-bound; allowing verification with
    // neither KB-JWT nor verification policy would make a stripped
    // presentation replayable (CVE-2026-77456).
    match (
        payload_obj.get("cnf"),
        kb_verify.as_ref(),
        artifact.kb_jwt.as_ref(),
    ) {
        (Some(_), Some(kb), Some(_)) => validate_confirmation_key(payload_obj, kb)?,
        (None, None, None) => {}
        _ => {
            return Err(IetfSdJwtVcError::MissingKeyBinding);
        }
    }

    let mut expected = BTreeSet::new();
    collect_expected_digests(&Value::Object(payload_obj.clone()), &mut expected)?;

    let mut pending: Vec<(String, Value)> = Vec::new();
    let mut seen_disclosures = BTreeSet::new();
    for disclosure_b64u in &artifact.disclosures {
        if !seen_disclosures.insert(disclosure_b64u.as_str()) {
            return Err(IetfSdJwtVcError::InvalidDisclosure);
        }
        let digest_b64u =
            bytes_to_base64url(sha2_256_digest(disclosure_b64u.as_bytes()).as_bytes());
        let disclosure_bytes = Zeroizing::new(
            base64url_to_bytes(disclosure_b64u).map_err(|_| IetfSdJwtVcError::InvalidDisclosure)?,
        );
        let disclosure_json: Value = serde_json::from_slice(&disclosure_bytes)
            .map_err(|_| IetfSdJwtVcError::InvalidDisclosure)?;
        let arr = disclosure_json
            .as_array()
            .ok_or(IetfSdJwtVcError::InvalidDisclosure)?;
        if arr.len() != 2 && arr.len() != 3 {
            return Err(IetfSdJwtVcError::InvalidDisclosure);
        }
        pending.push((digest_b64u, disclosure_json));
    }

    let mut provided = Vec::new();
    let mut progress = true;
    while progress {
        progress = false;
        let mut next_pending = Vec::new();

        for (digest, disclosure_json) in pending {
            if expected.contains(&digest) {
                if let Some(arr) = disclosure_json.as_array() {
                    let nested_value = if arr.len() == 3 {
                        arr.get(2)
                    } else {
                        arr.get(1)
                    };
                    if let Some(v) = nested_value {
                        collect_expected_digests(v, &mut expected)?;
                    }
                }
                provided.push(disclosure_json);
                progress = true;
            } else {
                next_pending.push((digest, disclosure_json));
            }
        }

        pending = next_pending;
    }

    if !pending.is_empty() {
        return Err(IetfSdJwtVcError::DisclosureDigestMismatch);
    }

    if let Some(kb) = kb_verify {
        let kb_jwt = artifact
            .kb_jwt
            .as_deref()
            .ok_or(IetfSdJwtVcError::MissingKeyBinding)?;
        let kb_payload: Value = decode_verify_jwt_signature_only_with_header_validation(
            kb_jwt,
            kb.holder_jwk,
            kb.holder_public_key,
            &JwtHeaderValidationOptions::new(false, false, &["kb+jwt"]),
        )
        .map_err(|_| IetfSdJwtVcError::Verification)?;

        let compact_without_kb = SdJwtArtifact {
            issuer_signed_jwt: artifact.issuer_signed_jwt.clone(),
            disclosures: artifact.disclosures.clone(),
            kb_jwt: None,
            records: Vec::new(),
        }
        .to_compact()?;

        let expected_sd_hash =
            bytes_to_base64url(sha2_256_digest(compact_without_kb.as_bytes()).as_bytes());
        let aud = kb_payload
            .get("aud")
            .and_then(Value::as_str)
            .ok_or(IetfSdJwtVcError::InvalidInput)?;
        let nonce = kb_payload
            .get("nonce")
            .and_then(Value::as_str)
            .ok_or(IetfSdJwtVcError::InvalidInput)?;
        let iat = kb_payload
            .get("iat")
            .and_then(Value::as_u64)
            .ok_or(IetfSdJwtVcError::InvalidInput)?;
        let sd_hash = kb_payload
            .get("sd_hash")
            .and_then(Value::as_str)
            .ok_or(IetfSdJwtVcError::InvalidInput)?;

        validate_kb_jwt_time(iat, &kb)?;

        if !constant_time_equal(aud.as_bytes(), kb.expected_audience.as_bytes())
            || !constant_time_equal(nonce.as_bytes(), kb.expected_nonce.as_bytes())
            || !constant_time_equal(sd_hash.as_bytes(), expected_sd_hash.as_bytes())
        {
            return Err(IetfSdJwtVcError::Verification);
        }
    }

    Ok(VerifiedRfc9901 {
        payload,
        provided_disclosures: provided,
    })
}

fn validate_kb_jwt_time(
    iat: u64,
    kb: &KbJwtVerifyParams<'_>,
) -> Result<(), IetfSdJwtVcError> {
    if kb.now_unix == 0
        || kb.max_iat_age_seconds == 0
        || kb.max_iat_age_seconds > MAX_KB_JWT_AGE_SECONDS
        || kb.max_future_iat_skew_seconds > MAX_KB_JWT_FUTURE_IAT_SKEW_SECONDS
    {
        return Err(IetfSdJwtVcError::Verification);
    }

    // RFC 9901 §4.3 requires `iat`; §7.3 requires validation within an
    // acceptable time window. Checked arithmetic makes hostile NumericDate
    // values fail closed instead of wrapping policy bounds.
    let latest_iat = kb
        .now_unix
        .checked_add(kb.max_future_iat_skew_seconds)
        .ok_or(IetfSdJwtVcError::Verification)?;
    let stale_after = iat
        .checked_add(kb.max_iat_age_seconds)
        .ok_or(IetfSdJwtVcError::Verification)?;

    if iat > latest_iat || stale_after < kb.now_unix {
        return Err(IetfSdJwtVcError::Verification);
    }

    Ok(())
}

fn validate_confirmation_key(
    payload: &Map<String, Value>,
    kb: &KbJwtVerifyParams<'_>,
) -> Result<(), IetfSdJwtVcError> {
    let confirmation_jwk = payload
        .get("cnf")
        .and_then(Value::as_object)
        .and_then(|confirmation| confirmation.get("jwk"))
        .ok_or(IetfSdJwtVcError::MissingKeyBinding)?;
    let confirmation_jwk: Jwk = serde_json::from_value(confirmation_jwk.clone())
        .map_err(|_| IetfSdJwtVcError::Verification)?;
    let confirmation_public_key = confirmation_jwk
        .public_key_bytes()
        .map_err(|_| IetfSdJwtVcError::Verification)?;
    let supplied_jwk_public_key = kb
        .holder_jwk
        .public_key_bytes()
        .map_err(|_| IetfSdJwtVcError::Verification)?;

    // RFC 9901 §§4.1.2 and 7.3 require the KB-JWT signature key to be the
    // holder key carried by (or referenced from) the issuer-signed SD-JWT.
    // Checking both representations prevents a caller from pairing an
    // attacker-controlled JWK with unrelated raw verification bytes.
    if confirmation_public_key.as_slice() != kb.holder_public_key
        || supplied_jwk_public_key.as_slice() != kb.holder_public_key
    {
        return Err(IetfSdJwtVcError::Verification);
    }

    Ok(())
}
