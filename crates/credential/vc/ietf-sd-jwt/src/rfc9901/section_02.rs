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
    let user_claims = input
        .user_claims
        .as_object()
        .ok_or(IetfSdJwtVcError::InvalidInput)?;
    // Registered claims come only from the typed input fields so a generic
    // user claim can never override issuer, subject, validity, type, or
    // holder binding after they were chosen explicitly.
    if user_claims.keys().any(|key| is_issuer_owned_claim(key)) {
        return Err(IetfSdJwtVcError::ReservedClaimKey);
    }
    if input.strategy == SelectiveDisclosureStrategy::JsonPaths
        && input
            .custom_json_paths
            .iter()
            .any(|path| json_path_targets_registered_claim(path))
    {
        return Err(IetfSdJwtVcError::ReservedClaimKey);
    }
    if input.issuer.trim().is_empty()
        || input.issuer.len() > MAX_SD_JWT_ISSUER_BYTES
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
            if payload.insert(k, v).is_some() {
                return Err(IetfSdJwtVcError::ReservedClaimKey);
            }
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
    temporal_policy: &IetfSdJwtTemporalPolicy,
    kb_verify: Option<KbJwtVerifyParams<'_>>,
) -> Result<VerifiedRfc9901, IetfSdJwtVcError> {
    // Validate every caller-supplied policy bound before any signature work.
    temporal_policy.validate()?;
    if let Some(kb) = kb_verify.as_ref() {
        validate_kb_verify_params(kb)?;
    }
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

    let mut processed = process_sd_jwt_disclosures(&payload, &artifact.disclosures)?;
    validate_credential_temporal_claims(&payload, &processed.resolved, temporal_policy)?;

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

        let compact_without_kb =
            compact_without_key_binding(&artifact.issuer_signed_jwt, &artifact.disclosures)?;

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

    let provided_disclosures = processed
        .disclosures
        .iter()
        .map(|disclosure| disclosure.to_json_array())
        .collect();
    Ok(VerifiedRfc9901 {
        payload,
        resolved_payload: core::mem::take(&mut processed.resolved),
        provided_disclosures,
    })
}

/// Serialize `<issuer-jwt>~<disclosure>~...~` for the KB-JWT `sd_hash` input.
fn compact_without_key_binding(
    issuer_signed_jwt: &str,
    disclosures: &[String],
) -> Result<Zeroizing<String>, IetfSdJwtVcError> {
    let capacity = compact_capacity(issuer_signed_jwt, disclosures, None)
        .ok_or(IetfSdJwtVcError::InvalidCompactFormat)?;
    let mut out = Zeroizing::new(String::with_capacity(capacity));
    out.push_str(issuer_signed_jwt);
    out.push('~');
    for disclosure in disclosures {
        out.push_str(disclosure);
        out.push('~');
    }
    Ok(out)
}

/// Reject vacuous or unbounded KB-JWT verification policy.
fn validate_kb_verify_params(kb: &KbJwtVerifyParams<'_>) -> Result<(), IetfSdJwtVcError> {
    if kb.expected_audience.is_empty()
        || kb.expected_nonce.is_empty()
        || kb.now_unix == 0
        || kb.max_iat_age_seconds == 0
        || kb.max_iat_age_seconds > MAX_KB_JWT_AGE_SECONDS
        || kb.max_future_iat_skew_seconds > MAX_KB_JWT_FUTURE_IAT_SKEW_SECONDS
    {
        return Err(IetfSdJwtVcError::Verification);
    }
    Ok(())
}

/// Return whether an explicit disclosure path targets a registered claim that
/// must stay in the issuer payload, or any member nested beneath it.
fn json_path_targets_registered_claim(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("$.") else {
        return false;
    };
    let top_level_name = rest.split(['.', '[']).next().unwrap_or(rest);
    is_non_selectively_disclosable_claim(top_level_name) || is_issuer_owned_claim(top_level_name)
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
