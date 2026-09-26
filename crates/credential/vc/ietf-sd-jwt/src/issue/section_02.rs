// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn build_common_payload(
    input: &IetfSdJwtIssueInput,
) -> Result<Map<String, Value>, IetfSdJwtVcError> {
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

    if let Some(jwk) = &input.confirmation_jwk {
        payload.insert("cnf".to_string(), serde_json::json!({ "jwk": jwk }));
    }

    if let Some(binding) = &input.me_profile_merkle_binding {
        // This extension is namespaced and additive; it does not alter SD-JWT core semantics.
        insert_me_profile_merkle_binding(&mut payload, binding)?;
    }

    for (k, v) in &input.public_claims {
        payload.insert(k.clone(), v.clone());
    }

    Ok(payload)
}

fn validate_issue_input(input: &IetfSdJwtIssueInput) -> Result<(), IetfSdJwtVcError> {
    if input.issuer.trim().is_empty()
        || input.issuer.len() > MAX_SD_JWT_ISSUER_BYTES
        || input.salt_len < 16
        || input.salt_len > MAX_SD_JWT_SALT_BYTES
        || input.public_claims.len() > MAX_SD_JWT_DISCLOSURES
        || input.selective_claims.len() > MAX_SD_JWT_DISCLOSURES
        || input
            .public_claims
            .len()
            .checked_add(input.selective_claims.len())
            .is_none_or(|total| total > MAX_SD_JWT_DISCLOSURES)
        || input
            .public_claims
            .values()
            .any(|value| !json_value_within_limits(value))
        || input
            .selective_claims
            .values()
            .any(|value| !json_value_within_limits(value))
    {
        return Err(IetfSdJwtVcError::InvalidInput);
    }

    for key in SD_JWT_STRUCTURAL_CLAIMS {
        if input.public_claims.contains_key(key) || input.selective_claims.contains_key(key) {
            return Err(IetfSdJwtVcError::ReservedClaimKey);
        }
    }
    // Registered claims come only from the typed input fields, and SD-JWT VC
    // registered claims such as `status` must never become disclosable.
    if input
        .public_claims
        .keys()
        .chain(input.selective_claims.keys())
        .any(|key| is_ietf_issuer_owned_claim(key))
        || input
            .selective_claims
            .keys()
            .any(|key| is_non_selectively_disclosable_claim(key))
    {
        return Err(IetfSdJwtVcError::ReservedClaimKey);
    }

    let mut seen = BTreeSet::new();

    for key in input.public_claims.keys() {
        if key.trim().is_empty() {
            return Err(IetfSdJwtVcError::InvalidInput);
        }
        if !seen.insert(key.clone()) {
            return Err(IetfSdJwtVcError::DuplicateClaimKey);
        }
    }

    for key in input.selective_claims.keys() {
        if key.trim().is_empty() {
            return Err(IetfSdJwtVcError::InvalidInput);
        }
        if !seen.insert(key.clone()) {
            return Err(IetfSdJwtVcError::DuplicateClaimKey);
        }
    }

    Ok(())
}

fn build_disclosure<R: SaltRng>(
    key: &str,
    value: Value,
    salt_len: usize,
    rng: &mut R,
) -> Result<SdJwtDisclosure, IetfSdJwtVcError> {
    let mut salt = Zeroizing::new(vec![0u8; salt_len]);
    fill_nonzero_salt(rng, &mut salt)?;

    Ok(SdJwtDisclosure {
        salt_b64u: bytes_to_base64url(&salt),
        key: key.to_string(),
        value,
    })
}

fn fill_nonzero_salt<R: SaltRng>(rng: &mut R, salt: &mut [u8]) -> Result<(), IetfSdJwtVcError> {
    for _ in 0..8 {
        rng.fill_bytes(salt)?;
        if salt.iter().any(|b| *b != 0) {
            return Ok(());
        }
    }
    Err(IetfSdJwtVcError::InvalidInput)
}

fn issue_jwt_with_typ(
    claims: &Value,
    jwk: &Jwk,
    private_key: &[u8],
    jwt_type: IetfSdJwtJwtType,
) -> Result<String, IetfSdJwtVcError> {
    encode_signed_jwt_with_header_options(
        claims,
        jwk,
        private_key,
        &JwtHeaderEncodeOptions::new(Some(jwt_type.as_str().to_string())),
    )
    .map_err(map_jwt_error)
}

fn issue_jwt_with_typ_using_signer(
    claims: &Value,
    jwk: &Jwk,
    signer: &dyn Signer,
    jwt_type: IetfSdJwtJwtType,
) -> Result<String, IetfSdJwtVcError> {
    encode_signed_jwt_with_signer_and_header_options(
        claims,
        jwk,
        signer,
        &JwtHeaderEncodeOptions::new(Some(jwt_type.as_str().to_string())),
    )
    .map_err(map_jwt_error)
}

fn map_jwt_error(err: envelopes_jwt::jwt::JwtError) -> IetfSdJwtVcError {
    match err {
        envelopes_jwt::jwt::JwtError::MissingAlgorithm => IetfSdJwtVcError::MissingAlgorithm,
        envelopes_jwt::jwt::JwtError::UnsupportedAlgorithm => {
            IetfSdJwtVcError::UnsupportedAlgorithm
        }
        envelopes_jwt::jwt::JwtError::InvalidSignature => IetfSdJwtVcError::Signature,
        envelopes_jwt::jwt::JwtError::AlgorithmMismatch => IetfSdJwtVcError::UnsupportedAlgorithm,
        _ => IetfSdJwtVcError::Serialization,
    }
}

pub(crate) fn parse_sd_alg(
    payload: &Map<String, Value>,
) -> Result<IetfSdJwtHashAlgorithm, IetfSdJwtVcError> {
    match payload.get("_sd_alg") {
        None => Ok(IetfSdJwtHashAlgorithm::Sha256),
        Some(Value::String(name)) if name == IetfSdJwtHashAlgorithm::Sha256.as_str() => {
            Ok(IetfSdJwtHashAlgorithm::Sha256)
        }
        Some(_) => Err(IetfSdJwtVcError::InvalidInput),
    }
}
