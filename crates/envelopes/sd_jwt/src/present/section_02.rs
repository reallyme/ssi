// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pub fn process_sd_jwt_payload(
    payload: Value,
    encoded_disclosures: &[String],
    policy: SdJwtProcessingPolicy,
) -> Result<Value, SdJwtEnvelopeError> {
    let root = payload
        .as_object()
        .ok_or(SdJwtEnvelopeError::PayloadNotObject)?;
    let hash_algorithm = resolve_hash_algorithm(root)?;
    validate_payload_shape(&payload, policy)?;

    let mut expected_digests = collect_payload_digests(&payload, policy)?;
    let disclosures = accept_disclosures(
        encoded_disclosures,
        hash_algorithm,
        &mut expected_digests,
        policy,
    )?;
    resolve_value(&payload, &disclosures, policy)
}

fn resolve_hash_algorithm(
    root: &Map<String, Value>,
) -> Result<SdJwtHashAlgorithm, SdJwtEnvelopeError> {
    match root.get(SD_ALG_CLAIM_NAME) {
        Some(Value::String(value)) => SdJwtHashAlgorithm::parse(value),
        Some(_) => Err(SdJwtEnvelopeError::InvalidHashAlgorithmClaim),
        None => Ok(SdJwtHashAlgorithm::default_for_sd_jwt()),
    }
}

fn accept_disclosures(
    encoded_disclosures: &[String],
    hash_algorithm: SdJwtHashAlgorithm,
    expected_digests: &mut HashSet<String>,
    policy: SdJwtProcessingPolicy,
) -> Result<HashMap<String, DisclosureKind>, SdJwtEnvelopeError> {
    let mut pending = Vec::new();
    let mut seen = HashSet::new();
    for encoded in encoded_disclosures {
        let disclosure = decode_disclosure(encoded)?;
        let digest = digest_disclosure(disclosure.encoded(), hash_algorithm)?;
        if !seen.insert(digest.clone()) {
            return Err(SdJwtEnvelopeError::DuplicateDisclosure);
        }
        pending.push((digest, disclosure.into_kind()));
    }

    let mut accepted = HashMap::new();
    let mut progress = true;
    while progress {
        progress = false;
        let mut next = Vec::new();

        for (digest, disclosure) in pending {
            if expected_digests.contains(&digest) {
                collect_disclosure_value_digests(&disclosure, expected_digests, policy)?;
                if accepted.insert(digest, disclosure).is_some() {
                    return Err(SdJwtEnvelopeError::DuplicateDisclosure);
                }
                progress = true;
            } else {
                next.push((digest, disclosure));
            }
        }

        pending = next;
    }

    if !pending.is_empty() {
        return Err(SdJwtEnvelopeError::UnmatchedDisclosure);
    }

    Ok(accepted)
}

fn collect_disclosure_value_digests(
    disclosure: &DisclosureKind,
    expected_digests: &mut HashSet<String>,
    policy: SdJwtProcessingPolicy,
) -> Result<(), SdJwtEnvelopeError> {
    let value = match disclosure {
        DisclosureKind::ObjectProperty { claim_value, .. }
        | DisclosureKind::ArrayElement { claim_value } => claim_value,
    };

    let nested = collect_payload_digests(value, policy)?;
    for digest in nested {
        if !expected_digests.insert(digest) {
            return Err(SdJwtEnvelopeError::DuplicateDigest);
        }
    }

    Ok(())
}

fn validate_payload_shape(
    value: &Value,
    policy: SdJwtProcessingPolicy,
) -> Result<(), SdJwtEnvelopeError> {
    let mut seen = HashSet::new();
    let mut nodes = 0usize;
    validate_value(value, 0, true, policy, &mut nodes, &mut seen)
}

fn validate_value(
    value: &Value,
    depth: usize,
    is_root: bool,
    policy: SdJwtProcessingPolicy,
    nodes: &mut usize,
    seen: &mut HashSet<String>,
) -> Result<(), SdJwtEnvelopeError> {
    count_node(depth, policy, nodes)?;

    match value {
        Value::Object(object) => validate_object(object, depth, is_root, policy, nodes, seen),
        Value::Array(array) => {
            for item in array {
                validate_value(item, depth + 1, false, policy, nodes, seen)?;
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(()),
    }
}

fn validate_object(
    object: &Map<String, Value>,
    depth: usize,
    is_root: bool,
    policy: SdJwtProcessingPolicy,
    nodes: &mut usize,
    seen: &mut HashSet<String>,
) -> Result<(), SdJwtEnvelopeError> {
    if is_array_digest_placeholder(object) {
        let digest = object
            .get(ARRAY_DIGEST_CLAIM_NAME)
            .and_then(Value::as_str)
            .ok_or(SdJwtEnvelopeError::InvalidDigestPlaceholder)?;
        insert_digest(seen, digest)?;
        return Ok(());
    }

    if !is_root && object.contains_key(SD_ALG_CLAIM_NAME) {
        return Err(SdJwtEnvelopeError::InvalidReservedClaimPlacement);
    }

    if let Some(sd_value) = object.get(SD_CLAIM_NAME) {
        let sd_array = sd_value
            .as_array()
            .ok_or(SdJwtEnvelopeError::InvalidDigestPlaceholder)?;
        for digest in sd_array {
            let digest = digest
                .as_str()
                .ok_or(SdJwtEnvelopeError::InvalidDigestPlaceholder)?;
            insert_digest(seen, digest)?;
        }
    }

    for (key, nested) in object {
        if key == ARRAY_DIGEST_CLAIM_NAME {
            return Err(SdJwtEnvelopeError::InvalidReservedClaimPlacement);
        }
        validate_value(nested, depth + 1, false, policy, nodes, seen)?;
    }

    Ok(())
}

fn collect_payload_digests(
    value: &Value,
    policy: SdJwtProcessingPolicy,
) -> Result<HashSet<String>, SdJwtEnvelopeError> {
    let mut digests = HashSet::new();
    let mut nodes = 0usize;
    collect_digests(value, 0, policy, &mut nodes, &mut digests)?;
    Ok(digests)
}

fn collect_digests(
    value: &Value,
    depth: usize,
    policy: SdJwtProcessingPolicy,
    nodes: &mut usize,
    digests: &mut HashSet<String>,
) -> Result<(), SdJwtEnvelopeError> {
    count_node(depth, policy, nodes)?;

    match value {
        Value::Object(object) => {
            if is_array_digest_placeholder(object) {
                let digest = object
                    .get(ARRAY_DIGEST_CLAIM_NAME)
                    .and_then(Value::as_str)
                    .ok_or(SdJwtEnvelopeError::InvalidDigestPlaceholder)?;
                insert_digest(digests, digest)?;
                return Ok(());
            }

            if let Some(sd_value) = object.get(SD_CLAIM_NAME) {
                let sd_array = sd_value
                    .as_array()
                    .ok_or(SdJwtEnvelopeError::InvalidDigestPlaceholder)?;
                for digest in sd_array {
                    let digest = digest
                        .as_str()
                        .ok_or(SdJwtEnvelopeError::InvalidDigestPlaceholder)?;
                    insert_digest(digests, digest)?;
                }
            }

            for nested in object.values() {
                collect_digests(nested, depth + 1, policy, nodes, digests)?;
            }
            Ok(())
        }
        Value::Array(array) => {
            for item in array {
                collect_digests(item, depth + 1, policy, nodes, digests)?;
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(()),
    }
}

fn resolve_value(
    value: &Value,
    disclosures: &HashMap<String, DisclosureKind>,
    policy: SdJwtProcessingPolicy,
) -> Result<Value, SdJwtEnvelopeError> {
    let mut nodes = 0usize;
    resolve_value_inner(value, disclosures, 0, policy, &mut nodes)
}

fn resolve_value_inner(
    value: &Value,
    disclosures: &HashMap<String, DisclosureKind>,
    depth: usize,
    policy: SdJwtProcessingPolicy,
    nodes: &mut usize,
) -> Result<Value, SdJwtEnvelopeError> {
    count_node(depth, policy, nodes)?;

    match value {
        Value::Object(object) => resolve_object(object, disclosures, depth, policy, nodes),
        Value::Array(array) => resolve_array(array, disclosures, depth, policy, nodes),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(value.clone()),
    }
}

fn resolve_object(
    object: &Map<String, Value>,
    disclosures: &HashMap<String, DisclosureKind>,
    depth: usize,
    policy: SdJwtProcessingPolicy,
    nodes: &mut usize,
) -> Result<Value, SdJwtEnvelopeError> {
    let mut resolved = Map::new();
    for (key, nested) in object {
        if key == SD_CLAIM_NAME || key == SD_ALG_CLAIM_NAME || key == ARRAY_DIGEST_CLAIM_NAME {
            continue;
        }
        resolved.insert(
            key.clone(),
            resolve_value_inner(nested, disclosures, depth + 1, policy, nodes)?,
        );
    }

    let sd_digests = match object.get(SD_CLAIM_NAME) {
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or(SdJwtEnvelopeError::InvalidDigestPlaceholder)
                    .map(ToOwned::to_owned)
            })
            .collect::<Result<Vec<String>, SdJwtEnvelopeError>>()?,
        Some(_) => return Err(SdJwtEnvelopeError::InvalidDigestPlaceholder),
        None => Vec::new(),
    };

    for digest in sd_digests {
        if let Some(DisclosureKind::ObjectProperty {
            claim_name,
            claim_value,
        }) = disclosures.get(&digest)
        {
            validate_object_claim_name(claim_name)?;
            if resolved.contains_key(claim_name) {
                return Err(SdJwtEnvelopeError::ConflictingDisclosureClaim);
            }
            resolved.insert(
                claim_name.clone(),
                resolve_value_inner(claim_value, disclosures, depth + 1, policy, nodes)?,
            );
        }
    }

    Ok(Value::Object(resolved))
}

fn resolve_array(
    array: &[Value],
    disclosures: &HashMap<String, DisclosureKind>,
    depth: usize,
    policy: SdJwtProcessingPolicy,
    nodes: &mut usize,
) -> Result<Value, SdJwtEnvelopeError> {
    let mut resolved = Vec::new();
    for item in array {
        if let Value::Object(object) = item {
            if is_array_digest_placeholder(object) {
                let digest = object
                    .get(ARRAY_DIGEST_CLAIM_NAME)
                    .and_then(Value::as_str)
                    .ok_or(SdJwtEnvelopeError::InvalidDigestPlaceholder)?;
                match disclosures.get(digest) {
                    Some(DisclosureKind::ArrayElement { claim_value }) => {
                        resolved.push(resolve_value_inner(
                            claim_value,
                            disclosures,
                            depth + 1,
                            policy,
                            nodes,
                        )?);
                    }
                    Some(DisclosureKind::ObjectProperty { .. }) => {
                        return Err(SdJwtEnvelopeError::InvalidDisclosureFormat);
                    }
                    None => {}
                }
                continue;
            }
        }

        resolved.push(resolve_value_inner(
            item,
            disclosures,
            depth + 1,
            policy,
            nodes,
        )?);
    }

    Ok(Value::Array(resolved))
}

fn is_array_digest_placeholder(object: &Map<String, Value>) -> bool {
    object.len() == 1 && object.contains_key(ARRAY_DIGEST_CLAIM_NAME)
}

fn insert_digest(seen: &mut HashSet<String>, digest: &str) -> Result<(), SdJwtEnvelopeError> {
    if digest.is_empty() || !seen.insert(digest.to_owned()) {
        return Err(SdJwtEnvelopeError::DuplicateDigest);
    }
    Ok(())
}

fn count_node(
    depth: usize,
    policy: SdJwtProcessingPolicy,
    nodes: &mut usize,
) -> Result<(), SdJwtEnvelopeError> {
    if depth > policy.max_depth {
        return Err(SdJwtEnvelopeError::ProcessingDepthExceeded);
    }
    *nodes = nodes
        .checked_add(1)
        .ok_or(SdJwtEnvelopeError::ProcessingNodeLimitExceeded)?;
    if *nodes > policy.max_nodes {
        return Err(SdJwtEnvelopeError::ProcessingNodeLimitExceeded);
    }
    Ok(())
}
