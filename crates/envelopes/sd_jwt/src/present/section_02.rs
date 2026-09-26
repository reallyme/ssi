// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdJwtProcessingPolicy {
    pub max_depth: usize,
    pub max_nodes: usize,
}

impl SdJwtProcessingPolicy {
    /// Clamp caller-supplied limits to the crate's hard processing ceilings.
    pub(crate) fn clamped(self) -> Self {
        SdJwtProcessingPolicy {
            max_depth: self.max_depth.min(MAX_SD_JWT_PROCESSING_DEPTH),
            max_nodes: self.max_nodes.min(MAX_SD_JWT_PROCESSING_NODES),
        }
    }
}

impl Default for SdJwtProcessingPolicy {
    fn default() -> Self {
        SdJwtProcessingPolicy {
            max_depth: DEFAULT_MAX_DEPTH,
            max_nodes: DEFAULT_MAX_NODES,
        }
    }
}

/// Resolve an issuer payload against its disclosures.
///
/// The owned payload is zeroized before returning because it can carry
/// plaintext claims that the caller has handed over to this function.
pub fn process_sd_jwt_payload(
    mut payload: Value,
    encoded_disclosures: &[String],
    policy: SdJwtProcessingPolicy,
) -> Result<Value, SdJwtEnvelopeError> {
    let result = resolve_sd_jwt_payload(&payload, encoded_disclosures, policy);
    zeroize_json_value(&mut payload);
    result
}

pub(crate) fn resolve_sd_jwt_payload(
    payload: &Value,
    encoded_disclosures: &[String],
    policy: SdJwtProcessingPolicy,
) -> Result<Value, SdJwtEnvelopeError> {
    let policy = policy.clamped();
    let root = payload
        .as_object()
        .ok_or(SdJwtEnvelopeError::PayloadNotObject)?;
    let hash_algorithm = resolve_hash_algorithm(root)?;

    let mut nodes = 0usize;
    let mut expected_digests = HashSet::new();
    validate_value(
        payload,
        ValuePosition::Root,
        0,
        policy,
        &mut nodes,
        &mut expected_digests,
    )?;
    let disclosures = accept_disclosures(
        encoded_disclosures,
        hash_algorithm,
        &mut expected_digests,
        policy,
        &mut nodes,
    )?;
    resolve_value(payload, &disclosures, policy)
}

/// Structural position of a JSON value inside an SD-JWT payload.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ValuePosition {
    /// The issuer payload root, the only place `_sd_alg` may appear.
    Root,
    /// A direct array element, the only place a `{"...": digest}` placeholder
    /// may appear.
    ArrayElement,
    /// Any other nested position.
    Nested,
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
    nodes: &mut usize,
) -> Result<HashMap<String, DisclosureKind>, SdJwtEnvelopeError> {
    let mut pending = Vec::with_capacity(encoded_disclosures.len());
    let mut seen = HashSet::with_capacity(encoded_disclosures.len());
    for encoded in encoded_disclosures {
        let disclosure = decode_disclosure(encoded)?;
        let digest = digest_disclosure(disclosure.encoded(), hash_algorithm)?;
        if !seen.insert(digest.clone()) {
            return Err(SdJwtEnvelopeError::DuplicateDisclosure);
        }
        pending.push((digest, disclosure.into_kind()));
    }

    let mut accepted = HashMap::with_capacity(pending.len());
    let mut progress = true;
    while progress {
        progress = false;
        let mut next = Vec::with_capacity(pending.len());

        for (digest, disclosure) in pending {
            if expected_digests.contains(&digest) {
                collect_disclosure_value_digests(&disclosure, expected_digests, policy, nodes)?;
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

/// Shape-validate a disclosed value and register the digests it embeds.
///
/// Disclosed values obey the same structural rules as the issuer payload:
/// `_sd_alg` is forbidden, `...` may appear only as an array placeholder, and
/// every digest must be globally unique across the whole disclosure graph.
fn collect_disclosure_value_digests(
    disclosure: &DisclosureKind,
    expected_digests: &mut HashSet<String>,
    policy: SdJwtProcessingPolicy,
    nodes: &mut usize,
) -> Result<(), SdJwtEnvelopeError> {
    let value = match disclosure {
        DisclosureKind::ObjectProperty { claim_value, .. }
        | DisclosureKind::ArrayElement { claim_value } => claim_value,
    };

    let mut nested = HashSet::new();
    validate_value(value, ValuePosition::Nested, 0, policy, nodes, &mut nested)?;
    for digest in nested {
        if !expected_digests.insert(digest) {
            return Err(SdJwtEnvelopeError::DuplicateDigest);
        }
    }

    Ok(())
}

fn validate_value(
    value: &Value,
    position: ValuePosition,
    depth: usize,
    policy: SdJwtProcessingPolicy,
    nodes: &mut usize,
    seen: &mut HashSet<String>,
) -> Result<(), SdJwtEnvelopeError> {
    count_node(depth, policy, nodes)?;

    match value {
        Value::Object(object) => validate_object(object, position, depth, policy, nodes, seen),
        Value::Array(array) => {
            let child_depth = next_depth(depth)?;
            for item in array {
                validate_value(
                    item,
                    ValuePosition::ArrayElement,
                    child_depth,
                    policy,
                    nodes,
                    seen,
                )?;
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(()),
    }
}

fn validate_object(
    object: &Map<String, Value>,
    position: ValuePosition,
    depth: usize,
    policy: SdJwtProcessingPolicy,
    nodes: &mut usize,
    seen: &mut HashSet<String>,
) -> Result<(), SdJwtEnvelopeError> {
    if is_array_digest_placeholder(object) {
        if position != ValuePosition::ArrayElement {
            return Err(SdJwtEnvelopeError::InvalidReservedClaimPlacement);
        }
        let digest = object
            .get(ARRAY_DIGEST_CLAIM_NAME)
            .and_then(Value::as_str)
            .ok_or(SdJwtEnvelopeError::InvalidDigestPlaceholder)?;
        insert_digest(seen, digest)?;
        return Ok(());
    }

    if position != ValuePosition::Root && object.contains_key(SD_ALG_CLAIM_NAME) {
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

    let child_depth = next_depth(depth)?;
    for (key, nested) in object {
        if key == ARRAY_DIGEST_CLAIM_NAME {
            return Err(SdJwtEnvelopeError::InvalidReservedClaimPlacement);
        }
        if key == SD_CLAIM_NAME || key == SD_ALG_CLAIM_NAME {
            continue;
        }
        validate_value(
            nested,
            ValuePosition::Nested,
            child_depth,
            policy,
            nodes,
            seen,
        )?;
    }

    Ok(())
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
            resolve_value_inner(nested, disclosures, next_depth(depth)?, policy, nodes)?,
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
        match disclosures.get(&digest) {
            Some(DisclosureKind::ObjectProperty {
                claim_name,
                claim_value,
            }) => {
                validate_object_claim_name(claim_name)?;
                if depth == 0 && is_non_selectively_disclosable_claim(claim_name) {
                    return Err(SdJwtEnvelopeError::NonSelectivelyDisclosableClaim);
                }
                if resolved.contains_key(claim_name) {
                    return Err(SdJwtEnvelopeError::ConflictingDisclosureClaim);
                }
                resolved.insert(
                    claim_name.clone(),
                    resolve_value_inner(
                        claim_value,
                        disclosures,
                        next_depth(depth)?,
                        policy,
                        nodes,
                    )?,
                );
            }
            // RFC 9901 §7.1: an array-element disclosure referenced from an
            // object `_sd` array is malformed and must not be silently skipped.
            Some(DisclosureKind::ArrayElement { .. }) => {
                return Err(SdJwtEnvelopeError::InvalidDisclosureFormat);
            }
            None => {}
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
                            next_depth(depth)?,
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
            next_depth(depth)?,
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

fn next_depth(depth: usize) -> Result<usize, SdJwtEnvelopeError> {
    depth
        .checked_add(1)
        .ok_or(SdJwtEnvelopeError::ProcessingDepthExceeded)
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
