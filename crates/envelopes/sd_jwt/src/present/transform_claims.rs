// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn transform_value(
    value: &Value,
    path: &str,
    is_root: bool,
    policy: &SdJwtIssuancePolicy,
    salt_source: &mut impl SdJwtSaltSource,
    records: &mut Vec<DisclosureRecord>,
    matched_paths: &mut BTreeSet<String>,
) -> Result<Value, SdJwtEnvelopeError> {
    match value {
        Value::Object(object) => {
            transform_object(
                object,
                path,
                is_root,
                policy,
                salt_source,
                records,
                matched_paths,
            )
        }
        Value::Array(array) => transform_array(
            array,
            path,
            policy,
            salt_source,
            records,
            matched_paths,
        ),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(value.clone()),
    }
}

fn transform_object(
    object: &Map<String, Value>,
    path: &str,
    is_root: bool,
    policy: &SdJwtIssuancePolicy,
    salt_source: &mut impl SdJwtSaltSource,
    records: &mut Vec<DisclosureRecord>,
    matched_paths: &mut BTreeSet<String>,
) -> Result<Value, SdJwtEnvelopeError> {
    let mut output = Map::new();
    let mut sd_digests = Vec::new();

    for (key, value) in object {
        if key == SD_CLAIM_NAME || key == SD_ALG_CLAIM_NAME || key == ARRAY_DIGEST_CLAIM_NAME {
            return Err(SdJwtEnvelopeError::InvalidReservedClaimPlacement);
        }

        let child_path = object_child_path(path, key);
        if is_root && is_non_selectively_disclosable_claim(key) {
            // Registered SD-JWT VC claims stay verbatim in the issuer payload;
            // neither the claim nor any nested member becomes disclosable.
            output.insert(key.clone(), value.clone());
            continue;
        }
        let transformed_child =
            transform_value(
                value,
                &child_path,
                false,
                policy,
                salt_source,
                records,
                matched_paths,
            )?;
        if should_disclose(&child_path, is_root, &policy.disclosure_strategy) {
            matched_paths.insert(child_path.clone());
            let salt = salt_source.next_salt()?;
            let disclosure =
                create_object_property_disclosure(&salt, key, transformed_child.clone())?;
            let digest = digest_disclosure(disclosure.encoded(), SdJwtHashAlgorithm::Sha256)?;
            sd_digests.push(digest.clone());
            records.push(DisclosureRecord {
                path: child_path,
                encoded: disclosure.encoded().to_owned(),
                digest,
            });
        } else {
            output.insert(key.clone(), transformed_child);
        }
    }

    add_object_decoys(policy, salt_source, &mut sd_digests)?;
    if !sd_digests.is_empty() {
        sd_digests.sort();
        output.insert(
            SD_CLAIM_NAME.to_owned(),
            Value::Array(sd_digests.into_iter().map(Value::String).collect()),
        );
        if is_root {
            output.insert(
                SD_ALG_CLAIM_NAME.to_owned(),
                Value::String(SdJwtHashAlgorithm::Sha256.name().to_owned()),
            );
        }
    }

    Ok(Value::Object(output))
}

fn transform_array(
    array: &[Value],
    path: &str,
    policy: &SdJwtIssuancePolicy,
    salt_source: &mut impl SdJwtSaltSource,
    records: &mut Vec<DisclosureRecord>,
    matched_paths: &mut BTreeSet<String>,
) -> Result<Value, SdJwtEnvelopeError> {
    let capacity = array
        .len()
        .checked_add(usize::from(policy.decoys.array_decoys))
        .ok_or(SdJwtEnvelopeError::InvalidIssuanceInput)?;
    let mut output = Vec::with_capacity(capacity);

    for (index, value) in array.iter().enumerate() {
        let child_path = array_child_path(path, index);
        let transformed_child =
            transform_value(
                value,
                &child_path,
                false,
                policy,
                salt_source,
                records,
                matched_paths,
            )?;
        if should_disclose(&child_path, false, &policy.disclosure_strategy) {
            matched_paths.insert(child_path.clone());
            let salt = salt_source.next_salt()?;
            let disclosure = create_array_element_disclosure(&salt, transformed_child)?;
            let digest = digest_disclosure(disclosure.encoded(), SdJwtHashAlgorithm::Sha256)?;
            output.push(array_placeholder(&digest));
            records.push(DisclosureRecord {
                path: child_path,
                encoded: disclosure.encoded().to_owned(),
                digest,
            });
        } else {
            output.push(transformed_child);
        }
    }

    add_array_decoys(policy, salt_source, &mut output)?;
    Ok(Value::Array(output))
}

fn add_object_decoys(
    policy: &SdJwtIssuancePolicy,
    salt_source: &mut impl SdJwtSaltSource,
    sd_digests: &mut Vec<String>,
) -> Result<(), SdJwtEnvelopeError> {
    for _ in 0..policy.decoys.object_decoys {
        sd_digests.push(salt_source.next_decoy_digest()?);
    }

    Ok(())
}

fn add_array_decoys(
    policy: &SdJwtIssuancePolicy,
    salt_source: &mut impl SdJwtSaltSource,
    output: &mut Vec<Value>,
) -> Result<(), SdJwtEnvelopeError> {
    for _ in 0..policy.decoys.array_decoys {
        let digest = salt_source.next_decoy_digest()?;
        // RFC 9901 §4.2.5: decoys appended at a fixed position would be
        // trivially distinguishable from real element placeholders.
        let position = random_insert_position(salt_source, output.len())?;
        output.insert(position, array_placeholder(&digest));
    }

    Ok(())
}

/// Draw an insertion index in `0..=len` from fresh, unpublished salt-source
/// entropy so decoy placement is independent of any published digest.
fn random_insert_position(
    salt_source: &mut impl SdJwtSaltSource,
    len: usize,
) -> Result<usize, SdJwtEnvelopeError> {
    const POSITION_ENTROPY_BYTES: usize = 8;
    let entropy = salt_source.next_decoy_digest()?;
    let decoded = Zeroizing::new(
        base64url_to_bytes(&entropy).map_err(|_| SdJwtEnvelopeError::InvalidIssuanceInput)?,
    );
    let sample_bytes = decoded
        .len()
        .checked_sub(POSITION_ENTROPY_BYTES)
        .and_then(|start| decoded.get(start..))
        .and_then(|tail| <[u8; POSITION_ENTROPY_BYTES]>::try_from(tail).ok())
        .ok_or(SdJwtEnvelopeError::InvalidIssuanceInput)?;
    let bound = len
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(SdJwtEnvelopeError::InvalidIssuanceInput)?;
    // The modulo bias is below bound / 2^64 for any bounded payload array.
    let position = u64::from_be_bytes(sample_bytes)
        .checked_rem(bound)
        .ok_or(SdJwtEnvelopeError::InvalidIssuanceInput)?;
    usize::try_from(position)
        .map_err(|_| SdJwtEnvelopeError::InvalidIssuanceInput)
}

/// Reject explicit JSON paths that would make a registered claim, or any
/// member nested under it, selectively disclosable.
fn validate_disclosure_strategy(
    strategy: &SdJwtDisclosureStrategy,
) -> Result<(), SdJwtEnvelopeError> {
    let SdJwtDisclosureStrategy::JsonPaths(paths) = strategy else {
        return Ok(());
    };
    for path in paths {
        let Some(rest) = path.strip_prefix("$.") else {
            continue;
        };
        let top_level_name = rest
            .find(['.', '['])
            .map_or(rest, |end| rest.get(..end).unwrap_or(rest));
        if is_non_selectively_disclosable_claim(top_level_name) {
            return Err(SdJwtEnvelopeError::NonSelectivelyDisclosableClaim);
        }
    }
    Ok(())
}

fn should_disclose(
    path: &str,
    is_direct_root_member: bool,
    strategy: &SdJwtDisclosureStrategy,
) -> bool {
    match strategy {
        SdJwtDisclosureStrategy::None => false,
        SdJwtDisclosureStrategy::TopLevel => is_direct_root_member,
        SdJwtDisclosureStrategy::AllLevels => true,
        SdJwtDisclosureStrategy::JsonPaths(paths) => paths.contains(path),
    }
}

fn object_child_path(parent: &str, key: &str) -> String {
    if parent == "$" {
        format!("$.{key}")
    } else {
        format!("{parent}.{key}")
    }
}

fn array_child_path(parent: &str, index: usize) -> String {
    format!("{parent}[{index}]")
}

fn array_placeholder(digest: &str) -> Value {
    let mut object = Map::new();
    object.insert(
        ARRAY_DIGEST_CLAIM_NAME.to_owned(),
        Value::String(digest.to_owned()),
    );
    Value::Object(object)
}
