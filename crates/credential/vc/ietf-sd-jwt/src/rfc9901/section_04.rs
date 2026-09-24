// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

struct TransformCtx<'a> {
    strategy: SelectiveDisclosureStrategy,
    json_paths: BTreeSet<String>,
    salt_rng: &'a mut dyn Rfc9901SaltRng,
    object_decoys: u8,
    array_decoys: u8,
    disclosures: Vec<DisclosureRecord>,
}

trait Rfc9901SaltRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), IetfSdJwtVcError>;

    fn random_bytes(&mut self, len: usize) -> Result<Zeroizing<Vec<u8>>, IetfSdJwtVcError> {
        let mut out = Zeroizing::new(vec![0u8; len]);
        self.fill_bytes(&mut out)?;
        Ok(out)
    }
}

struct Rfc9901OsSaltRng;

impl Rfc9901SaltRng for Rfc9901OsSaltRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), IetfSdJwtVcError> {
        fill_secure_random(out, RngOutputKind::Generic).map_err(|_| IetfSdJwtVcError::InvalidInput)
    }
}

#[cfg(feature = "conformance-vectors")]
#[derive(Debug, Clone)]
struct Rfc9901DeterministicSaltRng {
    state: u64,
}

#[cfg(feature = "conformance-vectors")]
impl Rfc9901DeterministicSaltRng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0xA5A5_1234_9E37_79B9
            } else {
                seed
            },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn fill(&mut self, out: &mut [u8]) {
        let mut idx = 0usize;
        while idx < out.len() {
            let block = self.next_u64().to_le_bytes();
            let take = (out.len() - idx).min(block.len());
            out[idx..idx + take].copy_from_slice(&block[..take]);
            idx += take;
        }
    }
}

#[cfg(feature = "conformance-vectors")]
impl Rfc9901SaltRng for Rfc9901DeterministicSaltRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), IetfSdJwtVcError> {
        self.fill(out);
        Ok(())
    }
}

fn transform_value(
    value: &Value,
    path: &str,
    ctx: &mut TransformCtx,
    is_root: bool,
) -> Result<Value, IetfSdJwtVcError> {
    match value {
        Value::Object(map) => transform_object(map, path, ctx, is_root),
        Value::Array(arr) => transform_array(arr, path, ctx),
        _ => Ok(value.clone()),
    }
}

fn transform_object(
    map: &Map<String, Value>,
    path: &str,
    ctx: &mut TransformCtx,
    is_root: bool,
) -> Result<Value, IetfSdJwtVcError> {
    let mut out = Map::new();
    let mut sd_digests = Vec::new();

    for (k, v) in map {
        if k == "_sd" || k == "_sd_alg" {
            return Err(IetfSdJwtVcError::ReservedClaimKey);
        }

        let child_path = if path == "$" {
            format!("$.{k}")
        } else {
            format!("{path}.{k}")
        };

        let transformed_child = transform_value(v, &child_path, ctx, false)?;

        if should_disclose(&child_path, ctx.strategy, &ctx.json_paths) {
            let encoded = encode_object_disclosure(ctx.salt_rng, k, transformed_child.clone())?;
            let digest = bytes_to_base64url(sha2_256_digest(encoded.as_bytes()).as_bytes());
            sd_digests.push(digest.clone());
            ctx.disclosures.push(DisclosureRecord {
                path: child_path,
                encoded,
                digest,
            });
        } else {
            out.insert(k.clone(), transformed_child);
        }
    }

    for _ in 0..ctx.object_decoys {
        let rnd = ctx.salt_rng.random_bytes(32)?;
        let decoy = bytes_to_base64url(sha2_256_digest(&rnd).as_bytes());
        sd_digests.push(decoy);
    }

    if !sd_digests.is_empty() {
        sd_digests.sort();
        out.insert(
            "_sd".to_string(),
            Value::Array(sd_digests.into_iter().map(Value::String).collect()),
        );
        if is_root {
            out.insert("_sd_alg".to_string(), Value::String("sha-256".to_string()));
        }
    }

    Ok(Value::Object(out))
}

fn transform_array(
    arr: &[Value],
    path: &str,
    ctx: &mut TransformCtx,
) -> Result<Value, IetfSdJwtVcError> {
    let mut out = Vec::with_capacity(arr.len() + ctx.array_decoys as usize);

    for (idx, v) in arr.iter().enumerate() {
        let child_path = format!("{path}[{idx}]");
        let transformed = transform_value(v, &child_path, ctx, false)?;

        if should_disclose(&child_path, ctx.strategy, &ctx.json_paths) {
            let encoded = encode_array_disclosure(ctx.salt_rng, transformed.clone())?;
            let digest = bytes_to_base64url(sha2_256_digest(encoded.as_bytes()).as_bytes());
            out.push(serde_json::json!({"...": digest.clone()}));
            ctx.disclosures.push(DisclosureRecord {
                path: child_path,
                encoded,
                digest,
            });
        } else {
            out.push(transformed);
        }
    }

    for _ in 0..ctx.array_decoys {
        let rnd = ctx.salt_rng.random_bytes(32)?;
        let decoy = bytes_to_base64url(sha2_256_digest(&rnd).as_bytes());
        out.push(serde_json::json!({"...": decoy}));
    }

    Ok(Value::Array(out))
}

fn should_disclose(
    path: &str,
    strategy: SelectiveDisclosureStrategy,
    json_paths: &BTreeSet<String>,
) -> bool {
    match strategy {
        SelectiveDisclosureStrategy::TopLevel => {
            if !path.starts_with("$.") {
                return false;
            }
            let rest = &path[2..];
            !rest.contains('.') && !rest.contains('[')
        }
        SelectiveDisclosureStrategy::AllLevels => true,
        SelectiveDisclosureStrategy::JsonPaths => json_paths.contains(path),
    }
}

fn encode_object_disclosure(
    rng: &mut dyn Rfc9901SaltRng,
    key: &str,
    value: Value,
) -> Result<String, IetfSdJwtVcError> {
    let salt_b64u = bytes_to_base64url(&rng.random_bytes(16)?);
    let disclosure = Value::Array(vec![
        Value::String(salt_b64u),
        Value::String(key.to_string()),
        value,
    ]);
    let bytes = Zeroizing::new(
        serde_json::to_vec(&disclosure).map_err(|_| IetfSdJwtVcError::Serialization)?,
    );
    Ok(bytes_to_base64url(&bytes))
}

fn encode_array_disclosure(
    rng: &mut dyn Rfc9901SaltRng,
    value: Value,
) -> Result<String, IetfSdJwtVcError> {
    let salt_b64u = bytes_to_base64url(&rng.random_bytes(16)?);
    let disclosure = Value::Array(vec![Value::String(salt_b64u), value]);
    let bytes = Zeroizing::new(
        serde_json::to_vec(&disclosure).map_err(|_| IetfSdJwtVcError::Serialization)?,
    );
    Ok(bytes_to_base64url(&bytes))
}
