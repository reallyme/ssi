// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Build Merkle tree, padding leaves to next power of 2 by repeating last leaf.
///
/// Returns:
/// - root
/// - depth
/// - merkle paths for each original leaf index (sibling hashes bottom-up)
fn build_merkle(mut leaves: Vec<Hash32>, node_tag: &[u8]) -> Result<MerkleBuild, VcError> {
    if leaves.is_empty() {
        return Err(VcError::InvalidCredential);
    }

    let orig_len = leaves.len();
    let target = next_pow2(orig_len)?;

    while leaves.len() < target {
        let last = *leaves.last().ok_or(VcError::InvalidCredential)?;
        leaves.push(last);
    }

    let mut levels: Vec<Vec<Hash32>> = Vec::new();
    levels.push(leaves);

    while levels.last().map(|lvl| lvl.len()).unwrap_or(0) > 1 {
        let cur = levels.last().ok_or(VcError::InvalidCredential)?;
        let mut nxt = Vec::with_capacity(cur.len().div_ceil(2));

        // Levels are padded to a power of two, so every node has a right
        // sibling. A remainder would indicate a construction invariant breach.
        let (pairs, remainder) = cur.as_chunks::<2>();
        if !remainder.is_empty() {
            return Err(VcError::InvalidCredential);
        }
        for [l, r] in pairs {
            nxt.push(node_digest(node_tag, l, r)?);
        }

        levels.push(nxt);
    }

    let root = levels
        .last()
        .and_then(|lvl| lvl.first().copied())
        .ok_or(VcError::InvalidCredential)?;
    let depth = levels.len().saturating_sub(1);

    // For each original leaf index, compute sibling path
    let mut paths_by_index: Vec<Vec<Hash32>> = vec![Vec::new(); orig_len];

    for (idx, slot) in paths_by_index.iter_mut().enumerate() {
        let mut path = Vec::with_capacity(depth);
        let mut i = idx;

        for lvl in levels.iter().take(depth) {
            let sib = lvl
                .get(i ^ 1)
                .or_else(|| lvl.get(i))
                .copied()
                .ok_or(VcError::InvalidCredential)?;
            path.push(sib);
            i >>= 1;
        }

        *slot = path;
    }

    Ok(MerkleBuild {
        root,
        depth,
        paths_by_index,
    })
}

fn next_pow2(n: usize) -> Result<usize, VcError> {
    if n <= 1 {
        Ok(1)
    } else {
        n.checked_next_power_of_two()
            .ok_or(VcError::InvalidCredential)
    }
}

// -----------------------------------------------------------------------------
// Helpers: claim encoding + hygiene
// -----------------------------------------------------------------------------

fn assert_safe_claim_name(name: &str) -> Result<(), VcError> {
    // Match TypeScript claim-name hygiene:
    // - reject '/'
    // - reject control chars
    // - reject DEL
    if name
        .chars()
        .any(|c| c == '/' || u32::from(c) < 0x20 || u32::from(c) == 0x7f)
    {
        return Err(VcError::InvalidCredential);
    }
    Ok(())
}

/// TS-compatible “JCS-like” canonical JSON bytes:
/// - objects: keys sorted recursively
/// - arrays: order preserved
/// - primitives: unchanged
fn jcs_utf8_bytes(v: &serde_json::Value) -> Result<Vec<u8>, VcError> {
    let norm = normalize_json_value(v);
    serde_json::to_vec(&norm).map_err(|_| VcError::InvalidCredential)
}

fn normalize_json_value(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(normalize_json_value).collect())
        }
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            // serde_json::Map preserves insertion order, so insert in sorted key order
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for k in keys {
                out.insert(k.clone(), normalize_json_value(&map[k]));
            }
            serde_json::Value::Object(out)
        }
        other => other.clone(),
    }
}

// -----------------------------------------------------------------------------
// Salts
// -----------------------------------------------------------------------------

pub trait SaltRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), VcError>;
}

pub struct OsSaltRng;

impl SaltRng for OsSaltRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), VcError> {
        fill_secure_random(out, RngOutputKind::Generic).map_err(|_| VcError::EntropyUnavailable)
    }
}

#[cfg(feature = "conformance-vectors")]
pub struct DeterministicRng {
    state: u64,
}

#[cfg(feature = "conformance-vectors")]
impl DeterministicRng {
    /// Creates a deterministic test-vector generator.
    ///
    /// This generator is reproducible and MUST NOT be used for production
    /// credential issuance. Production callers should use [`OsSaltRng`].
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
        }
    }
}

#[cfg(feature = "conformance-vectors")]
impl SaltRng for DeterministicRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), VcError> {
        for b in out.iter_mut() {
            self.state ^= self.state << 13;
            self.state ^= self.state >> 7;
            self.state ^= self.state << 17;
            *b = (self.state & 0xff) as u8;
        }
        Ok(())
    }
}

fn generate_nonzero_salt<R: SaltRng + ?Sized>(
    rng: &mut R,
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, VcError> {
    let mut salt = Zeroizing::new(vec![0u8; len]);
    for _ in 0..8 {
        rng.fill_bytes(&mut salt)?;
        if salt.iter().any(|b| *b != 0) {
            return Ok(salt);
        }
    }
    Err(VcError::EntropyUnavailable)
}
