// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Update authority decoded from signed canonical core state.
//!
//! The JSON `verificationMethod` and `updatePolicy` members of a DID document are
//! an unsigned projection. Attestations must therefore be verified against the
//! controller keys and update policy committed in canonical core bytes whose CID
//! is known, never against the JSON projection.

use std::collections::HashSet;

use reallyme_codec::cbor::CborValue;
use reallyme_did_types::{UpdatePolicy, VerificationMethod};

use crate::validate::limits::{MAX_RELATIONSHIP_REFERENCES, MAX_VERIFICATION_METHODS};

/// Controller keys and update policy committed into one canonical core.
pub(crate) struct CoreAuthority {
    /// Controller keys decoded from `core.controllerKeys`.
    pub(crate) verification_methods: Vec<VerificationMethod>,

    /// Update policy decoded from `core.updatePolicy`.
    pub(crate) update_policy: UpdatePolicy,
}

/// Decode the update authority committed into a canonical core value.
///
/// Returns `None` when the core omits the authority members, encodes them with
/// the wrong shape, repeats a controller key id, or exceeds resource limits.
pub(crate) fn decode_core_authority(did: &str, core: &CborValue) -> Option<CoreAuthority> {
    let keys = match map_get(core, "controllerKeys") {
        Some(CborValue::Array(items)) if items.len() <= MAX_VERIFICATION_METHODS => items,
        _ => return None,
    };

    let mut seen_ids = HashSet::with_capacity(keys.len());
    let mut verification_methods = Vec::with_capacity(keys.len());
    for key in keys {
        let id = map_get_string(key, "id")?;
        if !seen_ids.insert(id) {
            return None;
        }
        verification_methods.push(VerificationMethod {
            id: id.to_owned(),
            vm_type: map_get_string(key, "type")?.to_owned(),
            controller: did.to_owned(),
            public_key_multibase: map_get_string(key, "publicKeyMultibase")?.to_owned(),
            algorithm: Some(map_get_string(key, "algorithm")?.to_owned()),
        });
    }

    let policy = map_get(core, "updatePolicy")?;
    let allowed = match map_get(policy, "allowedVerificationMethods") {
        Some(CborValue::Array(items)) if items.len() <= MAX_RELATIONSHIP_REFERENCES => items,
        _ => return None,
    };
    let mut allowed_verification_methods = Vec::with_capacity(allowed.len());
    for item in allowed {
        match item {
            CborValue::String(value) => allowed_verification_methods.push(value.clone()),
            _ => return None,
        }
    }

    let threshold = match map_get(policy, "threshold") {
        None => None,
        Some(CborValue::Int(value)) if *value > 0 => Some(u64::try_from(*value).ok()?),
        Some(_) => return None,
    };

    Some(CoreAuthority {
        verification_methods,
        update_policy: UpdatePolicy {
            allowed_verification_methods,
            threshold,
        },
    })
}

fn map_get<'a>(value: &'a CborValue, key: &str) -> Option<&'a CborValue> {
    match value {
        CborValue::Map(entries) => {
            entries
                .iter()
                .find_map(|(candidate, child)| if candidate == key { Some(child) } else { None })
        }
        _ => None,
    }
}

fn map_get_string<'a>(value: &'a CborValue, key: &str) -> Option<&'a str> {
    match map_get(value, key) {
        Some(CborValue::String(text)) => Some(text),
        _ => None,
    }
}
