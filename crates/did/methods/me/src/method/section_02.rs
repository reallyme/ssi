// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn core_key_to_cbor(vm: &CoreVerificationMethod) -> CborValue {
    CborValue::Map(vec![
        ("id".into(), CborValue::String(vm.id.clone())),
        ("type".into(), CborValue::String(vm.vm_type.clone())),
        (
            "algorithm".into(),
            CborValue::String(alg_to_did_alg_str(vm.algorithm).into()),
        ),
        (
            "publicKeyMultibase".into(),
            CborValue::String(vm.public_key_multibase.clone()),
        ),
    ])
}

fn parse_update_policy(core: &CborValue) -> Result<UpdatePolicy, DidMeError> {
    let policy = map_get(core, "updatePolicy")
        .ok_or(DidMeError::new(DidMeErrorReason::InvalidUpdatePolicy))?;

    let allowed = match map_get(policy, "allowedVerificationMethods") {
        Some(CborValue::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    CborValue::String(value) => out.push(value.clone()),
                    _ => return Err(DidMeError::new(DidMeErrorReason::InvalidUpdatePolicy)),
                }
            }
            out
        }
        _ => return Err(DidMeError::new(DidMeErrorReason::InvalidUpdatePolicy)),
    };

    let threshold = match map_get(policy, "threshold") {
        Some(CborValue::Int(value)) if *value > 0 => Some(
            u64::try_from(*value)
                .map_err(|_| DidMeError::new(DidMeErrorReason::InvalidUpdatePolicy))?,
        ),
        Some(_) => return Err(DidMeError::new(DidMeErrorReason::InvalidUpdatePolicy)),
        None => None,
    };

    Ok(UpdatePolicy {
        allowed_verification_methods: allowed,
        threshold,
    })
}

fn parse_controller_keys(core: &CborValue) -> Result<Vec<CoreVerificationMethod>, DidMeError> {
    let keys = match map_get(core, "controllerKeys") {
        Some(CborValue::Array(items)) => items,
        _ => return Err(DidMeError::new(DidMeErrorReason::InvalidControllerKeys)),
    };

    let mut out = Vec::with_capacity(keys.len());
    for key in keys {
        let id = map_get_string(key, "id")
            .ok_or(DidMeError::new(DidMeErrorReason::InvalidControllerKeys))?
            .to_owned();
        let vm_type = map_get_string(key, "type")
            .ok_or(DidMeError::new(DidMeErrorReason::InvalidControllerKeys))?
            .to_owned();
        let algorithm = map_get_string(key, "algorithm")
            .ok_or(DidMeError::new(DidMeErrorReason::InvalidControllerKeys))?;
        let public_key_multibase = map_get_string(key, "publicKeyMultibase")
            .ok_or(DidMeError::new(DidMeErrorReason::InvalidControllerKeys))?
            .to_owned();
        let algorithm = algorithm
            .parse::<Algorithm>()
            .map_err(|_| DidMeError::new(DidMeErrorReason::InvalidAlgorithm))?;

        out.push(CoreVerificationMethod {
            id,
            vm_type,
            algorithm,
            public_key_multibase,
        });
    }

    Ok(out)
}

fn controller_keys_are_sorted_by_id(keys: &[CoreVerificationMethod]) -> bool {
    keys.windows(2)
        .all(|pair| pair[0].id.as_bytes() <= pair[1].id.as_bytes())
}

fn map_get<'a>(core: &'a CborValue, key: &str) -> Option<&'a CborValue> {
    match core {
        CborValue::Map(entries) => {
            entries
                .iter()
                .find_map(|(candidate, value)| if candidate == key { Some(value) } else { None })
        }
        _ => None,
    }
}

fn map_get_string<'a>(core: &'a CborValue, key: &str) -> Option<&'a str> {
    match map_get(core, key) {
        Some(CborValue::String(value)) => Some(value),
        _ => None,
    }
}

#[cfg(test)]
#[path = "../lib_tests.rs"]
mod tests;
