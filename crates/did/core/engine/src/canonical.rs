// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use identity_core_primitives::algorithm_map::alg_to_did_alg_str;

use crate::core::DidCore;
use crate::error::{CanonicalStateViolation, DidCoreError};
use reallyme_codec::cbor::{encode_dag_cbor, CborValue};

/// Trait for objects that have a canonical CBOR representation.
pub trait Canonical {
    /// Return the DAG-CBOR bytes that define this value's stable content address.
    fn canonical_cbor(&self) -> Result<Vec<u8>, DidCoreError>;
}

impl Canonical for DidCore {
    fn canonical_cbor(&self) -> Result<Vec<u8>, DidCoreError> {
        let value = did_core_to_cbor(self)?;
        encode_dag_cbor(&value)
            .map_err(|_| DidCoreError::InvalidCanonicalState(CanonicalStateViolation::CborEncoding))
    }
}

fn did_core_to_cbor(core: &DidCore) -> Result<CborValue, DidCoreError> {
    use reallyme_codec::cbor::CborValue::{Array, Bytes, Int, Map, String};

    let sequence = i64::try_from(core.sequence).map_err(|_| {
        DidCoreError::InvalidCanonicalState(CanonicalStateViolation::SequenceOutOfRange)
    })?;

    let mut entries = vec![
        ("id".into(), String(core.id.clone())),
        ("sequence".into(), Int(sequence)),
        (
            "controller".into(),
            Array(core.controller.iter().cloned().map(String).collect()),
        ),
        (
            "controllerKeys".into(),
            Array(core.controller_keys.iter().map(vm_to_cbor).collect()),
        ),
        (
            "authenticationKeys".into(),
            Array(core.authentication.iter().cloned().map(String).collect()),
        ),
        (
            "assertionKeys".into(),
            Array(core.assertion.iter().cloned().map(String).collect()),
        ),
        (
            "keyAgreementKeys".into(),
            Array(core.key_agreement.iter().cloned().map(String).collect()),
        ),
        (
            "services".into(),
            Array(core.services.iter().map(service_to_cbor).collect()),
        ),
        (
            "updatePolicy".into(),
            update_policy_to_cbor(&core.update_policy)?,
        ),
    ];

    if let Some(prev) = &core.prev {
        entries.push(("prev".into(), String(prev.clone())));
    }

    if let Some(nonce) = &core.nonce {
        entries.push(("nonce".into(), Bytes(nonce.clone())));
    }

    Ok(Map(entries))
}

use crate::core::{CanonicalService, CoreVerificationMethod, UpdatePolicy};

fn vm_to_cbor(vm: &CoreVerificationMethod) -> reallyme_codec::cbor::CborValue {
    use reallyme_codec::cbor::CborValue::{Map, String};

    Map(vec![
        ("id".into(), String(vm.id.clone())),
        ("type".into(), String(vm.vm_type.clone())),
        (
            "algorithm".into(),
            String(alg_to_did_alg_str(vm.algorithm).into()),
        ),
        (
            "publicKeyMultibase".into(),
            String(vm.public_key_multibase.clone()),
        ),
    ])
}

fn service_to_cbor(svc: &CanonicalService) -> reallyme_codec::cbor::CborValue {
    use reallyme_codec::cbor::CborValue::{Map, String};

    Map(vec![
        ("id".into(), String(svc.id.clone())),
        ("type".into(), String(svc.service_type.clone())),
        ("serviceEndpoint".into(), svc.service_endpoint.clone()),
    ])
}

/// Convert an update policy into its canonical CBOR map representation.
pub fn update_policy_to_cbor(
    p: &UpdatePolicy,
) -> Result<reallyme_codec::cbor::CborValue, DidCoreError> {
    use reallyme_codec::cbor::CborValue::{Array, Int, Map, String};

    let mut entries = vec![(
        "allowedVerificationMethods".into(),
        Array(
            p.allowed_verification_methods
                .iter()
                .cloned()
                .map(String)
                .collect(),
        ),
    )];

    if let Some(threshold) = p.threshold {
        let threshold = i64::try_from(threshold).map_err(|_| {
            DidCoreError::InvalidCanonicalState(CanonicalStateViolation::ThresholdOutOfRange)
        })?;
        entries.push(("threshold".into(), Int(threshold)));
    }

    Ok(Map(entries))
}

use serde_json::Value;

/// Canonicalize JSON values for deterministic encoding.
///
/// Rules:
/// - Arrays: preserve order, recurse
/// - Objects: keys explicitly sorted before insertion into the output map
/// - Primitives: unchanged
pub fn normalize_json_value(v: &Value) -> Value {
    match v {
        Value::Array(arr) => Value::Array(arr.iter().map(normalize_json_value).collect()),
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            for (k, val) in entries {
                out.insert(k.clone(), normalize_json_value(val));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Convert a JSON value into the restricted CBOR value profile used by DID services.
pub fn json_to_cbor_value(value: &Value) -> Result<CborValue, DidCoreError> {
    match value {
        Value::Null => Ok(CborValue::Null),
        Value::Bool(v) => Ok(CborValue::Bool(*v)),
        Value::Number(n) => {
            n.as_i64()
                .map(CborValue::Int)
                .ok_or(DidCoreError::InvalidCanonicalState(
                    CanonicalStateViolation::ServiceEndpointNumber,
                ))
        }
        Value::String(s) => Ok(CborValue::String(s.clone())),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(json_to_cbor_value(item)?);
            }
            Ok(CborValue::Array(out))
        }
        Value::Object(map) => {
            let mut out = Vec::with_capacity(map.len());
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            for (key, item) in entries {
                out.push((key.clone(), json_to_cbor_value(item)?));
            }
            Ok(CborValue::Map(out))
        }
    }
}

/// Convert a canonical CBOR value back into its JSON DID Document projection.
///
/// # Errors
///
/// Returns an error when Codec exposes a CBOR value outside the deliberately
/// bounded DID canonical-state profile.
pub fn cbor_to_json_value(value: &CborValue) -> Result<serde_json::Value, DidCoreError> {
    match value {
        CborValue::Null => Ok(serde_json::Value::Null),
        CborValue::Bool(v) => Ok(serde_json::Value::Bool(*v)),
        CborValue::Int(v) => Ok(serde_json::Value::Number(serde_json::Number::from(*v))),
        CborValue::String(v) => Ok(serde_json::Value::String(v.clone())),
        // JSON has no byte-string primitive. Projecting bytes as an integer
        // array would collide with a genuine CBOR array and make the mapping
        // non-injective, so this boundary fails closed instead.
        CborValue::Bytes(_) => Err(DidCoreError::InvalidCanonicalState(
            CanonicalStateViolation::UnsupportedCborValue,
        )),
        CborValue::Array(items) => Ok(serde_json::Value::Array(
            items
                .iter()
                .map(cbor_to_json_value)
                .collect::<Result<Vec<_>, _>>()?,
        )),
        CborValue::Map(entries) => {
            let mut out = serde_json::Map::new();
            for (key, item) in entries {
                out.insert(key.clone(), cbor_to_json_value(item)?);
            }
            Ok(serde_json::Value::Object(out))
        }
        _ => Err(DidCoreError::InvalidCanonicalState(
            CanonicalStateViolation::UnsupportedCborValue,
        )),
    }
}
