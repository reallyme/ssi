// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use std::io::Write;
use zeroize::Zeroizing;

use super::{
    encode_proto, presentation_to_proto, take_proto_into_presentation,
    validate_presentation_resource_limits, validate_proto_resource_limits, PbPresentation,
    Presentation, SensitivePresentationProto, VpProtoError, MAX_PRESENTATION_PROTO_JSON_BYTES,
    MAX_PRESENTATION_PROTO_JSON_COLLECTION_ITEMS, MAX_PRESENTATION_PROTO_JSON_NODES,
};

/// Serialize the generated protobuf message using Buffa's protobuf JSON rules.
pub fn proto_to_json(presentation: &PbPresentation) -> Result<Zeroizing<String>, VpProtoError> {
    validate_proto_resource_limits(presentation)?;
    let mut writer = BoundedJsonWriter::new(MAX_PRESENTATION_PROTO_JSON_BYTES);
    serde_json::to_writer(&mut writer, presentation).map_err(|_| VpProtoError::JsonSerialize)?;
    writer.into_string()
}

struct BoundedJsonWriter {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}

impl BoundedJsonWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::with_capacity(limit)),
            limit,
        }
    }

    fn into_string(mut self) -> Result<Zeroizing<String>, VpProtoError> {
        match String::from_utf8(core::mem::take(&mut *self.bytes)) {
            Ok(value) => Ok(Zeroizing::new(value)),
            Err(error) => {
                let mut bytes = error.into_bytes();
                zeroize::Zeroize::zeroize(&mut bytes);
                Err(VpProtoError::JsonSerialize)
            }
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let new_len = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("JSON output limit exceeded"))?;
        if new_len > self.limit {
            return Err(std::io::Error::other("JSON output limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Deserialize a generated protobuf message using Buffa's protobuf JSON rules.
pub fn json_to_proto(json: &str) -> Result<SensitivePresentationProto, VpProtoError> {
    if json.len() > MAX_PRESENTATION_PROTO_JSON_BYTES {
        return Err(VpProtoError::JsonTooLarge);
    }

    let value = serde_json::from_str::<DuplicateRejectingJsonValue>(json)
        .map_err(|_| VpProtoError::JsonDeserialize)?
        .0;
    validate_json_resource_limits(&value)?;
    validate_proto_json_shape(&value)?;
    let presentation: PbPresentation =
        serde_json::from_value(value).map_err(|_| VpProtoError::JsonDeserialize)?;
    let encoded = encode_proto(&presentation)?;
    drop(encoded);
    Ok(SensitivePresentationProto::new(presentation))
}

fn validate_proto_json_shape(value: &serde_json::Value) -> Result<(), VpProtoError> {
    let root = json_object_with_keys(value, &["zk", "sdJwtVc", "sd_jwt_vc", "mdoc"])?;
    if root.len() != 1 {
        return Err(VpProtoError::JsonDeserialize);
    }
    if let Some(value) = root.get("zk") {
        validate_zk_json(value)?;
    }
    if let Some(value) = root.get("sdJwtVc").or_else(|| root.get("sd_jwt_vc")) {
        json_object_with_keys(
            value,
            &[
                "sdJwt",
                "sd_jwt",
                "disclosures",
                "kbJwt",
                "kb_jwt",
                "vct",
                "envelopeHash",
                "envelope_hash",
            ],
        )?;
    }
    if let Some(value) = root.get("mdoc") {
        json_object_with_keys(
            value,
            &[
                "deviceResponse",
                "device_response",
                "envelopeHash",
                "envelope_hash",
                "docType",
                "doc_type",
            ],
        )?;
    }
    Ok(())
}

fn validate_zk_json(value: &serde_json::Value) -> Result<(), VpProtoError> {
    let zk = json_object_with_keys(
        value,
        &[
            "freshness",
            "credential",
            "disclosures",
            "zkProof",
            "zk_proof",
            "qeaa",
        ],
    )?;
    if let Some(value) = zk.get("freshness") {
        json_object_with_keys(
            value,
            &[
                "challenge",
                "audienceHash",
                "audience_hash",
                "expiryUnix",
                "expiry_unix",
            ],
        )?;
    }
    if let Some(value) = zk.get("credential") {
        let credential = json_object_with_keys(
            value,
            &[
                "envelopeHash",
                "envelope_hash",
                "issuerDid",
                "issuer_did",
                "status",
            ],
        )?;
        if let Some(status) = credential.get("status") {
            json_object_with_keys(
                status,
                &[
                    "statusListUrl",
                    "status_list_url",
                    "statusListId",
                    "status_list_id",
                    "statusListIndex",
                    "status_list_index",
                    "purpose",
                ],
            )?;
        }
    }
    if let Some(serde_json::Value::Array(disclosures)) = zk.get("disclosures") {
        for disclosure in disclosures {
            let disclosure = json_object_with_keys(
                disclosure,
                &[
                    "claimPath",
                    "claim_path",
                    "mode",
                    "revealedValue",
                    "revealed_value",
                    "threshold",
                    "range",
                    "set",
                ],
            )?;
            if let Some(range) = disclosure.get("range") {
                json_object_with_keys(range, &["min", "max"])?;
            }
            if let Some(set) = disclosure.get("set") {
                json_object_with_keys(set, &["values"])?;
            }
        }
    } else if zk.contains_key("disclosures") {
        return Err(VpProtoError::JsonDeserialize);
    }
    if let Some(value) = zk.get("zkProof").or_else(|| zk.get("zk_proof")) {
        let proof = json_object_with_keys(
            value,
            &[
                "circuitId",
                "circuit_id",
                "circuitVersion",
                "circuit_version",
                "vkId",
                "vk_id",
                "proofBytes",
                "proof_bytes",
                "publicInputs",
                "public_inputs",
                "proofSuite",
                "proof_suite",
                "artifactManifestSha256",
                "artifact_manifest_sha256",
            ],
        )?;
        if proof
            .get("publicInputs")
            .or_else(|| proof.get("public_inputs"))
            .is_some_and(|inputs| !inputs.is_object())
        {
            return Err(VpProtoError::JsonDeserialize);
        }
    }
    if let Some(value) = zk.get("qeaa").filter(|value| !value.is_null()) {
        json_object_with_keys(
            value,
            &[
                "required",
                "auditReportHash",
                "audit_report_hash",
                "maxStatusAgeSeconds",
                "max_status_age_seconds",
            ],
        )?;
    }
    Ok(())
}

struct DuplicateRejectingJsonValue(serde_json::Value);

impl<'de> Deserialize<'de> for DuplicateRejectingJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateRejectingJsonVisitor)
    }
}

struct DuplicateRejectingJsonVisitor;

impl<'de> Visitor<'de> for DuplicateRejectingJsonVisitor {
    type Value = DuplicateRejectingJsonValue;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a JSON value without duplicate object members")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJsonValue(serde_json::Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJsonValue(serde_json::Value::Number(
            value.into(),
        )))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJsonValue(serde_json::Value::Number(
            value.into(),
        )))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .map(DuplicateRejectingJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJsonValue(serde_json::Value::String(
            value.to_owned(),
        )))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJsonValue(serde_json::Value::String(
            value,
        )))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJsonValue(serde_json::Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJsonValue(serde_json::Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<DuplicateRejectingJsonValue>()? {
            values.push(value.0);
        }
        Ok(DuplicateRejectingJsonValue(serde_json::Value::Array(
            values,
        )))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some((key, value)) = map.next_entry::<String, DuplicateRejectingJsonValue>()? {
            if values.insert(key, value.0).is_some() {
                return Err(serde::de::Error::custom("duplicate JSON object member"));
            }
        }
        Ok(DuplicateRejectingJsonValue(serde_json::Value::Object(
            values,
        )))
    }
}

fn json_object_with_keys<'a>(
    value: &'a serde_json::Value,
    allowed: &[&str],
) -> Result<&'a serde_json::Map<String, serde_json::Value>, VpProtoError> {
    let object = value.as_object().ok_or(VpProtoError::JsonDeserialize)?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(VpProtoError::JsonDeserialize);
    }
    Ok(object)
}

fn validate_json_resource_limits(value: &serde_json::Value) -> Result<(), VpProtoError> {
    let mut pending = vec![value];
    let mut nodes = 0_usize;
    while let Some(current) = pending.pop() {
        nodes = nodes.checked_add(1).ok_or(VpProtoError::JsonTooLarge)?;
        if nodes > MAX_PRESENTATION_PROTO_JSON_NODES {
            return Err(VpProtoError::JsonTooLarge);
        }
        match current {
            serde_json::Value::Array(values) => {
                if values.len() > MAX_PRESENTATION_PROTO_JSON_COLLECTION_ITEMS {
                    return Err(VpProtoError::JsonTooLarge);
                }
                pending.extend(values);
            }
            serde_json::Value::Object(values) => {
                if values.len() > MAX_PRESENTATION_PROTO_JSON_COLLECTION_ITEMS {
                    return Err(VpProtoError::JsonTooLarge);
                }
                pending.extend(values.values());
            }
            _ => {}
        }
    }
    Ok(())
}

/// Serialize a Rust VP model through the generated protobuf JSON mapping.
pub fn presentation_to_proto_json(
    presentation: &Presentation,
) -> Result<Zeroizing<String>, VpProtoError> {
    validate_presentation_resource_limits(presentation)?;
    let proto = presentation_to_proto(presentation)?;
    proto_to_json(&proto)
}

/// Deserialize Buffa protobuf JSON into the Rust VP model.
pub fn proto_json_to_presentation(json: &str) -> Result<Presentation, VpProtoError> {
    let mut proto = json_to_proto(json)?;
    take_proto_into_presentation(proto.as_proto_mut())
}
