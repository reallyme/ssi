// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[path = "mapping.rs"]
mod mapping;
#[path = "own_presentation_proto.rs"]
mod own_presentation_proto;

pub use mapping::{presentation_to_proto, proto_to_presentation};

use mapping::{take_proto_into_presentation, validate_presentation_semantics};
pub use own_presentation_proto::{zeroize_presentation_proto, SensitivePresentationProto};

use buffa::{DecodeOptions, Message};
use reallyme_ssi_proto::generated::proto::identity::presentation::v1::__buffa::oneof::presentation;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use std::io::Write;
use thiserror::Error;
use zeroize::Zeroizing;

use reallyme_ssi_proto::generated::proto::identity::presentation::v1::Presentation as PbPresentation;
use reallyme_vp_core::Presentation;

/// Maximum accepted or generated presentation protobuf size.
///
/// The limit is enforced before decoding so hostile length-delimited fields
/// cannot force allocation beyond this codec's resource budget.
pub const MAX_PRESENTATION_PROTO_MESSAGE_BYTES: usize = 2_097_152;

/// Maximum CBOR bytes accepted in `MdocPresentation.device_response`.
///
/// This field-specific ceiling leaves bounded headroom for the protobuf tag,
/// length prefix, optional envelope hash, and document type inside the public
/// message limit. Generated protobuf structs remain allocation containers;
/// callers must use this codec at untrusted boundaries.
pub const MAX_MDOC_DEVICE_RESPONSE_BYTES: usize = 2_000_000;

/// Maximum accepted or generated presentation ProtoJSON size.
///
/// The JSON allowance accounts for base64 expansion while preserving a fixed
/// upper bound for callers that require the interoperability encoding.
pub const MAX_PRESENTATION_PROTO_JSON_BYTES: usize = 3_145_728;

const PRESENTATION_PROTO_RECURSION_LIMIT: u32 = 64;
const PRESENTATION_PROTO_UNKNOWN_FIELD_LIMIT: usize = 0;
const MAX_PRESENTATION_PROTO_JSON_COLLECTION_ITEMS: usize = 4_096;
const MAX_PRESENTATION_PROTO_JSON_NODES: usize = 65_536;

/// Fixed VP proto codec errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum VpProtoError {
    /// Protobuf bytes could not be decoded.
    #[error("invalid presentation protobuf")]
    Decode,

    /// Protobuf bytes could not be encoded.
    #[error("invalid presentation protobuf encoding")]
    Encode,

    /// The protobuf representation exceeded the public codec resource limit.
    #[error("presentation protobuf exceeds configured limit")]
    MessageTooLarge,

    /// An mdoc `DeviceResponse` exceeded its field-specific resource limit.
    #[error("mdoc device response exceeds configured limit")]
    MdocDeviceResponseTooLarge,

    /// Required protobuf field is absent.
    #[error("required presentation protobuf field missing")]
    MissingField,

    /// A fixed-width byte field had the wrong length.
    #[error("invalid presentation protobuf byte length")]
    InvalidBytesLen,

    /// A protobuf enum value is not supported by the Rust model.
    #[error("invalid presentation protobuf enum value")]
    InvalidEnumValue,

    /// A claim disclosure value does not match its declared disclosure mode.
    #[error("presentation claim disclosure value does not match its mode")]
    InconsistentDisclosure,

    /// Generated protobuf JSON serialization failed.
    #[error("invalid presentation protobuf JSON serialization")]
    JsonSerialize,

    /// Generated protobuf JSON deserialization failed.
    #[error("invalid presentation protobuf JSON")]
    JsonDeserialize,

    /// The ProtoJSON representation exceeded the public codec resource limit.
    #[error("presentation protobuf JSON exceeds configured limit")]
    JsonTooLarge,

    /// Brotli compression failed.
    #[error("presentation protobuf compression failed")]
    Compression,

    /// Brotli decompression failed.
    #[error("presentation protobuf decompression failed")]
    Decompression,
}

/// Encode a generated presentation protobuf message.
pub fn encode_proto(presentation: &PbPresentation) -> Result<Zeroizing<Vec<u8>>, VpProtoError> {
    validate_proto_resource_limits(presentation)?;
    let encoded = Zeroizing::new(presentation.encode_to_vec());
    if encoded.len() > MAX_PRESENTATION_PROTO_MESSAGE_BYTES {
        return Err(VpProtoError::MessageTooLarge);
    }

    Ok(encoded)
}

/// Decode a generated presentation protobuf message.
pub fn decode_proto(bytes: &[u8]) -> Result<SensitivePresentationProto, VpProtoError> {
    if bytes.len() > MAX_PRESENTATION_PROTO_MESSAGE_BYTES {
        return Err(VpProtoError::MessageTooLarge);
    }

    let presentation = DecodeOptions::new()
        .with_recursion_limit(PRESENTATION_PROTO_RECURSION_LIMIT)
        .with_max_message_size(MAX_PRESENTATION_PROTO_MESSAGE_BYTES)
        .with_unknown_field_limit(PRESENTATION_PROTO_UNKNOWN_FIELD_LIMIT)
        .decode_from_slice(bytes)
        .map_err(|_| VpProtoError::Decode)?;
    let sensitive = SensitivePresentationProto::new(presentation);
    validate_proto_resource_limits(sensitive.as_proto())?;
    Ok(sensitive)
}

/// Encode a Rust VP model as generated protobuf bytes.
pub fn encode_presentation_proto(
    presentation: &Presentation,
) -> Result<Zeroizing<Vec<u8>>, VpProtoError> {
    validate_presentation_resource_limits(presentation)?;
    let proto = presentation_to_proto(presentation)?;
    encode_proto(&proto)
}

/// Decode generated protobuf bytes into the Rust VP model.
pub fn decode_presentation_proto(bytes: &[u8]) -> Result<Presentation, VpProtoError> {
    let mut proto = decode_proto(bytes)?;
    take_proto_into_presentation(proto.as_proto_mut())
}

/// Encode a Rust VP model as protobuf bytes and then bounded Brotli.
pub fn encode_presentation_proto_brotli(
    presentation: &Presentation,
) -> Result<Zeroizing<Vec<u8>>, VpProtoError> {
    let proto = encode_presentation_proto(presentation)?;
    let compressed = reallyme_compression_brotli::brotli_compress(&proto)
        .map_err(|_| VpProtoError::Compression)?;
    Ok(compressed)
}

/// Decode bounded Brotli protobuf bytes into the Rust VP model.
pub fn decode_presentation_proto_brotli(bytes: &[u8]) -> Result<Presentation, VpProtoError> {
    let proto = reallyme_compression_brotli::brotli_decompress_with_limit(
        bytes,
        MAX_PRESENTATION_PROTO_MESSAGE_BYTES,
    )
    .map_err(|error| match error {
        reallyme_compression_brotli::BrotliError::OutputTooLarge => VpProtoError::MessageTooLarge,
        reallyme_compression_brotli::BrotliError::CompressionFailed
        | reallyme_compression_brotli::BrotliError::DecompressionFailed
        | reallyme_compression_brotli::BrotliError::TrailingData => VpProtoError::Decompression,
        _ => VpProtoError::Decompression,
    })?;
    let proto = Zeroizing::new(proto);
    decode_presentation_proto(&proto)
}

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

    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|_| VpProtoError::JsonDeserialize)?;
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
        &["freshness", "credential", "disclosures", "zkProof", "qeaa"],
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
    if let Some(value) = zk.get("zkProof") {
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
    if let Some(value) = zk.get("qeaa") {
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

fn validate_presentation_resource_limits(presentation: &Presentation) -> Result<(), VpProtoError> {
    validate_presentation_semantics(presentation)?;
    if let Presentation::Mdoc(mdoc) = presentation {
        if mdoc.device_response.len() > MAX_MDOC_DEVICE_RESPONSE_BYTES {
            return Err(VpProtoError::MdocDeviceResponseTooLarge);
        }
    }
    Ok(())
}

fn validate_proto_resource_limits(presentation_model: &PbPresentation) -> Result<(), VpProtoError> {
    if let Some(presentation::Kind::Mdoc(mdoc)) = presentation_model.kind.as_ref() {
        if mdoc.device_response.len() > MAX_MDOC_DEVICE_RESPONSE_BYTES {
            return Err(VpProtoError::MdocDeviceResponseTooLarge);
        }
    }
    Ok(())
}

/// Deserialize Buffa protobuf JSON into the Rust VP model.
pub fn proto_json_to_presentation(json: &str) -> Result<Presentation, VpProtoError> {
    let mut proto = json_to_proto(json)?;
    take_proto_into_presentation(proto.as_proto_mut())
}

impl From<VpProtoError> for IdentityCoreErrorReason {
    fn from(error: VpProtoError) -> Self {
        match error {
            VpProtoError::Decode
            | VpProtoError::InvalidBytesLen
            | VpProtoError::InvalidEnumValue
            | VpProtoError::JsonDeserialize
            | VpProtoError::Decompression => Self::IDENTITY_CORE_ERROR_REASON_INVALID_ENCODING,
            VpProtoError::Encode | VpProtoError::JsonSerialize | VpProtoError::Compression => {
                Self::IDENTITY_CORE_ERROR_REASON_SERIALIZATION_FAILED
            }
            VpProtoError::MissingField => {
                Self::IDENTITY_CORE_ERROR_REASON_PRESENTATION_INVALID_RESPONSE
            }
            VpProtoError::InconsistentDisclosure => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_INVALID_DISCLOSURE_MODE
            }
            VpProtoError::MessageTooLarge
            | VpProtoError::MdocDeviceResponseTooLarge
            | VpProtoError::JsonTooLarge => {
                Self::IDENTITY_CORE_ERROR_REASON_RESOURCE_LIMIT_EXCEEDED
            }
        }
    }
}
