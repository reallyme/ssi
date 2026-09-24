// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[path = "mapping.rs"]
mod mapping;
#[path = "own_presentation_proto.rs"]
mod own_presentation_proto;

pub use mapping::{presentation_to_proto, proto_to_presentation};
pub use own_presentation_proto::{zeroize_presentation_proto, SensitivePresentationProto};

use buffa::{DecodeOptions, Message};
use reallyme_ssi_proto::generated::proto::identity::presentation::v1::__buffa::oneof::presentation;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
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

/// Fixed VP proto codec errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
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
    let proto = presentation_to_proto(presentation);
    encode_proto(&proto)
}

/// Decode generated protobuf bytes into the Rust VP model.
pub fn decode_presentation_proto(bytes: &[u8]) -> Result<Presentation, VpProtoError> {
    let proto = decode_proto(bytes)?;
    proto_to_presentation(proto.as_proto())
}

/// Encode a Rust VP model as protobuf bytes and then bounded Brotli.
pub fn encode_presentation_proto_brotli(
    presentation: &Presentation,
) -> Result<Zeroizing<Vec<u8>>, VpProtoError> {
    let proto = encode_presentation_proto(presentation)?;
    let compressed = reallyme_compression_brotli::brotli_compress(&proto)
        .map_err(|_| VpProtoError::Compression)?;
    Ok(Zeroizing::new(compressed))
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
        | reallyme_compression_brotli::BrotliError::DecompressionFailed => {
            VpProtoError::Decompression
        }
    })?;
    let proto = Zeroizing::new(proto);
    decode_presentation_proto(&proto)
}

/// Serialize the generated protobuf message using Buffa's protobuf JSON rules.
pub fn proto_to_json(presentation: &PbPresentation) -> Result<Zeroizing<String>, VpProtoError> {
    validate_proto_resource_limits(presentation)?;
    let json = serde_json::to_string(presentation).map_err(|_| VpProtoError::JsonSerialize)?;
    if json.len() > MAX_PRESENTATION_PROTO_JSON_BYTES {
        return Err(VpProtoError::JsonTooLarge);
    }

    Ok(Zeroizing::new(json))
}

/// Deserialize a generated protobuf message using Buffa's protobuf JSON rules.
pub fn json_to_proto(json: &str) -> Result<SensitivePresentationProto, VpProtoError> {
    if json.len() > MAX_PRESENTATION_PROTO_JSON_BYTES {
        return Err(VpProtoError::JsonTooLarge);
    }

    let presentation: PbPresentation =
        serde_json::from_str(json).map_err(|_| VpProtoError::JsonDeserialize)?;
    let encoded = encode_proto(&presentation)?;
    drop(encoded);
    Ok(SensitivePresentationProto::new(presentation))
}

/// Serialize a Rust VP model through the generated protobuf JSON mapping.
pub fn presentation_to_proto_json(
    presentation: &Presentation,
) -> Result<Zeroizing<String>, VpProtoError> {
    validate_presentation_resource_limits(presentation)?;
    let proto = presentation_to_proto(presentation);
    proto_to_json(&proto)
}

fn validate_presentation_resource_limits(presentation: &Presentation) -> Result<(), VpProtoError> {
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
    let proto = json_to_proto(json)?;
    proto_to_presentation(proto.as_proto())
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
            VpProtoError::MessageTooLarge
            | VpProtoError::MdocDeviceResponseTooLarge
            | VpProtoError::JsonTooLarge => {
                Self::IDENTITY_CORE_ERROR_REASON_RESOURCE_LIMIT_EXCEEDED
            }
        }
    }
}
