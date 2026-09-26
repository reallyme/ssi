// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[path = "json_to_proto.rs"]
mod json_to_proto;
#[path = "proto_to_json.rs"]
mod proto_to_json;
#[path = "sensitive_document.rs"]
mod sensitive_document;

/// Field-level mappings between JSON DID structs and protobuf messages.
#[path = "mapping/mod.rs"]
pub mod mapping;

pub use json_to_proto::json_to_proto;
pub use proto_to_json::proto_to_json;
pub use sensitive_document::SensitiveDidDocument;

pub use identity_core_primitives::algorithm_map::{
    alg_str_to_alg, alg_to_did_alg_str, alg_to_vc_alg_str,
};

use buffa::{DecodeOptions, Message};
use reallyme_ssi_proto::generated::proto::meid::did::v1::DIDDocument as PbDIDDocument;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Maximum accepted or generated DID document protobuf size.
///
/// The limit is enforced before decoding so hostile length-delimited fields
/// cannot force allocation beyond this codec's resource budget.
pub const MAX_DID_PROTO_MESSAGE_BYTES: usize = 1_048_576;

/// Maximum protobuf nesting depth accepted for DID documents.
///
/// DID documents embed `google.protobuf.Value` trees for controllers and
/// service endpoints; this bound prevents deeply nested hostile values from
/// exhausting the decoder stack.
const DID_PROTO_RECURSION_LIMIT: u32 = 32;

/// DID document protobufs are closed at the transport boundary.
const DID_PROTO_UNKNOWN_FIELD_LIMIT: usize = 0;

/// Error type for DID protobuf transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DidProtoCodecError {
    /// A protobuf message could not be encoded.
    #[error("DID protobuf encode failed")]
    EncodeFailed,
    /// A protobuf message could not be decoded.
    #[error("DID protobuf decode failed")]
    DecodeFailed,
    /// The protobuf representation exceeded the public codec resource limit.
    #[error("DID protobuf exceeds configured limit")]
    MessageTooLarge,
    /// A base64url field was malformed.
    #[error("DID protobuf base64url field is invalid")]
    InvalidBase64Url,
    /// A required DID document field was absent.
    #[error("DID protobuf document is missing a required field")]
    MissingRequiredField,
    /// A string algorithm could not be mapped to the crypto protobuf contract.
    #[error("DID protobuf algorithm is unsupported")]
    UnsupportedAlgorithm,
    /// A google.protobuf.Value did not match the supported DID controller model.
    #[error("DID protobuf controller value is invalid")]
    InvalidController,
    /// A google.protobuf.Value service endpoint was outside the supported JSON model.
    #[error("DID protobuf service endpoint is invalid")]
    InvalidServiceEndpoint,
    /// A domain verification method or binding was invalid.
    #[error("DID protobuf domain verification is invalid")]
    InvalidDomainVerification,
}

/// Encode a did:me protobuf DID document to wire bytes.
pub fn encode_proto(doc: &PbDIDDocument) -> Result<Vec<u8>, DidProtoCodecError> {
    let encoded = doc.encode_to_vec();
    if encoded.len() > MAX_DID_PROTO_MESSAGE_BYTES {
        return Err(DidProtoCodecError::MessageTooLarge);
    }
    Ok(encoded)
}

/// Decode wire bytes into a did:me protobuf DID document.
///
/// Decoding is bounded by [`MAX_DID_PROTO_MESSAGE_BYTES`], a fixed nesting
/// depth, and rejects unknown fields.
pub fn decode_proto(bytes: &[u8]) -> Result<PbDIDDocument, DidProtoCodecError> {
    if bytes.len() > MAX_DID_PROTO_MESSAGE_BYTES {
        return Err(DidProtoCodecError::MessageTooLarge);
    }

    DecodeOptions::new()
        .with_recursion_limit(DID_PROTO_RECURSION_LIMIT)
        .with_max_message_size(MAX_DID_PROTO_MESSAGE_BYTES)
        .with_unknown_field_limit(DID_PROTO_UNKNOWN_FIELD_LIMIT)
        .decode_from_slice(bytes)
        .map_err(|_| DidProtoCodecError::DecodeFailed)
}

/// Convert an authoritative did:me protobuf document into a non-cloneable,
/// zeroizing domain owner for validation and dispatch paths.
pub fn proto_to_sensitive_json(
    document: &PbDIDDocument,
) -> Result<SensitiveDidDocument, DidProtoCodecError> {
    proto_to_json(document).map(SensitiveDidDocument::from_document)
}

impl From<DidProtoCodecError> for IdentityCoreErrorReason {
    fn from(error: DidProtoCodecError) -> Self {
        match error {
            DidProtoCodecError::EncodeFailed => {
                Self::IDENTITY_CORE_ERROR_REASON_SERIALIZATION_FAILED
            }
            DidProtoCodecError::DecodeFailed | DidProtoCodecError::InvalidBase64Url => {
                Self::IDENTITY_CORE_ERROR_REASON_INVALID_ENCODING
            }
            DidProtoCodecError::UnsupportedAlgorithm => {
                Self::IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_ALGORITHM
            }
            DidProtoCodecError::MessageTooLarge => {
                Self::IDENTITY_CORE_ERROR_REASON_RESOURCE_LIMIT_EXCEEDED
            }
            DidProtoCodecError::InvalidServiceEndpoint => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_SERVICE
            }
            _ => Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOCUMENT,
        }
    }
}

#[cfg(test)]
#[path = "mod_proto_error_tests.rs"]
mod proto_error_tests;
