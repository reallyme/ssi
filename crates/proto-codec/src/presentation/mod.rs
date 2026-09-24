// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protocol-neutral VP protobuf codec.
//!
//! The primary transport boundary is Buffa-generated protobuf bytes. JSON
//! helpers are provided for interoperability with existing DID/credential
//! ecosystems, but they intentionally operate over the same generated proto
//! messages instead of defining a separate JSON-first schema.

mod codec;

pub use codec::{
    decode_presentation_proto, decode_presentation_proto_brotli, decode_proto,
    encode_presentation_proto, encode_presentation_proto_brotli, encode_proto, json_to_proto,
    presentation_to_proto, presentation_to_proto_json, proto_json_to_presentation, proto_to_json,
    proto_to_presentation, zeroize_presentation_proto, SensitivePresentationProto, VpProtoError,
    MAX_MDOC_DEVICE_RESPONSE_BYTES, MAX_PRESENTATION_PROTO_JSON_BYTES,
    MAX_PRESENTATION_PROTO_MESSAGE_BYTES,
};
