// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Buffa protobuf transport for ReallyMe DID documents.

mod codec;

pub use codec::{
    alg_str_to_alg, alg_to_did_alg_str, alg_to_vc_alg_str, decode_proto, encode_proto,
    json_to_proto, mapping, proto_to_json, proto_to_sensitive_json, DidProtoCodecError,
    SensitiveDidDocument,
};
