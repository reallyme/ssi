// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_compression_brotli::{brotli_compress, brotli_decompress};
use reallyme_did_types::DIDDocument;
use reallyme_ssi_proto_codec::did::{decode_proto, encode_proto, json_to_proto, proto_to_json};

use crate::error::DidApiError;

/// Convert a DID document to protobuf bytes and compress them with Brotli.
pub fn did_to_proto_brotli(doc: &DIDDocument) -> Result<Vec<u8>, DidApiError> {
    // IMPORTANT: no mutation, no normalization, no ES256 logic here
    let pb = json_to_proto(doc).map_err(|_| DidApiError::ProtoEncodeFailed)?;
    let bytes = encode_proto(&pb).map_err(|_| DidApiError::ProtoEncodeFailed)?;
    brotli_compress(&bytes).map_err(|_| DidApiError::BrotliEncodeFailed)
}

/// Decompress Brotli protobuf bytes and convert them back to a DID document.
pub fn proto_brotli_to_did(bytes: &[u8]) -> Result<DIDDocument, DidApiError> {
    let decompressed = brotli_decompress(bytes).map_err(|_| DidApiError::BrotliDecodeFailed)?;
    let pb = decode_proto(&decompressed).map_err(|_| DidApiError::ProtoDecodeFailed)?;
    proto_to_json(&pb).map_err(|_| DidApiError::ProtoDecodeFailed)
}
