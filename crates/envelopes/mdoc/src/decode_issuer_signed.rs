// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical ISO IssuerSigned decoding for issuance transports.

use crate::cbor::decode_issuer_signed_cbor;
use crate::{MdocEnvelopeError, MdocInvalidInputReason, MdocIssuerSignedDocument};

const MAX_DOC_TYPE_BYTES: usize = 256;

/// Decode the raw ISO IssuerSigned CBOR map returned by an OpenID4VCI issuer.
///
/// ISO IssuerSigned does not carry its document type outside the signed MSO.
/// The caller supplies the credential-configuration document type so the
/// subsequent canonical verifier can require it to match the signed MSO.
pub fn decode_mdoc_issuer_signed_cbor(
    bytes: &[u8],
    expected_doc_type: &str,
) -> Result<MdocIssuerSignedDocument, MdocEnvelopeError> {
    if expected_doc_type.trim().is_empty() || expected_doc_type.len() > MAX_DOC_TYPE_BYTES {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::EmptyDocType,
        ));
    }
    let issuer_signed = decode_issuer_signed_cbor(bytes)?;
    Ok(MdocIssuerSignedDocument {
        doc_type: expected_doc_type.to_owned(),
        issuer_signed,
    })
}
