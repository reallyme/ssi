// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical ISO IssuerSigned encoding for issuance transports.

use crate::cbor::encode_issuer_signed_cbor;
use crate::{MdocEnvelopeError, MdocIssuerSignedDocument};

/// Encode the raw ISO IssuerSigned map used by OpenID4VCI mdoc issuance.
///
/// The returned bytes are the IssuerSigned CBOR map itself, not a DeviceResponse.
/// `issuerAuth` is embedded as a COSE_Sign1 data item rather than wrapped in a
/// byte string, preserving the ISO wire shape consumed by interoperable wallets.
pub fn encode_mdoc_issuer_signed_cbor(
    document: &MdocIssuerSignedDocument,
) -> Result<Vec<u8>, MdocEnvelopeError> {
    encode_issuer_signed_cbor(&document.issuer_signed)
}
