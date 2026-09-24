// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(feature = "mdoc-crypto")]
use crate::cbor::decode_issuer_signed_item;
use crate::cbor::{decode_device_response_cbor, empty_cbor_map, encode_device_response_cbor};
#[cfg(feature = "mdoc-crypto")]
use crate::device_auth::{
    build_device_authentication_cbor, DeviceAuthSigner, DeviceAuthenticationInput,
};
#[cfg(feature = "mdoc-crypto")]
use crate::{
    IssuerNameSpaces, MdocDeviceDocument, MdocDeviceSigned, MdocInvalidInputReason,
    MAX_MDOC_ELEMENTS_PER_NAMESPACE, MAX_MDOC_NAMESPACES,
};
use crate::{MdocDeviceResponse, MdocEnvelopeError, MdocIssuerSignedDocument};
use serde::{Deserialize, Serialize};
#[cfg(feature = "mdoc-crypto")]
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroize;

/// ISO 18013-5 DeviceResponse version emitted by this crate.
pub const DEVICE_RESPONSE_VERSION: &str = "1.0";

/// ISO 18013-5 successful DeviceResponse status.
pub const DEVICE_RESPONSE_STATUS_OK: u64 = 0;

/// Issuer namespace disclosures requested for presentation.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct IssuerNamespaceSelection {
    /// ISO mdoc namespace.
    pub namespace: String,

    /// Data element identifiers to disclose from this namespace.
    pub element_identifiers: Vec<String>,
}

/// Input for building an ISO 18013-5 DeviceResponse from an issuer-signed mdoc.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BuildMdocDeviceResponseInput {
    /// Issuer-signed mdoc document to present.
    pub issuer_signed: MdocIssuerSignedDocument,

    /// Caller-supplied SessionTranscript CBOR bytes.
    pub session_transcript_cbor: Vec<u8>,

    /// Optional CBOR bytes for `deviceSigned.nameSpaces`; defaults to an empty map.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name_spaces_cbor: Option<Vec<u8>>,

    /// Optional issuer namespace disclosure filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_namespaces: Option<Vec<IssuerNamespaceSelection>>,
}

impl Drop for BuildMdocDeviceResponseInput {
    fn drop(&mut self) {
        self.session_transcript_cbor.zeroize();
        if let Some(device_name_spaces_cbor) = &mut self.device_name_spaces_cbor {
            device_name_spaces_cbor.zeroize();
        }
        if let Some(issuer_namespaces) = &mut self.issuer_namespaces {
            issuer_namespaces.zeroize();
        }
    }
}

/// Return canonical CBOR bytes for an empty `deviceSigned.nameSpaces` map.
pub fn empty_device_name_spaces_cbor() -> Result<Vec<u8>, MdocEnvelopeError> {
    empty_cbor_map()
}

#[cfg(feature = "mdoc-crypto")]
/// Build a signed ISO 18013-5 DeviceResponse.
pub fn present_mdoc(
    input: BuildMdocDeviceResponseInput,
    signer: &dyn DeviceAuthSigner,
) -> Result<Vec<u8>, MdocEnvelopeError> {
    build_mdoc_device_response_cbor(input, signer)
}

#[cfg(feature = "mdoc-crypto")]
/// Build canonical CBOR bytes for a signed ISO 18013-5 DeviceResponse.
pub fn build_mdoc_device_response_cbor(
    input: BuildMdocDeviceResponseInput,
    signer: &dyn DeviceAuthSigner,
) -> Result<Vec<u8>, MdocEnvelopeError> {
    if input.issuer_signed.doc_type.trim().is_empty() {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::EmptyDocType,
        ));
    }

    let device_name_spaces_cbor = match &input.device_name_spaces_cbor {
        Some(bytes) => bytes.clone(),
        None => empty_device_name_spaces_cbor()?,
    };
    let issuer_signed =
        filter_issuer_signed(input.issuer_signed.clone(), input.issuer_namespaces.clone())?;
    let device_authentication = build_device_authentication_cbor(&DeviceAuthenticationInput {
        session_transcript_cbor: input.session_transcript_cbor.as_slice(),
        doc_type: issuer_signed.doc_type.as_str(),
        device_name_spaces_cbor: device_name_spaces_cbor.as_slice(),
    })?;
    let device_auth = signer.sign_device_auth(&device_authentication)?;
    let response = MdocDeviceResponse {
        version: DEVICE_RESPONSE_VERSION.to_owned(),
        documents: vec![MdocDeviceDocument {
            doc_type: issuer_signed.doc_type.clone(),
            issuer_signed,
            device_signed: MdocDeviceSigned {
                name_spaces_cbor: device_name_spaces_cbor,
                device_auth,
            },
        }],
        status: DEVICE_RESPONSE_STATUS_OK,
    };

    encode_device_response_cbor(&response)
}

/// Encode a DeviceResponse model to canonical CBOR bytes.
pub fn encode_mdoc_device_response_cbor(
    response: &MdocDeviceResponse,
) -> Result<Vec<u8>, MdocEnvelopeError> {
    encode_device_response_cbor(response)
}

/// Decode canonical CBOR bytes into a DeviceResponse model.
pub fn decode_mdoc_device_response_cbor(
    bytes: &[u8],
) -> Result<MdocDeviceResponse, MdocEnvelopeError> {
    decode_device_response_cbor(bytes)
}

#[cfg(feature = "mdoc-crypto")]
fn filter_issuer_signed(
    mut document: MdocIssuerSignedDocument,
    selection: Option<Vec<IssuerNamespaceSelection>>,
) -> Result<MdocIssuerSignedDocument, MdocEnvelopeError> {
    let Some(selection) = selection else {
        return Ok(document);
    };
    validate_selection_limits(&selection)?;
    let Some(namespaces) = document.issuer_signed.name_spaces.take() else {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::MissingDisclosedElement,
        ));
    };

    let selected = selected_elements(&selection)?;
    let mut filtered: IssuerNameSpaces = BTreeMap::new();
    for (namespace, requested_elements) in &selected {
        let Some(items) = namespaces.get(namespace) else {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::MissingDisclosedElement,
            ));
        };
        let mut namespace_items = Vec::new();
        for item in items {
            let decoded = decode_issuer_signed_item(item)?;
            if requested_elements.contains(decoded.element_identifier.as_str()) {
                namespace_items.push(item.clone());
            }
        }
        if namespace_items.len() != requested_elements.len() {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::MissingDisclosedElement,
            ));
        }
        filtered.insert(namespace.clone(), namespace_items);
    }

    document.issuer_signed.name_spaces = Some(filtered);
    Ok(document)
}

#[cfg(feature = "mdoc-crypto")]
fn selected_elements(
    selection: &[IssuerNamespaceSelection],
) -> Result<BTreeMap<String, BTreeSet<String>>, MdocEnvelopeError> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for entry in selection {
        if entry.namespace.trim().is_empty() {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::EmptyNamespace,
            ));
        }
        for element in &entry.element_identifiers {
            if element.trim().is_empty() {
                return Err(MdocEnvelopeError::InvalidInput(
                    MdocInvalidInputReason::EmptyElementIdentifier,
                ));
            }
            out.entry(entry.namespace.clone())
                .or_default()
                .insert(element.clone());
        }
    }
    Ok(out)
}

#[cfg(feature = "mdoc-crypto")]
fn validate_selection_limits(
    selection: &[IssuerNamespaceSelection],
) -> Result<(), MdocEnvelopeError> {
    if selection.len() > MAX_MDOC_NAMESPACES {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::TooManyNamespaces,
        ));
    }

    for entry in selection {
        if entry.element_identifiers.len() > MAX_MDOC_ELEMENTS_PER_NAMESPACE {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::TooManyElementsPerNamespace,
            ));
        }
    }

    Ok(())
}
