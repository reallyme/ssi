// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ISO mdoc identity envelope surface.
//!
//! Protocol-neutral issuer-signed mdoc and DeviceResponse behavior. Issuer
//! authentication is COSE_Sign1 via `reallyme-cose`; signed MSO and issuer item
//! bytes use bounded ISO 18013-5 CBOR structures. OpenID4VP handover, Digital
//! Credentials API transport, wallet policy, and platform SDK bindings remain
//! in their owning repositories.

mod cbor;
mod data_element;
mod decode_issuer_signed;
#[cfg(feature = "mdoc-crypto")]
/// mdoc device authentication validation.
pub mod device_auth;
mod encode_issuer_signed;
mod error;
/// ISO/IEC TS 23220-2 relationship attribute boundary types.
pub mod iso23220;
#[cfg(feature = "mdoc-crypto")]
/// mdoc issuance entry points.
pub mod issue;
#[cfg(feature = "mdoc-crypto")]
/// mdoc issuer authentication validation.
pub mod issuer_auth;
/// mdoc issuer-signed data model.
pub mod model;
mod mso_status;
/// mdoc presentation entry points.
pub mod present;
mod status;
#[cfg(feature = "mdoc-crypto")]
mod validate_item_random;
mod validate_mso_status;
#[cfg(feature = "mdoc-crypto")]
mod validity;
#[cfg(feature = "mdoc-crypto")]
/// mdoc verification entry points.
pub mod verify;
#[cfg(feature = "mdoc-crypto")]
pub use cbor::decode_issuer_signed_item;
pub use data_element::{decode_mdoc_data_element_json, MdocDataElementJson};
pub use decode_issuer_signed::decode_mdoc_issuer_signed_cbor;
#[cfg(feature = "mdoc-crypto")]
pub use device_auth::{
    build_device_authentication_cbor, device_public_key_from_cose_key_cbor, validate_device_auth,
    CoseDeviceAuthSigner, DeviceAuthSigner, DeviceAuthenticationInput,
    DeviceAuthenticationValidationInput, DEVICE_AUTHENTICATION_CONTEXT,
};
pub use encode_issuer_signed::encode_mdoc_issuer_signed_cbor;
pub use error::{MdocEnvelopeError, MdocEnvelopeStatus, MdocInvalidInputReason};
#[cfg(feature = "mdoc-crypto")]
pub use iso23220::iso23220_relationship_element;
pub use iso23220::{
    parse_iso23220_relationship_value, Iso23220RelationshipKind, Iso23220RelationshipValue,
    ISO_23220_NAMESPACE,
};
#[cfg(feature = "mdoc-crypto")]
pub use issue::{build_mso_mdoc, issue_mdoc, IssuedMdoc, MdocElement, MdocIssueConfig};
#[cfg(feature = "mdoc-crypto")]
pub use issuer_auth::{
    validate_issuer_auth, validate_x5chain_issuer_auth, CoseIssuerAuthSigner,
    CoseX5ChainIssuerAuthSigner, IssuerAuthSigner, ValidatedX5ChainIssuerAuth,
};
pub use model::{
    DeviceKeyInfo, IssuerNameSpaces, IssuerSigned, IssuerSignedItem, IssuerSignedItemBytes,
    MdocDeviceDocument, MdocDeviceResponse, MdocDeviceSigned, MdocIssuerSignedDocument,
    MobileSecurityObject, ValidityInfo, ValueDigests, DIGEST_ALG_SHA256,
    ENCODED_CBOR_DATA_ITEM_TAG, MAX_MDOC_CBOR_ARRAY_ITEMS, MAX_MDOC_CBOR_DEPTH,
    MAX_MDOC_CBOR_INPUT_BYTES, MAX_MDOC_CBOR_ITEMS, MAX_MDOC_CBOR_MAP_ENTRIES,
    MAX_MDOC_DEVICE_RESPONSE_DOCUMENTS, MAX_MDOC_ELEMENTS_PER_NAMESPACE,
    MAX_MDOC_ELEMENT_VALUE_BYTES, MAX_MDOC_ISSUER_ELEMENTS, MAX_MDOC_ITEM_RANDOM_BYTES,
    MAX_MDOC_NAMESPACES, MAX_MDOC_TOTAL_ELEMENT_VALUE_BYTES, MIN_MDOC_ITEM_RANDOM_BYTES,
    MSO_VERSION, SHA256_DIGEST_LEN,
};
pub use mso_status::{
    MdocIdentifierList, MdocStatus, MdocStatusExtension, MdocStatusList,
    MAX_MDOC_STATUS_CERTIFICATE_BYTES, MAX_MDOC_STATUS_EXTENSIONS,
    MAX_MDOC_STATUS_EXTENSION_NAME_BYTES, MAX_MDOC_STATUS_EXTENSION_VALUE_BYTES,
    MAX_MDOC_STATUS_IDENTIFIER_BYTES, MAX_MDOC_STATUS_URI_BYTES,
};
#[cfg(feature = "mdoc-crypto")]
pub use present::{
    build_mdoc_device_response_cbor, present_mdoc, BuildMdocDeviceResponseInput,
    IssuerNamespaceSelection,
};
pub use present::{
    decode_mdoc_device_response_cbor, empty_device_name_spaces_cbor,
    encode_mdoc_device_response_cbor, DEVICE_RESPONSE_STATUS_OK, DEVICE_RESPONSE_VERSION,
};
pub use status::mdoc_envelope_status;
#[cfg(feature = "mdoc-crypto")]
pub use verify::{
    verify_issuer_signed_mdoc, verify_issuer_signed_mdoc_receipt_with_x5chain,
    verify_issuer_signed_mdoc_with_x5chain, verify_mdoc, verify_mdoc_device_response,
    verify_mdoc_device_response_with_x5chain, VerifiedMdoc, VerifiedMdocDeviceResponse,
};
