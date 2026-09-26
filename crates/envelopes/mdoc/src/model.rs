// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroize;

use crate::mso_status::MdocStatus;

/// ISO 18013-5 MSO version emitted by this crate.
pub const MSO_VERSION: &str = "1.0";

/// Digest algorithm label used by ISO 18013-5 MobileSecurityObject.
pub const DIGEST_ALG_SHA256: &str = "SHA-256";

/// CBOR tag number for encoded CBOR data item, used by IssuerSignedItemBytes.
pub const ENCODED_CBOR_DATA_ITEM_TAG: u64 = 24;

/// Length in bytes of SHA-256 value digests.
pub const SHA256_DIGEST_LEN: usize = 32;

/// Maximum issuer-signed elements accepted for a single mdoc.
///
/// The limit keeps issuance and verification bounded while leaving enough room
/// for realistic PID, mDL, and EAA documents with optional national extensions.
pub const MAX_MDOC_ISSUER_ELEMENTS: usize = 256;

/// Maximum namespaces accepted in issuer-signed mdoc namespace maps.
pub const MAX_MDOC_NAMESPACES: usize = 32;

/// Maximum issuer-signed elements accepted inside a single namespace.
pub const MAX_MDOC_ELEMENTS_PER_NAMESPACE: usize = 128;

/// Maximum documents accepted in one ISO 18013-5 DeviceResponse.
pub const MAX_MDOC_DEVICE_RESPONSE_DOCUMENTS: usize = 8;

/// Maximum decoded CBOR nesting depth accepted at mdoc trust boundaries.
pub const MAX_MDOC_CBOR_DEPTH: usize = 64;

/// Maximum decoded CBOR map entries accepted in an mdoc CBOR container.
pub const MAX_MDOC_CBOR_MAP_ENTRIES: usize = 512;

/// Maximum decoded CBOR array items accepted in an mdoc CBOR container.
pub const MAX_MDOC_CBOR_ARRAY_ITEMS: usize = 512;

/// Maximum CBOR data items (including nested items, tags, and string chunks)
/// accepted in one serialized mdoc CBOR input.
///
/// The limit is enforced by a structural pre-scan before any decoded value
/// tree is allocated, bounding the memory amplification of many small items.
pub const MAX_MDOC_CBOR_ITEMS: usize = 65_536;

/// Maximum serialized CBOR input accepted at an mdoc parsing boundary.
///
/// Decoded byte strings can expand substantially when projected through JSON
/// adapters, so this ceiling is intentionally lower than the process memory
/// budget and is enforced before allocating a decoded value tree.
pub const MAX_MDOC_CBOR_INPUT_BYTES: usize = 1024 * 1024;

/// Minimum `IssuerSignedItem.random` length, per ISO/IEC 18013-5 §9.1.2.5.
pub const MIN_MDOC_ITEM_RANDOM_BYTES: usize = 16;

/// Maximum `IssuerSignedItem.random` length accepted at issuance.
pub const MAX_MDOC_ITEM_RANDOM_BYTES: usize = 64;

/// Maximum encoded value for one issuer-signed data element.
pub const MAX_MDOC_ELEMENT_VALUE_BYTES: usize = 256 * 1024;

/// Maximum combined encoded element values accepted for one issuance.
pub const MAX_MDOC_TOTAL_ELEMENT_VALUE_BYTES: usize = 1024 * 1024;

/// ISO `IssuerSignedItem` map containing `digestID`, `random`,
/// `elementIdentifier`, and `elementValue`.
///
/// The `element_value_cbor` field stores the already-encoded CBOR data element
/// value. Keeping the value encoded avoids forcing a JSON-like data model over
/// ISO mdoc namespaces and lets higher layers own schema-specific validation.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct IssuerSignedItem {
    /// Digest identifier referenced by the MobileSecurityObject valueDigests map.
    pub digest_id: u64,

    /// Per-item randomizer bytes.
    pub random: Vec<u8>,

    /// ISO mdoc data element identifier.
    pub element_identifier: String,

    /// Canonical CBOR bytes for the data element value.
    pub element_value_cbor: Vec<u8>,
}

/// ISO `IssuerSignedItemBytes`: tag 24 over a byte string containing an
/// encoded [`IssuerSignedItem`].
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct IssuerSignedItemBytes {
    /// CBOR tag number. Must be [`ENCODED_CBOR_DATA_ITEM_TAG`].
    pub tag: u64,

    /// Encoded `IssuerSignedItem` map carried by the tag-24 byte string.
    pub bstr: Vec<u8>,
}

impl IssuerSignedItemBytes {
    /// Build `IssuerSignedItemBytes` from an encoded `IssuerSignedItem` map.
    pub fn new_tag24(item_bytes_cbor: Vec<u8>) -> Self {
        Self {
            tag: ENCODED_CBOR_DATA_ITEM_TAG,
            bstr: item_bytes_cbor,
        }
    }
}

/// IssuerNameSpaces maps each namespace to its disclosed issuer-signed items.
pub type IssuerNameSpaces = BTreeMap<String, Vec<IssuerSignedItemBytes>>;

/// ValueDigests maps namespace and unsigned digestID to SHA-256 digest bytes.
pub type ValueDigests = BTreeMap<String, BTreeMap<u64, Vec<u8>>>;

/// MobileSecurityObject validity window.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct ValidityInfo {
    /// Timestamp at which the MSO was signed.
    pub signed: u64,

    /// Inclusive validity start timestamp.
    pub valid_from: u64,

    /// Exclusive validity end timestamp.
    pub valid_until: u64,
}

/// Holder device key information.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct DeviceKeyInfo {
    /// CBOR bytes encoding the holder device COSE_Key.
    pub device_key_cose_key_cbor: Vec<u8>,
}

/// MobileSecurityObject fields signed by issuerAuth.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MobileSecurityObject {
    /// MSO version.
    pub version: String,

    /// Digest algorithm label.
    pub digest_algorithm: String,

    /// mdoc document type.
    pub doc_type: String,

    /// Signed validity window.
    pub validity_info: ValidityInfo,

    /// Holder device key binding information.
    pub device_key_info: DeviceKeyInfo,

    /// Per-namespace value digests.
    pub value_digests: ValueDigests,

    /// Optional ISO/IEC 18013-5 credential status reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<MdocStatus>,
}

impl Drop for MobileSecurityObject {
    fn drop(&mut self) {
        self.version.zeroize();
        self.digest_algorithm.zeroize();
        self.doc_type.zeroize();
        self.validity_info.zeroize();
        self.device_key_info.device_key_cose_key_cbor.zeroize();
        zeroize_value_digests(&mut self.value_digests);
        self.status.zeroize();
    }
}

/// IssuerSigned container: optional issuer namespaces plus issuerAuth COSE_Sign1.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct IssuerSigned {
    /// Disclosed issuer namespaces.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_spaces: Option<IssuerNameSpaces>,

    /// COSE_Sign1 bytes over the MobileSecurityObject payload.
    pub issuer_auth: Vec<u8>,
}

impl Drop for IssuerSigned {
    fn drop(&mut self) {
        if let Some(name_spaces) = &mut self.name_spaces {
            zeroize_issuer_namespaces(name_spaces);
        }
        self.issuer_auth.zeroize();
    }
}

/// Portable issuer-signed mdoc document.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MdocIssuerSignedDocument {
    /// mdoc document type.
    pub doc_type: String,

    /// Issuer-signed namespaces and issuerAuth.
    pub issuer_signed: IssuerSigned,
}

impl Drop for MdocIssuerSignedDocument {
    fn drop(&mut self) {
        self.doc_type.zeroize();
    }
}

/// ISO 18013-5 DeviceResponse.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MdocDeviceResponse {
    /// DeviceResponse version.
    pub version: String,

    /// Documents presented by the device.
    pub documents: Vec<MdocDeviceDocument>,

    /// Required DeviceResponse status. A successful response uses status `0`.
    pub status: u64,
}

impl Drop for MdocDeviceResponse {
    fn drop(&mut self) {
        self.version.zeroize();
    }
}

/// A single document inside an ISO 18013-5 DeviceResponse.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MdocDeviceDocument {
    /// mdoc document type.
    pub doc_type: String,

    /// Issuer-signed document content and issuerAuth.
    pub issuer_signed: MdocIssuerSignedDocument,

    /// Device-signed holder binding data.
    pub device_signed: MdocDeviceSigned,
}

impl Drop for MdocDeviceDocument {
    fn drop(&mut self) {
        self.doc_type.zeroize();
    }
}

/// Device-signed namespace data and DeviceAuth COSE_Sign1.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct MdocDeviceSigned {
    /// CBOR bytes of `deviceSigned.nameSpaces`.
    pub name_spaces_cbor: Vec<u8>,

    /// COSE_Sign1 bytes in `deviceAuth.deviceSignature`.
    pub device_auth: Vec<u8>,
}

fn zeroize_issuer_namespaces(namespaces: &mut IssuerNameSpaces) {
    while let Some((mut namespace, mut items)) = namespaces.pop_first() {
        namespace.zeroize();
        for item in &mut items {
            item.tag.zeroize();
            item.bstr.zeroize();
        }
        items.zeroize();
    }
}

fn zeroize_value_digests(value_digests: &mut ValueDigests) {
    while let Some((mut namespace, mut digest_map)) = value_digests.pop_first() {
        namespace.zeroize();
        while let Some((_digest_id, mut digest)) = digest_map.pop_first() {
            digest.zeroize();
        }
    }
}
