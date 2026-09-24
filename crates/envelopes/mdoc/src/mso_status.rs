// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::validate_mso_status::{
    validate_certificate, validate_extension, validate_extensions, validate_identifier,
    validate_index, validate_uri,
};
use crate::{MdocEnvelopeError, MdocInvalidInputReason};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Maximum UTF-8 byte length accepted for an MSO revocation-list URI.
pub const MAX_MDOC_STATUS_URI_BYTES: usize = 2_048;

/// Maximum byte length accepted for an identifier-list credential identifier.
pub const MAX_MDOC_STATUS_IDENTIFIER_BYTES: usize = 64;

/// Maximum DER certificate length accepted in an MSO Status reference.
pub const MAX_MDOC_STATUS_CERTIFICATE_BYTES: usize = 64 * 1_024;

/// Maximum number of forward-compatible text members retained per Status map.
pub const MAX_MDOC_STATUS_EXTENSIONS: usize = 16;

/// Maximum UTF-8 byte length of a forward-compatible Status member name.
pub const MAX_MDOC_STATUS_EXTENSION_NAME_BYTES: usize = 128;

/// Maximum encoded CBOR byte length retained for one Status extension value.
pub const MAX_MDOC_STATUS_EXTENSION_VALUE_BYTES: usize = 64 * 1_024;

const STATUS_EXTENSION_RESERVED_NAMES: &[&str] = &["status_list", "identifier_list"];
const STATUS_LIST_EXTENSION_RESERVED_NAMES: &[&str] = &["idx", "uri", "certificate"];
const IDENTIFIER_LIST_EXTENSION_RESERVED_NAMES: &[&str] = &["id", "uri", "certificate"];

/// ISO/IEC 18013-5 `Status` mechanism authenticated by the MSO.
///
/// This is the ISO CBOR protocol representation. It is intentionally distinct
/// from product-level credential status and status-list contracts owned by the
/// credential and status domains.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[serde(try_from = "UncheckedMdocStatus")]
#[zeroize(drop)]
pub struct MdocStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    status_list: Option<MdocStatusList>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identifier_list: Option<MdocIdentifierList>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    extensions: Vec<MdocStatusExtension>,
}

#[derive(Deserialize, Zeroize)]
#[zeroize(drop)]
struct UncheckedMdocStatus {
    status_list: Option<MdocStatusList>,
    identifier_list: Option<MdocIdentifierList>,
    #[serde(default)]
    extensions: Vec<MdocStatusExtension>,
}

impl TryFrom<UncheckedMdocStatus> for MdocStatus {
    type Error = MdocEnvelopeError;

    fn try_from(mut value: UncheckedMdocStatus) -> Result<Self, Self::Error> {
        Self::from_parts(
            value.status_list.take(),
            value.identifier_list.take(),
            core::mem::take(&mut value.extensions),
        )
    }
}

impl MdocStatus {
    /// Construct a Status map containing one or both standardized mechanisms.
    pub fn new(
        status_list: Option<MdocStatusList>,
        identifier_list: Option<MdocIdentifierList>,
    ) -> Result<Self, MdocEnvelopeError> {
        Self::from_parts(status_list, identifier_list, Vec::new())
    }

    /// Construct a Status map containing only an index-based list reference.
    #[must_use]
    pub fn status_list(status_list: MdocStatusList) -> Self {
        Self {
            status_list: Some(status_list),
            identifier_list: None,
            extensions: Vec::new(),
        }
    }

    /// Construct a Status map containing only an identifier-list reference.
    #[must_use]
    pub fn identifier_list(identifier_list: MdocIdentifierList) -> Self {
        Self {
            status_list: None,
            identifier_list: Some(identifier_list),
            extensions: Vec::new(),
        }
    }

    /// Optional index-based list mechanism authenticated by the MSO.
    #[must_use]
    pub const fn status_list_ref(&self) -> Option<&MdocStatusList> {
        self.status_list.as_ref()
    }

    /// Optional identifier-list mechanism authenticated by the MSO.
    #[must_use]
    pub const fn identifier_list_ref(&self) -> Option<&MdocIdentifierList> {
        self.identifier_list.as_ref()
    }

    /// Forward-compatible top-level text members retained as bounded CBOR.
    #[must_use]
    pub fn extensions(&self) -> &[MdocStatusExtension] {
        &self.extensions
    }

    pub(crate) fn from_parts(
        status_list: Option<MdocStatusList>,
        identifier_list: Option<MdocIdentifierList>,
        extensions: Vec<MdocStatusExtension>,
    ) -> Result<Self, MdocEnvelopeError> {
        if status_list.is_none() && identifier_list.is_none() && extensions.is_empty() {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::UnknownMsoStatusMechanism,
            ));
        }
        validate_extensions(&extensions, STATUS_EXTENSION_RESERVED_NAMES)?;
        Ok(Self {
            status_list,
            identifier_list,
            extensions,
        })
    }

    #[cfg(feature = "mdoc-crypto")]
    pub(crate) fn validate(&self) -> Result<(), MdocEnvelopeError> {
        if let Some(status) = &self.status_list {
            status.validate()?;
        }
        if let Some(status) = &self.identifier_list {
            status.validate()?;
        }
        validate_extensions(&self.extensions, STATUS_EXTENSION_RESERVED_NAMES)
    }
}

/// Bounded forward-compatible Status member.
///
/// The value is retained as one validated CBOR data item so unknown RFU
/// members survive decode/re-encode without exposing an unsanitized generic
/// value tree to callers.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[serde(try_from = "UncheckedMdocStatusExtension")]
#[zeroize(drop)]
pub struct MdocStatusExtension {
    name: String,
    value_cbor: Vec<u8>,
}

#[derive(Deserialize, Zeroize)]
#[zeroize(drop)]
struct UncheckedMdocStatusExtension {
    name: String,
    value_cbor: Vec<u8>,
}

impl TryFrom<UncheckedMdocStatusExtension> for MdocStatusExtension {
    type Error = MdocEnvelopeError;

    fn try_from(mut value: UncheckedMdocStatusExtension) -> Result<Self, Self::Error> {
        Self::new(
            core::mem::take(&mut value.name),
            core::mem::take(&mut value.value_cbor),
        )
    }
}

impl MdocStatusExtension {
    pub(crate) fn new(name: String, value_cbor: Vec<u8>) -> Result<Self, MdocEnvelopeError> {
        let extension = Self { name, value_cbor };
        validate_extension(&extension)?;
        Ok(extension)
    }

    /// Text member name from the authenticated Status map.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Encoded, bounded CBOR value for the unknown member.
    #[must_use]
    pub fn value_cbor(&self) -> &[u8] {
        &self.value_cbor
    }
}

/// ISO/IEC 18013-5 `status_list` reference.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[serde(try_from = "UncheckedStatusList")]
#[zeroize(drop)]
pub struct MdocStatusList {
    #[serde(rename = "idx")]
    index: u64,
    uri: String,
    certificate: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    extensions: Vec<MdocStatusExtension>,
}

impl MdocStatusList {
    /// Construct a bounded, retrievable status-list reference.
    pub fn new(
        index: u64,
        uri: String,
        certificate: Option<Vec<u8>>,
    ) -> Result<Self, MdocEnvelopeError> {
        validate_index(index)?;
        validate_uri(&uri)?;
        validate_certificate(certificate.as_deref())?;
        Ok(Self {
            index,
            uri,
            certificate,
            extensions: Vec::new(),
        })
    }

    pub(crate) fn new_with_extensions(
        index: u64,
        uri: String,
        certificate: Option<Vec<u8>>,
        extensions: Vec<MdocStatusExtension>,
    ) -> Result<Self, MdocEnvelopeError> {
        validate_index(index)?;
        validate_uri(&uri)?;
        validate_certificate(certificate.as_deref())?;
        validate_extensions(&extensions, STATUS_LIST_EXTENSION_RESERVED_NAMES)?;
        Ok(Self {
            index,
            uri,
            certificate,
            extensions,
        })
    }

    /// Zero-based entry index in the referenced status list.
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Absolute URI of the referenced status list.
    ///
    /// Network adapters must independently enforce transport and SSRF policy
    /// before dereferencing this authenticated protocol value.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Optional DER-encoded trust certificate for the referenced list.
    pub fn certificate_der(&self) -> Option<&[u8]> {
        self.certificate.as_deref()
    }

    /// Forward-compatible text members retained from StatusListInfo.
    #[must_use]
    pub fn extensions(&self) -> &[MdocStatusExtension] {
        &self.extensions
    }

    #[cfg(feature = "mdoc-crypto")]
    fn validate(&self) -> Result<(), MdocEnvelopeError> {
        validate_index(self.index)?;
        validate_uri(&self.uri)?;
        validate_certificate(self.certificate.as_deref())?;
        validate_extensions(&self.extensions, STATUS_LIST_EXTENSION_RESERVED_NAMES)
    }
}

/// ISO/IEC 18013-5 `identifier_list` reference.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[serde(try_from = "UncheckedIdentifierList")]
#[zeroize(drop)]
pub struct MdocIdentifierList {
    #[serde(rename = "id")]
    identifier: Vec<u8>,
    uri: String,
    certificate: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    extensions: Vec<MdocStatusExtension>,
}

impl MdocIdentifierList {
    /// Construct a bounded identifier-list reference.
    pub fn new(
        identifier: Vec<u8>,
        uri: String,
        certificate: Option<Vec<u8>>,
    ) -> Result<Self, MdocEnvelopeError> {
        validate_identifier(&identifier)?;
        validate_uri(&uri)?;
        validate_certificate(certificate.as_deref())?;
        Ok(Self {
            identifier,
            uri,
            certificate,
            extensions: Vec::new(),
        })
    }

    pub(crate) fn new_with_extensions(
        identifier: Vec<u8>,
        uri: String,
        certificate: Option<Vec<u8>>,
        extensions: Vec<MdocStatusExtension>,
    ) -> Result<Self, MdocEnvelopeError> {
        validate_identifier(&identifier)?;
        validate_uri(&uri)?;
        validate_certificate(certificate.as_deref())?;
        validate_extensions(&extensions, IDENTIFIER_LIST_EXTENSION_RESERVED_NAMES)?;
        Ok(Self {
            identifier,
            uri,
            certificate,
            extensions,
        })
    }

    /// Credential identifier looked up in the referenced identifier list.
    pub fn identifier(&self) -> &[u8] {
        &self.identifier
    }

    /// Absolute URI of the referenced identifier list.
    ///
    /// Network adapters must independently enforce transport and SSRF policy
    /// before dereferencing this authenticated protocol value.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Optional DER-encoded trust certificate for the referenced list.
    pub fn certificate_der(&self) -> Option<&[u8]> {
        self.certificate.as_deref()
    }

    /// Forward-compatible text members retained from IdentifierListInfo.
    #[must_use]
    pub fn extensions(&self) -> &[MdocStatusExtension] {
        &self.extensions
    }

    #[cfg(feature = "mdoc-crypto")]
    fn validate(&self) -> Result<(), MdocEnvelopeError> {
        validate_identifier(&self.identifier)?;
        validate_uri(&self.uri)?;
        validate_certificate(self.certificate.as_deref())?;
        validate_extensions(&self.extensions, IDENTIFIER_LIST_EXTENSION_RESERVED_NAMES)
    }
}

#[derive(Deserialize, Zeroize)]
#[zeroize(drop)]
struct UncheckedStatusList {
    #[serde(rename = "idx")]
    index: u64,
    uri: String,
    certificate: Option<Vec<u8>>,
    #[serde(default)]
    extensions: Vec<MdocStatusExtension>,
}

impl TryFrom<UncheckedStatusList> for MdocStatusList {
    type Error = MdocEnvelopeError;

    fn try_from(mut value: UncheckedStatusList) -> Result<Self, Self::Error> {
        let uri = std::mem::take(&mut value.uri);
        let certificate = value.certificate.take();
        let extensions = core::mem::take(&mut value.extensions);
        Self::new_with_extensions(value.index, uri, certificate, extensions)
    }
}

#[derive(Deserialize, Zeroize)]
#[zeroize(drop)]
struct UncheckedIdentifierList {
    #[serde(rename = "id")]
    identifier: Vec<u8>,
    uri: String,
    certificate: Option<Vec<u8>>,
    #[serde(default)]
    extensions: Vec<MdocStatusExtension>,
}

impl TryFrom<UncheckedIdentifierList> for MdocIdentifierList {
    type Error = MdocEnvelopeError;

    fn try_from(mut value: UncheckedIdentifierList) -> Result<Self, Self::Error> {
        let identifier = std::mem::take(&mut value.identifier);
        let uri = std::mem::take(&mut value.uri);
        let certificate = value.certificate.take();
        let extensions = core::mem::take(&mut value.extensions);
        Self::new_with_extensions(identifier, uri, certificate, extensions)
    }
}
