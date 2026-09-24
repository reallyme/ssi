// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded validation for authenticated MSO Status values.

use url::Url;

use crate::{
    MdocEnvelopeError, MdocInvalidInputReason, MdocStatusExtension,
    MAX_MDOC_STATUS_CERTIFICATE_BYTES, MAX_MDOC_STATUS_EXTENSIONS,
    MAX_MDOC_STATUS_EXTENSION_NAME_BYTES, MAX_MDOC_STATUS_EXTENSION_VALUE_BYTES,
    MAX_MDOC_STATUS_IDENTIFIER_BYTES, MAX_MDOC_STATUS_URI_BYTES,
};

pub(crate) fn validate_identifier(identifier: &[u8]) -> Result<(), MdocEnvelopeError> {
    if identifier.is_empty() {
        return Err(invalid(MdocInvalidInputReason::EmptyMsoStatusIdentifier));
    }
    if identifier.len() > MAX_MDOC_STATUS_IDENTIFIER_BYTES {
        return Err(invalid(MdocInvalidInputReason::MsoStatusIdentifierTooLong));
    }
    Ok(())
}

pub(crate) fn validate_index(index: u64) -> Result<(), MdocEnvelopeError> {
    if i64::try_from(index).is_err() {
        return Err(invalid(MdocInvalidInputReason::InvalidMsoStatusListIndex));
    }
    Ok(())
}

pub(crate) fn validate_uri(uri: &str) -> Result<(), MdocEnvelopeError> {
    if uri.is_empty() {
        return Err(invalid(MdocInvalidInputReason::EmptyMsoStatusUri));
    }
    if uri.len() > MAX_MDOC_STATUS_URI_BYTES {
        return Err(invalid(MdocInvalidInputReason::MsoStatusUriTooLong));
    }
    if uri.trim() != uri || Url::parse(uri).is_err() {
        return Err(invalid(MdocInvalidInputReason::InvalidMsoStatusUri));
    }
    Ok(())
}

pub(crate) fn validate_certificate(certificate: Option<&[u8]>) -> Result<(), MdocEnvelopeError> {
    let Some(certificate) = certificate else {
        return Ok(());
    };
    if certificate.is_empty() {
        return Err(invalid(MdocInvalidInputReason::InvalidMsoStatusCertificate));
    }
    if certificate.len() > MAX_MDOC_STATUS_CERTIFICATE_BYTES {
        return Err(invalid(MdocInvalidInputReason::MsoStatusCertificateTooLong));
    }
    Ok(())
}

pub(crate) fn validate_extensions(
    extensions: &[MdocStatusExtension],
    reserved_names: &[&str],
) -> Result<(), MdocEnvelopeError> {
    if extensions.len() > MAX_MDOC_STATUS_EXTENSIONS {
        return Err(invalid(MdocInvalidInputReason::TooManyMsoStatusExtensions));
    }
    for (index, extension) in extensions.iter().enumerate() {
        validate_extension(extension)?;
        if reserved_names.contains(&extension.name()) {
            return Err(invalid(MdocInvalidInputReason::DuplicateMsoStatusMember));
        }
        if extensions[..index]
            .iter()
            .any(|existing| existing.name() == extension.name())
        {
            return Err(invalid(MdocInvalidInputReason::DuplicateMsoStatusMember));
        }
    }
    Ok(())
}

pub(crate) fn validate_extension(extension: &MdocStatusExtension) -> Result<(), MdocEnvelopeError> {
    if extension.name().is_empty()
        || extension.name().len() > MAX_MDOC_STATUS_EXTENSION_NAME_BYTES
        || extension.value_cbor().is_empty()
    {
        return Err(invalid(MdocInvalidInputReason::InvalidMsoStatusExtension));
    }
    if extension.value_cbor().len() > MAX_MDOC_STATUS_EXTENSION_VALUE_BYTES {
        return Err(invalid(MdocInvalidInputReason::MsoStatusExtensionTooLong));
    }
    crate::cbor::cbor_bytes_to_value(extension.value_cbor())
        .map_err(|_| invalid(MdocInvalidInputReason::InvalidMsoStatusExtension))?;
    Ok(())
}

const fn invalid(reason: MdocInvalidInputReason) -> MdocEnvelopeError {
    MdocEnvelopeError::InvalidInput(reason)
}
