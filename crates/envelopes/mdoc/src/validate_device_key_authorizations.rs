// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;

use crate::{
    DeviceKeyAuthorizations, MdocEnvelopeError, MdocInvalidInputReason,
    MAX_MDOC_ELEMENTS_PER_NAMESPACE, MAX_MDOC_IDENTIFIER_BYTES, MAX_MDOC_NAMESPACES,
};

/// Validate the issuer-authenticated authorization projection shared by
/// issuance and presentation verification. A value accepted for issuance must
/// never create an MSO that this crate's verifier subsequently rejects.
pub(crate) fn validate_device_key_authorizations(
    authorizations: &DeviceKeyAuthorizations,
) -> Result<(), MdocEnvelopeError> {
    if authorizations.name_spaces.is_empty() && authorizations.data_elements.is_empty() {
        return Err(invalid_authorization());
    }
    if authorizations.name_spaces.len() > MAX_MDOC_NAMESPACES
        || authorizations.data_elements.len() > MAX_MDOC_NAMESPACES
    {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::TooManyNamespaces,
        ));
    }

    let mut namespaces = BTreeSet::new();
    for namespace in &authorizations.name_spaces {
        if namespace.trim().is_empty() || !namespaces.insert(namespace.as_str()) {
            return Err(invalid_authorization());
        }
        validate_identifier_len(namespace)?;
    }
    for (namespace, elements) in &authorizations.data_elements {
        if namespace.trim().is_empty()
            || !namespaces.insert(namespace.as_str())
            || elements.is_empty()
        {
            return Err(invalid_authorization());
        }
        validate_identifier_len(namespace)?;
        if elements.len() > MAX_MDOC_ELEMENTS_PER_NAMESPACE {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::TooManyElementsPerNamespace,
            ));
        }
        let mut unique_elements = BTreeSet::new();
        for element in elements {
            if element.trim().is_empty() || !unique_elements.insert(element.as_str()) {
                return Err(invalid_authorization());
            }
            validate_identifier_len(element)?;
        }
    }
    if namespaces.len() > MAX_MDOC_NAMESPACES {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::TooManyNamespaces,
        ));
    }
    Ok(())
}

fn validate_identifier_len(value: &str) -> Result<(), MdocEnvelopeError> {
    if value.len() > MAX_MDOC_IDENTIFIER_BYTES {
        Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::IdentifierTooLong,
        ))
    } else {
        Ok(())
    }
}

const fn invalid_authorization() -> MdocEnvelopeError {
    MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidDeviceAuthentication)
}
