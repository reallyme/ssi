// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{MdocEnvelopeError, MdocInvalidInputReason};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn mdoc_invalid_reason_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(MdocInvalidInputReason::InvalidDeviceAuthentication),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_MDOC_INVALID_DEVICE_AUTHENTICATION
    );
    assert_eq!(
        IdentityCoreErrorReason::from(MdocInvalidInputReason::TooManyDocuments),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_MDOC_TOO_MANY_DOCUMENTS
    );
    assert_eq!(
        IdentityCoreErrorReason::from(MdocInvalidInputReason::CborTooManyItems),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_RESOURCE_LIMIT_EXCEEDED
    );
    assert_eq!(
        IdentityCoreErrorReason::from(MdocInvalidInputReason::InvalidRandomLength),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_MDOC_MALFORMED_ISSUER_SIGNED_ITEM
    );
    assert_eq!(
        IdentityCoreErrorReason::from(MdocInvalidInputReason::DeviceKeyAlgorithmMismatch),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_MDOC_INVALID_DEVICE_AUTH
    );
}

#[test]
fn mdoc_error_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(MdocEnvelopeError::InvalidSignature),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_MDOC_INVALID_ISSUER_AUTH
    );
}
