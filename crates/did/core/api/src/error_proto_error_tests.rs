// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::DidApiError;
use reallyme_did_method_web::{DidWebError, DidWebErrorReason};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn did_api_error_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(DidApiError::UnsupportedDidMethod),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_UNSUPPORTED_METHOD
    );
    assert_eq!(
        IdentityCoreErrorReason::from(DidApiError::ProtoDecodeFailed),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_INVALID_ENCODING
    );
    assert_eq!(
        IdentityCoreErrorReason::from(DidApiError::DidWeb(DidWebErrorReason::TlsFailure)),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_WEB_TLS_FAILURE
    );
    assert_eq!(
        IdentityCoreErrorReason::from(DidApiError::DidWeb(DidWebErrorReason::ResponseTooLarge)),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_WEB_RESPONSE_TOO_LARGE
    );
    assert_eq!(
        IdentityCoreErrorReason::from(DidApiError::DidWeb(
            DidWebErrorReason::DocumentIdentifierMismatch,
        )),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_DOCUMENT_IDENTIFIER_MISMATCH
    );
    let cases = [
        (
            DidApiError::DidWeb(DidWebErrorReason::JsonLdProcessorUnavailable),
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_JSON_LD_PROCESSOR_UNAVAILABLE,
        ),
        (
            DidApiError::DidWeb(DidWebErrorReason::InvalidJsonLd),
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_INVALID_JSON_LD,
        ),
        (
            DidApiError::DidWeb(DidWebErrorReason::HttpStatusRejected),
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_WEB_HTTP_STATUS_REJECTED,
        ),
        (
            DidApiError::DidWeb(DidWebErrorReason::ProviderUnavailable),
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_WEB_PROVIDER_UNAVAILABLE,
        ),
        (
            DidApiError::DidWeb(DidWebErrorReason::ProviderUnauthenticated),
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_WEB_PROVIDER_UNAUTHENTICATED,
        ),
        (
            DidApiError::DidWeb(DidWebErrorReason::ProviderFailure),
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_WEB_PROVIDER_FAILURE,
        ),
    ];
    for (source, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(source), expected);
    }
}

#[test]
fn did_web_error_converts_without_losing_actionable_reason() {
    let cases = [
        (
            DidWebErrorReason::JsonLdProcessorUnavailable,
            DidApiError::DidWeb(DidWebErrorReason::JsonLdProcessorUnavailable),
        ),
        (
            DidWebErrorReason::InvalidJsonLd,
            DidApiError::DidWeb(DidWebErrorReason::InvalidJsonLd),
        ),
        (
            DidWebErrorReason::HttpStatusRejected,
            DidApiError::DidWeb(DidWebErrorReason::HttpStatusRejected),
        ),
        (
            DidWebErrorReason::ProviderUnavailable,
            DidApiError::DidWeb(DidWebErrorReason::ProviderUnavailable),
        ),
        (
            DidWebErrorReason::ProviderUnauthenticated,
            DidApiError::DidWeb(DidWebErrorReason::ProviderUnauthenticated),
        ),
        (
            DidWebErrorReason::ProviderFailure,
            DidApiError::DidWeb(DidWebErrorReason::ProviderFailure),
        ),
    ];

    for (source, expected) in cases {
        assert_eq!(DidApiError::from(DidWebError::new(source)), expected);
    }
}
