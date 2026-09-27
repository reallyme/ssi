// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::DidWebErrorReason;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn did_web_reason_maps_to_identity_core_proto_reason() {
    let cases = [
        (
            DidWebErrorReason::InvalidPrefix,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_INVALID_PREFIX,
        ),
        (
            DidWebErrorReason::InvalidDomain,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOMAIN,
        ),
        (
            DidWebErrorReason::InvalidDidUrl,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_INVALID_URL,
        ),
        (
            DidWebErrorReason::JsonLdProcessorUnavailable,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_JSON_LD_PROCESSOR_UNAVAILABLE,
        ),
        (
            DidWebErrorReason::InvalidJsonLd,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_INVALID_JSON_LD,
        ),
        (
            DidWebErrorReason::DnsResolutionFailed,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_WEB_NETWORK_FAILURE,
        ),
        (
            DidWebErrorReason::DestinationDenied,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_WEB_POLICY_VIOLATION,
        ),
        (
            DidWebErrorReason::DnsRebindingDetected,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_WEB_POLICY_VIOLATION,
        ),
        (
            DidWebErrorReason::NetworkFailure,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_WEB_NETWORK_FAILURE,
        ),
        (
            DidWebErrorReason::TlsFailure,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_WEB_TLS_FAILURE,
        ),
        (
            DidWebErrorReason::Timeout,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_WEB_TIMEOUT,
        ),
        (
            DidWebErrorReason::Cancelled,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_WEB_CANCELLED,
        ),
        (
            DidWebErrorReason::UnsupportedMediaType,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_WEB_MEDIA_TYPE_REJECTED,
        ),
        (
            DidWebErrorReason::ResponseTooLarge,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_WEB_RESPONSE_TOO_LARGE,
        ),
        (
            DidWebErrorReason::ProviderUnauthenticated,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_WEB_PROVIDER_UNAUTHENTICATED,
        ),
        (
            DidWebErrorReason::UnsupportedMethod,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_UNSUPPORTED_METHOD,
        ),
    ];
    for (reason, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(reason), expected);
    }
}
