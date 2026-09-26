// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    TslDigitalIdentityFailure, TslError, TslPointerPolicyFailure, TslPointerQualifierFailure,
    TslProviderFailure, TslQualificationFailure, TslRequiredField, TslResourceLimit,
};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn tsl_errors_map_to_stable_proto_reasons() {
    let cases = [
        (
            TslError::InvalidXml,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_XML,
        ),
        (
            TslError::InvalidTag,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_TAG,
        ),
        (
            TslError::MissingField(TslRequiredField::Version),
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_MISSING_FIELD,
        ),
        (
            TslError::UnsupportedVersion,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_UNSUPPORTED_VERSION,
        ),
        (
            TslError::InvalidTimestamp,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_TIMESTAMP,
        ),
        (
            TslError::InvalidUpdateWindow,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_UPDATE_WINDOW,
        ),
        (
            TslError::ClosedListNonExpiredService,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_CLOSED_LIST_NON_EXPIRED_SERVICE,
        ),
        (
            TslError::Expired,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_EXPIRED,
        ),
        (
            TslError::NotYetIssued,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_TIMESTAMP,
        ),
        (
            TslError::SequenceRollback,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_EXPIRED,
        ),
        (
            TslError::ResourceLimit(TslResourceLimit::XmlDepth),
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_RESOURCE_LIMIT,
        ),
        (
            TslError::UnsupportedCriticalExtension,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_UNSUPPORTED_CRITICAL_EXTENSION,
        ),
        (
            TslError::PointerPolicy(TslPointerPolicyFailure::Cycle),
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_CYCLE,
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}

#[test]
fn digital_identity_failures_map_to_distinct_proto_reasons() {
    let cases = [
        (TslDigitalIdentityFailure::Empty, IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_EMPTY),
        (TslDigitalIdentityFailure::RepresentationLimit, IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_REPRESENTATION_LIMIT),
        (TslDigitalIdentityFailure::MalformedRepresentation, IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_MALFORMED_REPRESENTATION),
        (TslDigitalIdentityFailure::DuplicateRepresentation, IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_DUPLICATE_REPRESENTATION),
        (TslDigitalIdentityFailure::MissingCertificate, IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_MISSING_CERTIFICATE),
        (TslDigitalIdentityFailure::MissingHistoricalSubjectKeyIdentifier, IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_HISTORY_MISSING_SKI),
        (TslDigitalIdentityFailure::HistoricalCertificate, IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_HISTORY_CONTAINS_CERTIFICATE),
        (TslDigitalIdentityFailure::MixedRepresentations, IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_MIXED_REPRESENTATIONS),
        (TslDigitalIdentityFailure::PublicKeyMismatch, IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_PUBLIC_KEY_MISMATCH),
        (TslDigitalIdentityFailure::SubjectNameMismatch, IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_SUBJECT_NAME_MISMATCH),
        (TslDigitalIdentityFailure::SubjectKeyIdentifierMismatch, IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_SKI_MISMATCH),
        (TslDigitalIdentityFailure::InvalidNonPkiIdentifier, IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_INVALID_NON_PKI_IDENTIFIER),
        (TslDigitalIdentityFailure::UnsupportedKeyValue, IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_UNSUPPORTED_KEY_VALUE),
        (TslDigitalIdentityFailure::UnsupportedOtherRepresentation, IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_MALFORMED_REPRESENTATION),
        (TslDigitalIdentityFailure::DuplicateServiceKey, IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_DUPLICATE_SERVICE_KEY),
    ];

    for (failure, expected) in cases {
        assert_eq!(
            IdentityCoreErrorReason::from(TslError::DigitalIdentity(failure)),
            expected
        );
    }
}

#[test]
fn provider_failures_map_to_distinct_proto_reasons() {
    let cases = [
        (TslProviderFailure::MissingRegistrationIdentifier, IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_PROVIDER_MISSING_REGISTRATION_IDENTIFIER),
        (TslProviderFailure::MalformedRegistrationIdentifier, IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_PROVIDER_MALFORMED_REGISTRATION_IDENTIFIER),
        (TslProviderFailure::ContradictoryRegistrationIdentifier, IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_PROVIDER_CONTRADICTORY_REGISTRATION_IDENTIFIER),
        (TslProviderFailure::InvalidAddress, IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_PROVIDER_INVALID_ADDRESS),
    ];

    for (failure, expected) in cases {
        assert_eq!(
            IdentityCoreErrorReason::from(TslError::Provider(failure)),
            expected
        );
    }
}

#[test]
fn qualification_failures_map_to_distinct_proto_reasons() {
    let cases = [
        (
            TslQualificationFailure::Malformed,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_QUALIFICATION_MALFORMED,
        ),
        (
            TslQualificationFailure::UnsupportedSemantics,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_QUALIFICATION_UNSUPPORTED_SEMANTICS,
        ),
        (
            TslQualificationFailure::WrongServiceType,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_QUALIFICATION_WRONG_SERVICE_TYPE,
        ),
    ];

    for (failure, expected) in cases {
        assert_eq!(
            IdentityCoreErrorReason::from(TslError::Qualification(failure)),
            expected
        );
    }
}

#[test]
fn pointer_policy_failures_map_to_distinct_proto_reasons() {
    let cases = [
        (
            TslPointerPolicyFailure::Depth,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_DEPTH,
        ),
        (
            TslPointerPolicyFailure::DocumentCount,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_DOCUMENT_COUNT,
        ),
        (
            TslPointerPolicyFailure::TotalBytes,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_TOTAL_BYTES,
        ),
        (
            TslPointerPolicyFailure::Cycle,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_CYCLE,
        ),
        (
            TslPointerPolicyFailure::InsecureTransport,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_INSECURE_TRANSPORT,
        ),
        (
            TslPointerPolicyFailure::Origin,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_ORIGIN,
        ),
        (
            TslPointerPolicyFailure::MediaType,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_MEDIA_TYPE,
        ),
    ];

    for (failure, expected) in cases {
        assert_eq!(
            IdentityCoreErrorReason::from(TslError::PointerPolicy(failure)),
            expected
        );
    }
}

#[test]
fn non_normative_pointer_mime_type_maps_to_a_distinct_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(TslError::PointerQualifier(
            TslPointerQualifierFailure::NonNormativeMimeType,
        )),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_NON_NORMATIVE_MIME_TYPE,
    );
}
