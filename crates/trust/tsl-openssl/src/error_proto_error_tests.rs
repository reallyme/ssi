// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    TslSignatureProfileFailureReason, TslSignerProfileFailureReason, TslSignerTrustFailureReason,
    TslTrustRootErrorReason,
};
use identity_trust_tsl_core::{TslError, TslProviderFailure};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn tsl_signer_trust_failures_map_to_stable_proto_reasons() {
    let cases = [
        (
            TslSignerTrustFailureReason::NoValidPath,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_NO_VALID_PATH,
        ),
        (
            TslSignerTrustFailureReason::InvalidTime,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_INVALID_TIME,
        ),
        (
            TslSignerTrustFailureReason::ChainLinkPolicy,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_CHAIN_LINK_POLICY,
        ),
        (
            TslSignerTrustFailureReason::InvalidSignature,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_INVALID_SIGNATURE,
        ),
        (
            TslSignerTrustFailureReason::Revoked,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_REVOKED,
        ),
        (
            TslSignerTrustFailureReason::StatusFailure,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_STATUS_FAILURE,
        ),
        (
            TslSignerTrustFailureReason::Internal,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_INTERNAL,
        ),
        (
            TslSignerTrustFailureReason::ResourceLimit,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_RESOURCE_LIMIT,
        ),
    ];

    for (reason, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(reason), expected);
    }
}

#[test]
fn tsl_openssl_errors_delegate_or_map_to_stable_proto_reasons() {
    assert_eq!(
        IdentityCoreErrorReason::from(super::TslOpenSslError::TrustedList(TslError::Provider(
            TslProviderFailure::ContradictoryRegistrationIdentifier,
        ))),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_PROVIDER_CONTRADICTORY_REGISTRATION_IDENTIFIER
    );
    assert_eq!(
        IdentityCoreErrorReason::from(super::TslOpenSslError::InvalidXml),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_OPENSSL_INVALID_XML
    );
    assert_eq!(
        IdentityCoreErrorReason::from(
            super::TslOpenSslError::ExternalSignerCertificateMismatch
        ),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_EXTERNAL_CERTIFICATE_MISMATCH
    );
    assert_eq!(
        IdentityCoreErrorReason::from(super::TslOpenSslError::InvalidTag),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_TAG
    );
    assert_eq!(
        IdentityCoreErrorReason::from(super::TslOpenSslError::InvalidUpdateWindow),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_UPDATE_WINDOW
    );
    assert_eq!(
        IdentityCoreErrorReason::from(super::TslOpenSslError::TrustFailure(
            TslSignerTrustFailureReason::Revoked
        )),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_REVOKED
    );
    assert_eq!(
        IdentityCoreErrorReason::from(super::TslOpenSslError::TrustRoots(
            TslTrustRootErrorReason::TooManyTrustRoots
        )),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_RESOURCE_TOO_MANY_ROOTS
    );
    assert_eq!(
        IdentityCoreErrorReason::from(super::TslOpenSslError::UnsupportedCriticalExtension),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_UNSUPPORTED_CRITICAL_EXTENSION
    );
    assert_eq!(
        IdentityCoreErrorReason::from(super::TslOpenSslError::ExpiredTrustedList),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_EXPIRED
    );
}

#[test]
fn trust_root_failures_map_to_existing_proto_resource_reasons() {
    let cases = [
        (
            TslTrustRootErrorReason::Empty,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_API_INVALID_INPUT,
        ),
        (
            TslTrustRootErrorReason::TooManyTrustRoots,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_RESOURCE_TOO_MANY_ROOTS,
        ),
        (
            TslTrustRootErrorReason::CertificateDerTooLarge,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_CERTIFICATE_DER_TOO_LARGE,
        ),
        (
            TslTrustRootErrorReason::PemBundleTooLarge,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_CERTIFICATE_PEM_BUNDLE_TOO_LARGE,
        ),
        (
            TslTrustRootErrorReason::AllocationFailed,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_RESOURCE_LIMIT_EXCEEDED,
        ),
        (
            TslTrustRootErrorReason::InvalidCertificateDer,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_INVALID_DER,
        ),
    ];

    for (reason, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(reason), expected);
    }
}

#[test]
fn signature_profile_failures_map_to_exact_proto_reasons() {
    let cases = [
        (
            TslSignatureProfileFailureReason::InvalidRootElement,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_INVALID_ROOT_ELEMENT,
        ),
        (
            TslSignatureProfileFailureReason::MissingRootId,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_MISSING_ROOT_ID,
        ),
        (
            TslSignatureProfileFailureReason::MissingRootElement,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_MISSING_ROOT_ELEMENT,
        ),
        (
            TslSignatureProfileFailureReason::RetrievalMethodNotAllowed,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_RETRIEVAL_METHOD_NOT_ALLOWED,
        ),
        (
            TslSignatureProfileFailureReason::KeyInfoReferenceNotAllowed,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_KEY_INFO_REFERENCE_NOT_ALLOWED,
        ),
        (
            TslSignatureProfileFailureReason::NonSameDocumentReference,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_NON_SAME_DOCUMENT_REFERENCE,
        ),
        (
            TslSignatureProfileFailureReason::InvalidSignatureProfile,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_INVALID_SIGNATURE_PROFILE,
        ),
        (
            TslSignatureProfileFailureReason::DuplicateId,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_DUPLICATE_ID,
        ),
        (
            TslSignatureProfileFailureReason::UnsupportedAlgorithm,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_UNSUPPORTED_ALGORITHM,
        ),
        (
            TslSignatureProfileFailureReason::SignerBindingMismatch,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_SIGNER_BINDING_MISMATCH,
        ),
        (
            TslSignatureProfileFailureReason::RootTransformProfile,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_ROOT_TRANSFORMS,
        ),
        (
            TslSignatureProfileFailureReason::InvalidSignedProperties,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XADES_SIGNED_PROPERTIES,
        ),
        (
            TslSignatureProfileFailureReason::InvalidSigningCertificate,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XADES_SIGNING_CERTIFICATE,
        ),
        (
            TslSignatureProfileFailureReason::InvalidSigningTime,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XADES_SIGNING_TIME,
        ),
        (
            TslSignatureProfileFailureReason::InvalidDataObjectFormat,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XADES_DATA_OBJECT_FORMAT,
        ),
        (
            TslSignatureProfileFailureReason::SigningCertificateMismatch,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XADES_CERTIFICATE_MISMATCH,
        ),
        (
            TslSignatureProfileFailureReason::KeyInfoCertificateCount,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_KEY_INFO_CERTIFICATE_COUNT,
        ),
    ];

    for (reason, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(reason), expected);
        assert_eq!(
            IdentityCoreErrorReason::from(super::TslOpenSslError::SignatureProfile(reason)),
            expected
        );
    }
}

#[test]
fn tlso_profile_failures_map_to_distinct_proto_reasons() {
    let cases = [
        (
            TslSignerProfileFailureReason::UnauthorizedIssuer,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_UNAUTHORIZED_ISSUER,
        ),
        (
            TslSignerProfileFailureReason::CommunityListLimit,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_COMMUNITY_LIST_LIMIT,
        ),
        (
            TslSignerProfileFailureReason::MissingSubjectKeyIdentifier,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_SUBJECT_KEY_IDENTIFIER,
        ),
        (
            TslSignerProfileFailureReason::InvalidSubjectKeyIdentifier,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_INVALID_SUBJECT_KEY_IDENTIFIER,
        ),
    ];

    for (reason, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(reason), expected);
    }
}
