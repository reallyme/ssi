// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    TrustApiError, TrustApiResourceLimitReason, TrustPolicyErrorReason,
    TrustedListPolicyErrorReason, TrustedListSignatureProfileErrorReason,
};
use identity_trust_tsl_core::{TslDigitalIdentityFailure, TslError};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn trust_api_errors_delegate_or_map_to_stable_proto_reasons() {
    assert_eq!(
        IdentityCoreErrorReason::from(TrustApiError::TrustedList(TslError::DigitalIdentity(
            TslDigitalIdentityFailure::PublicKeyMismatch,
        ))),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_PUBLIC_KEY_MISMATCH
    );
    assert_eq!(
        IdentityCoreErrorReason::from(TrustApiError::InvalidInput),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_API_INVALID_INPUT
    );
    assert_eq!(
        IdentityCoreErrorReason::from(TrustApiError::Policy(
            TrustPolicyErrorReason::UnknownTrustPolicy
        )),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_POLICY_UNKNOWN_TRUST_POLICY
    );
    assert_eq!(
        IdentityCoreErrorReason::from(TrustApiError::ResourceLimit(
            TrustApiResourceLimitReason::TooManyTrustRoots
        )),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_RESOURCE_TOO_MANY_ROOTS
    );
    assert_eq!(
        IdentityCoreErrorReason::from(TrustApiError::TrustedListPolicy(
            TrustedListPolicyErrorReason::SignatureProfile(
                TrustedListSignatureProfileErrorReason::InvalidSignatureProfile
            )
        )),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_INVALID_SIGNATURE_PROFILE
    );
}

#[test]
fn trusted_list_policy_reasons_map_to_stable_proto_reasons() {
    let cases = [
        (
            TrustedListPolicyErrorReason::InvalidTag,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_TAG,
        ),
        (
            TrustedListPolicyErrorReason::InvalidUpdateWindow,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_UPDATE_WINDOW,
        ),
        (
            TrustedListPolicyErrorReason::UnauthorizedIssuer,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_UNAUTHORIZED_ISSUER,
        ),
        (
            TrustedListPolicyErrorReason::CommunityListLimit,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_COMMUNITY_LIST_LIMIT,
        ),
        (
            TrustedListPolicyErrorReason::ExternalSignerCertificateMismatch,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_EXTERNAL_CERTIFICATE_MISMATCH,
        ),
        (
            TrustedListPolicyErrorReason::CountryMismatch,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_COUNTRY_MISMATCH,
        ),
        (
            TrustedListPolicyErrorReason::OrganizationMismatch,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_ORGANIZATION_MISMATCH,
        ),
        (
            TrustedListPolicyErrorReason::MissingKeyUsage,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_MISSING_KEY_USAGE,
        ),
        (
            TrustedListPolicyErrorReason::InvalidKeyUsage,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_KEY_USAGE,
        ),
        (
            TrustedListPolicyErrorReason::MissingSubjectKeyIdentifier,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_SUBJECT_KEY_IDENTIFIER,
        ),
        (
            TrustedListPolicyErrorReason::InvalidSubjectKeyIdentifier,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_INVALID_SUBJECT_KEY_IDENTIFIER,
        ),
        (
            TrustedListPolicyErrorReason::InvalidBasicConstraints,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_BASIC_CONSTRAINTS,
        ),
        (
            TrustedListPolicyErrorReason::InvalidExtendedKeyUsage,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_EXTENDED_KEY_USAGE,
        ),
        (
            TrustedListPolicyErrorReason::AlgorithmLifetime,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_PROFILE_ALGORITHM_LIFETIME,
        ),
        (
            TrustedListPolicyErrorReason::Expired,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_EXPIRED,
        ),
        (
            TrustedListPolicyErrorReason::UnsupportedCriticalExtension,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_UNSUPPORTED_CRITICAL_EXTENSION,
        ),
    ];

    for (reason, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(reason), expected);
    }
}

#[test]
fn trusted_list_signature_profile_reasons_retain_proto_identity() {
    let cases = [
        (
            TrustedListSignatureProfileErrorReason::InvalidSignedProperties,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XADES_SIGNED_PROPERTIES,
        ),
        (
            TrustedListSignatureProfileErrorReason::InvalidSigningCertificate,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XADES_SIGNING_CERTIFICATE,
        ),
        (
            TrustedListSignatureProfileErrorReason::InvalidSigningTime,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XADES_SIGNING_TIME,
        ),
        (
            TrustedListSignatureProfileErrorReason::InvalidDataObjectFormat,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XADES_DATA_OBJECT_FORMAT,
        ),
        (
            TrustedListSignatureProfileErrorReason::SigningCertificateMismatch,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XADES_CERTIFICATE_MISMATCH,
        ),
        (
            TrustedListSignatureProfileErrorReason::KeyInfoCertificateCount,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_KEY_INFO_CERTIFICATE_COUNT,
        ),
    ];

    for (reason, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(reason), expected);
        assert_eq!(
            IdentityCoreErrorReason::from(TrustedListPolicyErrorReason::SignatureProfile(reason)),
            expected
        );
    }
}

#[test]
fn trust_policy_reasons_map_to_stable_proto_reasons() {
    let cases = [
            (
                TrustPolicyErrorReason::UnknownTrustPolicy,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_POLICY_UNKNOWN_TRUST_POLICY,
            ),
            (
                TrustPolicyErrorReason::IssuerDistinguishedNameMismatch,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_POLICY_ISSUER_DISTINGUISHED_NAME_MISMATCH,
            ),
            (
                TrustPolicyErrorReason::AuthorityKeyIdentifierMismatch,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_POLICY_AUTHORITY_KEY_IDENTIFIER_MISMATCH,
            ),
            (
                TrustPolicyErrorReason::MissingAuthorityKeyIdentifier,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_POLICY_MISSING_AUTHORITY_KEY_IDENTIFIER,
            ),
            (
                TrustPolicyErrorReason::MissingSubjectKeyIdentifier,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_POLICY_MISSING_SUBJECT_KEY_IDENTIFIER,
            ),
            (
                TrustPolicyErrorReason::MissingKeyIdentifiers,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_POLICY_MISSING_KEY_IDENTIFIERS,
            ),
        ];

    for (reason, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(reason), expected);
    }
}

#[test]
fn trust_api_resource_limits_map_to_stable_proto_reasons() {
    let cases = [
        (
            TrustApiResourceLimitReason::TooManyTrustRoots,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_RESOURCE_TOO_MANY_ROOTS,
        ),
        (
            TrustApiResourceLimitReason::CertificateDerTooLarge,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_CERTIFICATE_DER_TOO_LARGE,
        ),
        (
            TrustApiResourceLimitReason::PemBundleTooLarge,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_CERTIFICATE_PEM_BUNDLE_TOO_LARGE,
        ),
        (
            TrustApiResourceLimitReason::AllocationFailed,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_RESOURCE_LIMIT_EXCEEDED,
        ),
    ];

    for (reason, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(reason), expected);
    }
}
