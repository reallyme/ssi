// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    X509Error, X509MissingField, X509PolicyFailure, X509ResourceLimit, X509SignatureFailure,
};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn x509_top_level_errors_delegate_or_map_to_stable_proto_reasons() {
    let cases = [
        (
            X509Error::InvalidDer,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_INVALID_DER,
        ),
        (
            X509Error::InvalidPem,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_INVALID_PEM,
        ),
        (
            X509Error::UnsupportedPemLabel,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_UNSUPPORTED_PEM_LABEL,
        ),
        (
            X509Error::ParseError,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_PARSE_ERROR,
        ),
        (
            X509Error::MissingField(X509MissingField::Leaf),
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_MISSING_FIELD_LEAF,
        ),
        (
            X509Error::SignatureFailed(X509SignatureFailure::InvalidSignature),
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_INVALID_SIGNATURE,
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}

#[test]
fn x509_policy_failures_map_to_stable_proto_reasons() {
    let cases = [
            (
                X509PolicyFailure::CertificateNotValidAtTime,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_CERTIFICATE_NOT_VALID_AT_TIME,
            ),
            (
                X509PolicyFailure::LeafMustNotBeCa,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_MUST_NOT_BE_CA,
            ),
            (
                X509PolicyFailure::MissingLeafKeyUsage,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_MISSING_LEAF_KEY_USAGE,
            ),
            (
                X509PolicyFailure::LeafMissingDigitalSignature,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_MISSING_DIGITAL_SIGNATURE,
            ),
            (
                X509PolicyFailure::MissingLeafExtendedKeyUsage,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_MISSING_LEAF_EXTENDED_KEY_USAGE,
            ),
            (
                X509PolicyFailure::LeafExtendedKeyUsageMismatch,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_EXTENDED_KEY_USAGE_MISMATCH,
            ),
            (
                X509PolicyFailure::LeafCertificatePolicyMismatch,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_CERTIFICATE_POLICY_MISMATCH,
            ),
            (
                X509PolicyFailure::LeafMissingRequiredQcStatement,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_MISSING_REQUIRED_QC_STATEMENT,
            ),
            (
                X509PolicyFailure::LeafQcTypeMismatch,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_QC_TYPE_MISMATCH,
            ),
            (
                X509PolicyFailure::LeafKeyIdentifierRequirement,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_KEY_IDENTIFIER_REQUIREMENT,
            ),
            (
                X509PolicyFailure::LeafAuthorityInformationAccessRequirement,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_AUTHORITY_INFORMATION_ACCESS_REQUIREMENT,
            ),
            (
                X509PolicyFailure::LeafMissingQscdStatement,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_MISSING_QSCD_STATEMENT,
            ),
            (
                X509PolicyFailure::TslTerritoryMismatch,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_TERRITORY_MISMATCH,
            ),
            (
                X509PolicyFailure::TslServiceTypeMismatch,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_SERVICE_TYPE_MISMATCH,
            ),
            (
                X509PolicyFailure::TslStatusNotGranted,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_STATUS_NOT_GRANTED,
            ),
            (
                X509PolicyFailure::TslStatusNotEffective,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_STATUS_NOT_EFFECTIVE,
            ),
            (
                X509PolicyFailure::TslStatusTooOld,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_STATUS_TOO_OLD,
            ),
            (
                X509PolicyFailure::TslCertificateBindingMissing,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_CERTIFICATE_BINDING_MISSING,
            ),
            (
                X509PolicyFailure::TslCertificateBindingMismatch,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_CERTIFICATE_BINDING_MISMATCH,
            ),
            (
                X509PolicyFailure::IntermediateMissingBasicConstraints,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_INTERMEDIATE_MISSING_BASIC_CONSTRAINTS,
            ),
            (
                X509PolicyFailure::IntermediateNotCa,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_INTERMEDIATE_NOT_CA,
            ),
            (
                X509PolicyFailure::IntermediateMissingKeyUsage,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_INTERMEDIATE_MISSING_KEY_USAGE,
            ),
            (
                X509PolicyFailure::IntermediateMissingKeyCertSign,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_INTERMEDIATE_MISSING_KEY_CERT_SIGN,
            ),
            (
                X509PolicyFailure::MissingRequiredExtension,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_MISSING_REQUIRED_EXTENSION,
            ),
            (
                X509PolicyFailure::ExtensionCriticality,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_EXTENSION_CRITICALITY,
            ),
            (
                X509PolicyFailure::LeafKeyUsageProfile,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_KEY_USAGE_PROFILE,
            ),
            (
                X509PolicyFailure::LeafSubjectNameProfile,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_SUBJECT_NAME_PROFILE,
            ),
            (
                X509PolicyFailure::LeafIssuerNameProfile,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_ISSUER_NAME_PROFILE,
            ),
            (
                X509PolicyFailure::LeafSelfIssued,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_SELF_ISSUED,
            ),
            (
                X509PolicyFailure::WrpacPolicyAmbiguous,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_WRPAC_POLICY_AMBIGUOUS,
            ),
            (
                X509PolicyFailure::WrpacQcStatements,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_WRPAC_QC_STATEMENTS,
            ),
            (
                X509PolicyFailure::TrustAnchorMissingBasicConstraints,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TRUST_ANCHOR_MISSING_BASIC_CONSTRAINTS,
            ),
            (
                X509PolicyFailure::TrustAnchorNotCa,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TRUST_ANCHOR_NOT_CA,
            ),
            (
                X509PolicyFailure::TrustAnchorMissingKeyUsage,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TRUST_ANCHOR_MISSING_KEY_USAGE,
            ),
            (
                X509PolicyFailure::TrustAnchorMissingKeyCertSign,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TRUST_ANCHOR_MISSING_KEY_CERT_SIGN,
            ),
            (
                X509PolicyFailure::TrustAnchorMissingCertificatePolicy,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TRUST_ANCHOR_MISSING_CERTIFICATE_POLICY,
            ),
            (
                X509PolicyFailure::LeafForbiddenNoRevAvail,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_FORBIDDEN_NO_REV_AVAIL,
            ),
            (
                X509PolicyFailure::LeafMissingPolicyCpsUri,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_MISSING_POLICY_CPS_URI,
            ),
            (
                X509PolicyFailure::AlgorithmParametersNotAllowed,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_ALGORITHM_PARAMETERS_NOT_ALLOWED,
            ),
            (
                X509PolicyFailure::PathLengthConstraintExceeded,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_PATH_LENGTH_CONSTRAINT_EXCEEDED,
            ),
        ];

    for (reason, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(reason), expected);
    }
}

#[test]
fn x509_signature_failures_map_to_stable_proto_reasons() {
    let cases = [
            (
                X509SignatureFailure::ChainTooShort,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_CHAIN_TOO_SHORT,
            ),
            (
                X509SignatureFailure::ChainIssuerMismatch,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_CHAIN_ISSUER_MISMATCH,
            ),
            (
                X509SignatureFailure::UnsupportedAlgorithm,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_UNSUPPORTED_ALGORITHM,
            ),
            (
                X509SignatureFailure::InvalidSignature,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_INVALID_SIGNATURE,
            ),
            (
                X509SignatureFailure::BackendFailure,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_BACKEND_FAILURE,
            ),
            (
                X509SignatureFailure::XmlDsigUnavailable,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_XMLDSIG_UNAVAILABLE,
            ),
        ];

    for (reason, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(reason), expected);
    }
}

#[test]
fn x509_resource_limits_map_to_stable_proto_reasons() {
    let cases = [
        (
            X509ResourceLimit::CertificateChainTooLong,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_CERTIFICATE_CHAIN_TOO_LONG,
        ),
        (
            X509ResourceLimit::CertificateDerTooLarge,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_CERTIFICATE_DER_TOO_LARGE,
        ),
        (
            X509ResourceLimit::CertificatePemTooLarge,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_CERTIFICATE_PEM_TOO_LARGE,
        ),
        (
            X509ResourceLimit::CertificatePemBundleTooLarge,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_CERTIFICATE_PEM_BUNDLE_TOO_LARGE,
        ),
        (
            X509ResourceLimit::TooManyExtensions,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_TOO_MANY_EXTENSIONS,
        ),
        (
            X509ResourceLimit::ObjectIdentifierTooLong,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_OBJECT_IDENTIFIER_TOO_LONG,
        ),
        (
            X509ResourceLimit::TooManyNameAttributes,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_TOO_MANY_NAME_ATTRIBUTES,
        ),
    ];

    for (reason, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(reason), expected);
    }
}
