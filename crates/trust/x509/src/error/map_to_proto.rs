// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

impl From<X509MissingField> for IdentityCoreErrorReason {
    fn from(reason: X509MissingField) -> Self {
        match reason {
            X509MissingField::Leaf => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_MISSING_FIELD_LEAF
            }
        }
    }
}

impl From<X509PolicyFailure> for IdentityCoreErrorReason {
    fn from(reason: X509PolicyFailure) -> Self {
        match reason {
            X509PolicyFailure::LeafMustBeV3 => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_MUST_BE_V3
            }
            X509PolicyFailure::UnknownCriticalExtension => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_UNKNOWN_CRITICAL_EXTENSION
            }
            X509PolicyFailure::CertificateNotValidAtTime => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_CERTIFICATE_NOT_VALID_AT_TIME
            }
            X509PolicyFailure::LeafMustNotBeCa => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_MUST_NOT_BE_CA
            }
            X509PolicyFailure::MissingLeafKeyUsage => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_MISSING_LEAF_KEY_USAGE
            }
            X509PolicyFailure::LeafMissingDigitalSignature => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_MISSING_DIGITAL_SIGNATURE
            }
            X509PolicyFailure::MissingLeafExtendedKeyUsage => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_MISSING_LEAF_EXTENDED_KEY_USAGE
            }
            X509PolicyFailure::LeafExtendedKeyUsageMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_EXTENDED_KEY_USAGE_MISMATCH
            }
            X509PolicyFailure::LeafCertificatePolicyMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_CERTIFICATE_POLICY_MISMATCH
            }
            X509PolicyFailure::LeafMissingRequiredQcStatement => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_MISSING_REQUIRED_QC_STATEMENT
            }
            X509PolicyFailure::LeafQcTypeMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_QC_TYPE_MISMATCH
            }
            X509PolicyFailure::WeakPublicKey => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_WEAK_PUBLIC_KEY
            }
            X509PolicyFailure::PublicKeyAlgorithmNotAllowed => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_PUBLIC_KEY_ALGORITHM_NOT_ALLOWED
            }
            X509PolicyFailure::SignatureAlgorithmNotAllowed => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_SIGNATURE_ALGORITHM_NOT_ALLOWED
            }
            X509PolicyFailure::LeafNameRequirement => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_NAME_REQUIREMENT
            }
            X509PolicyFailure::LeafKeyIdentifierRequirement => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_KEY_IDENTIFIER_REQUIREMENT
            }
            X509PolicyFailure::LeafAuthorityInformationAccessRequirement => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_AUTHORITY_INFORMATION_ACCESS_REQUIREMENT
            }
            X509PolicyFailure::LeafMissingQscdStatement => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_MISSING_QSCD_STATEMENT
            }
            X509PolicyFailure::RevocationPointerMissing => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_REVOCATION_POINTER_MISSING
            }
            X509PolicyFailure::TslTerritoryMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_TERRITORY_MISMATCH
            }
            X509PolicyFailure::TslServiceTypeMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_SERVICE_TYPE_MISMATCH
            }
            X509PolicyFailure::TslStatusNotGranted => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_STATUS_NOT_GRANTED
            }
            X509PolicyFailure::TslStatusNotEffective => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_STATUS_NOT_EFFECTIVE
            }
            X509PolicyFailure::TslStatusTooOld => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_STATUS_TOO_OLD
            }
            X509PolicyFailure::TslCertificateBindingMissing => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_CERTIFICATE_BINDING_MISSING
            }
            X509PolicyFailure::TslCertificateBindingMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TSL_CERTIFICATE_BINDING_MISMATCH
            }
            X509PolicyFailure::IntermediateMissingBasicConstraints => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_INTERMEDIATE_MISSING_BASIC_CONSTRAINTS
            }
            X509PolicyFailure::IntermediateNotCa => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_INTERMEDIATE_NOT_CA
            }
            X509PolicyFailure::IntermediateMissingKeyUsage => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_INTERMEDIATE_MISSING_KEY_USAGE
            }
            X509PolicyFailure::IntermediateMissingKeyCertSign => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_INTERMEDIATE_MISSING_KEY_CERT_SIGN
            }
            X509PolicyFailure::MissingRequiredExtension => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_MISSING_REQUIRED_EXTENSION
            }
            X509PolicyFailure::ExtensionCriticality => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_EXTENSION_CRITICALITY
            }
            X509PolicyFailure::LeafKeyUsageProfile => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_KEY_USAGE_PROFILE
            }
            X509PolicyFailure::LeafSubjectNameProfile => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_SUBJECT_NAME_PROFILE
            }
            X509PolicyFailure::LeafIssuerNameProfile => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_ISSUER_NAME_PROFILE
            }
            X509PolicyFailure::LeafSelfIssued => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_SELF_ISSUED
            }
            X509PolicyFailure::WrpacPolicyAmbiguous => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_WRPAC_POLICY_AMBIGUOUS
            }
            X509PolicyFailure::WrpacQcStatements => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_WRPAC_QC_STATEMENTS
            }
            X509PolicyFailure::TrustAnchorMissingBasicConstraints => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TRUST_ANCHOR_MISSING_BASIC_CONSTRAINTS
            }
            X509PolicyFailure::TrustAnchorNotCa => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TRUST_ANCHOR_NOT_CA
            }
            X509PolicyFailure::TrustAnchorMissingKeyUsage => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TRUST_ANCHOR_MISSING_KEY_USAGE
            }
            X509PolicyFailure::TrustAnchorMissingKeyCertSign => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TRUST_ANCHOR_MISSING_KEY_CERT_SIGN
            }
            X509PolicyFailure::TrustAnchorMissingCertificatePolicy => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_TRUST_ANCHOR_MISSING_CERTIFICATE_POLICY
            }
            X509PolicyFailure::LeafForbiddenNoRevAvail => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_FORBIDDEN_NO_REV_AVAIL
            }
            X509PolicyFailure::LeafMissingPolicyCpsUri => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_LEAF_MISSING_POLICY_CPS_URI
            }
            X509PolicyFailure::AlgorithmParametersNotAllowed => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_ALGORITHM_PARAMETERS_NOT_ALLOWED
            }
            X509PolicyFailure::PathLengthConstraintExceeded => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_POLICY_PATH_LENGTH_CONSTRAINT_EXCEEDED
            }
        }
    }
}

impl From<X509SignatureFailure> for IdentityCoreErrorReason {
    fn from(reason: X509SignatureFailure) -> Self {
        match reason {
            X509SignatureFailure::ChainTooShort => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_CHAIN_TOO_SHORT
            }
            X509SignatureFailure::ChainIssuerMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_CHAIN_ISSUER_MISMATCH
            }
            X509SignatureFailure::UnsupportedAlgorithm => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_UNSUPPORTED_ALGORITHM
            }
            X509SignatureFailure::InvalidSignature => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_INVALID_SIGNATURE
            }
            X509SignatureFailure::BackendFailure => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_BACKEND_FAILURE
            }
            X509SignatureFailure::XmlDsigUnavailable => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_XMLDSIG_UNAVAILABLE
            }
            // A mismatched inner/outer identifier means the signed structure is
            // not the one the signature value covers under the declared
            // algorithm; it is reported as an invalid signature.
            X509SignatureFailure::AlgorithmIdentifierMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_INVALID_SIGNATURE
            }
            // The lane lacks the capability to process the constraint, which
            // is the same fail-closed class as an unsupported algorithm.
            X509SignatureFailure::UnsupportedPathConstraint => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_SIGNATURE_UNSUPPORTED_ALGORITHM
            }
        }
    }
}

impl From<X509ResourceLimit> for IdentityCoreErrorReason {
    fn from(reason: X509ResourceLimit) -> Self {
        match reason {
            X509ResourceLimit::CertificateChainTooLong => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_CERTIFICATE_CHAIN_TOO_LONG
            }
            X509ResourceLimit::CertificateDerTooLarge => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_CERTIFICATE_DER_TOO_LARGE
            }
            X509ResourceLimit::CertificatePemTooLarge => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_CERTIFICATE_PEM_TOO_LARGE
            }
            X509ResourceLimit::CertificatePemBundleTooLarge => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_CERTIFICATE_PEM_BUNDLE_TOO_LARGE
            }
            X509ResourceLimit::TooManyExtensions => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_TOO_MANY_EXTENSIONS
            }
            X509ResourceLimit::ObjectIdentifierTooLong => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_OBJECT_IDENTIFIER_TOO_LONG
            }
            X509ResourceLimit::TooManyNameAttributes => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_RESOURCE_TOO_MANY_NAME_ATTRIBUTES
            }
        }
    }
}

impl From<X509Error> for IdentityCoreErrorReason {
    fn from(reason: X509Error) -> Self {
        match reason {
            X509Error::InvalidDer => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_INVALID_DER
            }
            X509Error::InvalidPem => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_INVALID_PEM
            }
            X509Error::UnsupportedPemLabel => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_UNSUPPORTED_PEM_LABEL
            }
            X509Error::ParseError => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_PARSE_ERROR
            }
            X509Error::InvalidSerialNumber | X509Error::DuplicateExtension => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_X509_INVALID_DER
            }
            X509Error::MissingField(reason) => reason.into(),
            X509Error::PolicyFailed(reason) => reason.into(),
            X509Error::SignatureFailed(reason) => reason.into(),
            X509Error::ResourceLimitExceeded(reason) => reason.into(),
        }
    }
}
