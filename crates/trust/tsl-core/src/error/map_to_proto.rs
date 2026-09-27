// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

impl From<TslError> for IdentityCoreErrorReason {
    fn from(reason: TslError) -> Self {
        match reason {
            TslError::InvalidXml => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_XML
            }
            TslError::Xml(_) => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_XML
            }
            TslError::InvalidStructure(_) => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_XML
            }
            TslError::InvalidTag => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_TAG
            }
            TslError::MissingField(_) => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_MISSING_FIELD
            }
            TslError::InvalidField(_) => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_URI
            }
            TslError::UnsupportedVersion => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_UNSUPPORTED_VERSION
            }
            TslError::InvalidTimestamp => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_TIMESTAMP
            }
            TslError::InvalidUpdateWindow => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_UPDATE_WINDOW
            }
            TslError::ClosedListNonExpiredService => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_CLOSED_LIST_NON_EXPIRED_SERVICE
            }
            TslError::Expired => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_EXPIRED
            }
            TslError::NotYetIssued => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_TIMESTAMP
            }
            // A superseded list is stale for the caller: a newer authentic
            // publication has already been accepted for this location.
            TslError::SequenceRollback => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_EXPIRED
            }
            TslError::InvalidUri => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_URI
            }
            TslError::InvalidCertificate => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_CERTIFICATE
            }
            TslError::DigitalIdentity(reason) => match reason {
                TslDigitalIdentityFailure::Empty => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_EMPTY
                }
                TslDigitalIdentityFailure::RepresentationLimit => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_REPRESENTATION_LIMIT
                }
                TslDigitalIdentityFailure::MalformedRepresentation => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_MALFORMED_REPRESENTATION
                }
                TslDigitalIdentityFailure::DuplicateRepresentation => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_DUPLICATE_REPRESENTATION
                }
                TslDigitalIdentityFailure::MissingCertificate => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_MISSING_CERTIFICATE
                }
                TslDigitalIdentityFailure::MissingHistoricalSubjectKeyIdentifier => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_HISTORY_MISSING_SKI
                }
                TslDigitalIdentityFailure::HistoricalCertificate => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_HISTORY_CONTAINS_CERTIFICATE
                }
                TslDigitalIdentityFailure::MixedRepresentations => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_MIXED_REPRESENTATIONS
                }
                TslDigitalIdentityFailure::PublicKeyMismatch => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_PUBLIC_KEY_MISMATCH
                }
                TslDigitalIdentityFailure::SubjectNameMismatch => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_SUBJECT_NAME_MISMATCH
                }
                TslDigitalIdentityFailure::CertificateAuthorityMismatch => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_MALFORMED_REPRESENTATION
                }
                TslDigitalIdentityFailure::SubjectKeyIdentifierMismatch => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_SKI_MISMATCH
                }
                TslDigitalIdentityFailure::InvalidNonPkiIdentifier => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_INVALID_NON_PKI_IDENTIFIER
                }
                TslDigitalIdentityFailure::UnsupportedKeyValue => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_UNSUPPORTED_KEY_VALUE
                }
                TslDigitalIdentityFailure::UnsupportedOtherRepresentation => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_MALFORMED_REPRESENTATION
                }
                TslDigitalIdentityFailure::DuplicateServiceKey => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_DIGITAL_IDENTITY_DUPLICATE_SERVICE_KEY
                }
            },
            TslError::Provider(reason) => match reason {
                TslProviderFailure::MissingRegistrationIdentifier => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_PROVIDER_MISSING_REGISTRATION_IDENTIFIER
                }
                TslProviderFailure::MalformedRegistrationIdentifier => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_PROVIDER_MALFORMED_REGISTRATION_IDENTIFIER
                }
                TslProviderFailure::ContradictoryRegistrationIdentifier => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_PROVIDER_CONTRADICTORY_REGISTRATION_IDENTIFIER
                }
                TslProviderFailure::InvalidAddress => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_PROVIDER_INVALID_ADDRESS
                }
            },
            TslError::Address(context, _) => match context {
                TslAddressContext::SchemeOperator => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_INVALID_XML
                }
                TslAddressContext::Provider => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_PROVIDER_INVALID_ADDRESS
                }
            },
            TslError::Qualification(reason) => match reason {
                TslQualificationFailure::Malformed
                | TslQualificationFailure::ElementCount
                | TslQualificationFailure::Qualifiers
                | TslQualificationFailure::MissingCriteria
                | TslQualificationFailure::InvalidAssertion
                | TslQualificationFailure::KeyUsage
                | TslQualificationFailure::DuplicateKeyUsage
                | TslQualificationFailure::EmptyCriteria
                | TslQualificationFailure::IdentifierCount
                | TslQualificationFailure::PolicyIdentifier
                | TslQualificationFailure::DescriptiveMetadata => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_QUALIFICATION_MALFORMED
                }
                TslQualificationFailure::UnsupportedSemantics => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_QUALIFICATION_UNSUPPORTED_SEMANTICS
                }
                TslQualificationFailure::WrongServiceType => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_QUALIFICATION_WRONG_SERVICE_TYPE
                }
            },
            TslError::UnsupportedCriticalExtension => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_UNSUPPORTED_CRITICAL_EXTENSION
            }
            TslError::ResourceLimit(_) => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_CORE_RESOURCE_LIMIT
            }
            TslError::PointerPolicy(reason) => match reason {
                TslPointerPolicyFailure::Depth => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_DEPTH
                }
                TslPointerPolicyFailure::DocumentCount => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_DOCUMENT_COUNT
                }
                TslPointerPolicyFailure::TotalBytes => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_TOTAL_BYTES
                }
                TslPointerPolicyFailure::Cycle => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_CYCLE
                }
                TslPointerPolicyFailure::InsecureTransport => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_INSECURE_TRANSPORT
                }
                TslPointerPolicyFailure::Origin => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_ORIGIN
                }
                TslPointerPolicyFailure::MediaType => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_MEDIA_TYPE
                }
                TslPointerPolicyFailure::TargetMetadataMismatch => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_TARGET_METADATA_MISMATCH
                }
            },
            TslError::PointerQualifier(reason) => match reason {
                TslPointerQualifierFailure::Missing => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_MISSING_QUALIFIER
                }
                TslPointerQualifierFailure::Duplicate => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_DUPLICATE_QUALIFIER
                }
                TslPointerQualifierFailure::Contradictory => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_CONTRADICTORY_QUALIFIER
                }
                TslPointerQualifierFailure::Malformed => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_MALFORMED_QUALIFIER
                }
                TslPointerQualifierFailure::MissingIssuerIdentity => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_MISSING_ISSUER_IDENTITY
                }
                TslPointerQualifierFailure::NonNormativeMimeType => {
                    IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_POINTER_NON_NORMATIVE_MIME_TYPE
                }
            },
        }
    }
}
