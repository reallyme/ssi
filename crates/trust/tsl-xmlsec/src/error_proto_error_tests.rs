// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{XmlSecError, XmlSecPolicyViolationReason};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn xmlsec_policy_reasons_map_to_stable_proto_reasons() {
    let cases = [
            (
                XmlSecPolicyViolationReason::InvalidRootElement,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_INVALID_ROOT_ELEMENT,
            ),
            (
                XmlSecPolicyViolationReason::MissingRootId,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_MISSING_ROOT_ID,
            ),
            (
                XmlSecPolicyViolationReason::MissingRootElement,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_MISSING_ROOT_ELEMENT,
            ),
            (
                XmlSecPolicyViolationReason::RetrievalMethodNotAllowed,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_RETRIEVAL_METHOD_NOT_ALLOWED,
            ),
            (
                XmlSecPolicyViolationReason::KeyInfoReferenceNotAllowed,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_KEY_INFO_REFERENCE_NOT_ALLOWED,
            ),
            (
                XmlSecPolicyViolationReason::NonSameDocumentReference,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_NON_SAME_DOCUMENT_REFERENCE,
            ),
            (
                XmlSecPolicyViolationReason::RootTransformProfile,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_ROOT_TRANSFORMS,
            ),
            (
                XmlSecPolicyViolationReason::InvalidSignedProperties,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XADES_SIGNED_PROPERTIES,
            ),
            (
                XmlSecPolicyViolationReason::InvalidSigningCertificate,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XADES_SIGNING_CERTIFICATE,
            ),
            (
                XmlSecPolicyViolationReason::InvalidSigningTime,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XADES_SIGNING_TIME,
            ),
            (
                XmlSecPolicyViolationReason::InvalidDataObjectFormat,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XADES_DATA_OBJECT_FORMAT,
            ),
            (
                XmlSecPolicyViolationReason::SigningCertificateMismatch,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XADES_CERTIFICATE_MISMATCH,
            ),
            (
                XmlSecPolicyViolationReason::KeyInfoCertificateCount,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_KEY_INFO_CERTIFICATE_COUNT,
            ),
        ];

    for (reason, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(reason), expected);
    }
}

#[test]
fn xmlsec_errors_delegate_or_map_to_stable_proto_reasons() {
    assert_eq!(
        IdentityCoreErrorReason::from(XmlSecError::BackendUnavailable),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_BACKEND_UNAVAILABLE
    );
    assert_eq!(
        IdentityCoreErrorReason::from(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::MissingRootId
        )),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_XMLSEC_POLICY_MISSING_ROOT_ID
    );
}
