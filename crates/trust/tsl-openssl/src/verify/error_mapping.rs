// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(all(feature = "native", feature = "xmlsec-ffi"))]
const fn map_xmlsec_policy_reason(
    reason: identity_trust_tsl_xmlsec::XmlSecPolicyViolationReason,
) -> TslSignatureProfileFailureReason {
    use identity_trust_tsl_xmlsec::XmlSecPolicyViolationReason as XmlSecReason;

    match reason {
        XmlSecReason::InvalidRootElement => TslSignatureProfileFailureReason::InvalidRootElement,
        XmlSecReason::MissingRootId => TslSignatureProfileFailureReason::MissingRootId,
        XmlSecReason::MissingRootElement => TslSignatureProfileFailureReason::MissingRootElement,
        XmlSecReason::RetrievalMethodNotAllowed => {
            TslSignatureProfileFailureReason::RetrievalMethodNotAllowed
        }
        XmlSecReason::KeyInfoReferenceNotAllowed => {
            TslSignatureProfileFailureReason::KeyInfoReferenceNotAllowed
        }
        XmlSecReason::NonSameDocumentReference => {
            TslSignatureProfileFailureReason::NonSameDocumentReference
        }
        XmlSecReason::InvalidSignatureProfile => {
            TslSignatureProfileFailureReason::InvalidSignatureProfile
        }
        XmlSecReason::DuplicateId => TslSignatureProfileFailureReason::DuplicateId,
        XmlSecReason::UnsupportedAlgorithm => {
            TslSignatureProfileFailureReason::UnsupportedAlgorithm
        }
        XmlSecReason::SignerBindingMismatch => {
            TslSignatureProfileFailureReason::SignerBindingMismatch
        }
        XmlSecReason::RootTransformProfile => {
            TslSignatureProfileFailureReason::RootTransformProfile
        }
        XmlSecReason::InvalidSignedProperties => {
            TslSignatureProfileFailureReason::InvalidSignedProperties
        }
        XmlSecReason::InvalidSigningCertificate => {
            TslSignatureProfileFailureReason::InvalidSigningCertificate
        }
        XmlSecReason::InvalidSigningTime => TslSignatureProfileFailureReason::InvalidSigningTime,
        XmlSecReason::InvalidDataObjectFormat => {
            TslSignatureProfileFailureReason::InvalidDataObjectFormat
        }
        XmlSecReason::SigningCertificateMismatch => {
            TslSignatureProfileFailureReason::SigningCertificateMismatch
        }
        XmlSecReason::KeyInfoCertificateCount => {
            TslSignatureProfileFailureReason::KeyInfoCertificateCount
        }
    }
}
