// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::cbor::{decode_device_response_cbor, decode_issuer_signed_item, decode_mso_cbor};
use crate::device_auth::{validate_device_auth, DeviceAuthenticationValidationInput};
use crate::issue::sha256;
use crate::present::{DEVICE_RESPONSE_STATUS_OK, DEVICE_RESPONSE_VERSION};
use crate::validity::validate_validity_window;
use reallyme_cose::Algorithm;

use crate::{
    validate_issuer_auth, validate_x5chain_issuer_auth, IssuerNameSpaces, MdocDeviceResponse,
    MdocEnvelopeError, MdocInvalidInputReason, MdocIssuerSignedDocument, MobileSecurityObject,
    ValueDigests, MAX_MDOC_DEVICE_RESPONSE_DOCUMENTS, MAX_MDOC_ELEMENTS_PER_NAMESPACE,
    MAX_MDOC_NAMESPACES, MSO_VERSION, SHA256_DIGEST_LEN,
};

const MSO_DIGEST_ALGORITHM_SHA_256: &str = "SHA-256";

/// Result of successful issuer-signed mdoc verification.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedMdoc {
    /// Verified mdoc document type.
    pub doc_type: String,

    /// MobileSecurityObject recovered from issuerAuth.
    pub mobile_security_object: MobileSecurityObject,

    /// Disclosed issuer namespaces, when present.
    pub namespaces: Option<IssuerNameSpaces>,
}

/// Result of successful ISO 18013-5 DeviceResponse verification.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedMdocDeviceResponse {
    /// Decoded DeviceResponse model.
    pub device_response: MdocDeviceResponse,

    /// Verified issuer-signed documents in DeviceResponse order.
    pub verified_documents: Vec<VerifiedMdoc>,
}

/// Verify an issuer-signed mdoc.
pub fn verify_mdoc(
    document: &MdocIssuerSignedDocument,
    issuer_public_key_resolver: impl Fn(Algorithm, &[u8]) -> Option<Vec<u8>>,
    now_unix: u64,
) -> Result<VerifiedMdoc, MdocEnvelopeError> {
    verify_issuer_signed_mdoc(document, issuer_public_key_resolver, now_unix)
}

/// Verify issuerAuth, issuer-signed item digests, and the authenticated MSO
/// validity interval at the caller-supplied time.
pub fn verify_issuer_signed_mdoc(
    document: &MdocIssuerSignedDocument,
    issuer_public_key_resolver: impl Fn(Algorithm, &[u8]) -> Option<Vec<u8>>,
    now_unix: u64,
) -> Result<VerifiedMdoc, MdocEnvelopeError> {
    let verified = authenticate_issuer_signed_mdoc(document, issuer_public_key_resolver)?;
    validate_mso_time(&verified.mobile_security_object, now_unix)?;
    Ok(verified)
}

fn authenticate_issuer_signed_mdoc(
    document: &MdocIssuerSignedDocument,
    issuer_public_key_resolver: impl Fn(Algorithm, &[u8]) -> Option<Vec<u8>>,
) -> Result<VerifiedMdoc, MdocEnvelopeError> {
    let mso_cbor = validate_issuer_auth(
        document.issuer_signed.issuer_auth.as_slice(),
        issuer_public_key_resolver,
    )?;
    verified_mdoc_from_mso_cbor(document, &mso_cbor)
}

/// Verify an issuer-signed mdoc through its RFC 9360 `x5chain` certificate path.
///
/// The resolver must perform certificate parsing, path and profile validation,
/// revocation policy, and trust-anchor selection before returning the leaf P-256
/// public key. Merely extracting the leaf key is not a trust decision.
pub fn verify_issuer_signed_mdoc_with_x5chain(
    document: &MdocIssuerSignedDocument,
    certificate_path_resolver: impl FnOnce(&[Vec<u8>]) -> Option<Vec<u8>>,
    now_unix: u64,
) -> Result<VerifiedMdoc, MdocEnvelopeError> {
    let verified =
        authenticate_issuer_signed_mdoc_with_x5chain(document, certificate_path_resolver)?;
    validate_mso_time(&verified.mobile_security_object, now_unix)?;
    Ok(verified)
}

fn authenticate_issuer_signed_mdoc_with_x5chain(
    document: &MdocIssuerSignedDocument,
    certificate_path_resolver: impl FnOnce(&[Vec<u8>]) -> Option<Vec<u8>>,
) -> Result<VerifiedMdoc, MdocEnvelopeError> {
    let verified = validate_x5chain_issuer_auth(
        document.issuer_signed.issuer_auth.as_slice(),
        certificate_path_resolver,
    )?;
    verified_mdoc_from_mso_cbor(document, &verified.payload)
}

/// Verify a newly issued mdoc receipt, including its authenticated validity
/// window, through an RFC 9360 `x5chain` trust resolver.
///
/// This is intentionally separate from presentation verification: issuance
/// receipts do not contain DeviceAuthentication, while the issuer signature,
/// item digests, trust path, document type, and current validity remain
/// mandatory before wallet import.
pub fn verify_issuer_signed_mdoc_receipt_with_x5chain(
    document: &MdocIssuerSignedDocument,
    certificate_path_resolver: impl FnOnce(&[Vec<u8>]) -> Option<Vec<u8>>,
    now_unix: u64,
) -> Result<VerifiedMdoc, MdocEnvelopeError> {
    let verified =
        authenticate_issuer_signed_mdoc_with_x5chain(document, certificate_path_resolver)?;
    validate_mso_time(&verified.mobile_security_object, now_unix)?;
    Ok(verified)
}

fn verified_mdoc_from_mso_cbor(
    document: &MdocIssuerSignedDocument,
    mso_cbor: &[u8],
) -> Result<VerifiedMdoc, MdocEnvelopeError> {
    let mobile_security_object = decode_mso_cbor(mso_cbor)?;
    if mobile_security_object.version != MSO_VERSION {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::UnsupportedMsoVersion,
        ));
    }
    if mobile_security_object.digest_algorithm != MSO_DIGEST_ALGORITHM_SHA_256 {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::UnsupportedDigestAlgorithm,
        ));
    }
    // issuerAuth authenticates these timestamps, but authenticity alone does
    // not make an impossible or zero-length validity window acceptable.
    validate_validity_window(&mobile_security_object.validity_info)?;

    if mobile_security_object.doc_type != document.doc_type {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::DocTypeMismatch,
        ));
    }

    if let Some(namespaces) = &document.issuer_signed.name_spaces {
        verify_value_digests(namespaces, &mobile_security_object.value_digests)?;
    }

    Ok(VerifiedMdoc {
        doc_type: document.doc_type.clone(),
        mobile_security_object,
        namespaces: document.issuer_signed.name_spaces.clone(),
    })
}

/// Verify an ISO 18013-5 DeviceResponse and each contained DeviceAuth.
///
/// OpenID4VP 1.0 Appendix B.2.6 requires the mdoc DeviceAuthentication
/// structure to bind the presentation to the transaction-specific
/// SessionTranscript. Verification therefore never degrades to issuerAuth-only
/// acceptance: every document must carry a DeviceSignature made by the device
/// key authenticated in its MobileSecurityObject. The caller must also supply
/// the trusted evaluation time used for authenticated MSO validity checks.
pub fn verify_mdoc_device_response<F>(
    device_response_cbor: &[u8],
    issuer_public_key_resolver: F,
    expected_session_transcript_cbor: &[u8],
    now_unix: u64,
) -> Result<VerifiedMdocDeviceResponse, MdocEnvelopeError>
where
    F: Fn(Algorithm, &[u8]) -> Option<Vec<u8>>,
{
    verify_mdoc_device_response_with(
        device_response_cbor,
        |document| authenticate_issuer_signed_mdoc(document, &issuer_public_key_resolver),
        expected_session_transcript_cbor,
        now_unix,
    )
}

/// Verify an ISO 18013-5 DeviceResponse whose issuerAuth uses RFC 9360 `x5chain`.
///
/// This is the OpenID4VP/HAIP verification lane. The injected resolver owns the
/// deployment's X.509 trust decision and must fail closed when any certificate
/// or trust evidence is unacceptable. The caller must supply the trusted
/// evaluation time; validity checking cannot be disabled.
pub fn verify_mdoc_device_response_with_x5chain<F>(
    device_response_cbor: &[u8],
    certificate_path_resolver: F,
    expected_session_transcript_cbor: &[u8],
    now_unix: u64,
) -> Result<VerifiedMdocDeviceResponse, MdocEnvelopeError>
where
    F: Fn(&[Vec<u8>]) -> Option<Vec<u8>>,
{
    verify_mdoc_device_response_with(
        device_response_cbor,
        |document| {
            authenticate_issuer_signed_mdoc_with_x5chain(document, &certificate_path_resolver)
        },
        expected_session_transcript_cbor,
        now_unix,
    )
}

fn verify_mdoc_device_response_with(
    device_response_cbor: &[u8],
    issuer_auth_verifier: impl Fn(&MdocIssuerSignedDocument) -> Result<VerifiedMdoc, MdocEnvelopeError>,
    expected_session_transcript_cbor: &[u8],
    now_unix: u64,
) -> Result<VerifiedMdocDeviceResponse, MdocEnvelopeError> {
    let device_response = decode_device_response_cbor(device_response_cbor)?;
    validate_device_response_header(&device_response)?;

    let mut verified_documents = Vec::new();
    for document in &device_response.documents {
        if document.doc_type.trim().is_empty() {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::EmptyDocType,
            ));
        }
        if document.doc_type != document.issuer_signed.doc_type {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::DocTypeMismatch,
            ));
        }

        let verified = issuer_auth_verifier(&document.issuer_signed)?;
        validate_mso_time(&verified.mobile_security_object, now_unix)?;
        // ISO/IEC 18013-5 §9.1.3.5 holder authentication is independent of
        // issuerAuth. The MSO-authenticated device key and the caller's exact
        // SessionTranscript are both required to prevent replay of a captured
        // DeviceResponse (CVE-2026-77456).
        validate_device_auth(&DeviceAuthenticationValidationInput {
            device_auth: document.device_signed.device_auth.as_slice(),
            device_key_cose_key_cbor: verified
                .mobile_security_object
                .device_key_info
                .device_key_cose_key_cbor
                .as_slice(),
            expected_session_transcript_cbor,
            doc_type: document.doc_type.as_str(),
            device_name_spaces_cbor: document.device_signed.name_spaces_cbor.as_slice(),
        })?;
        verified_documents.push(verified);
    }

    Ok(VerifiedMdocDeviceResponse {
        device_response,
        verified_documents,
    })
}

fn verify_value_digests(
    namespaces: &IssuerNameSpaces,
    value_digests: &ValueDigests,
) -> Result<(), MdocEnvelopeError> {
    if namespaces.len() > MAX_MDOC_NAMESPACES {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::TooManyNamespaces,
        ));
    }

    for (namespace, items) in namespaces {
        if items.len() > MAX_MDOC_ELEMENTS_PER_NAMESPACE {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::TooManyElementsPerNamespace,
            ));
        }

        let Some(namespace_digests) = value_digests.get(namespace) else {
            return Err(MdocEnvelopeError::InvalidDigest);
        };

        for tagged in items {
            let issuer_signed_item_bytes = crate::cbor::encode_tagged_cbor_bytes(&tagged.bstr)?;
            let digest = sha256(&issuer_signed_item_bytes)?;
            // A malformed disclosed item is indistinguishable from a digest
            // mismatch at this trust boundary and must not expose parser detail.
            let item =
                decode_issuer_signed_item(tagged).map_err(|_| MdocEnvelopeError::InvalidDigest)?;
            let Some(expected) = namespace_digests.get(&item.digest_id) else {
                return Err(MdocEnvelopeError::InvalidDigest);
            };

            let expected_digest = <[u8; SHA256_DIGEST_LEN]>::try_from(expected.as_slice())
                .map_err(|_| MdocEnvelopeError::InvalidDigest)?;
            if digest != expected_digest {
                return Err(MdocEnvelopeError::InvalidDigest);
            }
        }
    }

    Ok(())
}

fn validate_device_response_header(
    device_response: &MdocDeviceResponse,
) -> Result<(), MdocEnvelopeError> {
    if device_response.version != DEVICE_RESPONSE_VERSION {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::UnsupportedDeviceResponseVersion,
        ));
    }
    if device_response.status != DEVICE_RESPONSE_STATUS_OK {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::InvalidDeviceResponseStatus,
        ));
    }
    if device_response.documents.is_empty() {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::MalformedDeviceResponse,
        ));
    }
    if device_response.documents.len() > MAX_MDOC_DEVICE_RESPONSE_DOCUMENTS {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::TooManyDocuments,
        ));
    }

    Ok(())
}

fn validate_mso_time(
    mobile_security_object: &MobileSecurityObject,
    now_unix: u64,
) -> Result<(), MdocEnvelopeError> {
    if now_unix < mobile_security_object.validity_info.valid_from
        || now_unix >= mobile_security_object.validity_info.valid_until
    {
        return Err(MdocEnvelopeError::Expired);
    }

    Ok(())
}
