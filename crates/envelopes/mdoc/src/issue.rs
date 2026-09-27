// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[path = "assign_digest_id.rs"]
mod assign_digest_id;
use crate::cbor::{encode_issuer_signed_item, encode_mso_cbor, encode_tagged_cbor_bytes};
use crate::device_auth::device_public_key_from_cose_key_cbor;
use crate::validity::validate_validity_window;
use crate::{
    DeviceKeyAuthorizations, DeviceKeyInfo, IssuerAuthSigner, IssuerNameSpaces, IssuerSigned,
    IssuerSignedItem, MdocEnvelopeError, MdocInvalidInputReason, MdocIssuerSignedDocument,
    MdocStatus, MobileSecurityObject, ValidityInfo, ValueDigests, DIGEST_ALG_SHA256,
    DIGEST_ALG_SHA384, DIGEST_ALG_SHA512, MAX_MDOC_ELEMENTS_PER_NAMESPACE,
    MAX_MDOC_ELEMENT_VALUE_BYTES, MAX_MDOC_IDENTIFIER_BYTES, MAX_MDOC_ISSUER_ELEMENTS,
    MAX_MDOC_KEY_INFO_BYTES, MAX_MDOC_NAMESPACES, MAX_MDOC_TOTAL_ELEMENT_VALUE_BYTES,
    MIN_MDOC_ITEM_RANDOM_BYTES, MSO_VERSION, SHA256_DIGEST_LEN,
};
use assign_digest_id::assign_digest_id;
use reallyme_crypto::core::{HashAlgorithm, RngOutputKind};
use reallyme_crypto::csprng::{generate_bytes, OsSecureRandom, SecureRandom};
use reallyme_crypto::dispatch::hash_digest;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroize;

/// Configuration for issuer-side mdoc issuance.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct MdocIssueConfig {
    /// mdoc document type.
    pub doc_type: String,

    /// MSO validity window.
    pub validity: ValidityInfo,

    /// CBOR bytes encoding the holder device COSE_Key.
    pub device_key_cose_key_cbor: Vec<u8>,

    /// Include issuer namespaces in the returned document.
    pub include_namespaces: bool,

    /// ISO value-digest algorithm label (`SHA-256`, `SHA-384`, or `SHA-512`).
    pub digest_algorithm: String,

    /// If true, random digest identifiers need only be unique within each namespace.
    pub digest_id_per_namespace: bool,

    /// Optional ISO/IEC 18013-5 status mechanism to authenticate in the MSO.
    pub status: Option<MdocStatus>,

    /// Optional issuer-authenticated limits on device-signed namespaces and elements.
    pub key_authorizations: Option<DeviceKeyAuthorizations>,

    /// Optional implementation-defined `KeyInfo` map encoded as bounded CBOR.
    pub key_info_cbor: Option<Vec<u8>>,
}

impl MdocIssueConfig {
    /// Create an mdoc issue config with the supported ReallyMe defaults.
    pub fn new(
        doc_type: impl Into<String>,
        validity: ValidityInfo,
        device_key_cose_key_cbor: Vec<u8>,
    ) -> Self {
        Self {
            doc_type: doc_type.into(),
            validity,
            device_key_cose_key_cbor,
            include_namespaces: true,
            digest_algorithm: DIGEST_ALG_SHA256.to_owned(),
            digest_id_per_namespace: false,
            status: None,
            key_authorizations: None,
            key_info_cbor: None,
        }
    }

    /// Authenticate an ISO/IEC 18013-5 status reference in the issued MSO.
    pub fn with_status(mut self, status: MdocStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Authenticate device-key authorization limits in the MSO.
    pub fn with_key_authorizations(mut self, authorizations: DeviceKeyAuthorizations) -> Self {
        self.key_authorizations = Some(authorizations);
        self
    }

    /// Authenticate implementation-defined device-key information in the MSO.
    pub fn with_key_info_cbor(mut self, key_info_cbor: Vec<u8>) -> Self {
        self.key_info_cbor = Some(key_info_cbor);
        self
    }
}

/// Data element to include in an issuer-signed mdoc.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct MdocElement {
    /// ISO mdoc namespace.
    pub namespace: String,

    /// Data element identifier.
    pub element_identifier: String,

    /// Canonical CBOR bytes for the element value.
    pub element_value_cbor: Vec<u8>,

    /// Legacy caller randomizer input.
    ///
    /// Issuance ignores this field and generates a fresh randomizer from the
    /// supplied CSPRNG. It remains only for source compatibility with 0.3.0
    /// prerelease callers and will be removed in the next breaking release.
    pub random: Vec<u8>,
}

/// Issuance output containing both the document and signed MSO model.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct IssuedMdoc {
    /// Portable issuer-signed document.
    pub document: MdocIssuerSignedDocument,

    /// MobileSecurityObject that was encoded and signed into issuerAuth.
    pub mobile_security_object: MobileSecurityObject,
}

/// Issue an issuer-signed mdoc.
pub fn issue_mdoc(
    cfg: &MdocIssueConfig,
    elements: &[MdocElement],
    signer: &dyn IssuerAuthSigner,
) -> Result<IssuedMdoc, MdocEnvelopeError> {
    let (document, mobile_security_object) = build_mso_mdoc(cfg, elements, signer)?;
    Ok(IssuedMdoc {
        document,
        mobile_security_object,
    })
}

/// Build issuer-side mdoc document plus MobileSecurityObject.
pub fn build_mso_mdoc(
    cfg: &MdocIssueConfig,
    elements: &[MdocElement],
    signer: &dyn IssuerAuthSigner,
) -> Result<(MdocIssuerSignedDocument, MobileSecurityObject), MdocEnvelopeError> {
    build_mso_mdoc_with_random(cfg, elements, signer, &mut OsSecureRandom)
}

/// Build an mdoc using an injected cryptographically secure random source.
///
/// Digest identifiers are independent of element position and private salts.
/// The caller must supply a CSPRNG; predictable sources are suitable only for tests.
pub fn build_mso_mdoc_with_random(
    cfg: &MdocIssueConfig,
    elements: &[MdocElement],
    signer: &dyn IssuerAuthSigner,
    random: &mut impl SecureRandom,
) -> Result<(MdocIssuerSignedDocument, MobileSecurityObject), MdocEnvelopeError> {
    validate_issue_config(cfg, elements)?;

    let mut sorted = elements.to_vec();
    sorted.sort_by(|left, right| {
        (left.namespace.as_str(), left.element_identifier.as_str())
            .cmp(&(right.namespace.as_str(), right.element_identifier.as_str()))
    });

    let mut namespaces: IssuerNameSpaces = BTreeMap::new();
    let mut value_digests: ValueDigests = BTreeMap::new();
    let mut global_digest_ids = BTreeSet::new();
    let mut per_namespace_digest_ids: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();

    for element in &sorted {
        validate_element(element)?;
        let used_ids = if cfg.digest_id_per_namespace {
            per_namespace_digest_ids
                .entry(element.namespace.clone())
                .or_default()
        } else {
            &mut global_digest_ids
        };
        let digest_id = assign_digest_id(used_ids, random)?;
        let item_random =
            generate_bytes::<MIN_MDOC_ITEM_RANDOM_BYTES>(random, RngOutputKind::Generic)
                .map_err(|_| MdocEnvelopeError::RandomnessUnavailable)?;
        let item = IssuerSignedItem {
            digest_id,
            random: item_random.as_bytes().to_vec(),
            element_identifier: element.element_identifier.clone(),
            element_value_cbor: element.element_value_cbor.clone(),
        };
        let item_bytes = encode_issuer_signed_item(&item)?;
        let encoded_item_bytes = encode_tagged_cbor_bytes(&item_bytes.bstr)?;
        let digest = value_digest(cfg.digest_algorithm.as_str(), &encoded_item_bytes)?;

        namespaces
            .entry(element.namespace.clone())
            .or_default()
            .push(item_bytes);
        value_digests
            .entry(element.namespace.clone())
            .or_default()
            .insert(digest_id, digest);
    }

    let mobile_security_object = MobileSecurityObject {
        version: MSO_VERSION.to_owned(),
        digest_algorithm: cfg.digest_algorithm.clone(),
        doc_type: cfg.doc_type.clone(),
        validity_info: cfg.validity,
        device_key_info: DeviceKeyInfo {
            device_key_cose_key_cbor: cfg.device_key_cose_key_cbor.clone(),
            key_authorizations: cfg.key_authorizations.clone(),
            key_info_cbor: cfg.key_info_cbor.clone(),
        },
        value_digests,
        status: cfg.status.clone(),
    };
    let mso_cbor = encode_mso_cbor(&mobile_security_object)?;
    let mobile_security_object_bytes = encode_tagged_cbor_bytes(&mso_cbor)?;
    let issuer_auth = signer.sign_issuer_auth(&mobile_security_object_bytes)?;
    let document = MdocIssuerSignedDocument {
        doc_type: cfg.doc_type.clone(),
        issuer_signed: IssuerSigned {
            name_spaces: if cfg.include_namespaces {
                Some(namespaces)
            } else {
                None
            },
            issuer_auth,
        },
    };

    Ok((document, mobile_security_object))
}

fn validate_issue_config(
    cfg: &MdocIssueConfig,
    elements: &[MdocElement],
) -> Result<(), MdocEnvelopeError> {
    if cfg.doc_type.trim().is_empty() {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::EmptyDocType,
        ));
    }
    if cfg.device_key_cose_key_cbor.is_empty() {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::EmptyDeviceKey,
        ));
    }
    device_public_key_from_cose_key_cbor(&cfg.device_key_cose_key_cbor).map_err(|_| {
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidDeviceAuthentication)
    })?;
    validate_validity_window(&cfg.validity)?;
    if !is_supported_digest_algorithm(cfg.digest_algorithm.as_str()) {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::UnsupportedDigestAlgorithm,
        ));
    }
    if let Some(status) = &cfg.status {
        status.validate()?;
    }
    if let Some(authorizations) = &cfg.key_authorizations {
        crate::validate_device_key_authorizations::validate_device_key_authorizations(
            authorizations,
        )?;
    }
    if cfg
        .key_info_cbor
        .as_ref()
        .is_some_and(|key_info| key_info.len() > MAX_MDOC_KEY_INFO_BYTES)
    {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::KeyInfoTooLarge,
        ));
    }
    if elements.is_empty() {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::EmptyElements,
        ));
    }
    validate_element_limits(elements)?;

    Ok(())
}

fn validate_element_limits(elements: &[MdocElement]) -> Result<(), MdocEnvelopeError> {
    if elements.len() > MAX_MDOC_ISSUER_ELEMENTS {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::TooManyElements,
        ));
    }

    let mut namespaces: BTreeMap<&str, usize> = BTreeMap::new();
    let mut identifiers = BTreeSet::new();
    let mut total_element_value_bytes = 0_usize;
    for element in elements {
        if element.element_value_cbor.len() > MAX_MDOC_ELEMENT_VALUE_BYTES {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::ElementValueTooLarge,
            ));
        }
        total_element_value_bytes = total_element_value_bytes
            .checked_add(element.element_value_cbor.len())
            .ok_or(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::IntegerOutOfRange,
            ))?;
        if total_element_value_bytes > MAX_MDOC_TOTAL_ELEMENT_VALUE_BYTES {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::TotalElementValuesTooLarge,
            ));
        }
        if !identifiers.insert((
            element.namespace.as_str(),
            element.element_identifier.as_str(),
        )) {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::DuplicateElementIdentifier,
            ));
        }
        let namespace_count = namespaces.entry(element.namespace.as_str()).or_insert(0);
        *namespace_count = namespace_count.checked_add(1).ok_or({
            MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::IntegerOutOfRange)
        })?;
        if *namespace_count > MAX_MDOC_ELEMENTS_PER_NAMESPACE {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::TooManyElementsPerNamespace,
            ));
        }
    }

    if namespaces.len() > MAX_MDOC_NAMESPACES {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::TooManyNamespaces,
        ));
    }

    Ok(())
}

fn validate_element(element: &MdocElement) -> Result<(), MdocEnvelopeError> {
    if element.namespace.trim().is_empty() {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::EmptyNamespace,
        ));
    }
    if element.namespace.len() > MAX_MDOC_IDENTIFIER_BYTES {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::IdentifierTooLong,
        ));
    }
    if element.element_identifier.trim().is_empty() {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::EmptyElementIdentifier,
        ));
    }
    if element.element_identifier.len() > MAX_MDOC_IDENTIFIER_BYTES {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::IdentifierTooLong,
        ));
    }
    if element.element_value_cbor.is_empty() {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::EmptyElementValue,
        ));
    }
    Ok(())
}

pub(crate) fn sha256(data: &[u8]) -> Result<[u8; SHA256_DIGEST_LEN], MdocEnvelopeError> {
    let digest = hash_digest(HashAlgorithm::Sha2_256, data).map_err(|_| MdocEnvelopeError::Cbor)?;
    <[u8; SHA256_DIGEST_LEN]>::try_from(digest.as_slice()).map_err(|_| MdocEnvelopeError::Cbor)
}

pub(crate) fn is_supported_digest_algorithm(algorithm: &str) -> bool {
    matches!(
        algorithm,
        DIGEST_ALG_SHA256 | DIGEST_ALG_SHA384 | DIGEST_ALG_SHA512
    )
}

pub(crate) fn value_digest(algorithm: &str, data: &[u8]) -> Result<Vec<u8>, MdocEnvelopeError> {
    let hash_algorithm = match algorithm {
        DIGEST_ALG_SHA256 => HashAlgorithm::Sha2_256,
        DIGEST_ALG_SHA384 => HashAlgorithm::Sha2_384,
        DIGEST_ALG_SHA512 => HashAlgorithm::Sha2_512,
        _ => {
            return Err(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::UnsupportedDigestAlgorithm,
            ));
        }
    };
    hash_digest(hash_algorithm, data).map_err(|_| MdocEnvelopeError::Cbor)
}
