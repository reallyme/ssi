// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;

use codec_base64::base64_to_bytes;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;
use quick_xml::XmlVersion;
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{XmlSecError, XmlSecPolicyViolationReason};

use super::TslXmlSignatureAlgorithm;

const TSL_NAMESPACE: &str = "http://uri.etsi.org/02231/v2#";
const XMLDSIG_NAMESPACE: &str = "http://www.w3.org/2000/09/xmldsig#";
const XADES_132_NAMESPACE: &str = "http://uri.etsi.org/01903/v1.3.2#";
const XADES_141_NAMESPACE: &str = "http://uri.etsi.org/01903/v1.4.1#";
const MAX_XML_BYTES: usize = 16 * 1024 * 1024;
const MAX_XML_DEPTH: usize = 128;
const MAX_XML_ELEMENTS: usize = 200_000;
const MAX_ATTRIBUTES_PER_ELEMENT: usize = 128;
/// Maximum XML ID attributes (any element, any prefix) admitted in one document.
const MAX_XML_ID_ATTRIBUTES: usize = 4_096;
/// Attribute local names that the native shim registers as XML IDs through
/// `xmlSecAddIDs`. xmlsec compares the libxml2 attribute local name, so a
/// prefixed attribute such as `foo:Id` or `xml:id` is registered too.
const XML_ID_ATTRIBUTE_LOCAL_NAMES: [&str; 3] = ["id", "Id", "ID"];
const MAX_KEY_INFO_CERTIFICATES: usize = 1;
const MAX_REFERENCES: usize = 8;
const MAX_CERTIFICATE_BASE64_BYTES: usize = 2 * 1024 * 1024;
const MAX_SIGNER_DER_BYTES: usize = 1024 * 1024;
const MAX_SIGNING_TIME_BYTES: usize = 64;
const MAX_MIME_TYPE_BYTES: usize = 128;

const C14N_EXCLUSIVE: &[u8] = b"http://www.w3.org/2001/10/xml-exc-c14n#";
const SIGNED_PROPERTIES_TYPE: &str = "http://uri.etsi.org/01903#SignedProperties";
const SIGNATURE_RSA_SHA256: &[u8] = b"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SIGNATURE_RSA_SHA384: &[u8] = b"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
const SIGNATURE_RSA_SHA512: &[u8] = b"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
const SIGNATURE_RSA_PSS_SHA256: &[u8] = b"http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
const SIGNATURE_RSA_PSS_SHA384: &[u8] = b"http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1";
const SIGNATURE_RSA_PSS_SHA512: &[u8] = b"http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1";
const SIGNATURE_ECDSA_SHA256: &[u8] = b"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
const SIGNATURE_ECDSA_SHA384: &[u8] = b"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
const SIGNATURE_ECDSA_SHA512: &[u8] = b"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
const DIGEST_SHA256: &[u8] = b"http://www.w3.org/2001/04/xmlenc#sha256";
const DIGEST_SHA384: &[u8] = b"http://www.w3.org/2001/04/xmldsig-more#sha384";
const DIGEST_SHA512: &[u8] = b"http://www.w3.org/2001/04/xmlenc#sha512";
const TRANSFORM_ENVELOPED_SIGNATURE: &[u8] =
    b"http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const TSL_MIME_TYPE: &str = "application/vnd.etsi.tsl+xml";
const APPLICATION_XML_MIME_TYPE: &str = "application/xml";
const TEXT_XML_MIME_TYPE: &str = "text/xml";

#[derive(Default, Zeroize, ZeroizeOnDrop)]
pub(super) struct SignatureProfile {
    root_id: Option<String>,
    ids: XmlIdSet,
    signature_depth: Option<usize>,
    signature_id: Option<String>,
    signature_count: usize,
    signed_info_count: usize,
    signed_info_depth: Option<usize>,
    references: Vec<ReferenceProfile>,
    current_reference: Option<usize>,
    current_reference_depth: Option<usize>,
    transforms_depth: Option<usize>,
    canonicalization_method_seen: bool,
    pub(super) signature_algorithm: Option<TslXmlSignatureAlgorithm>,
    key_info_count: usize,
    key_info_depth: Option<usize>,
    x509_data_count: usize,
    x509_data_depth: Option<usize>,
    x509_certificate_depth: Option<usize>,
    certificate_text: Option<String>,
    pub(super) key_info_certificates_der: Vec<Vec<u8>>,
    object_depth: Option<usize>,
    qualifying_properties_count: usize,
    qualifying_properties_depth: Option<usize>,
    signed_properties_count: usize,
    signed_properties_id: Option<String>,
    signed_properties_depth: Option<usize>,
    signed_signature_properties_count: usize,
    signed_signature_properties_depth: Option<usize>,
    signing_time_count: usize,
    signing_time_depth: Option<usize>,
    signing_time_text: Option<String>,
    signing_time_validated: bool,
    signing_certificate_v2_count: usize,
    signing_certificate_v2_depth: Option<usize>,
    signing_certificate_cert_count: usize,
    signing_certificate_cert_depth: Option<usize>,
    certificate_digest_depth: Option<usize>,
    certificate_digest_value_depth: Option<usize>,
    certificate_digest_algorithm: Option<DigestAlgorithm>,
    certificate_digest_text: Option<String>,
    certificate_digest: Option<Vec<u8>>,
    signed_data_object_properties_count: usize,
    signed_data_object_properties_depth: Option<usize>,
    data_object_formats: Vec<DataObjectFormatProfile>,
    current_data_object_format: Option<usize>,
    current_data_object_format_depth: Option<usize>,
    mime_type_depth: Option<usize>,
    mime_type_text: Option<String>,
}

/// Ordered set of XML ID values with O(log n) duplicate detection and lookup.
#[derive(Default)]
struct XmlIdSet {
    values: BTreeSet<String>,
}

impl XmlIdSet {
    /// Insert a new ID value, rejecting empty values, duplicates, and values
    /// beyond the document-wide ID attribute budget.
    fn insert_unique(&mut self, value: &str) -> Result<(), XmlSecError> {
        if value.is_empty() || self.values.contains(value) {
            return Err(XmlSecError::PolicyViolation(
                XmlSecPolicyViolationReason::DuplicateId,
            ));
        }
        if self.values.len() >= MAX_XML_ID_ATTRIBUTES {
            return Err(profile_violation());
        }
        self.values.insert(value.to_owned());
        Ok(())
    }

    fn contains(&self, value: &str) -> bool {
        self.values.contains(value)
    }
}

impl Zeroize for XmlIdSet {
    fn zeroize(&mut self) {
        let values = core::mem::take(&mut self.values);
        for mut value in values {
            value.zeroize();
        }
    }
}

#[derive(Default, Zeroize, ZeroizeOnDrop)]
struct ReferenceProfile {
    id: Option<String>,
    uri: String,
    reference_type: Option<String>,
    transforms_count: usize,
    transforms: Vec<String>,
    digest_method_seen: bool,
}

#[derive(Default, Zeroize, ZeroizeOnDrop)]
struct DataObjectFormatProfile {
    object_reference: String,
    mime_type: Option<String>,
}

#[derive(Clone, Copy, Zeroize)]
enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

pub(super) fn verify_signing_certificate_v2(
    profile: &SignatureProfile,
    signer_certificate_der: &[u8],
) -> Result<(), XmlSecError> {
    let algorithm = profile
        .certificate_digest_algorithm
        .ok_or(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::InvalidSigningCertificate,
        ))?;
    let expected = profile
        .certificate_digest
        .as_deref()
        .ok_or(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::InvalidSigningCertificate,
        ))?;
    let actual = match algorithm {
        DigestAlgorithm::Sha256 => reallyme_crypto::sha2::digest(signer_certificate_der)
            .into_bytes()
            .to_vec(),
        DigestAlgorithm::Sha384 => reallyme_crypto::sha2::digest_sha2_384(signer_certificate_der)
            .into_bytes()
            .to_vec(),
        DigestAlgorithm::Sha512 => reallyme_crypto::sha2::digest_sha2_512(signer_certificate_der)
            .into_bytes()
            .to_vec(),
    };
    if actual != expected {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::SigningCertificateMismatch,
        ));
    }
    Ok(())
}

pub(super) fn enforce_signature_profile(xml: &str) -> Result<SignatureProfile, XmlSecError> {
    if xml.len() > MAX_XML_BYTES {
        return Err(profile_violation());
    }

    let mut reader = NsReader::from_str(xml);
    reader.config_mut().trim_text(true);
    reader.config_mut().check_comments = true;

    let mut profile = SignatureProfile::default();
    let mut depth = 0_usize;
    let mut elements = 0_usize;
    let mut root_seen = false;

    loop {
        match reader.read_event() {
            Ok(Event::Decl(declaration)) => {
                if let Some(encoding) = declaration.encoding() {
                    let encoding = encoding.map_err(|_| profile_violation())?;
                    if !encoding.eq_ignore_ascii_case("UTF-8")
                        && !encoding.eq_ignore_ascii_case("UTF8")
                    {
                        return Err(profile_violation());
                    }
                }
            }
            Ok(Event::Start(element)) => {
                depth = checked_increment(depth)?;
                elements = checked_element_increment(elements)?;
                inspect_element(
                    &reader,
                    &element,
                    depth,
                    false,
                    &mut profile,
                    &mut root_seen,
                )?;
            }
            Ok(Event::Empty(element)) => {
                depth = checked_increment(depth)?;
                elements = checked_element_increment(elements)?;
                inspect_element(&reader, &element, depth, true, &mut profile, &mut root_seen)?;
                close_profile_scope(&mut profile, element.local_name().as_ref(), depth);
                depth = depth.checked_sub(1).ok_or_else(profile_violation)?;
            }
            Ok(Event::Text(text)) => {
                if let Some(certificate_text) = profile.certificate_text.as_mut() {
                    let decoded = text.xml10_content();
                    let new_length = certificate_text
                        .len()
                        .checked_add(decoded.len())
                        .ok_or_else(profile_violation)?;
                    if new_length > MAX_CERTIFICATE_BASE64_BYTES {
                        return Err(profile_violation());
                    }
                    certificate_text.push_str(&decoded);
                }
                if let Some(digest_text) = profile.certificate_digest_text.as_mut() {
                    let decoded = text.xml10_content();
                    let new_length = digest_text
                        .len()
                        .checked_add(decoded.len())
                        .ok_or_else(profile_violation)?;
                    if new_length > 128 {
                        return Err(profile_violation());
                    }
                    digest_text.push_str(&decoded);
                }
                if let Some(signing_time_text) = profile.signing_time_text.as_mut() {
                    let decoded = text.xml10_content();
                    let new_length = signing_time_text
                        .len()
                        .checked_add(decoded.len())
                        .ok_or_else(profile_violation)?;
                    if new_length > MAX_SIGNING_TIME_BYTES {
                        return Err(XmlSecError::PolicyViolation(
                            XmlSecPolicyViolationReason::InvalidSigningTime,
                        ));
                    }
                    signing_time_text.push_str(&decoded);
                }
                if let Some(mime_type_text) = profile.mime_type_text.as_mut() {
                    let decoded = text.xml10_content();
                    let new_length = mime_type_text
                        .len()
                        .checked_add(decoded.len())
                        .ok_or_else(profile_violation)?;
                    if new_length > MAX_MIME_TYPE_BYTES {
                        return Err(XmlSecError::PolicyViolation(
                            XmlSecPolicyViolationReason::InvalidDataObjectFormat,
                        ));
                    }
                    mime_type_text.push_str(&decoded);
                }
            }
            Ok(Event::End(element)) => {
                if profile.certificate_text.is_some()
                    && profile.x509_certificate_depth == Some(depth)
                    && element.local_name().as_ref() == "X509Certificate"
                {
                    finish_certificate(&mut profile)?;
                }
                if profile.certificate_digest_text.is_some()
                    && profile.certificate_digest_value_depth == Some(depth)
                    && element.local_name().as_ref() == "DigestValue"
                {
                    finish_certificate_digest(&mut profile)?;
                }
                if profile.signing_time_text.is_some()
                    && profile.signing_time_depth == Some(depth)
                    && element.local_name().as_ref() == "SigningTime"
                {
                    finish_signing_time(&mut profile)?;
                }
                if profile.mime_type_text.is_some()
                    && profile.mime_type_depth == Some(depth)
                    && element.local_name().as_ref() == "MimeType"
                {
                    finish_mime_type(&mut profile)?;
                }
                close_profile_scope(&mut profile, element.local_name().as_ref(), depth);
                depth = depth.checked_sub(1).ok_or_else(profile_violation)?;
            }
            Ok(Event::DocType(_)) => return Err(profile_violation()),
            // The structural pre-pass and libxml2 must authenticate the same
            // text nodes. Reject CDATA rather than letting the pre-pass ignore
            // content that xmlsec treats as signed character data.
            Ok(Event::CData(_)) => return Err(profile_violation()),
            Ok(Event::Eof) => break,
            Err(_) => return Err(XmlSecError::Internal),
            _ => {}
        }
    }

    validate_complete_profile(root_seen, &profile)?;
    Ok(profile)
}

fn close_profile_scope(profile: &mut SignatureProfile, local_name: &str, depth: usize) {
    match local_name {
        "Signature" if profile.signature_depth == Some(depth) => {
            profile.signature_depth = None;
        }
        "SignedInfo" if profile.signed_info_depth == Some(depth) => {
            profile.signed_info_depth = None;
        }
        "Reference" if profile.current_reference_depth == Some(depth) => {
            profile.current_reference = None;
            profile.current_reference_depth = None;
        }
        "Transforms" if profile.transforms_depth == Some(depth) => {
            profile.transforms_depth = None;
        }
        "KeyInfo" if profile.key_info_depth == Some(depth) => {
            profile.key_info_depth = None;
        }
        "X509Data" if profile.x509_data_depth == Some(depth) => {
            profile.x509_data_depth = None;
        }
        "X509Certificate" if profile.x509_certificate_depth == Some(depth) => {
            profile.x509_certificate_depth = None;
        }
        "Object" if profile.object_depth == Some(depth) => {
            profile.object_depth = None;
        }
        "QualifyingProperties" if profile.qualifying_properties_depth == Some(depth) => {
            profile.qualifying_properties_depth = None;
        }
        "SignedProperties" if profile.signed_properties_depth == Some(depth) => {
            profile.signed_properties_depth = None;
        }
        "SignedSignatureProperties" if profile.signed_signature_properties_depth == Some(depth) => {
            profile.signed_signature_properties_depth = None;
        }
        "SigningTime" if profile.signing_time_depth == Some(depth) => {
            profile.signing_time_depth = None;
        }
        "SigningCertificateV2" if profile.signing_certificate_v2_depth == Some(depth) => {
            profile.signing_certificate_v2_depth = None;
        }
        "Cert" if profile.signing_certificate_cert_depth == Some(depth) => {
            profile.signing_certificate_cert_depth = None;
        }
        "CertDigest" if profile.certificate_digest_depth == Some(depth) => {
            profile.certificate_digest_depth = None;
        }
        "DigestValue" if profile.certificate_digest_value_depth == Some(depth) => {
            profile.certificate_digest_value_depth = None;
        }
        "SignedDataObjectProperties"
            if profile.signed_data_object_properties_depth == Some(depth) =>
        {
            profile.signed_data_object_properties_depth = None;
        }
        "DataObjectFormat" if profile.current_data_object_format_depth == Some(depth) => {
            profile.current_data_object_format = None;
            profile.current_data_object_format_depth = None;
        }
        "MimeType" if profile.mime_type_depth == Some(depth) => {
            profile.mime_type_depth = None;
        }
        _ => {}
    }
}

fn checked_increment(value: usize) -> Result<usize, XmlSecError> {
    let next = value.checked_add(1).ok_or_else(profile_violation)?;
    if next > MAX_XML_DEPTH {
        return Err(profile_violation());
    }
    Ok(next)
}

fn checked_element_increment(value: usize) -> Result<usize, XmlSecError> {
    let next = value.checked_add(1).ok_or_else(profile_violation)?;
    if next > MAX_XML_ELEMENTS {
        return Err(profile_violation());
    }
    Ok(next)
}

include!("inspect_element.rs");

fn collect_ids(
    element: &BytesStart<'_>,
    is_root: bool,
    profile: &mut SignatureProfile,
) -> Result<(), XmlSecError> {
    let mut root_id_count = 0_usize;
    for attribute in element.attributes().with_checks(true) {
        let attribute = attribute.map_err(|_| XmlSecError::Internal)?;
        // Namespace declarations are not attributes in the libxml2 tree and
        // are never registered as IDs, even when declared as `xmlns:Id`.
        if attribute.key.as_namespace_binding().is_some() {
            continue;
        }
        // Match by local name, exactly as xmlSecAddIDs does. Matching the
        // qualified name would let `foo:Id` register a second, unchecked ID
        // in xmlsec that the pre-pass never saw.
        if !XML_ID_ATTRIBUTE_LOCAL_NAMES.contains(&attribute.key.local_name().as_ref()) {
            continue;
        }
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|_| XmlSecError::Internal)?;
        let value = value.as_ref();
        profile.ids.insert_unique(value)?;
        if is_root {
            root_id_count = root_id_count.checked_add(1).ok_or_else(profile_violation)?;
            profile.root_id = Some(value.to_owned());
        }
    }
    // TS 119 612 Annex B.1 permits any same-document reference to the
    // enveloping TrustServiceStatusList. XML Signature 1.1 defines an empty
    // URI as the whole document, and the TSL schema makes the root Id
    // optional. An Id is therefore required only when a non-empty root
    // reference addresses it; multiple competing root identifiers remain
    // ambiguous and are rejected.
    if is_root && root_id_count > 1 {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::InvalidSignatureProfile,
        ));
    }
    Ok(())
}

include!("finish_profile.rs");
include!("validate_profile.rs");
