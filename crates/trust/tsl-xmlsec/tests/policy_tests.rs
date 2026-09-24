// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::unwrap_used)]
//! Tests for XMLDSig policy pre-screening before xmlsec execution.

use identity_trust_tsl_xmlsec::{
    verify_tsl_xmldsig_xmlsec, XmlSecError, XmlSecPolicyViolationReason,
};

#[test]
fn rejects_reference_uri_not_same_doc() {
    // Minimal Signature skeleton with an external URI.
    let xml = r##"
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" xml:id="TSL" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:Signature Id="SIG">
    <ds:SignedInfo>
      <ds:Reference URI="https://example.com/evil"/>
    </ds:SignedInfo>
  </ds:Signature>
</TrustServiceStatusList>
"##;

    let err = verify_policy_rejection(xml);
    assert!(matches!(
        err,
        XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::NonSameDocumentReference)
    ));
}

#[test]
fn rejects_retrieval_method() {
    let xml = r##"
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" xml:id="TSL" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:Signature Id="SIG">
    <ds:KeyInfo>
      <ds:RetrievalMethod URI="#foo"/>
    </ds:KeyInfo>
  </ds:Signature>
</TrustServiceStatusList>
"##;

    let err = verify_policy_rejection(xml);
    assert!(matches!(
        err,
        XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::RetrievalMethodNotAllowed)
    ));
}

#[test]
fn rejects_key_info_reference() {
    let xml = r##"
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" xml:id="TSL" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
  <dsig11:KeyInfoReference URI="#foo"/>
</TrustServiceStatusList>
"##;

    let err = verify_policy_rejection(xml);
    assert!(matches!(
        err,
        XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::KeyInfoReferenceNotAllowed)
    ));
}

#[test]
fn rejects_reference_to_non_root_id() {
    let xml = signed_fixture().replace("URI=\"#TSL\"", "URI=\"#OTHER\"");
    assert!(matches!(
        verify_policy_rejection(&xml),
        XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::InvalidSignatureProfile)
    ));
}

#[test]
fn accepts_empty_same_document_root_reference_uri() {
    // XML Signature 1.1 section 4.4.3 defines the empty URI as a same-document
    // reference. This is also the shape used by current official EU LOTL and
    // national trusted-list signatures.
    let xml = signed_fixture().replacen("URI=\"#TSL\"", "URI=\"\"", 1);
    assert!(!matches!(
        verify_policy_rejection(&xml),
        XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::InvalidSignatureProfile
                | XmlSecPolicyViolationReason::RootTransformProfile
        )
    ));
}

#[test]
fn accepts_idless_root_with_empty_same_document_reference() {
    let xml =
        signed_fixture()
            .replacen(" Id=\"TSL\"", "", 1)
            .replacen("URI=\"#TSL\"", "URI=\"\"", 1);
    assert!(!matches!(
        verify_policy_rejection(&xml),
        XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::MissingRootId
                | XmlSecPolicyViolationReason::InvalidSignatureProfile
                | XmlSecPolicyViolationReason::RootTransformProfile
        )
    ));
}

#[test]
fn rejects_duplicate_id_values() {
    let xml = signed_fixture().replace("<SchemeInformation>", "<SchemeInformation xml:id=\"TSL\">");
    assert!(matches!(
        verify_policy_rejection(&xml),
        XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::DuplicateId)
    ));
}

#[test]
fn rejects_second_signature() {
    let xml = signed_fixture().replace(
        "</TrustServiceStatusList>",
        "<ds:Signature/></TrustServiceStatusList>",
    );
    assert!(matches!(
        verify_policy_rejection(&xml),
        XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::InvalidSignatureProfile)
    ));
}

#[test]
fn rejects_sha1_signature_algorithm() {
    let xml = signed_fixture().replace(
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    );
    assert!(matches!(
        verify_policy_rejection(&xml),
        XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::UnsupportedAlgorithm)
    ));
}

#[test]
fn admits_fixed_sha2_rsassa_pss_signature_methods() {
    for algorithm in [
        "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1",
        "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1",
        "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1",
    ] {
        let xml = signed_fixture().replace(
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            algorithm,
        );
        assert!(!matches!(
            verify_policy_rejection(&xml),
            XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::UnsupportedAlgorithm)
        ));
    }
}

#[test]
fn rejects_reordered_missing_and_extra_root_transforms() {
    let reordered = signed_fixture().replacen(
        "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n          <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
        "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n          <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>",
        1,
    );
    let missing = signed_fixture().replacen(
        "          <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n",
        "",
        1,
    );
    let extra = signed_fixture().replacen(
        "        </ds:Transforms>",
        "          <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n        </ds:Transforms>",
        1,
    );
    for xml in [reordered, missing, extra] {
        assert!(matches!(
            verify_policy_rejection(&xml),
            XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::RootTransformProfile)
                | XmlSecError::PolicyViolation(
                    XmlSecPolicyViolationReason::InvalidSignatureProfile
                )
        ));
    }
}

#[test]
fn rejects_missing_or_unbound_xades_signed_properties() {
    let missing = signed_fixture().replace(
        "Type=\"http://uri.etsi.org/01903#SignedProperties\"",
        "Type=\"http://example.test/not-signed-properties\"",
    );
    assert!(matches!(
        verify_policy_rejection(&missing),
        XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::InvalidSignedProperties)
    ));

    let unbound = signed_fixture().replace("URI=\"#SIGNED-PROPS\"", "URI=\"#SIG\"");
    assert!(matches!(
        verify_policy_rejection(&unbound),
        XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::InvalidSignedProperties)
    ));
}

#[test]
fn rejects_missing_duplicate_malformed_and_non_utc_signing_time() {
    let fixture = signed_fixture();
    let signing_time = "<xades:SigningTime>2026-09-15T01:00:00Z</xades:SigningTime>";
    let missing = fixture.replacen(signing_time, "", 1);
    let duplicate = fixture.replacen(signing_time, &format!("{signing_time}{signing_time}"), 1);
    let malformed = fixture.replacen(
        signing_time,
        "<xades:SigningTime>not-a-time</xades:SigningTime>",
        1,
    );
    let non_utc = fixture.replacen(
        signing_time,
        "<xades:SigningTime>2026-09-15T02:00:00+01:00</xades:SigningTime>",
        1,
    );
    let nested = fixture.replacen(
        signing_time,
        "<xades:SigningTime><xades:CounterSignature/>2026-09-15T01:00:00Z</xades:SigningTime>",
        1,
    );

    for xml in [missing, duplicate, malformed, non_utc, nested] {
        let error = verify_policy_rejection(&xml);
        assert!(
            matches!(
                error,
                XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::InvalidSigningTime)
            ),
            "unexpected rejection: {error:?}"
        );
    }
}

#[test]
fn rejects_missing_unbound_duplicate_and_incomplete_data_object_format() {
    let fixture = signed_fixture();
    let start = fixture
        .find("          <xades:SignedDataObjectProperties>")
        .unwrap();
    let end_marker = "          </xades:SignedDataObjectProperties>\n";
    let end = fixture[start..]
        .find(end_marker)
        .map(|offset| start + offset + end_marker.len())
        .unwrap();
    let block = &fixture[start..end];
    let missing = fixture.replacen(block, "", 1);
    let unbound = fixture.replacen(
        "ObjectReference=\"#ROOT-REF\"",
        "ObjectReference=\"#NOPE\"",
        1,
    );
    let duplicate = fixture.replacen(
        "            </xades:DataObjectFormat>",
        "            </xades:DataObjectFormat>\n            <xades:DataObjectFormat ObjectReference=\"#ROOT-REF\"><xades:MimeType>application/vnd.etsi.tsl+xml</xades:MimeType></xades:DataObjectFormat>",
        1,
    );
    let missing_mime_type = fixture.replacen(
        "<xades:MimeType>application/vnd.etsi.tsl+xml</xades:MimeType>",
        "",
        1,
    );

    for xml in [missing, unbound, duplicate, missing_mime_type] {
        assert!(matches!(
            verify_policy_rejection(&xml),
            XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::InvalidDataObjectFormat)
        ));
    }
}

#[test]
fn rejects_missing_reference_id_and_non_xml_data_object_type() {
    let missing_reference_id = signed_fixture().replacen(" Id=\"ROOT-REF\"", "", 1);
    let wrong_mime_type = signed_fixture().replacen(
        "<xades:MimeType>application/vnd.etsi.tsl+xml</xades:MimeType>",
        "<xades:MimeType>application/pdf</xades:MimeType>",
        1,
    );

    for xml in [missing_reference_id, wrong_mime_type] {
        assert!(matches!(
            verify_policy_rejection(&xml),
            XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::InvalidDataObjectFormat)
        ));
    }
}

#[test]
fn accepts_registered_xml_data_object_media_types() {
    for mime_type in ["application/xml", "text/xml"] {
        let xml = signed_fixture().replacen("application/vnd.etsi.tsl+xml", mime_type, 1);
        assert!(!matches!(
            verify_policy_rejection(&xml),
            XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::InvalidDataObjectFormat)
        ));
    }
}

#[test]
fn rejects_indirect_qualifying_properties_and_legacy_signing_certificate() {
    let indirect = signed_fixture().replacen(
        "    <ds:Object>",
        "    <ds:Object><xades:QualifyingPropertiesReference xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" URI=\"#SIGNED-PROPS\"/>",
        1,
    );
    let legacy = signed_fixture().replace("SigningCertificateV2", "SigningCertificate");

    for xml in [indirect, legacy] {
        assert!(matches!(
            verify_policy_rejection(&xml),
            XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::InvalidSignedProperties)
        ));
    }
}

#[test]
fn rejects_wrong_xades_core_namespace_and_deprecated_properties() {
    let wrong_namespace = signed_fixture().replace(
        "http://uri.etsi.org/01903/v1.3.2#",
        "http://uri.etsi.org/01903/v1.4.1#",
    );
    let mixed_namespace = signed_fixture()
        .replacen(
            "<xades:SigningTime>",
            "<xades141:SigningTime xmlns:xades141=\"http://uri.etsi.org/01903/v1.4.1#\">",
            1,
        )
        .replacen("</xades:SigningTime>", "</xades141:SigningTime>", 1);
    let legacy_role = signed_fixture().replacen(
        "</xades:SignedSignatureProperties>",
        "<xades:SignerRole/></xades:SignedSignatureProperties>",
        1,
    );
    let legacy_place = signed_fixture().replacen(
        "</xades:SignedSignatureProperties>",
        "<xades:SignatureProductionPlace/></xades:SignedSignatureProperties>",
        1,
    );

    for xml in [wrong_namespace, mixed_namespace, legacy_role, legacy_place] {
        assert!(matches!(
            verify_policy_rejection(&xml),
            XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::InvalidSignedProperties)
        ));
    }
}

#[test]
fn rejects_signing_certificate_uri_indirection() {
    let xml = signed_fixture().replacen("<xades:Cert>", "<xades:Cert URI=\"#CERT\">", 1);
    assert!(matches!(
        verify_policy_rejection(&xml),
        XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::InvalidSigningCertificate)
    ));
}

#[test]
fn rejects_xades_properties_targeting_another_element() {
    let xml = signed_fixture().replace("Target=\"#SIG\"", "Target=\"#TSL\"");
    assert!(matches!(
        verify_policy_rejection(&xml),
        XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::InvalidSignedProperties)
    ));
}

#[test]
fn rejects_signing_certificate_v2_outside_signed_properties() {
    let fixture = signed_fixture();
    let start = fixture.find("<xades:SigningCertificateV2>").unwrap();
    let end_marker = "</xades:SigningCertificateV2>";
    let end = fixture[start..]
        .find(end_marker)
        .map(|offset| start + offset + end_marker.len())
        .unwrap();
    let binding = &fixture[start..end];
    let without_binding = fixture.replacen(binding, "", 1);
    let moved = without_binding.replacen(
        "</xades:SignedProperties>",
        &format!("</xades:SignedProperties>{binding}"),
        1,
    );

    // A matching digest outside the referenced SignedProperties is attacker-
    // controlled metadata, even when the XMLDSig backend accepts the envelope.
    assert!(matches!(
        verify_policy_rejection(&moved),
        XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::InvalidSigningCertificate)
    ));
}

#[test]
fn rejects_key_info_certificate_chain() {
    let certificate = signed_fixture()
        .split("<ds:X509Certificate>")
        .nth(1)
        .and_then(|value| value.split("</ds:X509Certificate>").next())
        .unwrap();
    let second = format!("<ds:X509Certificate>{certificate}</ds:X509Certificate>");
    let xml = signed_fixture().replace("</ds:X509Data>", &format!("{second}</ds:X509Data>"));
    assert!(matches!(
        verify_policy_rejection(&xml),
        XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::InvalidSignatureProfile)
            | XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::KeyInfoCertificateCount)
    ));
}

fn signed_fixture() -> &'static str {
    include_str!("../../tsl-openssl/tests/fixtures/signed_tsl.xml")
}

fn verify_policy_rejection(xml: &str) -> XmlSecError {
    let verification_time = time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
    match verify_tsl_xmldsig_xmlsec(xml, "/nope", verification_time) {
        Ok(_) => XmlSecError::Internal,
        Err(error) => error,
    }
}
