// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use super::project_name::{name, Budget};
use super::read_der::{one, take, validate_tree};
use super::{
    project_certificate, Asn1Class, DecodedNameValue, DistributionPointNameProjection,
    GeneralNameValue, ProjectionErrorReason, MAX_PROJECTION_DER_DEPTH, MAX_PROJECTION_DER_ELEMENTS,
    MAX_PROJECTION_DISTRIBUTION_POINTS, MAX_PROJECTION_GENERAL_NAMES,
    MAX_PROJECTION_NAME_ATTRIBUTES,
};
use reallyme_codec::base64::base64_to_bytes;

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 128 {
        out.push(u8::try_from(content.len()).unwrap());
    } else {
        let bytes = content.len().to_be_bytes();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap();
        let length = &bytes[first..];
        out.push(0x80 | u8::try_from(length.len()).unwrap());
        out.extend_from_slice(length);
    }
    out.extend_from_slice(content);
    out
}
fn attribute(value: &[u8]) -> Vec<u8> {
    tlv(0x30, &[tlv(6, &[0x55, 4, 3]), value.to_vec()].concat())
}
fn rdn(values: &[Vec<u8>]) -> Vec<u8> {
    let mut attributes: Vec<_> = values.iter().map(|value| attribute(value)).collect();
    attributes.sort();
    tlv(0x31, &attributes.concat())
}
fn dn(tag: u8, content: &[u8]) -> Vec<u8> {
    tlv(0x30, &rdn(&[tlv(tag, content)]))
}
fn extension(last_oid: u8, critical: bool, value: &[u8]) -> Vec<u8> {
    let mut content = tlv(6, &[0x55, 0x1d, last_oid]);
    if critical {
        content.extend(tlv(1, &[0xff]));
    }
    content.extend(tlv(4, value));
    tlv(0x30, &content)
}
fn fixture() -> Vec<u8> {
    base64_to_bytes(include_str!("../../tests/fixtures/qwac_server_auth_cert.der.b64").trim())
        .unwrap()
}
// Rebuild only the signed syntax; these projections deliberately make no claim
// that the fixture's original signature authenticates the modified certificate.
fn certificate(subject: &[u8], issuer: &[u8], extensions: &[Vec<u8>]) -> Vec<u8> {
    let der = fixture();
    let outer = one(&der).unwrap();
    let mut outer_fields = outer.content;
    let tbs = take(&mut outer_fields).unwrap();
    let mut fields = tbs.content;
    let mut encoded = Vec::new();
    let mut index = 0;
    while !fields.is_empty() {
        let field = take(&mut fields).unwrap();
        match index {
            3 => encoded.extend_from_slice(issuer),
            5 => encoded.extend_from_slice(subject),
            _ if field.encoding.class == Asn1Class::ContextSpecific
                && field.encoding.tag_number == 3 => {}
            _ => encoded.extend_from_slice(field.der),
        }
        index += 1;
    }
    if !extensions.is_empty() {
        encoded.extend(tlv(0xa3, &tlv(0x30, &extensions.concat())));
    }
    tlv(0x30, &[tlv(0x30, &encoded), outer_fields.to_vec()].concat())
}
fn with_extensions(extensions: &[Vec<u8>]) -> Vec<u8> {
    certificate(
        &dn(12, b"subject-secret"),
        &dn(19, b"issuer-secret"),
        extensions,
    )
}
fn full_name(uri: &[u8]) -> Vec<u8> {
    tlv(0xa0, &tlv(0xa0, &tlv(0x86, uri)))
}
fn points(points: &[Vec<u8>], critical: bool) -> Vec<u8> {
    extension(31, critical, &tlv(0x30, &points.concat()))
}
fn error(der: &[u8], expected: ProjectionErrorReason) {
    assert_eq!(project_certificate(der).unwrap_err().reason, expected);
}

#[test]
fn preserves_dn_encoding_for_identical_text_in_both_existing_and_borrowed_models() {
    let der = certificate(&dn(19, b"US"), &dn(12, b"US"), &[]);
    let view = project_certificate(&der).unwrap();
    let subject = &view.subject().rdns()[0].attributes()[0];
    let issuer = &view.issuer().rdns()[0].attributes()[0];
    assert_eq!(subject.decoded().text(), Some("US"));
    assert_eq!(issuer.decoded().text(), Some("US"));
    assert_eq!(subject.value().encoding().tag_number, 19);
    assert_eq!(issuer.value().encoding().tag_number, 12);
    assert_eq!(subject.value().der(), tlv(19, b"US"));
    let owned = crate::parse_cert_der(&der).unwrap();
    assert_eq!(
        owned.profile.subject.rdns[0].attributes[0].encoding,
        subject.value().encoding()
    );
    assert_eq!(
        owned.profile.issuer.rdns[0].attributes[0].encoding,
        issuer.value().encoding()
    );
}

#[test]
fn preserves_rdn_grouping_order_and_attribute_multiplicity() {
    let subject = tlv(
        0x30,
        &[
            rdn(&[tlv(12, b"A"), tlv(12, b"A"), tlv(19, b"US")]),
            rdn(&[tlv(12, b"B")]),
        ]
        .concat(),
    );
    let der = certificate(&subject, &dn(12, b"issuer"), &[]);
    let view = project_certificate(&der).unwrap();
    assert_eq!(view.subject().rdns().len(), 2);
    assert_eq!(view.subject().rdns()[0].attributes().len(), 3);
    assert_eq!(
        view.subject().rdns()[1].attributes()[0].decoded().text(),
        Some("B")
    );
    assert_eq!(view.subject().encoded().der(), subject);
}

#[test]
fn preserves_nonuniversal_and_high_tag_identifiers_without_text_guessing() {
    for (encoded, class, tag, constructed) in [
        (
            vec![0xdf, 0x81, 0x49, 2, b'U', b'S'],
            Asn1Class::Private,
            201,
            false,
        ),
        (
            vec![0x7f, 0x21, 3, 2, 1, 1],
            Asn1Class::Application,
            33,
            true,
        ),
        (
            vec![0x85, 2, b'U', b'S'],
            Asn1Class::ContextSpecific,
            5,
            false,
        ),
    ] {
        let der = tlv(0x30, &rdn(std::slice::from_ref(&encoded)));
        let view = name(&der, &mut Budget::default()).unwrap();
        let value = &view.rdns()[0].attributes()[0];
        assert_eq!(
            value.value().encoding(),
            super::AttributeEncoding {
                class,
                tag_number: tag,
                constructed
            }
        );
        assert!(matches!(value.decoded(), DecodedNameValue::Unsupported));
        assert_eq!(value.value().der(), encoded);
    }
}

#[test]
fn decodes_bmp_and_universal_strings_into_zeroizing_owners() {
    fn zeroizes<T: zeroize::ZeroizeOnDrop>() {}
    zeroizes::<super::ProtectedNameText>();
    for (tag, bytes) in [
        (30, vec![0, b'U', 0, b'S']),
        (28, vec![0, 0, 0, b'U', 0, 0, 0, b'S']),
    ] {
        let der = dn(tag, &bytes);
        let view = name(&der, &mut Budget::default()).unwrap();
        let value = view.rdns()[0].attributes()[0].decoded();
        assert!(
            matches!(value, DecodedNameValue::Unicode(owner) if !format!("{owner:?}").contains("US"))
        );
        assert_eq!(value.text(), Some("US"));
    }
}

#[test]
fn validates_supported_string_repertoires_and_marks_legacy_charset_unsupported() {
    for (tag, bytes) in [
        (12, "é".as_bytes()),
        (18, b"12 34".as_slice()),
        (19, b"US '()+,-./:=?".as_slice()),
        (22, b"a@b".as_slice()),
        (26, b"visible".as_slice()),
    ] {
        let der = dn(tag, bytes);
        let view = name(&der, &mut Budget::default()).unwrap();
        assert_eq!(
            view.rdns()[0].attributes()[0].decoded().text(),
            core::str::from_utf8(bytes).ok()
        );
    }
    let der = dn(20, &[0xe9]);
    let view = name(&der, &mut Budget::default()).unwrap();
    assert!(matches!(
        view.rdns()[0].attributes()[0].decoded(),
        DecodedNameValue::Unsupported
    ));
    assert_eq!(view.rdns()[0].attributes()[0].value().content(), &[0xe9]);
}

#[test]
fn rejects_malformed_declared_strings_in_both_parsers() {
    for (tag, bytes) in [
        (12, vec![0xc0, 0xaf]),
        (18, b"A".to_vec()),
        (19, b"@".to_vec()),
        (19, "é".as_bytes().to_vec()),
        (22, vec![0xff]),
        (26, vec![0x1f]),
        (30, vec![0]),
        (30, vec![0xd8, 0]),
        (28, vec![0, 0x11, 0, 0]),
        (28, vec![0, 0, 0]),
    ] {
        let der = certificate(&dn(tag, &bytes), &dn(12, b"issuer"), &[]);
        error(&der, ProjectionErrorReason::InvalidStringEncoding);
        assert_eq!(
            crate::parse_cert_der(&der).unwrap_err(),
            crate::X509Error::InvalidDer
        );
    }
}

#[test]
fn san_and_ian_are_separate_present_extensions_with_exact_values_and_criticality() {
    let san = extension(17, false, &tlv(0x30, &tlv(0x81, b"subject@example.test")));
    let ian = extension(
        18,
        true,
        &tlv(
            0x30,
            &[
                tlv(0x81, b"Issuer@EXAMPLE.test"),
                tlv(0x86, b"https://EXAMPLE.test/%41"),
            ]
            .concat(),
        ),
    );
    let der = with_extensions(&[san, ian]);
    let view = project_certificate(&der).unwrap();
    assert!(!view.subject_alternative_names().unwrap().critical());
    let ian = view.issuer_alternative_names().unwrap();
    assert!(ian.critical());
    assert!(
        matches!(ian.names()[0].value(), GeneralNameValue::Rfc822Name(text) if text.as_str() == "Issuer@EXAMPLE.test")
    );
    assert!(
        matches!(ian.names()[1].value(), GeneralNameValue::UniformResourceIdentifier(text) if text.as_str() == "https://EXAMPLE.test/%41")
    );
    let empty = with_extensions(&[]);
    let view = project_certificate(&empty).unwrap();
    assert!(view.subject_alternative_names().is_none());
    assert!(view.issuer_alternative_names().is_none());
    assert!(view.crl_distribution_points().is_none());
}

#[test]
fn retains_all_nine_general_name_alternatives_and_original_der() {
    let general_names = vec![
        tlv(
            0xa0,
            &[tlv(6, &[0x2a, 3]), tlv(0xa0, &tlv(12, b"other-secret"))].concat(),
        ),
        tlv(0x81, b"mail-secret@example.test"),
        tlv(0x82, b"dns-secret.test"),
        tlv(0xa3, &tlv(0x30, &[])),
        tlv(0xa4, &dn(12, b"directory-secret")),
        tlv(0xa5, &tlv(0xa1, &tlv(12, b"party-secret"))),
        tlv(0x86, b"https://uri-secret.test"),
        tlv(0x87, &[127, 0, 0, 1]),
        tlv(0x88, &[0x2a, 3]),
    ];
    let der = with_extensions(&[extension(18, false, &tlv(0x30, &general_names.concat()))]);
    let view = project_certificate(&der).unwrap();
    let names = view.issuer_alternative_names().unwrap().names();
    assert_eq!(names.len(), 9);
    for (name, expected) in names.iter().zip(&general_names) {
        assert_eq!(name.encoded().der(), expected);
    }
    assert!(
        matches!(names[0].value(), GeneralNameValue::OtherName { type_id, value } if type_id.content() == [0x2a, 3] && value.content() == tlv(12, b"other-secret"))
    );
    assert!(matches!(names[2].value(), GeneralNameValue::DnsName(_)));
    assert!(matches!(
        names[3].value(),
        GeneralNameValue::UnsupportedX400Address
    ));
    assert!(matches!(
        names[4].value(),
        GeneralNameValue::DirectoryName(_)
    ));
    assert!(matches!(
        names[5].value(),
        GeneralNameValue::UnsupportedEdiPartyName
    ));
    assert!(
        matches!(names[7].value(), GeneralNameValue::IpAddress(raw) if raw.content() == [127, 0, 0, 1])
    );
    assert!(
        matches!(names[8].value(), GeneralNameValue::RegisteredId(raw) if raw.content() == [0x2a, 3])
    );
    let diagnostic = format!("{view:?}");
    assert!(!diagnostic.contains("secret"));
    assert!(!diagnostic.contains("127"));
}

#[test]
fn rejects_invalid_general_names_even_in_noncritical_extensions() {
    for value in [
        tlv(0x81, &[0xff]),
        tlv(0x86, &[0xc3, 0xa9]),
        tlv(0x89, b"unknown"),
        tlv(0xa1, &tlv(12, b"mail")),
        tlv(0x88, &[0x80, 1]),
        tlv(0xa0, &tlv(6, &[0x2a, 3])),
        tlv(0xa4, &[]),
    ] {
        let der = with_extensions(&[extension(18, false, &tlv(0x30, &value))]);
        assert!(project_certificate(&der).is_err());
    }
    let der = with_extensions(&[extension(18, false, &tlv(0x30, &[]))]);
    error(&der, ProjectionErrorReason::InvalidDer);
}

#[test]
fn preserves_ordered_points_choices_reasons_presence_and_crl_issuer() {
    let first = tlv(0x30, &full_name(b"https://crl.test/first"));
    let second = tlv(
        0x30,
        &[
            full_name(b"https://crl.test/second"),
            tlv(0x81, &[0]),
            tlv(0xa2, &tlv(0xa4, &dn(12, b"crl issuer"))),
        ]
        .concat(),
    );
    let relative = tlv(0xa1, &attribute(&tlv(19, b"US")));
    let third = tlv(
        0x30,
        &[tlv(0xa0, &relative), tlv(0x81, &[7, 0x40, 0x80])].concat(),
    );
    let issuer_only = tlv(0x30, &tlv(0xa2, &tlv(0x86, b"https://issuer.test")));
    let der = with_extensions(&[points(
        &[first.clone(), second.clone(), third, issuer_only],
        true,
    )]);
    let view = project_certificate(&der).unwrap();
    let extension = view.crl_distribution_points().unwrap();
    assert!(extension.critical());
    let points = extension.points();
    assert_eq!(points.len(), 4);
    assert_eq!(points[0].encoded().der(), first);
    assert!(points[0].reasons().is_none());
    assert!(points[0].crl_issuer().is_none());
    assert_eq!(points[1].reasons().unwrap().encoded().content(), [0]);
    assert!(!points[1].reasons().unwrap().contains(1));
    assert!(matches!(
        points[1].crl_issuer().unwrap()[0].value(),
        GeneralNameValue::DirectoryName(_)
    ));
    assert!(
        matches!(points[2].distribution_point(), Some(DistributionPointNameProjection::RelativeName(name)) if name.attributes()[0].decoded().text() == Some("US"))
    );
    assert!(points[2].reasons().unwrap().contains(1));
    assert!(points[2].reasons().unwrap().contains(8));
    assert!(!points[2].reasons().unwrap().contains(usize::MAX));
    assert!(points[3].distribution_point().is_none());
    assert!(
        matches!(points[0].distribution_point(), Some(DistributionPointNameProjection::FullName(names)) if matches!(names[0].value(), GeneralNameValue::UniformResourceIdentifier(uri) if uri.as_str() == "https://crl.test/first"))
    );
}

#[test]
fn preserves_unknown_reason_bits_without_applying_profile_policy() {
    let point = tlv(
        0x30,
        &[full_name(b"https://crl.test"), tlv(0x81, &[7, 0, 0, 0x80])].concat(),
    );
    let der = with_extensions(&[points(&[point], false)]);
    let view = project_certificate(&der).unwrap();
    let reasons = view.crl_distribution_points().unwrap().points()[0]
        .reasons()
        .unwrap();
    assert!(reasons.contains(16));
    assert!(!reasons.contains(8));
    assert_eq!(reasons.encoded().content(), [7, 0, 0, 0x80]);
}

#[test]
fn keeps_non_uri_full_names_and_multiple_names_in_a_point() {
    let name = tlv(
        0xa0,
        &tlv(
            0xa0,
            &[tlv(0x82, b"crl.test"), tlv(0x86, b"https://crl.test")].concat(),
        ),
    );
    let der = with_extensions(&[points(&[tlv(0x30, &name)], false)]);
    let view = project_certificate(&der).unwrap();
    let extension = view.crl_distribution_points().unwrap();
    assert!(!extension.critical());
    assert!(
        matches!(extension.points()[0].distribution_point(), Some(DistributionPointNameProjection::FullName(names)) if names.len() == 2 && matches!(names[0].value(), GeneralNameValue::DnsName(_)))
    );
}

#[test]
fn rejects_duplicate_out_of_order_or_malformed_crl_fields() {
    let full = full_name(b"https://crl.test");
    for fields in [
        [full.clone(), full.clone()].concat(),
        [tlv(0x81, &[0]), full.clone()].concat(),
        [full.clone(), tlv(0x81, &[8, 0])].concat(),
        [full.clone(), tlv(0x81, &[1, 1])].concat(),
        [full.clone(), tlv(0x81, &[0, 0])].concat(),
        [full.clone(), tlv(0x81, &[0, 0x80, 0x80])].concat(),
        tlv(0xa0, &tlv(0xa2, &tlv(0x86, b"https://wrong.test"))),
        tlv(0xa2, &[]),
        tlv(
            0xa0,
            &[
                tlv(0xa0, &tlv(0x86, b"https://a")),
                tlv(0xa0, &tlv(0x86, b"https://b")),
            ]
            .concat(),
        ),
    ] {
        error(
            &with_extensions(&[points(&[tlv(0x30, &fields)], false)]),
            ProjectionErrorReason::InvalidDer,
        );
    }
    error(
        &with_extensions(&[points(&[], false)]),
        ProjectionErrorReason::InvalidDer,
    );
}

#[test]
fn rejects_duplicate_known_and_unknown_extensions() {
    for id in [17, 18, 31, 99] {
        let value = if id == 31 {
            tlv(0x30, &tlv(0x30, &full_name(b"https://crl.test")))
        } else {
            tlv(0x30, &tlv(0x86, b"https://name.test"))
        };
        let ext = extension(id, false, &value);
        error(
            &with_extensions(&[ext.clone(), ext]),
            ProjectionErrorReason::DuplicateExtension,
        );
    }
}

#[test]
fn enforces_shared_attribute_general_name_point_and_extension_limits() {
    let attributes = vec![tlv(12, b"A"); MAX_PROJECTION_NAME_ATTRIBUTES];
    let subject = tlv(0x30, &rdn(&attributes));
    assert!(project_certificate(&certificate(&subject, &tlv(0x30, &[]), &[])).is_ok());
    let subject = tlv(
        0x30,
        &rdn(&vec![tlv(12, b"A"); MAX_PROJECTION_NAME_ATTRIBUTES + 1]),
    );
    error(
        &certificate(&subject, &tlv(0x30, &[]), &[]),
        ProjectionErrorReason::TooManyNameAttributes,
    );
    let gn = tlv(0x86, b"https://name.test");
    let san = extension(
        17,
        false,
        &tlv(
            0x30,
            &vec![gn.clone(); MAX_PROJECTION_GENERAL_NAMES].concat(),
        ),
    );
    assert!(project_certificate(&with_extensions(std::slice::from_ref(&san))).is_ok());
    error(
        &with_extensions(&[san, extension(18, false, &tlv(0x30, &gn))]),
        ProjectionErrorReason::TooManyGeneralNames,
    );
    let point = tlv(0x30, &full_name(b"https://crl.test"));
    assert!(project_certificate(&with_extensions(&[points(
        &vec![point.clone(); MAX_PROJECTION_DISTRIBUTION_POINTS],
        false
    )]))
    .is_ok());
    error(
        &with_extensions(&[points(
            &vec![point; MAX_PROJECTION_DISTRIBUTION_POINTS + 1],
            false,
        )]),
        ProjectionErrorReason::TooManyDistributionPoints,
    );
    let extensions: Vec<_> = (63..128)
        .map(|id| extension(id, false, &tlv(5, &[])))
        .collect();
    error(
        &with_extensions(&extensions),
        ProjectionErrorReason::TooManyExtensions,
    );
    error(
        &vec![0; crate::MAX_X509_CERTIFICATE_DER_BYTES + 1],
        ProjectionErrorReason::CertificateTooLarge,
    );
}

#[test]
fn rejects_noncanonical_der_lengths_tags_sets_defaults_and_trailing_data() {
    for value in [
        vec![0x30, 0x80, 0, 0],
        vec![0x30, 0x81, 0],
        vec![0x1f, 0x1e, 0],
        vec![0x1f, 0x80, 0x20, 0],
        vec![0x30, 2, 5],
        vec![5, 0xff],
        vec![0x30, 0x89, 1],
        vec![2, 2, 0, 1],
        vec![1, 1, 1],
    ] {
        assert!(validate_tree(&value).is_err());
    }
    let mut der = fixture();
    der.push(0);
    error(&der, ProjectionErrorReason::InvalidDer);
    let default_false = tlv(
        0x30,
        &[
            tlv(6, &[0x55, 0x1d, 18]),
            tlv(1, &[0]),
            tlv(4, &tlv(0x30, &tlv(0x86, b"https://ian.test"))),
        ]
        .concat(),
    );
    error(
        &with_extensions(&[default_false]),
        ProjectionErrorReason::InvalidDer,
    );
    let unsorted = tlv(
        0x30,
        &tlv(
            0x31,
            &[attribute(&tlv(12, b"Z")), attribute(&tlv(12, b"A"))].concat(),
        ),
    );
    error(
        &certificate(&unsorted, &dn(12, b"issuer"), &[]),
        ProjectionErrorReason::InvalidDer,
    );
    error(
        &certificate(&dn(0x2c, &tlv(12, b"constructed")), &dn(12, b"issuer"), &[]),
        ProjectionErrorReason::InvalidDer,
    );
}

#[test]
fn bounds_der_recursion_and_element_work_before_projection_allocation() {
    let mut nested = tlv(5, &[]);
    for _ in 0..MAX_PROJECTION_DER_DEPTH + 2 {
        nested = tlv(0x30, &nested);
    }
    assert_eq!(
        validate_tree(&nested).unwrap_err().reason,
        ProjectionErrorReason::DerComplexityLimit
    );
    let elements = tlv(
        0x30,
        &vec![tlv(5, &[]); MAX_PROJECTION_DER_ELEMENTS].concat(),
    );
    assert_eq!(
        validate_tree(&elements).unwrap_err().reason,
        ProjectionErrorReason::DerComplexityLimit
    );
}

#[test]
fn binds_views_to_original_der_and_ignores_mutable_legacy_projections() {
    let der = fixture();
    let mut owner = crate::parse_cert_der(&der).unwrap();
    owner.profile.subject.rdns.clear();
    owner.profile.crl_distribution_point_uris.clear();
    let view = owner.projections().unwrap();
    assert_eq!(view.der().as_ptr(), owner.der.as_ptr());
    assert_eq!(view.der(), der);
    assert!(!view.subject().rdns().is_empty());
    let start = owner.der.as_ptr_range();
    let value = view.subject().rdns()[0].attributes()[0].value();
    assert!(start.contains(&value.content().as_ptr()));
    let der = with_extensions(&[extension(
        18,
        false,
        &tlv(0x30, &tlv(0x86, b"https://private-name.test")),
    )]);
    let view = project_certificate(&der).unwrap();
    assert!(!format!("{view:?}").contains("private-name"));
}
