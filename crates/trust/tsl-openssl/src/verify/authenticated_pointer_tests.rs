// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(all(feature = "native", feature = "xmlsec-ffi"))]
#![allow(clippy::indexing_slicing)]

use envelopes_x509::{parse_cert_pem, policy::X509Policy, X509Certificate};
use identity_revocation_core::{StatusCheckError, StatusChecker};
use identity_trust_tsl_core::{parse_tsl_xml, TslError, TslMediaType, TslPointerPolicyFailure};
use time::OffsetDateTime;

use crate::signer_profile::validate_tlso_signer_profile;
use crate::{TslSignatureAlgorithm, TslSignerProfileFailureReason};

use super::{
    verify_tsl_xml_openssl_from_authenticated_pointer, verify_tsl_xml_openssl_with_external_signer,
    AuthenticatedPointerVerification, TslOpenSslError, TslSignerAuthorizationEvidence,
    VerifiedTrustedList,
};

const SIGNED_TSL_XML: &str = include_str!("../../tests/fixtures/signed_tsl.xml");
const SIGNER_CERT_PEM: &[u8] = include_bytes!("../../tests/fixtures/cert.pem");
const TRUST_ROOT_CERT_PEM: &[u8] = include_bytes!("../../tests/fixtures/root-cert.pem");
const EU_GENERIC_TYPE: &str = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric";

struct GoodStatus;

impl StatusChecker for GoodStatus {
    fn check(&self, _cert: &X509Certificate, _now_unix: u64) -> Result<(), StatusCheckError> {
        Ok(())
    }
}

fn verification_time() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("fixed test time is valid")
}

fn signer() -> X509Certificate {
    parse_cert_pem(SIGNER_CERT_PEM).expect("fixture signer certificate is valid")
}

fn trust_root() -> X509Certificate {
    parse_cert_pem(TRUST_ROOT_CERT_PEM).expect("fixture trust-root certificate is valid")
}

fn eu_lotl_parent(pointer_targets_fixture: bool) -> VerifiedTrustedList {
    let signer = signer();
    let trust_root = trust_root();
    let mut parent = verify_tsl_xml_openssl_with_external_signer(
        SIGNED_TSL_XML,
        core::slice::from_ref(&trust_root),
        &signer,
        verification_time(),
        X509Policy::default(),
        &GoodStatus,
    )
    .expect("fixture signature and external signer must verify");

    let mut lotl_xml = SIGNED_TSL_XML.replacen(
        &format!("<TSLType>{EU_GENERIC_TYPE}</TSLType>"),
        &format!(
            "<TSLType>{}</TSLType>",
            identity_trust_tsl_core::EU_LOTL_TSL_TYPE
        ),
        1,
    );
    lotl_xml = lotl_xml.replacen(
        "<SchemeTerritory>MT</SchemeTerritory>",
        "<SchemeTerritory>EU</SchemeTerritory>",
        1,
    );
    if pointer_targets_fixture {
        lotl_xml = lotl_xml.replace(
            &format!(
                "<OtherInformation><TSLType>{}</TSLType></OtherInformation>",
                identity_trust_tsl_core::EU_LOTL_TSL_TYPE
            ),
            &format!("<OtherInformation><TSLType>{EU_GENERIC_TYPE}</TSLType></OtherInformation>"),
        );
        lotl_xml = lotl_xml.replace(
            "<OtherInformation><SchemeTerritory>EU</SchemeTerritory></OtherInformation>",
            "<OtherInformation><SchemeTerritory>MT</SchemeTerritory></OtherInformation>",
        );
    }
    parent.list = parse_tsl_xml(&lotl_xml).expect("mutated semantic fixture must parse");
    if pointer_targets_fixture {
        let operator_names = parent.list.scheme_operator_names.clone();
        let community_rules = parent.list.scheme_type_community_rules.clone();
        parent.list.pointers[0].scheme_operator_names = operator_names;
        parent.list.pointers[0].scheme_type_community_rules = community_rules;
    }
    parent
}

fn verify_child(
    parent: &VerifiedTrustedList,
    pointer_index: usize,
    fetched_url: &str,
    media_type: TslMediaType,
    xml: &str,
) -> Result<VerifiedTrustedList, TslOpenSslError> {
    let trust_root = trust_root();
    verify_tsl_xml_openssl_from_authenticated_pointer(AuthenticatedPointerVerification {
        parent,
        pointer_index,
        fetched_url,
        fetched_media_type: media_type,
        xml,
        trust_roots: core::slice::from_ref(&trust_root),
        now: verification_time(),
        policy: X509Policy::default(),
        status_checker: &GoodStatus,
    })
}

#[test]
fn valid_eu_lotl_pointer_applies_tlso_profile_and_exact_signer_binding() {
    let parent = eu_lotl_parent(true);
    let child = verify_child(
        &parent,
        0,
        "https://example.test/eu-lotl.xml",
        TslMediaType::EtsiTrustedListXml,
        SIGNED_TSL_XML,
    )
    .expect("the pointer metadata and signer fixture must bind");
    assert!(matches!(
        child.signer_authorization(),
        TslSignerAuthorizationEvidence::AuthenticatedPointerCertificate(_)
    ));
}

#[test]
fn pointer_tlso_profile_rejects_a_nonconforming_authenticated_signer() {
    let parent = eu_lotl_parent(true);
    let child = parse_tsl_xml(SIGNED_TSL_XML).expect("signed child fixture must parse");
    let mut nonconforming_signer = signer();
    nonconforming_signer.key_usage = None;

    assert!(matches!(
        validate_tlso_signer_profile(
            &nonconforming_signer,
            &child,
            &[&parent],
            verification_time(),
            TslSignatureAlgorithm::RsaSha256,
        ),
        Err(TslOpenSslError::SignerProfile(
            TslSignerProfileFailureReason::MissingKeyUsage
        ))
    ));
}

#[test]
fn pointer_rejects_invalid_index_url_and_media_type() {
    let parent = eu_lotl_parent(true);
    assert!(matches!(
        verify_child(
            &parent,
            1,
            "https://example.test/eu-lotl.xml",
            TslMediaType::EtsiTrustedListXml,
            "not XML",
        ),
        Err(TslOpenSslError::TrustedList(TslError::PointerPolicy(
            TslPointerPolicyFailure::TargetMetadataMismatch
        )))
    ));
    assert!(matches!(
        verify_child(
            &parent,
            0,
            "https://other.example/list.xml",
            TslMediaType::EtsiTrustedListXml,
            "not XML",
        ),
        Err(TslOpenSslError::TrustedList(TslError::PointerPolicy(
            TslPointerPolicyFailure::TargetMetadataMismatch
        )))
    ));
    assert!(matches!(
        verify_child(
            &parent,
            0,
            "https://example.test/eu-lotl.xml",
            TslMediaType::Unsupported,
            SIGNED_TSL_XML,
        ),
        Err(TslOpenSslError::TrustedList(TslError::PointerPolicy(
            TslPointerPolicyFailure::TargetMetadataMismatch
        )))
    ));
}

#[test]
fn pointer_rechecks_eu_lotl_freshness_before_parsing_child_bytes() {
    let parent = eu_lotl_parent(true);
    let trust_root = trust_root();
    let at_parent_deadline =
        OffsetDateTime::from_unix_timestamp(1_806_195_600).expect("fixed deadline is valid");
    let result =
        verify_tsl_xml_openssl_from_authenticated_pointer(AuthenticatedPointerVerification {
            parent: &parent,
            pointer_index: 0,
            fetched_url: "https://example.test/eu-lotl.xml",
            fetched_media_type: TslMediaType::EtsiTrustedListXml,
            xml: "not XML",
            trust_roots: core::slice::from_ref(&trust_root),
            now: at_parent_deadline,
            policy: X509Policy::default(),
            status_checker: &GoodStatus,
        });
    assert!(matches!(result, Err(TslOpenSslError::ExpiredTrustedList)));
}

#[test]
fn pointer_rejects_empty_pointer_set_and_missing_signer_identity() {
    let mut empty = eu_lotl_parent(true);
    empty.list.pointers.clear();
    assert!(matches!(
        verify_child(
            &empty,
            0,
            "https://example.test/eu-lotl.xml",
            TslMediaType::EtsiTrustedListXml,
            "not XML",
        ),
        Err(TslOpenSslError::TrustedList(TslError::PointerPolicy(
            TslPointerPolicyFailure::TargetMetadataMismatch
        )))
    ));

    let mut no_signer = eu_lotl_parent(true);
    no_signer.list.pointers[0].digital_identities.clear();
    assert!(matches!(
        verify_child(
            &no_signer,
            0,
            "https://example.test/eu-lotl.xml",
            TslMediaType::EtsiTrustedListXml,
            SIGNED_TSL_XML,
        ),
        Err(TslOpenSslError::TrustedList(TslError::PointerPolicy(
            TslPointerPolicyFailure::TargetMetadataMismatch
        )))
    ));
}
