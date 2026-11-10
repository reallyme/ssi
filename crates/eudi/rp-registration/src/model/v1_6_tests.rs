// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used, clippy::indexing_slicing)]
//! Strict profile fixtures use assertions and direct fixture indexing only in tests.

use serde_json::Value;

use super::{ProtocolProfile, WalletRelyingParty};
use crate::{prepare_registration_document, RegistrationErrorReason};

const V1_6_DOCUMENT: &str = r#"{
  "country":"MT",
  "isPSB":false,
  "supervisoryAuthority":{"name":"Example Authority","country":"MT","email":["dpa@example.test"]},
  "identifier":[{"identifier":"MT-C-123","type":"http://data.europa.eu/eudi/id/EUID"}],
  "legalPerson":{"legalName":["Example Limited"]},
  "policy":[{"policyURI":"https://rp.example/policy","type":"http://data.europa.eu/eudi/policy/privacy-policy"}],
  "providerType":"WalletRelyingParty",
  "x5c":["MIIB-public-certificate"],
  "tradeName":"Example",
  "registryURI":"https://registry.example/",
  "createdAt":"2026-10-01",
  "services":[{
    "serviceTradeName":"Example Login",
    "serviceIdentifier":"login",
    "supportURI":"https://rp.example/support",
    "srvDescription":[{"lang":"en","content":"Login service"}],
    "intendedUses":[{
      "purpose":[{"lang":"en","content":"Age verification"}],
      "privacyPolicy":[{"policyURI":"https://rp.example/privacy","type":"http://data.europa.eu/eudi/policy/privacy-statement"}],
      "intendedUseIdentifier":"age-check",
      "createdAt":"2026-10-01",
      "credentials":[{
        "format":"dc+sd-jwt",
        "meta":{"vct_values":["urn:example:pid"]},
        "claims":[{"path":["age_over_18",0,null]}]
      }]
    }],
    "entitlements":["https://uri.etsi.org/19475/Entitlement/Service_Provider"],
    "issuerPolicies":[{"policyURI":"https://rp.example/issuer-policy","type":"http://data.europa.eu/eudi/policy/privacy-policy"}],
    "usesIntermediaries":[{
      "identifier":[{"identifier":"MT-C-456","type":"http://data.europa.eu/eudi/id/EUID"}],
      "serviceIdentifier":"gateway",
      "registryURI":"https://other-registry.example/"
    }],
    "isIntermediary":false
  }]
}"#;

#[test]
fn parses_and_losslessly_prepares_ts5_v1_6_document() {
    let wrp = WalletRelyingParty::from_json_for_profile(
        ProtocolProfile::Ts5V1_6,
        V1_6_DOCUMENT.as_bytes(),
    )
    .expect("valid TS5 v1.6 fixture");
    assert_eq!(wrp.source_profile(), ProtocolProfile::Ts5V1_6);
    assert_eq!(
        wrp.services()[0].registered_service_identifier(),
        Some("login")
    );
    assert_eq!(
        wrp.services()[0].intended_uses()[0].credentials()[0].claims()[0].path(),
        r#"["age_over_18",0,null]"#
    );
    assert!(!wrp.services()[0].profile_specific_material().is_empty());

    let prepared = prepare_registration_document(ProtocolProfile::Ts5V1_6, "internal-rp", 1, &wrp)
        .expect("validated v1.6 document is encodable");
    let expected: Value = serde_json::from_str(V1_6_DOCUMENT).expect("fixture JSON");
    let actual: Value = serde_json::from_slice(prepared.expose_encoded_document())
        .expect("prepared canonical JSON");
    assert_eq!(actual, expected);
}

#[test]
fn keeps_v1_5_and_v1_6_shapes_separate() {
    let v1_5_result = WalletRelyingParty::from_json_for_profile(
        ProtocolProfile::Ts5V1_5,
        V1_6_DOCUMENT.as_bytes(),
    );
    assert!(v1_5_result.is_err());

    let nested_descriptions = V1_6_DOCUMENT.replace(
        r#""srvDescription":[{"lang":"en","content":"Login service"}]"#,
        r#""srvDescription":[[{"lang":"en","content":"Login service"}]]"#,
    );
    let error = WalletRelyingParty::from_json_for_profile(
        ProtocolProfile::Ts5V1_6,
        nested_descriptions.as_bytes(),
    )
    .expect_err("v1.5 nested descriptions must not enter v1.6");
    assert_eq!(error.reason(), RegistrationErrorReason::InvalidField);
}

#[test]
fn rejects_unpublished_openapi_spelling_and_malicious_claim_segments() {
    let attestation = V1_6_DOCUMENT.replace(
        r#""issuerPolicies":[{"policyURI":"https://rp.example/issuer-policy","type":"http://data.europa.eu/eudi/policy/privacy-policy"}]"#,
        r#""providesAttestations":[{"format":"dc+sd-jwt","type":"urn:example:pid","trustAuthorities":[]}],"issuerPolicies":[{"policyURI":"https://rp.example/issuer-policy","type":"http://data.europa.eu/eudi/policy/privacy-policy"}]"#,
    );
    assert!(WalletRelyingParty::from_json_for_profile(
        ProtocolProfile::Ts5V1_6,
        attestation.as_bytes(),
    )
    .is_err());

    let negative_index =
        V1_6_DOCUMENT.replace(r#"["age_over_18",0,null]"#, r#"["age_over_18",-1,null]"#);
    let error = WalletRelyingParty::from_json_for_profile(
        ProtocolProfile::Ts5V1_6,
        negative_index.as_bytes(),
    )
    .expect_err("negative claim index must fail");
    assert_eq!(error.reason(), RegistrationErrorReason::InvalidClaimPath);
}

fn document_value() -> Value {
    serde_json::from_str(V1_6_DOCUMENT).expect("fixture JSON")
}

fn parse_value(value: &Value) -> Result<WalletRelyingParty, crate::RegistrationError> {
    let encoded = serde_json::to_vec(value).expect("fixture JSON is serializable");
    WalletRelyingParty::from_json_for_profile(ProtocolProfile::Ts5V1_6, &encoded)
}

#[test]
fn accepts_normative_optional_names_and_both_published_date_forms() {
    let mut value = document_value();
    value.as_object_mut().expect("object").remove("tradeName");
    value["services"][0]
        .as_object_mut()
        .expect("service object")
        .remove("serviceIdentifier");
    value["services"][0]
        .as_object_mut()
        .expect("service object")
        .remove("usesIntermediaries");
    value["createdAt"] = Value::String("2026-10-01T00:00:00Z".to_owned());
    value["services"][0]["intendedUses"][0]["createdAt"] =
        Value::String("2026-10-01T00:00:00Z".to_owned());

    let wrp = parse_value(&value).expect("valid optional omissions and schema date-time");
    assert_eq!(wrp.registered_trade_name(), None);
    assert_eq!(wrp.services()[0].registered_service_identifier(), None);
}

#[test]
fn rejects_missing_mandatory_v1_6_and_inherited_fields() {
    for field in [
        "country",
        "isPSB",
        "supervisoryAuthority",
        "policy",
        "providerType",
        "createdAt",
    ] {
        let mut value = document_value();
        value.as_object_mut().expect("object").remove(field);
        assert!(parse_value(&value).is_err(), "missing {field} must fail");
    }

    let mut value = document_value();
    value["services"][0]["intendedUses"][0]
        .as_object_mut()
        .expect("intended-use object")
        .remove("createdAt");
    assert!(parse_value(&value).is_err());
}

#[test]
fn enforces_legal_entity_choice_policy_uris_and_service_identifier_uniqueness() {
    let mut both_people = document_value();
    both_people["naturalPerson"] = serde_json::json!({
        "givenName": "Example",
        "familyName": "Person"
    });
    let error = parse_value(&both_people).expect_err("legal entity cannot be two person kinds");
    assert_eq!(
        error.reason(),
        RegistrationErrorReason::SemanticBindingMismatch
    );

    let mut bad_policy = document_value();
    bad_policy["policy"][0]["type"] = Value::String("privacy".to_owned());
    let error = parse_value(&bad_policy).expect_err("policy type must be a URI");
    assert_eq!(error.reason(), RegistrationErrorReason::InvalidUri);

    let mut urn_policy = document_value();
    urn_policy["policy"][0]["type"] = Value::String("urn:example:policy:privacy".to_owned());
    parse_value(&urn_policy).expect("an absolute RFC 3986 policy-type URN is valid");

    let mut duplicate_service = document_value();
    let service = duplicate_service["services"][0].clone();
    duplicate_service["services"]
        .as_array_mut()
        .expect("services array")
        .push(service);
    let error = parse_value(&duplicate_service).expect_err("service identifiers must be unique");
    assert_eq!(
        error.reason(),
        RegistrationErrorReason::SemanticBindingMismatch
    );
}

#[test]
fn requires_service_identifier_for_intermediated_service_and_exact_wire_spelling() {
    let mut missing_identifier = document_value();
    missing_identifier["services"][0]
        .as_object_mut()
        .expect("service object")
        .remove("serviceIdentifier");
    let error = parse_value(&missing_identifier).expect_err("intermediated service needs an id");
    assert_eq!(error.reason(), RegistrationErrorReason::MissingField);

    let mut wrong_spelling = document_value();
    wrong_spelling["services"][0]["servedWrpServices"] = Value::Array(Vec::new());
    assert!(parse_value(&wrong_spelling).is_err());

    let mut correct_spelling = document_value();
    let service = correct_spelling["services"][0]
        .as_object_mut()
        .expect("service object");
    service.remove("usesIntermediaries");
    service.remove("entitlements");
    service.remove("intendedUses");
    service.remove("issuerPolicies");
    service.insert("isIntermediary".to_owned(), Value::Bool(true));
    service.insert(
        "servedWRPServices".to_owned(),
        serde_json::json!([{
            "identifier": [{
                "identifier": "MT-C-456",
                "type": "http://data.europa.eu/eudi/id/EUID"
            }],
            "serviceIdentifier": "customer-service",
            "registryURI": "https://other-registry.example/"
        }]),
    );
    parse_value(&correct_spelling).expect("normative servedWRPServices spelling must parse");
}

#[test]
fn validates_trust_authority_encoding_and_lote_semantics() {
    let mut valid = document_value();
    valid["services"][0]["entitlements"] = Value::Array(vec![Value::String(
        "https://uri.etsi.org/19475/Entitlement/QEAA_Provider".to_owned(),
    )]);
    valid["services"][0]["providesAttestations"] = serde_json::json!([{
        "format": "dc+sd-jwt",
        "type": "urn:example:pid",
        "trustedAuthorities": [{"frameworkType": "aki", "value": "AQID"}]
    }]);
    parse_value(&valid).expect("canonical base64url AKI");

    let mut invalid_aki = valid.clone();
    invalid_aki["services"][0]["providesAttestations"][0]["trustedAuthorities"][0]["value"] =
        Value::String("a".to_owned());
    assert!(parse_value(&invalid_aki).is_err());

    let mut invalid_lote = valid;
    invalid_lote["services"][0]["providesAttestations"][0]["trustedAuthorities"][0] = serde_json::json!({
        "frameworkType": "openid_federation",
        "value": "https://federation.example/",
        "isLOTE": true
    });
    let error = parse_value(&invalid_lote).expect_err("LoTE only applies to ETSI trust lists");
    assert_eq!(
        error.reason(),
        RegistrationErrorReason::SemanticBindingMismatch
    );
}

fn intermediary_document() -> Value {
    let mut value = document_value();
    let service = value["services"][0]
        .as_object_mut()
        .expect("service object");
    service.remove("usesIntermediaries");
    service.remove("entitlements");
    service.remove("intendedUses");
    service.remove("issuerPolicies");
    service.insert("isIntermediary".to_owned(), Value::Bool(true));
    value
}

#[test]
fn intermediary_roles_reject_service_provider_and_issuer_entitlements() {
    for (entitlement, provides_attestations) in
        [("Service_Provider", false), ("QEAA_Provider", true)]
    {
        let mut value = intermediary_document();
        value["services"][0]["entitlements"] = serde_json::json!([format!(
            "https://uri.etsi.org/19475/Entitlement/{entitlement}"
        )]);
        if provides_attestations {
            value["services"][0]["providesAttestations"] = serde_json::json!([{
                "format": "dc+sd-jwt",
                "type": "urn:example:pid"
            }]);
        }
        let error = parse_value(&value).expect_err("intermediary cannot hold an entitlement");
        assert_eq!(
            error.reason(),
            RegistrationErrorReason::SemanticBindingMismatch
        );
    }

    let mut value = intermediary_document();
    parse_value(&value).expect("intermediary with no entitlement member");
    value["services"][0]["entitlements"] = serde_json::json!([]);
    parse_value(&value).expect("empty entitlements do not assign a role");
}

#[test]
fn relationship_presence_constraints_include_empty_arrays() {
    let mut regular = document_value();
    regular["services"][0]["servedWRPServices"] = serde_json::json!([]);
    let error = parse_value(&regular).expect_err("served services are intermediary-only");
    assert_eq!(
        error.reason(),
        RegistrationErrorReason::SemanticBindingMismatch
    );

    let mut intermediary = intermediary_document();
    intermediary["services"][0]["usesIntermediaries"] = serde_json::json!([]);
    let error =
        parse_value(&intermediary).expect_err("intermediary dependency requires regular role");
    assert_eq!(
        error.reason(),
        RegistrationErrorReason::SemanticBindingMismatch
    );

    let mut regular = document_value();
    regular["services"][0]["usesIntermediaries"] = serde_json::json!([]);
    parse_value(&regular).expect("regular service may declare empty intermediary dependencies");

    let mut intermediary = intermediary_document();
    intermediary["services"][0]["servedWRPServices"] = serde_json::json!([]);
    parse_value(&intermediary).expect("intermediary may declare empty served services");
}

#[test]
fn intended_use_requires_privacy_statement_type_for_every_policy() {
    for policy_type in [
        "http://data.europa.eu/eudi/policy/privacy-policy",
        "http://data.europa.eu/eudi/policy/terms-and-conditions",
        "http://data.europa.eu/eudi/policy/registration-policy",
        "http://data.europa.eu/eudi/policy/trust-service-practice-statement",
        "urn:example:terms-and-conditions",
        "http://data.europa.eu/eudi/policy/privacy-statement/",
    ] {
        let mut value = document_value();
        value["services"][0]["intendedUses"][0]["privacyPolicy"][0]["type"] =
            serde_json::json!(policy_type);
        let error = parse_value(&value).expect_err("intended use requires a privacy statement");
        assert_eq!(
            error.reason(),
            RegistrationErrorReason::SemanticBindingMismatch
        );
    }

    let mut mixed = document_value();
    mixed["services"][0]["intendedUses"][0]["privacyPolicy"]
        .as_array_mut()
        .expect("privacy-policy array")
        .push(serde_json::json!({
            "policyURI": "https://rp.example/terms",
            "type": "http://data.europa.eu/eudi/policy/terms-and-conditions"
        }));
    let error = parse_value(&mixed).expect_err("one valid entry cannot mask another policy type");
    assert_eq!(
        error.reason(),
        RegistrationErrorReason::SemanticBindingMismatch
    );
}

#[test]
fn provider_and_issuer_policies_retain_their_general_policy_types() {
    let mut value = document_value();
    value["policy"][0]["type"] =
        serde_json::json!("http://data.europa.eu/eudi/policy/registration-policy");
    value["services"][0]["issuerPolicies"][0]["type"] =
        serde_json::json!("urn:example:issuer-terms");
    parse_value(&value).expect("only intended-use privacy policies require a privacy statement");

    let privacy_policy = value["services"][0]["intendedUses"][0]["privacyPolicy"][0].clone();
    value["services"][0]["intendedUses"][0]["privacyPolicy"]
        .as_array_mut()
        .expect("privacy-policy array")
        .push(privacy_policy);
    parse_value(&value).expect("multiple localized privacy statements remain valid");
}
