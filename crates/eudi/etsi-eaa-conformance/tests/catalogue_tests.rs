// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Adversarial and happy-path coverage for the EU catalogue JSON boundary.

use reallyme_etsi_eaa_conformance::{
    validate_attestation_catalogue_json, validate_attribute_catalogue_json, CatalogueErrorReason,
};

const ATTRIBUTE: &[u8] = br#"{
  "name":["Family name@en"],
  "identifier":"https://example.eu/attributes/family_name/1",
  "description":"Current family name",
  "semanticDataSpecification":"https://example.eu/spec/family-name",
  "distributions":[{"accessURL":"https://example.eu/schema/family-name.json","mediaType":"application/json-schema"}],
  "nameSpace":"https://example.eu/attributes",
  "contactInfo":["https://example.eu/contact"],
  "legalBasis":"CIR 2025/1569",
  "authenticSources":[{"country":"IT","nationalSubID":"anpr","endpointDescription":"National source","endpointURI":"https://example.eu/source"}]
}"#;

const ATTESTATION: &[u8] = br#"{
  "id":"123e4567-e89b-12d3-a456-426614174000",
  "version":"1.2.0",
  "rulebookURI":"https://example.eu/rulebooks/pid",
  "trustedAuthorities":[{"frameworkType":"etsi_tl","value":"https://example.eu/trusted-list","isLOTE":true}],
  "attestationLoS":"iso_18045_high",
  "bindingType":"key",
  "supportedFormats":["dc+sd-jwt","mso_mdoc"],
  "schemaURIs":[
    {"formatIdentifier":"dc+sd-jwt","uri":"https://example.eu/schema/pid-sd-jwt"},
    {"formatIdentifier":"mso_mdoc","uri":"https://example.eu/schema/pid-mdoc"}
  ]
}"#;

const OVERSIZED_CATALOGUE_BYTES: usize = 1_048_577;

#[test]
fn validates_complete_attribute_catalogue_entry() {
    let result = validate_attribute_catalogue_json(ATTRIBUTE);
    assert_eq!(result.map(|value| value.localized_name_count), Ok(1));
    assert_eq!(result.map(|value| value.distribution_count), Ok(1));
    assert_eq!(result.map(|value| value.authentic_source_count), Ok(1));
    assert_eq!(
        result.map(|value| value.semantic_review_required),
        Ok(false)
    );
}

#[test]
fn preserves_schema_valid_empty_name_array_for_semantic_review() {
    let input = ATTRIBUTE.replace(b"[\"Family name@en\"]", b"[]");
    let result = validate_attribute_catalogue_json(&input);
    assert_eq!(result.map(|value| value.semantic_review_required), Ok(true));
}

#[test]
fn rejects_attribute_unknown_duplicate_and_missing_schema_distribution() {
    let unknown = ATTRIBUTE.replace(
        b"\"legalBasis\":\"CIR 2025/1569\",",
        b"\"legalBasis\":\"CIR 2025/1569\",\"unexpected\":true,",
    );
    assert_eq!(
        validate_attribute_catalogue_json(&unknown).map_err(|error| error.reason()),
        Err(CatalogueErrorReason::UnknownMember)
    );

    let duplicate = br#"{"name":[],"name":[],"identifier":"https://example.eu/a/1","description":"a","distributions":[{"accessURL":"https://example.eu/s","mediaType":"application/json-schema"}],"authenticSources":[{"country":"IT","endpointDescription":"source","endpointURI":"https://example.eu"}]}"#;
    assert_eq!(
        validate_attribute_catalogue_json(duplicate).map_err(|error| error.reason()),
        Err(CatalogueErrorReason::DuplicateJsonMember)
    );

    let wrong_media = ATTRIBUTE.replace(b"application/json-schema", b"application/schema+json");
    assert_eq!(
        validate_attribute_catalogue_json(&wrong_media).map_err(|error| error.reason()),
        Err(CatalogueErrorReason::MissingJsonSchemaDistribution)
    );
}

#[test]
fn validates_complete_attestation_catalogue_entry() {
    let result = validate_attestation_catalogue_json(ATTESTATION);
    assert_eq!(result.map(|value| value.supported_format_count), Ok(2));
    assert_eq!(result.map(|value| value.schema_count), Ok(2));
    assert_eq!(result.map(|value| value.trust_authority_count), Ok(1));
}

#[test]
fn rejects_attestation_format_schema_mismatch_and_invalid_trust_identifier() {
    let mismatch = ATTESTATION.replace(
        b"{\"formatIdentifier\":\"mso_mdoc\",\"uri\":\"https://example.eu/schema/pid-mdoc\"}",
        b"{\"formatIdentifier\":\"jwt_vc_json\",\"uri\":\"https://example.eu/schema/pid-mdoc\"}",
    );
    assert_eq!(
        validate_attestation_catalogue_json(&mismatch).map_err(|error| error.reason()),
        Err(CatalogueErrorReason::FormatSchemaMismatch)
    );

    let invalid_trust =
        ATTESTATION.replace(b"https://example.eu/trusted-list", b"not an absolute URI");
    assert_eq!(
        validate_attestation_catalogue_json(&invalid_trust).map_err(|error| error.reason()),
        Err(CatalogueErrorReason::InvalidUri)
    );
}

#[test]
fn rejects_noncanonical_semantic_versions() {
    for invalid in [
        "01.2.3",
        "1.2",
        "1.2.3-",
        "1.2.3-01",
        "1.2.3+",
        "1.2.3+bad+",
    ] {
        let input = ATTESTATION.replace(b"1.2.0", invalid.as_bytes());
        assert_eq!(
            validate_attestation_catalogue_json(&input).map_err(|error| error.reason()),
            Err(CatalogueErrorReason::InvalidMember),
            "invalid version was accepted: {invalid}"
        );
    }

    let valid = ATTESTATION.replace(b"1.2.0", b"1.2.3-rc.1+build.07");
    assert!(validate_attestation_catalogue_json(&valid).is_ok());
}

#[test]
fn rejects_catalogue_inputs_that_exceed_the_byte_limit() {
    let oversized = vec![b' '; OVERSIZED_CATALOGUE_BYTES];

    assert_eq!(
        validate_attribute_catalogue_json(&oversized).map_err(|error| error.reason()),
        Err(CatalogueErrorReason::ResourceLimitExceeded)
    );
}

#[test]
fn rejects_catalogue_inputs_that_exceed_the_depth_limit() {
    let excessively_nested = br#"[[[[[[[[[[[[[[[[[null]]]]]]]]]]]]]]]]]"#;

    assert_eq!(
        validate_attribute_catalogue_json(excessively_nested).map_err(|error| error.reason()),
        Err(CatalogueErrorReason::ResourceLimitExceeded)
    );
}

#[test]
fn rejects_trailing_non_whitespace_json_data() {
    let mut trailing = ATTRIBUTE.to_vec();
    trailing.extend_from_slice(br#"{}"#);

    assert_eq!(
        validate_attribute_catalogue_json(&trailing).map_err(|error| error.reason()),
        Err(CatalogueErrorReason::InvalidJson)
    );
}

trait ReplaceBytes {
    fn replace(&self, from: &[u8], to: &[u8]) -> Vec<u8>;
}

impl ReplaceBytes for [u8] {
    fn replace(&self, from: &[u8], to: &[u8]) -> Vec<u8> {
        let Some(position) = self.windows(from.len()).position(|window| window == from) else {
            return self.to_vec();
        };
        let capacity = self
            .len()
            .checked_sub(from.len())
            .and_then(|value| value.checked_add(to.len()))
            .unwrap_or(self.len());
        let mut result = Vec::with_capacity(capacity);
        result.extend_from_slice(&self[..position]);
        result.extend_from_slice(to);
        result.extend_from_slice(&self[position + from.len()..]);
        result
    }
}
