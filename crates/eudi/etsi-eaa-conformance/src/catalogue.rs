// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict validators for the Commission TS11 attribute and attestation catalogues.
//!
//! These validators implement the pinned wire schemas recorded by the Identity
//! Taxonomy. They deliberately reject duplicate JSON members and apply explicit
//! resource limits before projecting any value into a domain decision. Catalogue
//! inputs may contain contact details and authentic-source endpoints, so the
//! temporary JSON tree is zeroized on drop.

use std::collections::BTreeSet;

mod json;

use json::{parse_strict, StrictObject, StrictValue};

const JSON_SCHEMA_MEDIA_TYPE: &str = "application/json-schema";

/// Stable failure reasons for TS11 catalogue validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogueErrorReason {
    /// Input is empty.
    EmptyInput,
    /// Input or a nested value exceeds a fixed resource limit.
    ResourceLimitExceeded,
    /// Input is not one complete JSON value.
    InvalidJson,
    /// An object repeats a member name.
    DuplicateJsonMember,
    /// An object contains an unknown member.
    UnknownMember,
    /// A mandatory member is absent.
    MissingMember,
    /// A member has the wrong JSON type or an invalid value.
    InvalidMember,
    /// A URI member is not an absolute URI.
    InvalidUri,
    /// A UUID member is not in canonical textual form.
    InvalidUuid,
    /// A required collection is empty.
    EmptyCollection,
    /// A collection contains a duplicate semantic value.
    DuplicateValue,
    /// The mandatory JSON Schema distribution is absent.
    MissingJsonSchemaDistribution,
    /// Attestation formats and format-specific schema entries disagree.
    FormatSchemaMismatch,
}

/// Privacy-safe TS11 catalogue validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("EUDI catalogue validation failed: {reason:?}")]
pub struct CatalogueError {
    reason: CatalogueErrorReason,
}

impl CatalogueError {
    const fn new(reason: CatalogueErrorReason) -> Self {
        Self { reason }
    }

    /// Return the stable reason without exposing catalogue content.
    #[must_use]
    pub const fn reason(self) -> CatalogueErrorReason {
        self.reason
    }
}

/// Non-identifying result of validating one attribute catalogue entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttributeCatalogueSummary {
    /// Number of localized names. The pinned schema permits zero, but prose
    /// requires at least one; zero is therefore surfaced for semantic review.
    pub localized_name_count: u16,
    /// Number of published schema distributions.
    pub distribution_count: u16,
    /// Number of authentic-source data services.
    pub authentic_source_count: u16,
    /// Whether the schema-valid entry needs review for the prose-only name rule.
    pub semantic_review_required: bool,
}

/// Non-identifying result of validating one attestation catalogue entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttestationCatalogueSummary {
    /// Number of supported credential formats.
    pub supported_format_count: u16,
    /// Number of format-specific schema entries.
    pub schema_count: u16,
    /// Number of trust-authority entries.
    pub trust_authority_count: u16,
}

/// Validate one JSON entry against the pinned Commission TS11 attribute schema.
pub fn validate_attribute_catalogue_json(
    input: &[u8],
) -> core::result::Result<AttributeCatalogueSummary, CatalogueError> {
    let value = parse_strict(input)?;
    let catalogue = object(&value)?;
    exact_members(
        catalogue,
        &[
            "name",
            "identifier",
            "description",
            "distributions",
            "authenticSources",
        ],
        &[
            "semanticDataSpecification",
            "nameSpace",
            "contactInfo",
            "legalBasis",
        ],
    )?;

    let names = string_array(member(catalogue, "name")?, false)?;
    absolute_uri(string(member(catalogue, "identifier")?)?)?;
    string(member(catalogue, "description")?)?;
    optional_uri(catalogue, "semanticDataSpecification")?;
    optional_uri(catalogue, "nameSpace")?;
    optional_string(catalogue, "legalBasis")?;

    if let Some(contact_info) = catalogue.get("contactInfo") {
        let contacts = string_array(contact_info, true)?;
        for contact in contacts {
            absolute_uri(contact)?;
        }
    }

    let distributions = array(member(catalogue, "distributions")?)?;
    if distributions.is_empty() {
        return Err(CatalogueError::new(CatalogueErrorReason::EmptyCollection));
    }
    let mut has_json_schema = false;
    for distribution in distributions {
        let distribution = object(distribution)?;
        exact_members(distribution, &["accessURL", "mediaType"], &[])?;
        absolute_uri(string(member(distribution, "accessURL")?)?)?;
        let media_type = string(member(distribution, "mediaType")?)?;
        has_json_schema |= media_type == JSON_SCHEMA_MEDIA_TYPE;
    }
    if !has_json_schema {
        return Err(CatalogueError::new(
            CatalogueErrorReason::MissingJsonSchemaDistribution,
        ));
    }

    let authentic_sources = array(member(catalogue, "authenticSources")?)?;
    if authentic_sources.is_empty() {
        return Err(CatalogueError::new(CatalogueErrorReason::EmptyCollection));
    }
    for service in authentic_sources {
        validate_data_service(service)?;
    }

    Ok(AttributeCatalogueSummary {
        localized_name_count: count_u16(names.len())?,
        distribution_count: count_u16(distributions.len())?,
        authentic_source_count: count_u16(authentic_sources.len())?,
        semantic_review_required: names.is_empty(),
    })
}

/// Validate one JSON entry against the pinned Commission TS11 attestation schema.
pub fn validate_attestation_catalogue_json(
    input: &[u8],
) -> core::result::Result<AttestationCatalogueSummary, CatalogueError> {
    let value = parse_strict(input)?;
    let catalogue = object(&value)?;
    exact_members(
        catalogue,
        &[
            "version",
            "rulebookURI",
            "attestationLoS",
            "bindingType",
            "supportedFormats",
            "schemaURIs",
        ],
        &["id", "trustedAuthorities"],
    )?;

    validate_semver(string(member(catalogue, "version")?)?)?;
    absolute_uri(string(member(catalogue, "rulebookURI")?)?)?;
    enum_value(
        string(member(catalogue, "attestationLoS")?)?,
        &[
            "iso_18045_high",
            "iso_18045_moderate",
            "iso_18045_enhanced-basic",
            "iso_18045_basic",
        ],
    )?;
    enum_value(
        string(member(catalogue, "bindingType")?)?,
        &["claim", "key", "biometric", "none"],
    )?;
    if let Some(id) = catalogue.get("id") {
        validate_uuid(string(id)?)?;
    }

    let formats = string_array(member(catalogue, "supportedFormats")?, true)?;
    let mut unique_formats = BTreeSet::new();
    for format in &formats {
        validate_format(format)?;
        if !unique_formats.insert(*format) {
            return Err(CatalogueError::new(CatalogueErrorReason::DuplicateValue));
        }
    }

    let schemas = array(member(catalogue, "schemaURIs")?)?;
    if schemas.is_empty() {
        return Err(CatalogueError::new(CatalogueErrorReason::EmptyCollection));
    }
    let mut schema_formats = BTreeSet::new();
    for schema in schemas {
        let schema = object(schema)?;
        exact_members(schema, &["formatIdentifier", "uri"], &[])?;
        let format = string(member(schema, "formatIdentifier")?)?;
        validate_format(format)?;
        absolute_uri(string(member(schema, "uri")?)?)?;
        if !unique_formats.contains(format) || !schema_formats.insert(format) {
            return Err(CatalogueError::new(
                CatalogueErrorReason::FormatSchemaMismatch,
            ));
        }
    }
    if schema_formats != unique_formats {
        return Err(CatalogueError::new(
            CatalogueErrorReason::FormatSchemaMismatch,
        ));
    }

    let trust_authority_count = if let Some(authorities) = catalogue.get("trustedAuthorities") {
        let authorities = array(authorities)?;
        for authority in authorities {
            validate_trust_authority(authority)?;
        }
        count_u16(authorities.len())?
    } else {
        0
    };

    Ok(AttestationCatalogueSummary {
        supported_format_count: count_u16(formats.len())?,
        schema_count: count_u16(schemas.len())?,
        trust_authority_count,
    })
}

fn validate_data_service(value: &StrictValue) -> core::result::Result<(), CatalogueError> {
    let object = object(value)?;
    exact_members(
        object,
        &["country", "endpointDescription", "endpointURI"],
        &["nationalSubID"],
    )?;
    string(member(object, "country")?)?;
    string(member(object, "endpointDescription")?)?;
    absolute_uri(string(member(object, "endpointURI")?)?)?;
    optional_string(object, "nationalSubID")?;
    Ok(())
}

fn validate_trust_authority(value: &StrictValue) -> core::result::Result<(), CatalogueError> {
    let object = object(value)?;
    exact_members(object, &["frameworkType", "value"], &["isLOTE"])?;
    let framework = string(member(object, "frameworkType")?)?;
    enum_value(framework, &["aki", "etsi_tl", "openid_federation"])?;
    let value = string(member(object, "value")?)?;
    if value.is_empty() {
        return Err(CatalogueError::new(CatalogueErrorReason::InvalidMember));
    }
    match framework {
        "aki" => validate_base64url(value)?,
        "etsi_tl" | "openid_federation" => absolute_uri(value)?,
        _ => return Err(CatalogueError::new(CatalogueErrorReason::InvalidMember)),
    }
    if let Some(is_lote) = object.get("isLOTE") {
        boolean(is_lote)?;
    }
    Ok(())
}

fn validate_format(value: &str) -> core::result::Result<(), CatalogueError> {
    enum_value(
        value,
        &[
            "dc+sd-jwt",
            "mso_mdoc",
            "jwt_vc_json",
            "jwt_vc_json-ld",
            "ldp_vc",
        ],
    )
}

fn validate_semver(value: &str) -> core::result::Result<(), CatalogueError> {
    let (without_build, build) = value
        .split_once('+')
        .map_or((value, None), |(left, right)| (left, Some(right)));
    let (core, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, None), |(left, right)| (left, Some(right)));
    let mut parts = core.split('.');
    for _ in 0..3 {
        let part = parts
            .next()
            .ok_or_else(|| CatalogueError::new(CatalogueErrorReason::InvalidMember))?;
        if part.is_empty()
            || (part.len() > 1 && part.starts_with('0'))
            || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(CatalogueError::new(CatalogueErrorReason::InvalidMember));
        }
    }
    if parts.next().is_some() {
        return Err(CatalogueError::new(CatalogueErrorReason::InvalidMember));
    }
    if let Some(prerelease) = prerelease {
        validate_semver_identifiers(prerelease, true)?;
    }
    if let Some(build) = build {
        validate_semver_identifiers(build, false)?;
    }
    Ok(())
}

fn validate_semver_identifiers(
    value: &str,
    reject_numeric_leading_zero: bool,
) -> core::result::Result<(), CatalogueError> {
    if value.is_empty() || value.contains('+') {
        return Err(CatalogueError::new(CatalogueErrorReason::InvalidMember));
    }
    for identifier in value.split('.') {
        if identifier.is_empty()
            || !identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || (reject_numeric_leading_zero
                && identifier.len() > 1
                && identifier.bytes().all(|byte| byte.is_ascii_digit())
                && identifier.starts_with('0'))
        {
            return Err(CatalogueError::new(CatalogueErrorReason::InvalidMember));
        }
    }
    Ok(())
}

fn validate_uuid(value: &str) -> core::result::Result<(), CatalogueError> {
    if value.len() != 36 {
        return Err(CatalogueError::new(CatalogueErrorReason::InvalidUuid));
    }
    for (index, byte) in value.bytes().enumerate() {
        let hyphen = matches!(index, 8 | 13 | 18 | 23);
        if (hyphen && byte != b'-') || (!hyphen && !byte.is_ascii_hexdigit()) {
            return Err(CatalogueError::new(CatalogueErrorReason::InvalidUuid));
        }
    }
    Ok(())
}

fn validate_base64url(value: &str) -> core::result::Result<(), CatalogueError> {
    if value.is_empty()
        || value.contains('=')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(CatalogueError::new(CatalogueErrorReason::InvalidMember));
    }
    Ok(())
}

fn absolute_uri(value: &str) -> core::result::Result<(), CatalogueError> {
    let parsed = url::Url::parse(value)
        .map_err(|_error| CatalogueError::new(CatalogueErrorReason::InvalidUri))?;
    if parsed.scheme().is_empty() {
        return Err(CatalogueError::new(CatalogueErrorReason::InvalidUri));
    }
    Ok(())
}

fn exact_members(
    object: &StrictObject,
    required: &[&str],
    optional: &[&str],
) -> core::result::Result<(), CatalogueError> {
    for name in required {
        if !object.contains_key(*name) {
            return Err(CatalogueError::new(CatalogueErrorReason::MissingMember));
        }
    }
    for name in object.keys() {
        if !required.contains(&name.as_str()) && !optional.contains(&name.as_str()) {
            return Err(CatalogueError::new(CatalogueErrorReason::UnknownMember));
        }
    }
    Ok(())
}

fn member<'a>(
    object: &'a StrictObject,
    name: &str,
) -> core::result::Result<&'a StrictValue, CatalogueError> {
    object
        .get(name)
        .ok_or_else(|| CatalogueError::new(CatalogueErrorReason::MissingMember))
}

fn object(value: &StrictValue) -> core::result::Result<&StrictObject, CatalogueError> {
    match value {
        StrictValue::Object(value) => Ok(value),
        _ => Err(CatalogueError::new(CatalogueErrorReason::InvalidMember)),
    }
}

fn array(value: &StrictValue) -> core::result::Result<&[StrictValue], CatalogueError> {
    match value {
        StrictValue::Array(value) => Ok(value),
        _ => Err(CatalogueError::new(CatalogueErrorReason::InvalidMember)),
    }
}

fn string(value: &StrictValue) -> core::result::Result<&str, CatalogueError> {
    match value {
        StrictValue::String(value) => Ok(value),
        _ => Err(CatalogueError::new(CatalogueErrorReason::InvalidMember)),
    }
}

fn boolean(value: &StrictValue) -> core::result::Result<bool, CatalogueError> {
    match value {
        StrictValue::Bool(value) => Ok(*value),
        _ => Err(CatalogueError::new(CatalogueErrorReason::InvalidMember)),
    }
}

fn optional_uri(object: &StrictObject, name: &str) -> core::result::Result<(), CatalogueError> {
    if let Some(value) = object.get(name) {
        absolute_uri(string(value)?)?;
    }
    Ok(())
}

fn optional_string(object: &StrictObject, name: &str) -> core::result::Result<(), CatalogueError> {
    if let Some(value) = object.get(name) {
        string(value)?;
    }
    Ok(())
}

fn string_array(
    value: &StrictValue,
    require_non_empty: bool,
) -> core::result::Result<Vec<&str>, CatalogueError> {
    let values = array(value)?;
    if require_non_empty && values.is_empty() {
        return Err(CatalogueError::new(CatalogueErrorReason::EmptyCollection));
    }
    values.iter().map(string).collect()
}

fn enum_value(value: &str, allowed: &[&str]) -> core::result::Result<(), CatalogueError> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(CatalogueError::new(CatalogueErrorReason::InvalidMember))
    }
}

fn count_u16(value: usize) -> core::result::Result<u16, CatalogueError> {
    u16::try_from(value)
        .map_err(|_error| CatalogueError::new(CatalogueErrorReason::ResourceLimitExceeded))
}
