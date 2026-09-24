// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Debug, Deserialize)]
struct RawExtensions {
    #[serde(rename = "Extension", default)]
    extensions: Vec<RawExtension>,
}

#[derive(Debug, Deserialize)]
struct RawExtension {
    #[serde(rename = "@Critical")]
    critical: Option<bool>,
    #[serde(rename = "AdditionalServiceInformation")]
    additional: Option<RawAdditionalServiceInformation>,
    #[serde(rename = "Qualifications")]
    qualifications: Option<RawQualifications>,
    #[serde(rename = "TakenOverBy")]
    taken_over_by: Option<RawTakenOverBy>,
}

#[derive(Debug, Deserialize)]
struct RawTakenOverBy {
    #[serde(rename = "URI")]
    uri: Option<RawLocalizedText>,
    #[serde(rename = "TSPName")]
    tsp_name: Option<RawInternationalNames>,
    #[serde(rename = "SchemeOperatorName")]
    scheme_operator_name: Option<RawInternationalNames>,
    #[serde(rename = "SchemeTerritory")]
    scheme_territory: Option<String>,
    #[serde(rename = "OtherQualifier")]
    other_qualifier: Option<RawAny>,
}

#[derive(Debug, Deserialize)]
struct RawAdditionalServiceInformation {
    #[serde(rename = "URI")]
    uri: Option<RawLocalizedText>,
    #[serde(rename = "InformationValue")]
    information_value: Option<String>,
    #[serde(rename = "OtherInformation")]
    other_information: Option<RawAny>,
}

#[derive(Debug, Deserialize)]
struct RawAny {
    #[serde(rename = "$text")]
    _text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawQualifications {
    #[serde(rename = "QualificationElement", default)]
    elements: Vec<RawQualificationElement>,
}

#[derive(Debug, Deserialize)]
struct RawQualificationElement {
    #[serde(rename = "Qualifiers")]
    qualifiers: Option<RawQualifiers>,
    #[serde(rename = "CriteriaList")]
    criteria: Option<RawCriteriaList>,
}

#[derive(Debug, Deserialize)]
struct RawQualifiers {
    #[serde(rename = "Qualifier", default)]
    qualifiers: Vec<RawQualifier>,
}

#[derive(Debug, Deserialize)]
struct RawQualifier {
    #[serde(rename = "@uri")]
    uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawCriteriaList {
    #[serde(rename = "@assert")]
    assertion: Option<String>,
    #[serde(rename = "KeyUsage", default)]
    key_usage: Vec<RawKeyUsage>,
    #[serde(rename = "PolicySet", default)]
    policy_sets: Vec<RawPolicySet>,
    #[serde(rename = "CriteriaList", default)]
    nested: Vec<RawCriteriaList>,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "otherCriteriaList")]
    other: Option<RawOtherCriteriaList>,
}

#[derive(Debug, Deserialize)]
struct RawKeyUsage {
    #[serde(rename = "KeyUsageBit", default)]
    bits: Vec<RawKeyUsageBit>,
}

#[derive(Debug, Deserialize)]
struct RawKeyUsageBit {
    #[serde(rename = "@name")]
    name: Option<String>,
    #[serde(rename = "$text")]
    expected: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct RawPolicySet {
    #[serde(rename = "PolicyIdentifier", default)]
    policies: Vec<RawPolicyIdentifier>,
}

#[derive(Debug, Deserialize)]
struct RawPolicyIdentifier {
    #[serde(rename = "Identifier")]
    identifier: Option<RawXadesIdentifier>,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "DocumentationReferences")]
    documentation_references: Option<RawDocumentationReferences>,
}

#[derive(Debug, Deserialize)]
struct RawXadesIdentifier {
    #[serde(rename = "@Qualifier")]
    qualifier: Option<String>,
    #[serde(rename = "$text")]
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawDocumentationReferences {
    #[serde(rename = "DocumentationReference", default)]
    references: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawOtherCriteriaList {
    #[serde(rename = "ExtendedKeyUsage")]
    extended_key_usage: Option<RawObjectIdentifierList>,
    #[serde(rename = "CertSubjectDNAttribute")]
    subject_dn_attributes: Option<RawObjectIdentifierList>,
}

#[derive(Debug, Deserialize)]
struct RawObjectIdentifierList {
    #[serde(rename = "KeyPurposeId", alias = "AttributeOID", default)]
    identifiers: Vec<RawPolicyIdentifier>,
}
