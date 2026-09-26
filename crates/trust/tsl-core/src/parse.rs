// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use codec_base64::base64_to_bytes;
use quick_xml::de::from_str;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;
use quick_xml::XmlVersion;
use serde::Deserialize;
use std::collections::BTreeMap;
use time::format_description::well_known::Rfc3339;
use time::{Date, Duration, Month, OffsetDateTime, UtcOffset};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    AdditionalServiceInformation, AdditionalServiceInformationKind, LocalizedText, LocalizedUri,
    PkiServiceDigitalIdentity, QualificationAssertion, QualificationCriteria,
    QualificationCriterion, QualificationKeyUsage, QualificationKeyUsageBit,
    ServiceDigitalIdentity, ServiceQualification, ServiceQualifier, ServiceQualifierKind,
    TrustService, TrustServiceHistoryEntry, TrustServiceProvider, TrustServiceStatus,
    TrustServiceType, TrustedList, TslAddress, TslAddressContext, TslAddressFailure,
    TslDigitalIdentityFailure, TslError, TslMediaType, TslNonPkiIdentifier, TslObjectIdentifier,
    TslPointer, TslPointerQualifierFailure, TslPostalAddress, TslProviderFailure,
    TslQualificationFailure, TslRequiredField, TslResourceLimit, TslStructureFailure, TslTimestamp,
    TslUri, TslVersion, TslXmlFailure, TspRegistrationIdentifier, TspRegistrationIdentifierKind,
    XmlDsigKeyValue, MAX_TSL_URI_BYTES,
};

const TSL_NAMESPACE: &str = "http://uri.etsi.org/02231/v2#";
const XMLDSIG_NAMESPACE: &str = "http://www.w3.org/2000/09/xmldsig#";
const XMLDSIG11_NAMESPACE: &str = "http://www.w3.org/2009/xmldsig11#";
const TSL_ADDITIONAL_TYPES_NAMESPACE: &str = "http://uri.etsi.org/02231/v2/additionaltypes#";
const XADES_132_NAMESPACE: &str = "http://uri.etsi.org/01903/v1.3.2#";
const XADES_141_NAMESPACE: &str = "http://uri.etsi.org/01903/v1.4.1#";
const TSL_QUALIFICATIONS_NAMESPACE: &str =
    "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#";
/// Maximum UTF-8 byte length accepted by the portable TSL XML parser.
pub const MAX_TSL_XML_BYTES: usize = 16 * 1024 * 1024;
const MAX_XML_DEPTH: usize = 128;
const MAX_XML_ELEMENTS: usize = 200_000;
const MAX_XML_TEXT_BYTES: usize = 32 * 1024 * 1024;
const MAX_ATTRIBUTES_PER_ELEMENT: usize = 128;
const MAX_POINTERS: usize = 256;
const MAX_POINTER_IDENTITIES: usize = 64;
const MAX_POINTER_QUALIFIERS: usize = 16;
const MAX_PROVIDERS: usize = 10_000;
const MAX_SERVICES: usize = 50_000;
const MAX_HISTORY_PER_SERVICE: usize = 1_024;
const MAX_CERTIFICATES_PER_IDENTITY: usize = 32;
const MAX_DIGITAL_IDENTITIES: usize = 64;
const MAX_KEY_COMPONENT_BASE64_BYTES: usize = 2 * 1024 * 1024;
const MAX_QUALIFICATION_ELEMENTS: usize = 1_024;
const MAX_QUALIFICATION_CRITERIA_DEPTH: usize = 16;
const MAX_QUALIFICATION_CRITERIA: usize = 4_096;
const MAX_QUALIFIERS_PER_ELEMENT: usize = 32;
const MAX_KEY_USAGE_ASSERTIONS: usize = 9;
const MAX_OBJECT_IDENTIFIERS_PER_ASSERTION: usize = 128;
const MAX_SUPPLY_POINTS_PER_SERVICE: usize = 64;
const MAX_NAMES_PER_FIELD: usize = 64;
const MAX_TEXT_FIELD_BYTES: usize = 4_096;
const MAX_CERTIFICATE_BASE64_BYTES: usize = 2 * 1024 * 1024;
const REQUIRED_HISTORICAL_INFORMATION_PERIOD_DAYS: u64 = 65_535;
const REQUIRED_TSL_TAG: &str = "http://uri.etsi.org/19612/TSLTag";
const MAX_UPDATE_INTERVAL_MONTHS: u16 = 6;
const MAX_UPDATE_DST_SHIFT_SECONDS: i64 = 3_600;
/// Maximum clock skew, in seconds, tolerated between a list's
/// `ListIssueDateTime` and the caller's evaluation time.
pub const MAX_TSL_ISSUE_DATE_TIME_CLOCK_SKEW_SECONDS: i64 = 300;
const EU_GENERIC_TSL_TYPE: &str = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric";
const EU_LIST_OF_TRUSTED_LISTS_TYPE: &str =
    "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists";

#[derive(Debug, Deserialize)]
struct RawEnvelope {
    #[serde(rename = "@TSLTag")]
    tsl_tag: Option<String>,
    #[serde(rename = "SchemeInformation")]
    scheme_information: Option<RawSchemeInformation>,
    #[serde(rename = "TrustServiceProviderList")]
    tsp_list: Option<RawTspList>,
}

#[derive(Debug, Deserialize)]
struct RawSchemeInformation {
    #[serde(rename = "TSLVersionIdentifier")]
    version: Option<i64>,
    #[serde(rename = "TSLSequenceNumber")]
    sequence_number: Option<u64>,
    #[serde(rename = "TSLType")]
    tsl_type: Option<String>,
    #[serde(rename = "SchemeOperatorName")]
    scheme_operator_name: Option<RawInternationalNames>,
    #[serde(rename = "SchemeOperatorAddress")]
    scheme_operator_address: Option<RawAddress>,
    #[serde(rename = "SchemeName")]
    scheme_name: Option<RawInternationalNames>,
    #[serde(rename = "SchemeInformationURI")]
    scheme_information_uri: Option<RawInternationalUris>,
    #[serde(rename = "StatusDeterminationApproach")]
    status_determination_approach: Option<String>,
    #[serde(rename = "SchemeTypeCommunityRules")]
    scheme_type_community_rules: Option<RawInternationalUris>,
    #[serde(rename = "SchemeTerritory")]
    territory: Option<String>,
    #[serde(rename = "PolicyOrLegalNotice")]
    policy_or_legal_notice: Option<RawPolicyOrLegalNotice>,
    #[serde(rename = "HistoricalInformationPeriod")]
    historical_information_period: Option<u64>,
    #[serde(rename = "ListIssueDateTime")]
    issue: Option<String>,
    #[serde(rename = "NextUpdate")]
    next_update: Option<RawNextUpdate>,
    #[serde(rename = "PointersToOtherTSL")]
    pointers: Option<RawPointers>,
}

#[derive(Debug, Deserialize)]
struct RawAddress {
    #[serde(rename = "PostalAddresses")]
    postal_addresses: Option<RawPostalAddresses>,
    #[serde(rename = "ElectronicAddress")]
    electronic_address: Option<RawInternationalUris>,
}

#[derive(Debug, Deserialize)]
struct RawPostalAddresses {
    #[serde(rename = "PostalAddress", default)]
    addresses: Vec<RawPostalAddress>,
}

#[derive(Debug, Deserialize)]
struct RawPostalAddress {
    #[serde(rename = "@lang", alias = "@xml:lang")]
    language: Option<String>,
    #[serde(rename = "StreetAddress")]
    street_address: Option<String>,
    #[serde(rename = "Locality")]
    locality: Option<String>,
    #[serde(rename = "StateOrProvince")]
    state_or_province: Option<String>,
    #[serde(rename = "PostalCode")]
    postal_code: Option<String>,
    #[serde(rename = "CountryName")]
    country_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawPolicyOrLegalNotice {
    #[serde(rename = "TSLPolicy", default)]
    policies: Vec<RawLocalizedText>,
    #[serde(rename = "TSLLegalNotice", default)]
    legal_notices: Vec<RawLocalizedText>,
}

#[derive(Debug, Deserialize)]
struct RawNextUpdate {
    #[serde(rename = "dateTime")]
    date_time: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RawInternationalNames {
    #[serde(rename = "Name", default)]
    names: Vec<RawLocalizedText>,
}

#[derive(Debug, Deserialize)]
struct RawLocalizedText {
    #[serde(rename = "@lang", alias = "@xml:lang")]
    language: Option<String>,
    #[serde(rename = "$text")]
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawPointers {
    #[serde(rename = "OtherTSLPointer", default)]
    pointers: Vec<RawPointer>,
}

#[derive(Debug, Deserialize)]
struct RawPointer {
    #[serde(rename = "TSLLocation")]
    url: Option<String>,
    #[serde(rename = "ServiceDigitalIdentities")]
    identities: Option<RawServiceDigitalIdentities>,
    #[serde(rename = "AdditionalInformation")]
    additional_information: Option<RawPointerAdditionalInformation>,
}

#[derive(Debug, Deserialize)]
struct RawPointerAdditionalInformation {
    #[serde(rename = "OtherInformation", default)]
    values: Vec<RawPointerQualifier>,
}

#[derive(Debug, Deserialize)]
struct RawPointerQualifier {
    #[serde(rename = "TSLType")]
    tsl_type: Option<String>,
    #[serde(rename = "SchemeOperatorName")]
    scheme_operator_name: Option<RawInternationalNames>,
    #[serde(rename = "SchemeTypeCommunityRules")]
    scheme_type_community_rules: Option<RawInternationalUris>,
    #[serde(rename = "SchemeTerritory")]
    territory: Option<String>,
    #[serde(rename = "MimeType")]
    mime_type: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RawInternationalUris {
    #[serde(rename = "URI", default)]
    uris: Vec<RawLocalizedText>,
}

#[derive(Debug, Deserialize)]
struct RawTspList {
    #[serde(rename = "TrustServiceProvider", default)]
    providers: Vec<RawTsp>,
}

#[derive(Debug, Deserialize)]
struct RawTsp {
    #[serde(rename = "TSPInformation")]
    information: Option<RawTspInformation>,
    #[serde(rename = "TSPServices")]
    services: Option<RawTspServices>,
}

#[derive(Debug, Deserialize)]
struct RawTspInformation {
    #[serde(rename = "TSPName")]
    names: Option<RawInternationalNames>,
    #[serde(rename = "TSPTradeName")]
    trade_names: Option<RawInternationalNames>,
    #[serde(rename = "TSPAddress")]
    address: Option<RawAddress>,
    #[serde(rename = "TSPInformationURI")]
    information_uris: Option<RawInternationalUris>,
}

#[derive(Debug, Deserialize)]
struct RawTspServices {
    #[serde(rename = "TSPService", default)]
    services: Vec<RawService>,
}

#[derive(Debug, Deserialize)]
struct RawService {
    #[serde(rename = "ServiceInformation")]
    information: Option<RawServiceInformation>,
    #[serde(rename = "ServiceHistory")]
    history: Option<RawServiceHistory>,
}

#[derive(Debug, Deserialize)]
struct RawServiceInformation {
    #[serde(rename = "ServiceTypeIdentifier")]
    service_type: Option<String>,
    #[serde(rename = "ServiceName")]
    service_names: Option<RawInternationalNames>,
    #[serde(rename = "ServiceStatus")]
    status: Option<String>,
    #[serde(rename = "StatusStartingTime")]
    status_time: Option<String>,
    #[serde(rename = "ServiceSupplyPoints")]
    supply_points: Option<RawSupplyPoints>,
    #[serde(rename = "ServiceDigitalIdentity")]
    identity: Option<RawServiceDigitalIdentity>,
    #[serde(rename = "ServiceInformationExtensions")]
    extensions: Option<RawExtensions>,
}

#[derive(Debug, Deserialize)]
struct RawSupplyPoints {
    #[serde(rename = "ServiceSupplyPoint", default)]
    points: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawServiceDigitalIdentities {
    #[serde(rename = "ServiceDigitalIdentity", default)]
    identities: Vec<RawServiceDigitalIdentity>,
}

#[derive(Debug, Deserialize)]
struct RawServiceDigitalIdentity {
    #[serde(rename = "DigitalId", default)]
    ids: Vec<RawDigitalId>,
}

#[derive(Debug, Deserialize)]
struct RawDigitalId {
    #[serde(rename = "X509Certificate")]
    certificate: Option<String>,
    #[serde(rename = "X509SubjectName")]
    subject_name: Option<String>,
    #[serde(rename = "KeyValue")]
    key_value: Option<RawKeyValue>,
    #[serde(rename = "X509SKI")]
    subject_key_identifier: Option<String>,
    #[serde(rename = "Other")]
    other: Option<RawOtherDigitalId>,
}

#[derive(Debug, Deserialize)]
struct RawOtherDigitalId {
    #[serde(rename = "$text")]
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawKeyValue {
    #[serde(rename = "RSAKeyValue")]
    rsa: Option<RawRsaKeyValue>,
    #[serde(rename = "DSAKeyValue")]
    dsa: Option<RawDsaKeyValue>,
    #[serde(rename = "ECKeyValue")]
    ec: Option<RawEcKeyValue>,
}

#[derive(Debug, Deserialize)]
struct RawEcKeyValue {
    #[serde(rename = "NamedCurve")]
    named_curve: Option<RawNamedCurve>,
    #[serde(rename = "PublicKey")]
    public_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawNamedCurve {
    #[serde(rename = "@URI")]
    uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawRsaKeyValue {
    #[serde(rename = "Modulus")]
    modulus: Option<String>,
    #[serde(rename = "Exponent")]
    exponent: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawDsaKeyValue {
    #[serde(rename = "P")]
    p: Option<String>,
    #[serde(rename = "Q")]
    q: Option<String>,
    #[serde(rename = "G")]
    g: Option<String>,
    #[serde(rename = "Y")]
    y: Option<String>,
    #[serde(rename = "J")]
    j: Option<String>,
    #[serde(rename = "Seed")]
    seed: Option<String>,
    #[serde(rename = "PgenCounter")]
    pgen_counter: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawServiceHistory {
    #[serde(rename = "ServiceHistoryInstance", default)]
    entries: Vec<RawServiceInformation>,
}

include!("parse/raw_extensions.rs");

include!("parse/document.rs");
include!("parse/boundary.rs");
include!("parse/project.rs");
