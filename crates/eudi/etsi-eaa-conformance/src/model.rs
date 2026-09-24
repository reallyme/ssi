// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Supported EAA/PID envelope realization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttestationFormat {
    /// SD-JWT VC as profiled by ETSI TS 119 472-1 clause 5.
    SdJwtVc,
    /// ISO/IEC mdoc as profiled by ETSI TS 119 472-1 clause 6.
    IsoMdoc,
    /// JSON-LD W3C VC protected with JOSE.
    JsonLdJose,
    /// JSON-LD W3C VC protected with SD-JWT.
    JsonLdSdJwt,
    /// X.509 Attribute Certificate.
    X509AttributeCertificate,
}

/// Regulatory category of the attestation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttestationCategory {
    /// Electronic attestation without a qualified or public-body designation.
    Eaa,
    /// Qualified electronic attestation of attributes.
    Qeaa,
    /// EAA issued by or on behalf of a public body responsible for an authentic source.
    PublicBodyEaa,
    /// Natural-person identification data.
    NaturalPersonPid,
    /// Legal-person identification data.
    LegalPersonPid,
}

/// Encoded signal identifying an attestation's regulatory category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttestationCategorySignal<'a> {
    /// The optional signal is absent.
    Absent,
    /// A URI category identifier carried by the selected realization.
    Uri(&'a str),
    /// A non-URI, format-native signal whose value was validated by its parser.
    FormatNative,
}

/// Privacy-safe description of subject binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubjectBinding {
    /// No subject binding is present.
    None,
    /// The attestation uses a subject identifier.
    Identifier,
    /// The attestation uses an explicitly signalled pseudonym.
    Pseudonym,
}

/// Issuer signature assurance established by the signature-verification layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssuerSignature {
    /// No valid issuer signature was established.
    Unverified,
    /// A valid advanced electronic signature or seal was established.
    Advanced,
    /// A valid qualified electronic signature or seal was established.
    Qualified,
    /// A qualified public-body signature/seal certificate with the required QcType was established.
    QualifiedPublicBody,
}

/// Technical and administrative validity facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidityFacts {
    /// Inclusive technical-validity start, in Unix seconds.
    pub technical_not_before: u64,
    /// Exclusive technical-validity end, in Unix seconds.
    pub technical_not_after: u64,
    /// Optional administrative-validity interval.
    pub administrative: Option<ValidityInterval>,
}

/// Inclusive start and exclusive end of a validity interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidityInterval {
    /// Inclusive validity start, in Unix seconds.
    pub not_before: u64,
    /// Exclusive validity end, in Unix seconds.
    pub not_after: u64,
}

/// Selective-disclosure consistency facts produced by the envelope parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectiveDisclosureFacts {
    /// Number of disclosures carried by the attestation.
    pub disclosure_count: u32,
    /// Number of signed disclosure references.
    pub signed_reference_count: u32,
    /// Whether every reference binds unambiguously to exactly one disclosure.
    pub references_unambiguous: bool,
    /// Whether the disclosure algorithm is present and supported when required.
    pub algorithm_valid: bool,
}

/// EAA identifier supplied to the common-profile validator.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum AttestationIdentifier<'a> {
    /// Absolute URI identifier.
    Uri(&'a str),
    /// Format-native opaque identifier with a bounded byte representation.
    Opaque(&'a [u8]),
}

/// Issuer acting on behalf of another identified entity.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct IssuedOnBehalf<'a> {
    /// Optional identifier of the represented entity.
    pub entity_identifier: Option<&'a str>,
    /// Optional name of the represented entity.
    pub entity_name: Option<&'a str>,
    /// Optional registration identifier of a represented legal entity.
    pub registration_identifier: Option<&'a str>,
}

/// Integrity-protected evidence used to establish an attested attribute.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AttributeEvidence<'a> {
    /// Absolute URI identifying the evidence type.
    pub evidence_type_uri: &'a str,
    /// Absolute URI locating or naming the evidence source.
    pub source_uri: &'a str,
    /// SHA-256 digest of the canonical evidence representation.
    pub sha256: &'a [u8; 32],
}

/// Renewal service advertised by an attestation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RenewalService<'a> {
    /// HTTPS renewal endpoint.
    pub endpoint: &'a str,
    /// Last instant at which renewal may be requested, in Unix seconds.
    pub available_until: u64,
}

/// Executable common-profile inputs.
///
/// The validator parses identifiers and URIs, bounds every collection, checks
/// uniqueness, and relates issuance and renewal times to credential validity.
/// Raw attribute values and evidence bodies remain outside this structure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommonProfileData<'a> {
    /// Whether component names are URLs and therefore require context metadata.
    pub components_use_uri_names: bool,
    /// Absolute context URIs carried by the selected EAA representation.
    pub context_uris: &'a [&'a str],
    /// Absolute schema URIs carried by the selected EAA representation.
    pub schema_uris: &'a [&'a str],
    /// Unique attestation identifier.
    pub attestation_identifier: Option<AttestationIdentifier<'a>>,
    /// Optional represented entity and authority.
    pub issued_on_behalf: Option<IssuedOnBehalf<'a>>,
    /// Credential issuance time, in Unix seconds.
    pub issued_at: Option<u64>,
    /// Audience identifiers. Empty means no audience restriction.
    pub audiences: &'a [&'a str],
    /// Whether the issuer limits the credential to one presentation.
    pub one_time_use: bool,
    /// Absolute terms-of-use URIs.
    pub terms_of_use_uris: &'a [&'a str],
    /// Integrity-protected attribute evidence references.
    pub attribute_evidence: &'a [AttributeEvidence<'a>],
    /// Optional renewal service.
    pub renewal_service: Option<RenewalService<'a>>,
}

/// Status facts already authenticated by the status layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusFacts {
    /// No status mechanism is present.
    Absent,
    /// The attestation invokes the short-lived exemption.
    ShortLivedExempt,
    /// A status mechanism is present.
    Revocation {
        /// Status lookup and representation are privacy preserving.
        privacy_preserving: bool,
        /// The status space contains only revoked and not-revoked outcomes.
        binary_only: bool,
        /// Revocation cannot be reverted.
        irreversible: bool,
    },
}

/// Facts common to all ETSI EAA realizations.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommonAttestationFacts<'a> {
    /// Envelope realization.
    pub format: AttestationFormat,
    /// Regulatory category.
    pub category: AttestationCategory,
    /// Type identifier carried by the attestation.
    pub type_identifier: &'a str,
    /// Encoded category signal, when present.
    pub category_signal: AttestationCategorySignal<'a>,
    /// Optional embedded issuer identifier.
    pub issuer_identifier: Option<&'a str>,
    /// Issuer country as an ISO 3166-1 alpha-2 code, when supplied.
    pub issuer_country: Option<&'a str>,
    /// Issuer name, when supplied by the selected category profile.
    pub issuer_name: Option<&'a str>,
    /// Download URL for the signature certificate, when required by category.
    pub issuer_signature_certificate_url: Option<&'a str>,
    /// Subject identifier or explicitly signalled pseudonym.
    pub subject_binding: SubjectBinding,
    /// Whether all QEAA attributes refer to the single QEAA subject.
    pub all_attributes_same_subject: bool,
    /// Validity facts.
    pub validity: ValidityFacts,
    /// Common profile data validated directly by this crate.
    pub profile: CommonProfileData<'a>,
    /// Whether every attribute has an unambiguous identifier.
    pub attribute_identifiers_complete: bool,
    /// Whether every attribute has a value conforming to its declared semantics.
    pub attribute_values_complete: bool,
    /// Whether every attribute is associated with one attribute subject.
    pub attribute_subjects_complete: bool,
    /// Selective-disclosure facts, if the envelope contains disclosures.
    pub selective_disclosure: Option<SelectiveDisclosureFacts>,
    /// Whether an issuer-authenticated holder public key is present.
    pub holder_public_key_bound: bool,
    /// Issuer-signature assurance.
    pub issuer_signature: IssuerSignature,
    /// Status facts.
    pub status: StatusFacts,
}

/// SD-JWT VC realization facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SdJwtFacts<'a> {
    /// Value of the `vct` claim.
    pub vct: &'a str,
    /// Whether `vct#integrity` correctly protects the resolved type metadata.
    pub vct_integrity_valid: bool,
    /// Whether `nbf` and `exp` express the technical validity interval.
    pub validity_claims_match: bool,
    /// Whether `_sd_alg` is present and supported when disclosures are used.
    pub disclosure_algorithm_valid: bool,
    /// Whether every profile claim required to be selectively disclosable is individually selectable.
    pub individual_claim_disclosure: bool,
    /// Whether `cnf` contains the holder public key when key binding is required.
    pub confirmation_key_present: bool,
    /// Whether the bound private key is held in the wallet WSCD.
    pub confirmation_key_wscd_protected: bool,
    /// Whether the protected header contains `x5u`.
    pub protected_x5u_present: bool,
    /// Whether the protected header contains `x5t#S256`.
    pub protected_x5t_s256_present: bool,
}

/// ISO/IEC mdoc realization facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MdocFacts<'a> {
    /// Mobile document type.
    pub doc_type: &'a str,
    /// Namespace containing the standard attributes.
    pub namespace: &'a str,
    /// Whether `deviceKeyInfo.deviceKey` contains a public key.
    pub device_key_present: bool,
    /// Whether the corresponding private key is held in the wallet WSCD.
    pub device_key_wscd_protected: bool,
    /// Whether the protected CB-AdES header contains `x5u`.
    pub protected_x5u_present: bool,
    /// Whether the protected CB-AdES header contains `x5t` using SHA-256.
    pub protected_x5t_sha256_present: bool,
    /// Whether deterministic/minimal CBOR encoding requirements were met.
    pub deterministic_cbor: bool,
    /// Whether every text value is valid Unicode and no longer than 150 characters.
    pub text_constraints_valid: bool,
    /// Whether date values use the required RFC 8943/RFC 3339 encodings.
    pub date_constraints_valid: bool,
}

/// JSON-LD W3C VC realization facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JsonLdFacts {
    /// The credential conforms to W3C Verifiable Credentials Data Model 2.0.
    pub vc_data_model_2: bool,
    /// Required contexts and types are present and integrity protected.
    pub context_and_type_valid: bool,
    /// Credential-subject structures preserve attribute-to-subject association.
    pub credential_subject_valid: bool,
    /// The JOSE or SD-JWT enveloping proof matches the selected format.
    pub enveloping_proof_valid: bool,
}

/// X.509 Attribute Certificate realization facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X509AttributeCertificateFacts {
    /// The certificate uses the profiled X.509 Attribute Certificate syntax.
    pub syntax_valid: bool,
    /// Holder, issuer, serial, validity, attributes, and signature fields are valid.
    pub mandatory_fields_valid: bool,
    /// Extensions comply with the ETSI profile and critical-extension policy.
    pub extensions_valid: bool,
}

/// Format-specific facts paired with a common attestation record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatFacts<'a> {
    /// SD-JWT VC facts.
    SdJwt(SdJwtFacts<'a>),
    /// ISO/IEC mdoc facts.
    Mdoc(MdocFacts<'a>),
    /// JSON-LD W3C VC facts.
    JsonLd(JsonLdFacts),
    /// X.509 Attribute Certificate facts.
    X509AttributeCertificate(X509AttributeCertificateFacts),
}
