// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{ConformanceError, Result};

mod eu_profile;
mod parse;

pub use eu_profile::{
    resolve_eu_profile_requirement, validate_eu_profile_requirement_registry,
    EuProfileRequirementControl, EuProfileRequirementSummary, EuProfileSource,
};

use parse::{
    normative_trace_lines, parse_applicability, parse_eu_profile_status, parse_handler,
    parse_trace_columns, source_metadata, validate_lookup_identifier,
};

/// Evidence disposition recorded for one exact requirement row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequirementDisposition {
    /// Executable local code plus any named composed evidence.
    CodeAndComposedEvidence,
    /// The obligation can only be established by external evidence.
    ExternalEvidenceRequired,
    /// The current consolidated profile makes the row non-applicable.
    NotApplicable,
}

impl RequirementDisposition {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "code_and_composed_evidence" => Ok(Self::CodeAndComposedEvidence),
            "external_evidence_required" => Ok(Self::ExternalEvidenceRequired),
            "not_applicable" => Ok(Self::NotApplicable),
            _ => Err(ConformanceError::InvalidNormativeRequirementRegistry),
        }
    }
}

/// Exact implementation, test, external-evidence, and justification mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequirementTraceEvidence {
    source_edition: &'static str,
    disposition: RequirementDisposition,
    owner_repository: &'static str,
    code_path: &'static str,
    code_symbol: &'static str,
    test_path: &'static str,
    test_symbol: &'static str,
    external_evidence: &'static str,
    justification: &'static str,
}

impl RequirementTraceEvidence {
    const fn from_columns(
        disposition: RequirementDisposition,
        columns: &parse::TraceColumns<'static>,
    ) -> Self {
        Self {
            source_edition: columns.source_edition,
            disposition,
            owner_repository: columns.owner_repository,
            code_path: columns.code_path,
            code_symbol: columns.code_symbol,
            test_path: columns.test_path,
            test_symbol: columns.test_symbol,
            external_evidence: columns.external_evidence,
            justification: columns.justification,
        }
    }

    /// Pinned source edition or consolidated-date identifier.
    #[must_use]
    pub const fn source_edition(self) -> &'static str {
        self.source_edition
    }
    /// Requirement disposition.
    #[must_use]
    pub const fn disposition(self) -> RequirementDisposition {
        self.disposition
    }
    /// Repository owning executable code or external evidence.
    #[must_use]
    pub const fn owner_repository(self) -> &'static str {
        self.owner_repository
    }
    /// Exact code path, or `-` when code is not applicable.
    #[must_use]
    pub const fn code_path(self) -> &'static str {
        self.code_path
    }
    /// Exact code symbol, or `-` when code is not applicable.
    #[must_use]
    pub const fn code_symbol(self) -> &'static str {
        self.code_symbol
    }
    /// Exact test path, or `-` when code is not applicable.
    #[must_use]
    pub const fn test_path(self) -> &'static str {
        self.test_path
    }
    /// Exact test symbol, or `-` when code is not applicable.
    #[must_use]
    pub const fn test_symbol(self) -> &'static str {
        self.test_symbol
    }
    /// Exact external-evidence obligation, or `-` when none is recorded.
    #[must_use]
    pub const fn external_evidence(self) -> &'static str {
        self.external_evidence
    }
    /// Fixed implementation or non-applicability justification.
    #[must_use]
    pub const fn justification(self) -> &'static str {
        self.justification
    }
}

const HANDLER_COUNT: usize = 16;
const EXPECTED_HANDLER_COUNTS: [u16; HANDLER_COUNT] =
    [145, 103, 100, 128, 72, 63, 21, 4, 59, 1, 6, 6, 2, 28, 1, 1];

/// ETSI TS 119 472 part owning a normative requirement identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormativeRequirementPart {
    /// ETSI TS 119 472-1 common and credential-format requirements.
    Part1,
    /// ETSI TS 119 472-2 presentation requirements.
    Part2,
    /// ETSI TS 119 472-3 issuance requirements.
    Part3,
}

/// Production enforcement route associated with a normative identifier.
///
/// A route identifies the validator that consumes the relevant verified facts.
/// It does not claim that the protocol, cryptographic, trust, UI, or deployment
/// evidence named by [`ComposedEvidenceBoundary`] was produced by this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormativeRequirementHandler {
    /// Common ETSI EAA/PID and category validation.
    CommonAttestation,
    /// SD-JWT VC credential-profile validation.
    SdJwtCredential,
    /// ISO/IEC mdoc credential-profile validation.
    MdocCredential,
    /// JSON-LD W3C VC credential-profile validation.
    JsonLdCredential,
    /// X.509 Attribute Certificate credential-profile validation.
    X509AttributeCertificate,
    /// OpenID4VP and HAIP presentation validation.
    OpenId4VpPresentation,
    /// ISO/IEC 18013-5 mdoc presentation validation.
    MdocPresentation,
    /// SD-JWT VC presentation validation.
    SdJwtPresentation,
    /// Signed Credential Issuer Metadata validation.
    IssuerMetadata,
    /// Credential Offer resolution and validation.
    CredentialOffer,
    /// Authorization Code flow validation.
    AuthorizationCode,
    /// Pre-Authorized Code flow validation.
    PreAuthorizedCode,
    /// DPoP-bound authorization validation.
    DpopAuthorization,
    /// Credential Request handling and proof validation.
    CredentialRequest,
    /// Encrypted Credential Response handling.
    CredentialResponseEncryption,
    /// Issuance notification handling.
    Notification,
}

/// Evidence outside this policy crate that remains necessary for conformity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComposedEvidenceBoundary {
    /// Credential parsing, signature verification, trust-path validation, and status resolution.
    CredentialVerification,
    /// OpenID4VP wire state, wallet UI, registrar, and deployed trust evidence.
    PresentationProtocol,
    /// OpenID4VCI wire state, issuer service, wallet custody, and deployed trust evidence.
    IssuanceProtocol,
}

/// Credential/category profile to which a normative identifier applies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormativeRequirementProfile {
    /// Generic EAA or PID behavior.
    EaaOrPid,
    /// Qualified EAA behavior.
    Qeaa,
    /// Public-body EAA behavior.
    PublicBodyEaa,
    /// SD-JWT VC behavior.
    SdJwtVc,
    /// ISO/IEC mdoc behavior.
    IsoMdoc,
    /// JSON-LD W3C VC behavior.
    JsonLdVc,
    /// X.509 Attribute Certificate behavior.
    X509AttributeCertificate,
    /// OpenID4VP HAIP behavior.
    OpenId4VpHaip,
}

/// Operation or realization selected by a normative applicability predicate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormativeRequirementArea {
    /// Every supported credential realization.
    AllFormats,
    /// Authorization or token exchange.
    AuthorizationOrToken,
    /// Credential Endpoint request/response processing.
    CredentialEndpoint,
    /// Credential Offer handling.
    CredentialOffer,
    /// ISO/IEC mdoc realization.
    IsoMdoc,
    /// General issuance behavior.
    Issuance,
    /// Issuance cryptographic-suite support.
    IssuanceCryptography,
    /// Issuance security policy.
    IssuanceSecurity,
    /// Credential Issuer Metadata.
    IssuerMetadata,
    /// JSON-LD W3C VC realization.
    JsonLdVc,
    /// Issuance notification handling.
    Notification,
    /// SD-JWT VC realization.
    SdJwtVc,
    /// X.509 Attribute Certificate realization.
    X509AttributeCertificate,
    /// Presentation behavior.
    Presentation,
}

/// Typed applicability predicate carried by one trace row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormativeRequirementApplicability {
    /// Credential/category profile.
    pub profile: NormativeRequirementProfile,
    /// Operation or realization.
    pub area: NormativeRequirementArea,
}

/// Status of an ETSI identifier in the current consolidated EU profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormativeEuProfileStatus {
    /// Applicable without an additional recorded adaptation.
    Applicable,
    /// Applicable subject to a current EU adaptation.
    ApplicableSubjectToAdaptations,
    /// Applicable when the corresponding format is selected.
    ApplicableWhenFormatSelected,
    /// Applicable when an issuance notification identifier was produced.
    ApplicableWhenNotificationIdentifierIssued,
    /// Part 1 is incorporated subject to the EU adaptations.
    IncorporatedSubjectToAdaptations,
    /// Both the EU-incorporated Part 2 edition and latest edition are tracked.
    Part2LegalAndLatestTracked,
    /// Part 3 Annex A is void in the current EU profile.
    AnnexAVoidInCurrentEuProfile,
}

/// Typed production route for one exact normative requirement identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormativeRequirementControl {
    identifier: &'static str,
    part: NormativeRequirementPart,
    handler: NormativeRequirementHandler,
    evidence_boundary: ComposedEvidenceBoundary,
    applicability: NormativeRequirementApplicability,
    eu_profile_status: NormativeEuProfileStatus,
    evidence: RequirementTraceEvidence,
}

impl NormativeRequirementControl {
    /// Exact identifier printed by the normative ETSI document.
    #[must_use]
    pub const fn identifier(self) -> &'static str {
        self.identifier
    }

    /// ETSI TS 119 472 part owning the identifier.
    #[must_use]
    pub const fn part(self) -> NormativeRequirementPart {
        self.part
    }

    /// Production validator or adapter route for the identifier.
    #[must_use]
    pub const fn handler(self) -> NormativeRequirementHandler {
        self.handler
    }

    /// Evidence boundary that must be composed with the local validator result.
    #[must_use]
    pub const fn evidence_boundary(self) -> ComposedEvidenceBoundary {
        self.evidence_boundary
    }

    /// Category/format/operation predicate controlling applicability.
    #[must_use]
    pub const fn applicability(self) -> NormativeRequirementApplicability {
        self.applicability
    }

    /// Treatment of the identifier in the current consolidated EU profile.
    #[must_use]
    pub const fn eu_profile_status(self) -> NormativeEuProfileStatus {
        self.eu_profile_status
    }

    /// Exact implementation, test, and external-evidence mapping.
    #[must_use]
    pub const fn evidence(self) -> RequirementTraceEvidence {
        self.evidence
    }
}

/// Counts established while validating the embedded normative registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormativeRequirementSummary {
    /// Part 1 identifier count.
    pub part1: u16,
    /// Part 2 identifier count.
    pub part2: u16,
    /// Part 3 identifier count.
    pub part3: u16,
    /// Total unique identifier count.
    pub total: u16,
}

/// Resolve one exact ETSI normative identifier to its production enforcement route.
///
/// The lookup is case-sensitive and rejects whitespace, control characters,
/// oversized input, unknown identifiers, malformed embedded rows, and routes
/// that are not recognized by this crate. This prevents a caller from silently
/// treating a newly introduced or misspelled identifier as covered.
pub fn resolve_normative_requirement(identifier: &str) -> Result<NormativeRequirementControl> {
    validate_lookup_identifier(identifier)?;

    let mut match_found = None;
    for line in normative_trace_lines() {
        let columns = parse_trace_columns(line)?;
        let Some((part, evidence_boundary)) = source_metadata(columns.source) else {
            continue;
        };
        if columns.identifier != identifier {
            continue;
        }
        if match_found.is_some() {
            return Err(ConformanceError::InvalidNormativeRequirementRegistry);
        }
        if columns.disposition != "code_and_composed_evidence" || columns.external_evidence == "-" {
            return Err(ConformanceError::InvalidNormativeRequirementRegistry);
        }
        let disposition = RequirementDisposition::parse(columns.disposition)?;
        match_found = Some(NormativeRequirementControl {
            identifier: columns.identifier,
            part,
            handler: parse_handler(columns.code_symbol)?,
            evidence_boundary,
            applicability: parse_applicability(columns.applicability)?,
            eu_profile_status: parse_eu_profile_status(columns.eu_profile_status)?,
            evidence: RequirementTraceEvidence::from_columns(disposition, &columns),
        });
    }

    match_found.ok_or(ConformanceError::UnknownNormativeRequirement)
}

/// Validate the complete embedded registry and return its exact per-part counts.
///
/// This operation is intentionally allocation-free. It resolves every row
/// through the same public fail-closed path used by callers and detects
/// duplicate identifiers by requiring each lookup to have exactly one match.
pub fn validate_normative_requirement_registry() -> Result<NormativeRequirementSummary> {
    let mut summary = NormativeRequirementSummary {
        part1: 0,
        part2: 0,
        part3: 0,
        total: 0,
    };
    let mut handler_counts = [0_u16; HANDLER_COUNT];

    for line in normative_trace_lines() {
        let columns = parse_trace_columns(line)?;
        let Some((part, _)) = source_metadata(columns.source) else {
            continue;
        };
        let control = resolve_normative_requirement(columns.identifier)?;
        if control.part != part {
            return Err(ConformanceError::InvalidNormativeRequirementRegistry);
        }
        let handler_index = handler_index(control.handler);
        handler_counts[handler_index] = handler_counts[handler_index]
            .checked_add(1)
            .ok_or(ConformanceError::InvalidNormativeRequirementRegistry)?;
        match part {
            NormativeRequirementPart::Part1 => {
                summary.part1 = summary
                    .part1
                    .checked_add(1)
                    .ok_or(ConformanceError::InvalidNormativeRequirementRegistry)?;
            }
            NormativeRequirementPart::Part2 => {
                summary.part2 = summary
                    .part2
                    .checked_add(1)
                    .ok_or(ConformanceError::InvalidNormativeRequirementRegistry)?;
            }
            NormativeRequirementPart::Part3 => {
                summary.part3 = summary
                    .part3
                    .checked_add(1)
                    .ok_or(ConformanceError::InvalidNormativeRequirementRegistry)?;
            }
        }
        summary.total = summary
            .total
            .checked_add(1)
            .ok_or(ConformanceError::InvalidNormativeRequirementRegistry)?;
    }

    if summary.part1 == 548
        && summary.part2 == 88
        && summary.part3 == 104
        && summary.total == 740
        && handler_counts == EXPECTED_HANDLER_COUNTS
    {
        Ok(summary)
    } else {
        Err(ConformanceError::InvalidNormativeRequirementRegistry)
    }
}

const fn handler_index(handler: NormativeRequirementHandler) -> usize {
    match handler {
        NormativeRequirementHandler::CommonAttestation => 0,
        NormativeRequirementHandler::SdJwtCredential => 1,
        NormativeRequirementHandler::MdocCredential => 2,
        NormativeRequirementHandler::JsonLdCredential => 3,
        NormativeRequirementHandler::X509AttributeCertificate => 4,
        NormativeRequirementHandler::OpenId4VpPresentation => 5,
        NormativeRequirementHandler::MdocPresentation => 6,
        NormativeRequirementHandler::SdJwtPresentation => 7,
        NormativeRequirementHandler::IssuerMetadata => 8,
        NormativeRequirementHandler::CredentialOffer => 9,
        NormativeRequirementHandler::AuthorizationCode => 10,
        NormativeRequirementHandler::PreAuthorizedCode => 11,
        NormativeRequirementHandler::DpopAuthorization => 12,
        NormativeRequirementHandler::CredentialRequest => 13,
        NormativeRequirementHandler::CredentialResponseEncryption => 14,
        NormativeRequirementHandler::Notification => 15,
    }
}
