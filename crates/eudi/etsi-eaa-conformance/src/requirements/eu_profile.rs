// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Current consolidated EU-profile requirement routing.

use crate::{ConformanceError, Result};

use super::{
    parse::{normative_trace_lines, parse_trace_columns, validate_lookup_identifier},
    RequirementDisposition, RequirementTraceEvidence,
};

const EU_PROFILE_LEDGER: &str = include_str!("../../requirements/eu-2026-profile.tsv");
const EU_LEDGER_COLUMN_COUNT: usize = 4;

/// Legal or incorporated-profile source owning an EU-profile row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EuProfileSource {
    /// Consolidated CIR (EU) 2024/2977.
    Cir2024_2977,
    /// Consolidated CIR (EU) 2024/2979.
    Cir2024_2979,
    /// Consolidated CIR (EU) 2024/2982.
    Cir2024_2982,
    /// Part 1 adaptations incorporated into the current EU profile.
    Etsi119472Part1Eu,
    /// Part 2 adaptations incorporated into the current EU profile.
    Etsi119472Part2Eu,
    /// Part 3 adaptations incorporated into the current EU profile.
    Etsi119472Part3Eu,
}

impl EuProfileSource {
    const fn trace_name(self) -> &'static str {
        match self {
            Self::Cir2024_2977 => "CIR-2024-2977",
            Self::Cir2024_2979 => "CIR-2024-2979",
            Self::Cir2024_2982 => "CIR-2024-2982",
            Self::Etsi119472Part1Eu => "ETSI-119-472-1-EU",
            Self::Etsi119472Part2Eu => "ETSI-119-472-2-EU",
            Self::Etsi119472Part3Eu => "ETSI-119-472-3-EU",
        }
    }
}

/// Exact production/evidence mapping for one EU-profile ledger row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EuProfileRequirementControl {
    source: EuProfileSource,
    identifier: &'static str,
    applicability: &'static str,
    eu_profile_status: &'static str,
    ledger_enforcement: &'static str,
    evidence: RequirementTraceEvidence,
}

impl EuProfileRequirementControl {
    /// Legal or incorporated-profile source.
    #[must_use]
    pub const fn source(self) -> EuProfileSource {
        self.source
    }

    /// Exact identifier used by the consolidated EU ledger.
    #[must_use]
    pub const fn identifier(self) -> &'static str {
        self.identifier
    }

    /// Applicability predicate recorded by the requirement trace.
    #[must_use]
    pub const fn applicability(self) -> &'static str {
        self.applicability
    }

    /// Current consolidated-profile status recorded by the requirement trace.
    #[must_use]
    pub const fn eu_profile_status(self) -> &'static str {
        self.eu_profile_status
    }

    /// Exact enforcement description from the consolidated EU ledger.
    #[must_use]
    pub const fn ledger_enforcement(self) -> &'static str {
        self.ledger_enforcement
    }

    /// Exact code, test, external-evidence, and justification mapping.
    #[must_use]
    pub const fn evidence(self) -> RequirementTraceEvidence {
        self.evidence
    }
}

/// Counts established while validating the 229-row consolidated EU registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EuProfileRequirementSummary {
    /// CIR (EU) 2024/2977 rows.
    pub cir_2024_2977: u16,
    /// CIR (EU) 2024/2979 rows.
    pub cir_2024_2979: u16,
    /// CIR (EU) 2024/2982 rows.
    pub cir_2024_2982: u16,
    /// Part 1 EU-adaptation rows.
    pub etsi_part1_eu: u16,
    /// Part 2 EU-adaptation rows.
    pub etsi_part2_eu: u16,
    /// Part 3 EU-adaptation rows.
    pub etsi_part3_eu: u16,
    /// Direct executable rows.
    pub direct: u16,
    /// Rows requiring external composed evidence.
    pub composed: u16,
    /// Rows voided by the current consolidated profile.
    pub void: u16,
    /// Total unique EU-profile rows.
    pub total: u16,
}

/// Resolve one exact EU-profile source/identifier pair.
pub fn resolve_eu_profile_requirement(
    source: EuProfileSource,
    identifier: &str,
) -> Result<EuProfileRequirementControl> {
    validate_lookup_identifier(identifier)?;
    let source_name = source.trace_name();
    let ledger_row = find_ledger_row(source, identifier)?;
    let expected_disposition = ledger_disposition(ledger_row.disposition)?;
    let mut match_found = None;
    for line in normative_trace_lines() {
        let columns = parse_trace_columns(line)?;
        if columns.source != source_name || columns.identifier != identifier {
            continue;
        }
        if match_found.is_some() {
            return Err(ConformanceError::InvalidNormativeRequirementRegistry);
        }
        let disposition = RequirementDisposition::parse(columns.disposition)?;
        if disposition != expected_disposition {
            return Err(ConformanceError::InvalidNormativeRequirementRegistry);
        }
        validate_trace_shape(disposition, &columns)?;
        match_found = Some(EuProfileRequirementControl {
            source,
            identifier: columns.identifier,
            applicability: columns.applicability,
            eu_profile_status: columns.eu_profile_status,
            ledger_enforcement: ledger_row.enforcement,
            evidence: RequirementTraceEvidence::from_columns(disposition, &columns),
        });
    }
    match_found.ok_or(ConformanceError::UnknownNormativeRequirement)
}

/// Validate the complete 229-row EU ledger and its one-to-one trace mapping.
pub fn validate_eu_profile_requirement_registry() -> Result<EuProfileRequirementSummary> {
    let mut summary = EuProfileRequirementSummary {
        cir_2024_2977: 0,
        cir_2024_2979: 0,
        cir_2024_2982: 0,
        etsi_part1_eu: 0,
        etsi_part2_eu: 0,
        etsi_part3_eu: 0,
        direct: 0,
        composed: 0,
        void: 0,
        total: 0,
    };
    for line in EU_PROFILE_LEDGER
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let row = parse_ledger_row(line)?;
        let control = resolve_eu_profile_requirement(row.source, row.identifier)?;
        let expected_disposition = ledger_disposition(row.disposition)?;
        if control.evidence.disposition() != expected_disposition
            || control.ledger_enforcement() != row.enforcement
        {
            return Err(ConformanceError::InvalidNormativeRequirementRegistry);
        }
        increment_source(&mut summary, row.source)?;
        increment_disposition(&mut summary, row.disposition)?;
        summary.total = checked_increment(summary.total)?;
    }
    if summary
        == (EuProfileRequirementSummary {
            cir_2024_2977: 33,
            cir_2024_2979: 124,
            cir_2024_2982: 32,
            etsi_part1_eu: 9,
            etsi_part2_eu: 26,
            etsi_part3_eu: 5,
            direct: 158,
            composed: 53,
            void: 18,
            total: 229,
        })
    {
        Ok(summary)
    } else {
        Err(ConformanceError::InvalidNormativeRequirementRegistry)
    }
}

#[derive(Clone, Copy)]
struct LedgerRow<'a> {
    source: EuProfileSource,
    identifier: &'a str,
    disposition: &'a str,
    enforcement: &'a str,
}

fn parse_ledger_row(line: &'static str) -> Result<LedgerRow<'static>> {
    let mut columns = line.split('\t');
    let source = parse_source(next_column(&mut columns)?)?;
    let identifier = next_column(&mut columns)?;
    let disposition = next_column(&mut columns)?;
    let enforcement = next_column(&mut columns)?;
    if columns.next().is_some()
        || line.split('\t').count() != EU_LEDGER_COLUMN_COUNT
        || enforcement.is_empty()
        || enforcement.trim() != enforcement
        || enforcement.chars().any(char::is_control)
    {
        return Err(ConformanceError::InvalidNormativeRequirementRegistry);
    }
    validate_lookup_identifier(identifier)?;
    Ok(LedgerRow {
        source,
        identifier,
        disposition,
        enforcement,
    })
}

fn next_column<'a>(columns: &mut impl Iterator<Item = &'a str>) -> Result<&'a str> {
    columns
        .next()
        .ok_or(ConformanceError::InvalidNormativeRequirementRegistry)
}

fn parse_source(source: &str) -> Result<EuProfileSource> {
    match source {
        "CIR-2024-2977" => Ok(EuProfileSource::Cir2024_2977),
        "CIR-2024-2979" => Ok(EuProfileSource::Cir2024_2979),
        "CIR-2024-2982" => Ok(EuProfileSource::Cir2024_2982),
        "ETSI-119-472-1-EU" => Ok(EuProfileSource::Etsi119472Part1Eu),
        "ETSI-119-472-2-EU" => Ok(EuProfileSource::Etsi119472Part2Eu),
        "ETSI-119-472-3-EU" => Ok(EuProfileSource::Etsi119472Part3Eu),
        _ => Err(ConformanceError::InvalidNormativeRequirementRegistry),
    }
}

fn find_ledger_row(source: EuProfileSource, identifier: &str) -> Result<LedgerRow<'static>> {
    let mut match_found = None;
    for line in EU_PROFILE_LEDGER
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let row = parse_ledger_row(line)?;
        if row.source != source || row.identifier != identifier {
            continue;
        }
        if match_found.is_some() {
            return Err(ConformanceError::InvalidNormativeRequirementRegistry);
        }
        match_found = Some(row);
    }
    match_found.ok_or(ConformanceError::UnknownNormativeRequirement)
}

fn ledger_disposition(value: &str) -> Result<RequirementDisposition> {
    match value {
        "direct" => Ok(RequirementDisposition::CodeAndComposedEvidence),
        "composed" => Ok(RequirementDisposition::ExternalEvidenceRequired),
        "void" => Ok(RequirementDisposition::NotApplicable),
        _ => Err(ConformanceError::InvalidNormativeRequirementRegistry),
    }
}

fn validate_trace_shape(
    disposition: RequirementDisposition,
    columns: &super::parse::TraceColumns<'_>,
) -> Result<()> {
    let valid = match disposition {
        RequirementDisposition::CodeAndComposedEvidence => {
            columns.code_path != "-"
                && columns.code_symbol != "-"
                && columns.test_path != "-"
                && columns.test_symbol != "-"
        }
        RequirementDisposition::ExternalEvidenceRequired => {
            columns.code_path == "-"
                && columns.code_symbol == "-"
                && columns.test_path == "-"
                && columns.test_symbol == "-"
                && columns.external_evidence != "-"
        }
        RequirementDisposition::NotApplicable => {
            columns.applicability.starts_with("not_applicable")
                && columns.code_path == "-"
                && columns.code_symbol == "-"
                && columns.test_path == "-"
                && columns.test_symbol == "-"
                && columns.external_evidence == "-"
        }
    };
    if valid && columns.justification != "-" {
        Ok(())
    } else {
        Err(ConformanceError::InvalidNormativeRequirementRegistry)
    }
}

fn increment_source(
    summary: &mut EuProfileRequirementSummary,
    source: EuProfileSource,
) -> Result<()> {
    let count = match source {
        EuProfileSource::Cir2024_2977 => &mut summary.cir_2024_2977,
        EuProfileSource::Cir2024_2979 => &mut summary.cir_2024_2979,
        EuProfileSource::Cir2024_2982 => &mut summary.cir_2024_2982,
        EuProfileSource::Etsi119472Part1Eu => &mut summary.etsi_part1_eu,
        EuProfileSource::Etsi119472Part2Eu => &mut summary.etsi_part2_eu,
        EuProfileSource::Etsi119472Part3Eu => &mut summary.etsi_part3_eu,
    };
    *count = checked_increment(*count)?;
    Ok(())
}

fn increment_disposition(summary: &mut EuProfileRequirementSummary, value: &str) -> Result<()> {
    let count = match value {
        "direct" => &mut summary.direct,
        "composed" => &mut summary.composed,
        "void" => &mut summary.void,
        _ => return Err(ConformanceError::InvalidNormativeRequirementRegistry),
    };
    *count = checked_increment(*count)?;
    Ok(())
}

fn checked_increment(value: u16) -> Result<u16> {
    value
        .checked_add(1)
        .ok_or(ConformanceError::InvalidNormativeRequirementRegistry)
}
