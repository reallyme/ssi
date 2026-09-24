// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;

use reallyme_etsi_eaa_conformance::{
    resolve_eu_profile_requirement, resolve_normative_requirement,
    validate_eu_profile_requirement_registry, validate_normative_requirement_registry,
    ComposedEvidenceBoundary, ConformanceError, EuProfileRequirementSummary, EuProfileSource,
    NormativeEuProfileStatus, NormativeRequirementArea, NormativeRequirementHandler,
    NormativeRequirementPart, NormativeRequirementProfile, NormativeRequirementSummary,
    RequirementDisposition,
};

#[test]
fn normative_requirement_index_is_complete_and_unique() {
    let manifest = include_str!("../../requirements/etsi-ts-119-472.tsv");
    let mut identifiers = BTreeSet::new();
    let mut counts = [0_u16; 3];

    for line in manifest.lines().filter(|line| !line.starts_with('#')) {
        let row = line.split_once('\t');
        assert!(row.is_some(), "malformed requirement index row");
        let Some((part, identifier)) = row else {
            return;
        };
        assert!(matches!(part, "1" | "2" | "3"));
        let index = if part == "1" {
            0
        } else if part == "2" {
            1
        } else {
            2
        };
        counts[index] = counts[index].saturating_add(1);
        assert!(!identifier.is_empty());
        assert!(identifiers.insert(identifier));
    }

    assert_eq!(counts, [548, 88, 104]);
    assert_eq!(identifiers.len(), 740);
}

#[test]
fn production_registry_resolves_all_740_normative_identifiers() {
    let manifest = include_str!("../../requirements/etsi-ts-119-472.tsv");
    let summary = validate_normative_requirement_registry();
    assert_eq!(
        summary,
        Ok(NormativeRequirementSummary {
            part1: 548,
            part2: 88,
            part3: 104,
            total: 740,
        })
    );

    for line in manifest.lines().filter(|line| !line.starts_with('#')) {
        let Some((part, identifier)) = line.split_once('\t') else {
            return;
        };
        let control = resolve_normative_requirement(identifier);
        assert!(control.is_ok(), "unresolved normative identifier");
        let Ok(control) = control else {
            return;
        };
        let expected_part = match part {
            "1" => NormativeRequirementPart::Part1,
            "2" => NormativeRequirementPart::Part2,
            "3" => NormativeRequirementPart::Part3,
            _ => return,
        };
        assert_eq!(control.identifier(), identifier);
        assert_eq!(control.part(), expected_part);
        assert_eq!(
            control.evidence_boundary(),
            match expected_part {
                NormativeRequirementPart::Part1 => {
                    ComposedEvidenceBoundary::CredentialVerification
                }
                NormativeRequirementPart::Part2 => {
                    ComposedEvidenceBoundary::PresentationProtocol
                }
                NormativeRequirementPart::Part3 => {
                    ComposedEvidenceBoundary::IssuanceProtocol
                }
            }
        );
    }
}

#[test]
fn production_registry_routes_representative_requirements_to_exact_handlers() {
    let cases = [
        (
            "EAA-4.2.1.2-01",
            NormativeRequirementHandler::CommonAttestation,
        ),
        (
            "EAA-5.2.1.2-01",
            NormativeRequirementHandler::SdJwtCredential,
        ),
        ("EAA-6.1-01", NormativeRequirementHandler::MdocCredential),
        ("EAA-7.1-01", NormativeRequirementHandler::JsonLdCredential),
        (
            "EAA-8.2.1.1-01",
            NormativeRequirementHandler::X509AttributeCertificate,
        ),
        (
            "OIDFVP-HAIP-COMMON-REQ-RO-01",
            NormativeRequirementHandler::OpenId4VpPresentation,
        ),
        (
            "ISO/IEC 18013-REQ-01",
            NormativeRequirementHandler::MdocPresentation,
        ),
        (
            "EAAP-SD-JWT VC-01",
            NormativeRequirementHandler::SdJwtPresentation,
        ),
        (
            "ISS-MDATA-4.2.1-01",
            NormativeRequirementHandler::IssuerMetadata,
        ),
        (
            "ISS-CRED-OFFER-4.3-01",
            NormativeRequirementHandler::CredentialOffer,
        ),
        ("NOT-REQ-4.7-01", NormativeRequirementHandler::Notification),
    ];

    for (identifier, expected_handler) in cases {
        let control = resolve_normative_requirement(identifier);
        assert!(control.is_ok());
        let Ok(control) = control else {
            return;
        };
        assert_eq!(control.handler(), expected_handler);
    }
}

#[test]
fn production_registry_rejects_unknown_and_noncanonical_identifiers() {
    assert_eq!(
        resolve_normative_requirement("EAA-DOES-NOT-EXIST"),
        Err(ConformanceError::UnknownNormativeRequirement)
    );
    assert_eq!(
        resolve_normative_requirement(" EAA-4.2.1.2-01"),
        Err(ConformanceError::InvalidNormativeRequirementIdentifier)
    );
    assert_eq!(
        resolve_normative_requirement("EAA-4.2.1.2-01\n"),
        Err(ConformanceError::InvalidNormativeRequirementIdentifier)
    );
    let oversized = "x".repeat(129);
    assert_eq!(
        resolve_normative_requirement(&oversized),
        Err(ConformanceError::InvalidNormativeRequirementIdentifier)
    );
}

#[test]
fn production_registry_preserves_typed_applicability_and_eu_status() {
    let qeaa = resolve_normative_requirement("QEAA-4.2.2.2-02");
    assert!(qeaa.is_ok());
    let Ok(qeaa) = qeaa else {
        return;
    };
    assert_eq!(
        qeaa.applicability().profile,
        NormativeRequirementProfile::Qeaa
    );
    assert_eq!(
        qeaa.applicability().area,
        NormativeRequirementArea::AllFormats
    );
    assert_eq!(
        qeaa.eu_profile_status(),
        NormativeEuProfileStatus::IncorporatedSubjectToAdaptations
    );

    let annex_a = resolve_normative_requirement("ISS-MDATA-A.2-01");
    assert!(annex_a.is_ok());
    let Ok(annex_a) = annex_a else {
        return;
    };
    assert_eq!(
        annex_a.eu_profile_status(),
        NormativeEuProfileStatus::AnnexAVoidInCurrentEuProfile
    );

    let notification = resolve_normative_requirement("NOT-REQ-4.7-01");
    assert!(notification.is_ok());
    let Ok(notification) = notification else {
        return;
    };
    assert_eq!(
        notification.eu_profile_status(),
        NormativeEuProfileStatus::ApplicableWhenNotificationIdentifierIssued
    );
}

#[test]
fn production_registry_exposes_exact_code_test_and_composed_evidence() {
    let control = resolve_normative_requirement("TOKEN-REQ-4.5.1-01");
    assert!(control.is_ok());
    let Ok(control) = control else {
        return;
    };
    let evidence = control.evidence();
    assert_eq!(evidence.source_edition(), "V1.1.1-2026-03");
    assert_eq!(
        evidence.disposition(),
        RequirementDisposition::CodeAndComposedEvidence
    );
    assert_eq!(evidence.owner_repository(), "ssi+openid4vci");
    assert_eq!(
        evidence.code_symbol(),
        "validate_issuance;PreAuthorizedTokenRequest"
    );
    assert_eq!(evidence.test_symbol(), "accepts_complete_issuance_profile");
    assert_eq!(
        evidence.external_evidence(),
        "openid4vci_wire_state_machine;issuer_service;wallet_custody;deployed_trust"
    );
}

#[test]
fn production_registry_resolves_all_229_eu_profile_rows() {
    assert_eq!(
        validate_eu_profile_requirement_registry(),
        Ok(EuProfileRequirementSummary {
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
    );

    let ledger = include_str!("../../requirements/eu-2026-profile.tsv");
    for line in ledger.lines().filter(|line| !line.starts_with('#')) {
        let columns = line.split('\t').collect::<Vec<_>>();
        let source = match columns.first().copied() {
            Some("CIR-2024-2977") => EuProfileSource::Cir2024_2977,
            Some("CIR-2024-2979") => EuProfileSource::Cir2024_2979,
            Some("CIR-2024-2982") => EuProfileSource::Cir2024_2982,
            Some("ETSI-119-472-1-EU") => EuProfileSource::Etsi119472Part1Eu,
            Some("ETSI-119-472-2-EU") => EuProfileSource::Etsi119472Part2Eu,
            Some("ETSI-119-472-3-EU") => EuProfileSource::Etsi119472Part3Eu,
            _ => return,
        };
        let Some(identifier) = columns.get(1).copied() else {
            return;
        };
        let control = resolve_eu_profile_requirement(source, identifier);
        assert!(control.is_ok(), "unresolved EU profile row");
    }
}

#[test]
fn eu_profile_registry_preserves_direct_composed_and_void_evidence() {
    let direct = resolve_eu_profile_requirement(EuProfileSource::Cir2024_2977, "ART-3.3");
    assert!(direct.is_ok());
    let Ok(direct) = direct else {
        return;
    };
    assert_eq!(
        direct.evidence().code_symbol(),
        "validate_natural_person_pid"
    );
    assert_eq!(
        direct.evidence().disposition(),
        RequirementDisposition::CodeAndComposedEvidence
    );

    let composed = resolve_eu_profile_requirement(EuProfileSource::Cir2024_2979, "ART-6.3(a)");
    assert!(composed.is_ok());
    let Ok(composed) = composed else {
        return;
    };
    assert_eq!(
        composed.evidence().disposition(),
        RequirementDisposition::ExternalEvidenceRequired
    );
    assert_eq!(
        composed.evidence().external_evidence(),
        "wallet-user rights and obligations information evidence"
    );

    let void = resolve_eu_profile_requirement(EuProfileSource::Cir2024_2979, "ART-3.2");
    assert!(void.is_ok());
    let Ok(void) = void else {
        return;
    };
    assert_eq!(
        void.evidence().disposition(),
        RequirementDisposition::NotApplicable
    );
    assert_eq!(
        void.evidence().justification(),
        "deleted by Regulation 2026/1731"
    );

    assert_eq!(
        resolve_eu_profile_requirement(EuProfileSource::Cir2024_2977, "UNKNOWN"),
        Err(ConformanceError::UnknownNormativeRequirement)
    );
}

#[test]
fn requirement_trace_maps_every_normative_and_eu_profile_row() {
    const COLUMN_COUNT: usize = 13;

    let manifest = include_str!("../../requirements/etsi-ts-119-472.tsv");
    let eu_ledger = include_str!("../../requirements/eu-2026-profile.tsv");
    let trace = include_str!("../../requirements/requirement-trace.tsv");

    let indexed = manifest
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once('\t'))
        .map(|(part, identifier)| {
            let source = match part {
                "1" => "ETSI-TS-119-472-1",
                "2" => "ETSI-TS-119-472-2",
                "3" => "ETSI-TS-119-472-3",
                _ => return ("", ""),
            };
            (source, identifier)
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(indexed.len(), 740);

    let eu_indexed = eu_ledger
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let mut columns = line.split('\t');
            Some((columns.next()?, columns.next()?))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(eu_indexed.len(), 229);

    let mut traced = BTreeSet::new();
    for line in trace.lines().filter(|line| !line.starts_with('#')) {
        let columns = line.split('\t').collect::<Vec<_>>();
        assert_eq!(columns.len(), COLUMN_COUNT, "malformed trace row");
        assert!(columns.iter().all(|column| !column.is_empty()));

        let source = columns[0];
        let identifier = columns[1];
        let applicability = columns[3];
        let disposition = columns[4];
        let code_path = columns[7];
        let code_symbol = columns[8];
        let test_path = columns[9];
        let test_symbol = columns[10];
        let external_evidence = columns[11];
        let justification = columns[12];

        assert!(traced.insert((source, identifier)));
        assert_ne!(justification, "-");
        assert!(matches!(
            disposition,
            "code_and_composed_evidence" | "external_evidence_required" | "not_applicable"
        ));
        match disposition {
            "code_and_composed_evidence" => {
                assert_ne!(code_path, "-");
                assert_ne!(code_symbol, "-");
                assert_ne!(test_path, "-");
                assert_ne!(test_symbol, "-");
            }
            "external_evidence_required" => {
                assert_eq!(code_path, "-");
                assert_eq!(code_symbol, "-");
                assert_eq!(test_path, "-");
                assert_eq!(test_symbol, "-");
                assert_ne!(external_evidence, "-");
            }
            "not_applicable" => {
                assert!(applicability.starts_with("not_applicable"));
                assert_eq!(code_path, "-");
                assert_eq!(code_symbol, "-");
                assert_eq!(test_path, "-");
                assert_eq!(test_symbol, "-");
                assert_eq!(external_evidence, "-");
            }
            _ => {}
        }
    }

    assert_eq!(traced.len(), 969);
    assert!(indexed.is_subset(&traced));
    assert!(eu_indexed.is_subset(&traced));
}

#[test]
fn eu_2026_coverage_ledger_is_closed_and_unique() {
    let ledger = include_str!("../../requirements/eu-2026-profile.tsv");
    let mut identifiers = BTreeSet::new();
    let mut rows = 0_usize;
    let mut composed = 0_usize;

    for line in ledger.lines().filter(|line| !line.starts_with('#')) {
        let mut columns = line.split('\t');
        let row = (
            columns.next(),
            columns.next(),
            columns.next(),
            columns.next(),
        );
        assert!(
            row.0.is_some() && row.1.is_some() && row.2.is_some() && row.3.is_some(),
            "malformed EU coverage row"
        );
        let (Some(source), Some(identifier), Some(disposition), Some(enforcement)) = row else {
            return;
        };
        assert!(columns.next().is_none());
        assert!(matches!(
            source,
            "CIR-2024-2977"
                | "CIR-2024-2979"
                | "CIR-2024-2982"
                | "ETSI-119-472-1-EU"
                | "ETSI-119-472-2-EU"
                | "ETSI-119-472-3-EU"
        ));
        assert!(matches!(disposition, "direct" | "composed" | "void"));
        assert!(!identifier.is_empty());
        assert!(!enforcement.is_empty());
        assert!(identifiers.insert((source, identifier)));
        rows = rows.saturating_add(1);
        if disposition == "composed" {
            composed = composed.saturating_add(1);
        }
    }

    assert!(rows >= 150);
    assert!(composed >= 10);
}
