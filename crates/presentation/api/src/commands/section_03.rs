// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn add_expected_checks(
    request: &PresentationVerifyRequest,
    checks: &mut Vec<PresentationCheckResult>,
) {
    checks.push(expected_text_binding_check(
        PresentationCheckName::State,
        request.expected.state.as_deref(),
        request.facts.state_ok,
    ));
    checks.push(expected_nonce_check(
        &request.presentation,
        request.expected.nonce,
    ));
    checks.push(expected_audience_check(
        &request.presentation,
        request.expected.audience_hash,
    ));
    checks.push(expected_text_binding_check(
        PresentationCheckName::ResponseUri,
        request.expected.response_uri.as_deref(),
        request.facts.response_uri_ok,
    ));
    checks.push(skipped(PresentationCheckName::OriginBinding, false));
}

fn validate_presentation_shape(
    presentation: &Presentation,
    now_unix: u64,
) -> Result<(), VpApiError> {
    match presentation {
        Presentation::Zk(zk) => {
            if is_zero_32(&zk.freshness.challenge)
                || is_zero_32(&zk.freshness.audience_hash)
                || zk.freshness.expiry_unix <= now_unix
                || zk.credential.issuer_did.trim().is_empty()
                || zk.zk_proof.circuit_id.trim().is_empty()
                || zk.zk_proof.circuit_version.trim().is_empty()
                || zk.zk_proof.vk_id.trim().is_empty()
                || zk.zk_proof.proof_bytes.is_empty()
            {
                return Err(VpApiError::InvalidCommand(
                    PresentationCommandReason::InvalidPresentation,
                ));
            }
            validate_core_disclosures(zk.disclosures.as_slice())
        }
        Presentation::SdJwtVc(sd_jwt) => {
            if sd_jwt.sd_jwt.trim().is_empty() || sd_jwt.disclosures.is_empty() {
                return Err(VpApiError::InvalidCommand(
                    PresentationCommandReason::InvalidPresentation,
                ));
            }
            Ok(())
        }
        Presentation::Mdoc(mdoc) => {
            if mdoc.device_response.is_empty() {
                return Err(VpApiError::InvalidCommand(
                    PresentationCommandReason::InvalidPresentation,
                ));
            }
            Ok(())
        }
    }
}

/// Maximum disclosure facts or disclosure requests accepted by one command.
///
/// Matches the VP policy engine's disclosure ceiling so the command layer
/// never accepts more input than the evaluator it forwards to.
const MAX_PRESENTATION_DISCLOSURES: usize = 4_096;

/// Maximum credential identifiers selected in one presentation record.
const MAX_SELECTED_CREDENTIALS: usize = 256;

fn validate_disclosures(disclosures: &[PresentationDisclosureFact]) -> Result<(), VpApiError> {
    if disclosures.len() > MAX_PRESENTATION_DISCLOSURES {
        return Err(VpApiError::InvalidCommand(
            PresentationCommandReason::InvalidDisclosure,
        ));
    }
    let mut seen = BTreeSet::new();
    for disclosure in disclosures {
        if disclosure.claim_path.trim().is_empty()
            || matches!(
                disclosure.mode,
                DisclosureMode::Unspecified | DisclosureMode::Hidden
            )
            || !seen.insert(disclosure.claim_path.as_str())
        {
            return Err(VpApiError::InvalidCommand(
                PresentationCommandReason::InvalidDisclosure,
            ));
        }
    }
    Ok(())
}

fn validate_selected_claims(
    presentation: &Presentation,
    selected: &[PresentationDisclosureFact],
) -> Result<(), VpApiError> {
    if matches!(presentation, Presentation::Mdoc(_)) {
        return if selected.is_empty() {
            Ok(())
        } else {
            Err(VpApiError::InvalidCommand(
                PresentationCommandReason::InvalidDisclosure,
            ))
        };
    }

    let actual = identity_presentation_vp_policy::extract_disclosed_claims(presentation).map_err(
        |_| VpApiError::InvalidCommand(PresentationCommandReason::InvalidDisclosure),
    )?;
    if actual.len() != selected.len() {
        return Err(VpApiError::InvalidCommand(
            PresentationCommandReason::InvalidDisclosure,
        ));
    }

    for selected_claim in selected {
        let matched = actual.iter().any(|actual_claim| {
            actual_claim.claim_path == selected_claim.claim_path
                && disclosure_modes_match(selected_claim.mode, actual_claim.mode)
        });
        if !matched {
            return Err(VpApiError::InvalidCommand(
                PresentationCommandReason::InvalidDisclosure,
            ));
        }
    }
    Ok(())
}

const fn disclosure_modes_match(
    selected: DisclosureMode,
    actual: identity_credential_claims_core::DisclosureMode,
) -> bool {
    use identity_credential_claims_core::DisclosureMode as Actual;

    matches!(
        (selected, actual),
        (DisclosureMode::Unspecified, Actual::Unspecified)
            | (DisclosureMode::Hidden, Actual::Hidden)
            | (DisclosureMode::Reveal, Actual::Reveal)
            | (DisclosureMode::Eq, Actual::Eq)
            | (DisclosureMode::Gte, Actual::Gte)
            | (DisclosureMode::Lte, Actual::Lte)
            | (DisclosureMode::Range, Actual::Range)
            | (DisclosureMode::MemberOfSet, Actual::MemberOfSet)
    )
}

/// Returns true when the identifiers exceed the selection ceiling or repeat.
fn has_duplicate_text(values: &[String]) -> bool {
    if values.len() > MAX_SELECTED_CREDENTIALS {
        return true;
    }
    let mut seen = BTreeSet::new();
    values.iter().any(|value| !seen.insert(value.as_str()))
}

fn zeroize_disclosure_facts(disclosures: &mut Vec<PresentationDisclosureFact>) {
    disclosures.zeroize();
}

fn zeroize_policy(policy: &mut VpPolicy) {
    policy.allowed_issuer_algorithms.clear();
    policy.allowed_holder_algorithms.clear();
    policy.allow_sd_jwt = false;
    policy.allow_zk = false;
    policy.allow_mdoc = false;
    for claim in &mut policy.required_claims {
        claim.claim_path.zeroize();
        claim.mode = DisclosureMode::Unspecified;
    }
    policy.required_claims.clear();
    policy.allowed_claimsets.zeroize();
    policy.require_status = false;
    policy.max_status_age_seconds.zeroize();
    policy.require_qeaa = false;
    policy.min_qeaa_profile.zeroize();
    policy.min_identity_proofing_level.zeroize();
}

fn validate_core_disclosures(disclosures: &[ClaimDisclosure]) -> Result<(), VpApiError> {
    if disclosures.len() > MAX_PRESENTATION_DISCLOSURES {
        return Err(VpApiError::InvalidCommand(
            PresentationCommandReason::InvalidDisclosure,
        ));
    }
    for disclosure in disclosures {
        if disclosure.claim_path.trim().is_empty()
            || matches!(
                disclosure.mode,
                DisclosureMode::Unspecified | DisclosureMode::Hidden
            )
        {
            return Err(VpApiError::InvalidCommand(
                PresentationCommandReason::InvalidDisclosure,
            ));
        }
    }
    Ok(())
}

fn extracted_disclosures(disclosures: &[PresentationDisclosureFact]) -> Vec<ExtractedDisclosure> {
    disclosures
        .iter()
        .map(|disclosure| ExtractedDisclosure {
            claim_path: disclosure.claim_path.clone(),
            mode: disclosure.mode,
        })
        .collect()
}

fn expected_nonce_check(
    presentation: &Presentation,
    expected: Option<[u8; 32]>,
) -> PresentationCheckResult {
    let Some(expected) = expected else {
        return skipped(PresentationCheckName::Nonce, false);
    };
    match presentation {
        Presentation::Zk(zk)
            if reallyme_crypto::operations::constant_time::equal_fixed(
                &zk.freshness.challenge,
                &expected,
            ) =>
        {
            pass(PresentationCheckName::Nonce, true)
        }
        Presentation::Zk(_) => fail(
            PresentationCheckName::Nonce,
            PresentationCheckCode::BindingMismatch,
            true,
        ),
        _ => indeterminate(PresentationCheckName::Nonce, true),
    }
}

fn expected_audience_check(
    presentation: &Presentation,
    expected: Option<[u8; 32]>,
) -> PresentationCheckResult {
    let Some(expected) = expected else {
        return skipped(PresentationCheckName::Audience, false);
    };
    match presentation {
        Presentation::Zk(zk)
            if reallyme_crypto::operations::constant_time::equal_fixed(
                &zk.freshness.audience_hash,
                &expected,
            ) =>
        {
            pass(PresentationCheckName::Audience, true)
        }
        Presentation::Zk(_) => fail(
            PresentationCheckName::Audience,
            PresentationCheckCode::BindingMismatch,
            true,
        ),
        _ => indeterminate(PresentationCheckName::Audience, true),
    }
}

fn disclosure_check(disclosures: &[PresentationDisclosureFact]) -> PresentationCheckResult {
    if disclosures.is_empty() {
        indeterminate(PresentationCheckName::Disclosures, true)
    } else if disclosures.len() > MAX_PRESENTATION_DISCLOSURES {
        fail(
            PresentationCheckName::Disclosures,
            PresentationCheckCode::InvalidDisclosure,
            true,
        )
    } else {
        pass(PresentationCheckName::Disclosures, true)
    }
}

fn status_check(
    status: Option<PresentationStatusFact>,
    mandatory: bool,
) -> PresentationCheckResult {
    let Some(status) = status else {
        return skipped_or_indeterminate(PresentationCheckName::CredentialStatus, mandatory);
    };
    if status.checked && !status.revoked && !status.suspended {
        pass(PresentationCheckName::CredentialStatus, mandatory)
    } else {
        fail(
            PresentationCheckName::CredentialStatus,
            PresentationCheckCode::InvalidCredentialStatus,
            mandatory,
        )
    }
}

fn optional_bool_check(
    name: PresentationCheckName,
    value: Option<bool>,
    mandatory: bool,
    code: PresentationCheckCode,
) -> PresentationCheckResult {
    match value {
        Some(true) => pass(name, mandatory),
        Some(false) => fail(name, code, mandatory),
        None => skipped_or_indeterminate(name, mandatory),
    }
}

/// Evaluates a text binding the caller expects the response to carry.
///
/// An expected value only establishes that a comparison is required; the
/// observed comparison result must come from the protocol layer. A present
/// expectation therefore makes the check mandatory, and a missing comparison
/// result is indeterminate rather than a pass.
fn expected_text_binding_check(
    name: PresentationCheckName,
    expected: Option<&str>,
    observed_match: Option<bool>,
) -> PresentationCheckResult {
    match expected {
        None => skipped(name, false),
        Some(value) if value.trim().is_empty() => {
            fail(name, PresentationCheckCode::BindingMismatch, true)
        }
        Some(_) => optional_bool_check(
            name,
            observed_match,
            true,
            PresentationCheckCode::BindingMismatch,
        ),
    }
}

fn bool_check(
    name: PresentationCheckName,
    value: bool,
    code: PresentationCheckCode,
    mandatory: bool,
) -> PresentationCheckResult {
    if value {
        pass(name, mandatory)
    } else {
        fail(name, code, mandatory)
    }
}

fn apply_requested_checks(
    checks: &mut Vec<PresentationCheckResult>,
    requested: &[PresentationCheckName],
) {
    if requested.is_empty() {
        return;
    }
    for check in checks.iter_mut() {
        if requested.contains(&check.name) && check.outcome == PresentationCheckOutcome::Skipped {
            check.outcome = PresentationCheckOutcome::Indeterminate;
            check.severity = PresentationCheckSeverity::Warning;
            check.mandatory = true;
        }
    }
    // Requested checks narrow the report, never the decision: mandatory
    // checks always stay in the set the aggregate decision is computed from.
    checks.retain(|check| check.mandatory || requested.contains(&check.name));
}

fn decision_from_checks(checks: &[PresentationCheckResult]) -> PresentationDecision {
    let mut has_indeterminate = false;
    for check in checks {
        if !check.mandatory {
            continue;
        }
        match check.outcome {
            PresentationCheckOutcome::Fail => return PresentationDecision::Deny,
            PresentationCheckOutcome::Indeterminate | PresentationCheckOutcome::Skipped => {
                has_indeterminate = true;
            }
            PresentationCheckOutcome::Pass => {}
        }
    }

    if has_indeterminate {
        PresentationDecision::Indeterminate
    } else {
        PresentationDecision::Allow
    }
}

fn pass(name: PresentationCheckName, mandatory: bool) -> PresentationCheckResult {
    PresentationCheckResult {
        name,
        outcome: PresentationCheckOutcome::Pass,
        severity: PresentationCheckSeverity::Info,
        code: PresentationCheckCode::Ok,
        mandatory,
    }
}

fn fail(
    name: PresentationCheckName,
    code: PresentationCheckCode,
    mandatory: bool,
) -> PresentationCheckResult {
    PresentationCheckResult {
        name,
        outcome: PresentationCheckOutcome::Fail,
        severity: PresentationCheckSeverity::Error,
        code,
        mandatory,
    }
}

fn skipped(name: PresentationCheckName, mandatory: bool) -> PresentationCheckResult {
    PresentationCheckResult {
        name,
        outcome: PresentationCheckOutcome::Skipped,
        severity: PresentationCheckSeverity::Info,
        code: PresentationCheckCode::EvidenceRequired,
        mandatory,
    }
}

fn indeterminate(name: PresentationCheckName, mandatory: bool) -> PresentationCheckResult {
    PresentationCheckResult {
        name,
        outcome: PresentationCheckOutcome::Indeterminate,
        severity: PresentationCheckSeverity::Warning,
        code: PresentationCheckCode::EvidenceRequired,
        mandatory,
    }
}

fn skipped_or_indeterminate(
    name: PresentationCheckName,
    mandatory: bool,
) -> PresentationCheckResult {
    if mandatory {
        indeterminate(name, true)
    } else {
        skipped(name, false)
    }
}

fn is_zero_32(value: &[u8; 32]) -> bool {
    value.iter().all(|byte| *byte == 0)
}
