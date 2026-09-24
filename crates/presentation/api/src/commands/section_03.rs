// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn add_expected_checks(
    request: &PresentationVerifyRequest,
    checks: &mut Vec<PresentationCheckResult>,
) {
    checks.push(optional_presence_check(
        PresentationCheckName::State,
        request
            .expected
            .state
            .as_ref()
            .map(|value| !value.trim().is_empty()),
        false,
        PresentationCheckCode::BindingMismatch,
    ));
    checks.push(expected_nonce_check(
        &request.presentation,
        request.expected.nonce,
    ));
    checks.push(expected_audience_check(
        &request.presentation,
        request.expected.audience_hash,
    ));
    checks.push(optional_presence_check(
        PresentationCheckName::ResponseUri,
        request
            .expected
            .response_uri
            .as_ref()
            .map(|value| !value.trim().is_empty()),
        false,
        PresentationCheckCode::BindingMismatch,
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

fn validate_disclosures(disclosures: &[PresentationDisclosureFact]) -> Result<(), VpApiError> {
    for (index, disclosure) in disclosures.iter().enumerate() {
        if disclosure.claim_path.trim().is_empty()
            || matches!(
                disclosure.mode,
                DisclosureMode::Unspecified | DisclosureMode::Hidden
            )
            || index
                .checked_add(1)
                .and_then(|start| disclosures.get(start..))
                .is_some_and(|remaining| {
                    remaining
                        .iter()
                        .any(|other| other.claim_path == disclosure.claim_path)
                })
        {
            return Err(VpApiError::InvalidCommand(
                PresentationCommandReason::InvalidDisclosure,
            ));
        }
    }
    Ok(())
}

fn has_duplicate_text(values: &[String]) -> bool {
    values.iter().enumerate().any(|(index, value)| {
        index
            .checked_add(1)
            .and_then(|start| values.get(start..))
            .is_some_and(|remaining| remaining.iter().any(|other| other == value))
    })
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

fn optional_presence_check(
    name: PresentationCheckName,
    value: Option<bool>,
    mandatory: bool,
    code: PresentationCheckCode,
) -> PresentationCheckResult {
    optional_bool_check(name, value, mandatory, code)
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
    checks.retain(|check| requested.contains(&check.name));
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
