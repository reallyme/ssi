// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Validate a credential using complete local issuer-signature and status evidence.
pub fn validate_credential_with_evidence(
    input: &CredentialEvidenceValidationInput<'_>,
) -> CredentialValidationResult {
    let mut checks = Vec::new();

    match validate_credential_envelope(input.envelope) {
        Ok(()) => {
            checks.push(pass(CredentialCheckName::Structure, true));
            checks.push(pass(CredentialCheckName::Format, true));
            checks.push(pass(CredentialCheckName::Issuer, true));
            checks.push(pass(CredentialCheckName::SubjectBinding, true));
            checks.push(pass(CredentialCheckName::Claims, true));
        }
        Err(error) => {
            checks.push(fail_with_code(
                CredentialCheckName::Structure,
                code_from_error(&error),
            ));
            return CredentialValidationResult {
                valid: false,
                decision: CredentialDecision::Deny,
                checks,
                status: status_from_error(&error),
            };
        }
    }

    match input.subject_bundle {
        Some(bundle) => match validate_credential_with_bundle(input.envelope, bundle) {
            Ok(()) => checks.push(pass(CredentialCheckName::HolderBinding, true)),
            Err(error) => checks.push(fail_with_code(
                CredentialCheckName::HolderBinding,
                code_from_error(&error),
            )),
        },
        None if input.policy.require_holder_binding => {
            checks.push(indeterminate(CredentialCheckName::HolderBinding, true));
        }
        None => checks.push(skipped(CredentialCheckName::HolderBinding, false)),
    }

    checks.push(skipped(CredentialCheckName::KeyBinding, false));
    checks.push(skipped(CredentialCheckName::Schema, false));
    checks.push(skipped(CredentialCheckName::RequiredClaims, false));
    add_time_checks(input.envelope, input.now_unix, &mut checks);

    match verify_credential_issuer_signature(input.envelope, input.issuer_verifier) {
        Ok(()) => checks.push(pass(CredentialCheckName::Signature, true)),
        Err(error) => checks.push(fail_with_code(
            CredentialCheckName::Signature,
            code_from_error(&error),
        )),
    }

    match u64::try_from(input.now_unix) {
        Ok(now_unix) => match verify_credential_status(
            input.envelope,
            input.status_list,
            now_unix,
            input.status_verifier,
        ) {
            Ok(()) => checks.push(pass(
                CredentialCheckName::Status,
                input.policy.require_status,
            )),
            Err(error) => checks.push(fail_with_code(
                CredentialCheckName::Status,
                code_from_error(&error),
            )),
        },
        Err(_) => checks.push(CredentialCheckResult {
            name: CredentialCheckName::Status,
            outcome: CredentialCheckOutcome::Fail,
            severity: CredentialCheckSeverity::Error,
            code: CredentialCheckCode::InvalidVerificationTime,
            mandatory: input.policy.require_status,
        }),
    }

    checks.push(skipped_or_indeterminate(
        CredentialCheckName::TrustChain,
        input.policy.require_trust_chain,
    ));
    checks.push(skipped(CredentialCheckName::TrustList, false));
    checks.push(pass(CredentialCheckName::AssuranceLevel, false));
    checks.push(pass(CredentialCheckName::CredentialType, false));
    checks.push(skipped(CredentialCheckName::Audience, false));
    checks.push(skipped(CredentialCheckName::Nonce, false));
    checks.push(pass(CredentialCheckName::Algorithm, false));
    checks.push(skipped(CredentialCheckName::CertificateChain, false));
    checks.push(skipped_or_indeterminate(
        CredentialCheckName::Policy,
        input.policy.require_policy,
    ));

    let decision = decision_from_checks(&checks);
    CredentialValidationResult {
        valid: decision == CredentialDecision::Allow,
        decision,
        status: derive_status_from_checks(input.envelope, input.now_unix, &checks),
        checks,
    }
}

/// Check local credential status from validity window and envelope structure.
pub fn check_credential_status_command(
    request: CredentialCheckStatusRequest,
) -> Result<CredentialStatusResult, CredentialError> {
    check_credential_envelope_status_command(request.credential, request.verification_context)
}

/// Derive local time/status state from an already decoded credential envelope.
///
/// The operation deliberately does not fetch or verify a remote status list.
/// Callers that need authoritative revocation or suspension evidence must use
/// an explicitly supplied status-list verifier.
pub fn check_credential_envelope_status_command(
    envelope: CredentialEnvelope,
    verification_context: CredentialVerificationContext,
) -> Result<CredentialStatusResult, CredentialError> {
    let mut checks = Vec::new();
    validate_credential_envelope(&envelope)?;
    add_time_checks(&envelope, verification_context.now_unix, &mut checks);
    checks.push(skipped(CredentialCheckName::Status, false));
    Ok(CredentialStatusResult {
        status: derive_local_status(&envelope, verification_context.now_unix),
        checks,
    })
}

fn requested_checks(checks: &[CredentialCheckName]) -> Vec<CredentialCheckName> {
    let mut requested = Vec::with_capacity(checks.len());
    for check in checks {
        if !requested.contains(check) {
            requested.push(*check);
        }
    }
    requested
}

fn apply_requested_checks(
    checks: &mut Vec<CredentialCheckResult>,
    requested: &[CredentialCheckName],
) {
    if requested.is_empty() {
        return;
    }

    for check in checks.iter_mut() {
        if requested.contains(&check.name) && check.outcome == CredentialCheckOutcome::Skipped {
            check.outcome = CredentialCheckOutcome::Indeterminate;
            check.severity = CredentialCheckSeverity::Warning;
            check.mandatory = true;
        }
    }
    checks.retain(|check| requested.contains(&check.name));
}

fn complete_local_validation(
    envelope: &CredentialEnvelope,
    now_unix: i64,
    policy: CredentialValidationPolicy,
    requested_checks: &[CredentialCheckName],
    mut checks: Vec<CredentialCheckResult>,
    issuer_verifier: Option<&dyn CredentialIssuerVerifier>,
) -> CredentialValidationResult {
    checks.push(skipped(CredentialCheckName::KeyBinding, false));
    checks.push(skipped(CredentialCheckName::Schema, false));
    checks.push(skipped(CredentialCheckName::RequiredClaims, false));
    add_time_checks(envelope, now_unix, &mut checks);
    match issuer_verifier {
        Some(verifier) => match verify_credential_issuer_signature(envelope, verifier) {
            Ok(()) => checks.push(pass(CredentialCheckName::Signature, true)),
            Err(error) => checks.push(fail_with_code(
                CredentialCheckName::Signature,
                code_from_error(&error),
            )),
        },
        None => checks.push(skipped_or_indeterminate(
            CredentialCheckName::Signature,
            policy.require_signature,
        )),
    }
    checks.push(skipped_or_indeterminate(
        CredentialCheckName::Status,
        policy.require_status,
    ));
    checks.push(skipped_or_indeterminate(
        CredentialCheckName::TrustChain,
        policy.require_trust_chain,
    ));
    checks.push(skipped(CredentialCheckName::TrustList, false));
    checks.push(pass(CredentialCheckName::AssuranceLevel, false));
    checks.push(pass(CredentialCheckName::CredentialType, false));
    checks.push(skipped(CredentialCheckName::Audience, false));
    checks.push(skipped(CredentialCheckName::Nonce, false));
    checks.push(pass(CredentialCheckName::Algorithm, false));
    checks.push(skipped(CredentialCheckName::CertificateChain, false));
    checks.push(skipped_or_indeterminate(
        CredentialCheckName::Policy,
        policy.require_policy,
    ));
    apply_requested_checks(&mut checks, requested_checks);

    let decision = decision_from_checks(&checks);
    CredentialValidationResult {
        valid: decision == CredentialDecision::Allow,
        decision,
        status: derive_local_status(envelope, now_unix),
        checks,
    }
}

fn add_time_checks(
    envelope: &CredentialEnvelope,
    now_unix: i64,
    checks: &mut Vec<CredentialCheckResult>,
) {
    if now_unix < envelope.valid_from {
        checks.push(CredentialCheckResult {
            name: CredentialCheckName::NotBefore,
            outcome: CredentialCheckOutcome::Fail,
            severity: CredentialCheckSeverity::Error,
            code: CredentialCheckCode::NotYetValid,
            mandatory: true,
        });
    } else {
        checks.push(pass(CredentialCheckName::NotBefore, true));
    }

    if now_unix >= envelope.valid_until {
        checks.push(CredentialCheckResult {
            name: CredentialCheckName::Expiration,
            outcome: CredentialCheckOutcome::Fail,
            severity: CredentialCheckSeverity::Error,
            code: CredentialCheckCode::Expired,
            mandatory: true,
        });
    } else {
        checks.push(pass(CredentialCheckName::Expiration, true));
    }
}

fn derive_local_status(envelope: &CredentialEnvelope, now_unix: i64) -> CredentialStatusValue {
    if now_unix >= envelope.valid_until {
        CredentialStatusValue::Expired
    } else if now_unix < envelope.valid_from {
        CredentialStatusValue::Unknown
    } else {
        CredentialStatusValue::Valid
    }
}

fn status_from_error(error: &CredentialError) -> CredentialStatusValue {
    match error {
        CredentialError::Status(CredentialStatusReason::Revoked) => CredentialStatusValue::Revoked,
        CredentialError::Status(CredentialStatusReason::Suspended) => {
            CredentialStatusValue::Suspended
        }
        CredentialError::Status(CredentialStatusReason::Expired) => CredentialStatusValue::Expired,
        _ => CredentialStatusValue::Unknown,
    }
}

fn pass(name: CredentialCheckName, mandatory: bool) -> CredentialCheckResult {
    CredentialCheckResult {
        name,
        outcome: CredentialCheckOutcome::Pass,
        severity: CredentialCheckSeverity::Info,
        code: CredentialCheckCode::Ok,
        mandatory,
    }
}

fn fail(name: CredentialCheckName) -> CredentialCheckResult {
    fail_with_code(name, CredentialCheckCode::InvalidCredential)
}

fn fail_with_code(name: CredentialCheckName, code: CredentialCheckCode) -> CredentialCheckResult {
    CredentialCheckResult {
        name,
        outcome: CredentialCheckOutcome::Fail,
        severity: CredentialCheckSeverity::Error,
        code,
        mandatory: true,
    }
}

fn skipped(name: CredentialCheckName, mandatory: bool) -> CredentialCheckResult {
    CredentialCheckResult {
        name,
        outcome: CredentialCheckOutcome::Skipped,
        severity: CredentialCheckSeverity::Info,
        code: CredentialCheckCode::EvidenceRequired,
        mandatory,
    }
}

fn indeterminate(name: CredentialCheckName, mandatory: bool) -> CredentialCheckResult {
    CredentialCheckResult {
        name,
        outcome: CredentialCheckOutcome::Indeterminate,
        severity: CredentialCheckSeverity::Warning,
        code: CredentialCheckCode::EvidenceRequired,
        mandatory,
    }
}

fn skipped_or_indeterminate(name: CredentialCheckName, mandatory: bool) -> CredentialCheckResult {
    if mandatory {
        indeterminate(name, true)
    } else {
        skipped(name, false)
    }
}

fn decision_from_checks(checks: &[CredentialCheckResult]) -> CredentialDecision {
    let mut has_indeterminate = false;
    for check in checks {
        if !check.mandatory {
            continue;
        }
        match check.outcome {
            CredentialCheckOutcome::Fail => return CredentialDecision::Deny,
            CredentialCheckOutcome::Indeterminate | CredentialCheckOutcome::Skipped => {
                has_indeterminate = true;
            }
            CredentialCheckOutcome::Pass | CredentialCheckOutcome::NotApplicable => {}
        }
    }

    if has_indeterminate {
        CredentialDecision::Indeterminate
    } else {
        CredentialDecision::Allow
    }
}

fn derive_status_from_checks(
    envelope: &CredentialEnvelope,
    now_unix: i64,
    checks: &[CredentialCheckResult],
) -> CredentialStatusValue {
    for check in checks {
        if check.name == CredentialCheckName::Status
            && check.outcome == CredentialCheckOutcome::Fail
        {
            return match check.code {
                CredentialCheckCode::Revoked => CredentialStatusValue::Revoked,
                CredentialCheckCode::Suspended => CredentialStatusValue::Suspended,
                CredentialCheckCode::Expired => CredentialStatusValue::Expired,
                _ => CredentialStatusValue::Unknown,
            };
        }
    }
    derive_local_status(envelope, now_unix)
}

fn code_from_error(error: &CredentialError) -> CredentialCheckCode {
    match error {
        CredentialError::Signature(_) => CredentialCheckCode::InvalidSignature,
        CredentialError::Status(CredentialStatusReason::Revoked) => CredentialCheckCode::Revoked,
        CredentialError::Status(CredentialStatusReason::Suspended) => {
            CredentialCheckCode::Suspended
        }
        CredentialError::Status(CredentialStatusReason::Expired) => CredentialCheckCode::Expired,
        CredentialError::Status(_) => CredentialCheckCode::InvalidStatusEvidence,
        CredentialError::InvalidInput(crate::CredentialInvalidReason::InvalidValidityWindow) => {
            CredentialCheckCode::Expired
        }
        CredentialError::InvalidInput(_)
        | CredentialError::Claims(_)
        | CredentialError::Qeaa
        | CredentialError::Canonical(_)
        | CredentialError::Proto(_) => CredentialCheckCode::InvalidCredential,
    }
}

impl core::fmt::Debug for CredentialVerificationContext {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialVerificationContext")
            .field("now_unix", &self.now_unix)
            .field("audience", &self.audience.as_ref().map(String::len))
            .field("nonce", &self.nonce.as_ref().map(String::len))
            .finish()
    }
}

impl Zeroize for CredentialVerificationContext {
    fn zeroize(&mut self) {
        self.now_unix.zeroize();
        self.audience.zeroize();
        self.nonce.zeroize();
    }
}

impl Drop for CredentialVerificationContext {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for CredentialVerificationContext {}

impl core::fmt::Debug for CredentialValidateRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialValidateRequest")
            .field("credential", &self.credential)
            .field("subject_bundle", &self.subject_bundle.is_some())
            .field("verification_context", &self.verification_context)
            .field("policy", &self.policy)
            .field("checks", &self.checks)
            .finish()
    }
}

impl core::fmt::Debug for CredentialCheckStatusRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialCheckStatusRequest")
            .field("credential", &self.credential)
            .field("verification_context", &self.verification_context)
            .finish()
    }
}
