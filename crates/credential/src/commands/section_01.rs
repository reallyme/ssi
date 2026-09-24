// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    validate_credential_envelope, validate_credential_with_bundle,
    verify_credential_issuer_signature, verify_credential_status, CredentialEnvelope,
    CredentialError, CredentialIssuerVerifier, CredentialStatusReason,
};
use reallyme_credential_claims::SubjectPrivateBundle;
use reallyme_credential_status::{StatusList, StatusListVerifier};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Taxonomy validation decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialDecision {
    /// Credential satisfies all mandatory local checks.
    Allow,
    /// Credential failed at least one mandatory local check.
    Deny,
    /// Local evidence is insufficient to reach a terminal decision.
    Indeterminate,
    /// Caller policy requires review.
    Review,
}

/// Check outcome aligned with the taxonomy `CheckResult` shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialCheckOutcome {
    /// Check passed.
    Pass,
    /// Check failed.
    Fail,
    /// Check was skipped because its evidence/provider was absent.
    Skipped,
    /// Check could not produce a terminal result.
    Indeterminate,
    /// Check does not apply to the supplied credential.
    NotApplicable,
}

/// Check severity aligned with the taxonomy `CheckResult` shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialCheckSeverity {
    /// Informational check.
    Info,
    /// Non-fatal warning.
    Warning,
    /// Error-level validation issue.
    Error,
    /// Fatal validation issue.
    Fatal,
}

/// Local credential validation check name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialCheckName {
    /// DTO and envelope structure.
    Structure,
    /// Credential format support.
    Format,
    /// Issuer identifier and signature metadata shape.
    Issuer,
    /// Subject binding shape.
    SubjectBinding,
    /// Holder-private bundle binding.
    HolderBinding,
    /// Proof or presentation key binding.
    KeyBinding,
    /// Credential schema conformance.
    Schema,
    /// Claim commitment and claim bundle checks.
    Claims,
    /// Caller-required claim presence checks.
    RequiredClaims,
    /// Inclusive validity start.
    NotBefore,
    /// Exclusive validity end.
    Expiration,
    /// Status pointer and local status state.
    Status,
    /// Issuer signature verification.
    Signature,
    /// External trust evaluation.
    TrustChain,
    /// Trust-list membership evaluation.
    TrustList,
    /// Assurance-level policy evaluation.
    AssuranceLevel,
    /// Credential-type policy evaluation.
    CredentialType,
    /// Audience binding evaluation.
    Audience,
    /// Nonce or anti-replay binding evaluation.
    Nonce,
    /// Algorithm policy evaluation.
    Algorithm,
    /// Certificate-chain validation.
    CertificateChain,
    /// Caller policy evaluation.
    Policy,
}

/// Audit-safe check result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialCheckResult {
    /// Stable check name.
    pub name: CredentialCheckName,
    /// Check outcome.
    pub outcome: CredentialCheckOutcome,
    /// Check severity.
    pub severity: CredentialCheckSeverity,
    /// Stable non-PII code.
    pub code: CredentialCheckCode,
    /// Whether this check is mandatory for local validation.
    pub mandatory: bool,
}

/// Stable non-PII check code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialCheckCode {
    /// Check completed successfully.
    Ok,
    /// Credential input was malformed.
    InvalidCredential,
    /// Credential is not yet valid.
    NotYetValid,
    /// Credential is expired.
    Expired,
    /// Evidence or provider was not supplied.
    EvidenceRequired,
    /// Verification time cannot be represented by the verifier interface.
    InvalidVerificationTime,
    /// Credential issuer signature verification failed.
    InvalidSignature,
    /// Status evidence is invalid or unavailable.
    InvalidStatusEvidence,
    /// Credential is revoked.
    Revoked,
    /// Credential is suspended.
    Suspended,
}

/// Taxonomy credential status value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialStatusValue {
    /// Credential appears valid for locally available evidence.
    Valid,
    /// Credential is suspended.
    Suspended,
    /// Credential is revoked.
    Revoked,
    /// Credential is expired.
    Expired,
    /// Credential was superseded.
    Superseded,
    /// Local evidence does not determine status.
    Unknown,
}

/// SDK request for `credentials.validate`.
pub struct CredentialValidateRequest {
    /// Owned credential envelope.
    pub credential: CredentialEnvelope,
    /// Optional holder-private bundle for holder binding and claim opening checks.
    pub subject_bundle: Option<SubjectPrivateBundle>,
    /// Verification context supplied by the caller.
    pub verification_context: CredentialVerificationContext,
    /// Local policy switches for checks whose evidence is caller supplied.
    pub policy: CredentialValidationPolicy,
    /// Optional requested checks. Empty means the default aggregate check set.
    pub checks: Vec<CredentialCheckName>,
}

/// SDK verification context for `credentials.validate`.
#[derive(Default, Eq, PartialEq)]
pub struct CredentialVerificationContext {
    /// Verification time as Unix seconds.
    pub now_unix: i64,
    /// Optional audience expected by caller policy.
    pub audience: Option<String>,
    /// Optional nonce expected by caller policy.
    pub nonce: Option<String>,
}

/// Local validation policy for checks that require caller evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialValidationPolicy {
    /// Whether issuer signature verification evidence is required.
    pub require_signature: bool,
    /// Whether status evidence is required.
    pub require_status: bool,
    /// Whether a holder-private bundle must be supplied and verified.
    pub require_holder_binding: bool,
    /// Whether trust-chain evidence is required.
    pub require_trust_chain: bool,
    /// Whether caller policy evaluation is required.
    pub require_policy: bool,
}

impl Default for CredentialValidationPolicy {
    fn default() -> Self {
        Self {
            require_signature: true,
            require_status: true,
            require_holder_binding: false,
            require_trust_chain: false,
            require_policy: false,
        }
    }
}

/// SDK result for `credentials.validate`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialValidationResult {
    /// Whether all mandatory local checks passed.
    pub valid: bool,
    /// Aggregate decision.
    pub decision: CredentialDecision,
    /// Check results.
    pub checks: Vec<CredentialCheckResult>,
    /// Locally derived status value.
    pub status: CredentialStatusValue,
}

/// SDK request for `credential_state.check_status`.
pub struct CredentialCheckStatusRequest {
    /// Owned credential envelope.
    pub credential: CredentialEnvelope,
    /// Verification context supplied by the caller.
    pub verification_context: CredentialVerificationContext,
}

/// SDK result for `credential_state.check_status`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialStatusResult {
    /// Locally derived status value.
    pub status: CredentialStatusValue,
    /// Status checks used to reach the result.
    pub checks: Vec<CredentialCheckResult>,
}

/// Evidence-backed input for complete local credential validation.
pub struct CredentialEvidenceValidationInput<'a> {
    /// Credential envelope to verify.
    pub envelope: &'a CredentialEnvelope,
    /// Optional holder-private bundle for holder binding checks.
    pub subject_bundle: Option<&'a SubjectPrivateBundle>,
    /// Issuer signature verifier with already-resolved issuer key material.
    pub issuer_verifier: &'a dyn CredentialIssuerVerifier,
    /// Status list referenced by the credential envelope.
    pub status_list: &'a StatusList,
    /// Status-list signature verifier with already-resolved status-list key material.
    pub status_verifier: &'a dyn StatusListVerifier,
    /// Verification time as Unix seconds.
    pub now_unix: i64,
    /// Local policy switches.
    pub policy: CredentialValidationPolicy,
}

/// Validate a credential using local, provider-free evidence.
pub fn validate_credential_command(
    request: CredentialValidateRequest,
) -> CredentialValidationResult {
    let mut checks = Vec::new();
    let requested_checks = requested_checks(&request.checks);
    let envelope = &request.credential;
    match validate_credential_envelope(envelope) {
        Ok(()) => {
            checks.push(pass(CredentialCheckName::Structure, true));
            checks.push(pass(CredentialCheckName::Format, true));
            checks.push(pass(CredentialCheckName::Issuer, true));
            checks.push(pass(CredentialCheckName::SubjectBinding, true));
            checks.push(pass(CredentialCheckName::Claims, true));
        }
        Err(error) => {
            checks.push(fail(CredentialCheckName::Structure));
            return CredentialValidationResult {
                valid: false,
                decision: CredentialDecision::Deny,
                checks,
                status: status_from_error(&error),
            };
        }
    }

    if let Some(bundle) = request.subject_bundle.as_ref() {
        match validate_credential_with_bundle(envelope, bundle) {
            Ok(()) => checks.push(pass(CredentialCheckName::HolderBinding, true)),
            Err(error) => checks.push(fail_with_code(
                CredentialCheckName::HolderBinding,
                code_from_error(&error),
            )),
        }
    } else if request.policy.require_holder_binding {
        checks.push(indeterminate(CredentialCheckName::HolderBinding, true));
    } else {
        checks.push(skipped(CredentialCheckName::HolderBinding, false));
    }

    complete_local_validation(
        envelope,
        request.verification_context.now_unix,
        request.policy,
        &requested_checks,
        checks,
        None,
    )
}

/// Validate an already decoded credential envelope without a JSON DTO round trip.
///
/// This is the pure domain entrypoint for generated protobuf dispatch. Signature,
/// status, trust, and policy evidence remain explicit provider/evidence concerns;
/// when required but absent they produce an indeterminate result rather than an
/// ambient lookup or an optimistic success.
pub fn validate_credential_envelope_command(
    envelope: CredentialEnvelope,
    subject_bundle: Option<&SubjectPrivateBundle>,
    issuer_verifier: Option<&dyn CredentialIssuerVerifier>,
    verification_context: CredentialVerificationContext,
    policy: CredentialValidationPolicy,
    selected_checks: Vec<CredentialCheckName>,
) -> CredentialValidationResult {
    let requested_checks = requested_checks(&selected_checks);
    let mut checks = Vec::new();
    if let Err(error) = validate_credential_envelope(&envelope) {
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

    checks.push(pass(CredentialCheckName::Structure, true));
    checks.push(pass(CredentialCheckName::Format, true));
    checks.push(pass(CredentialCheckName::Issuer, true));
    checks.push(pass(CredentialCheckName::SubjectBinding, true));
    checks.push(pass(CredentialCheckName::Claims, true));
    match subject_bundle {
        Some(bundle) => match validate_credential_with_bundle(&envelope, bundle) {
            Ok(()) => checks.push(pass(CredentialCheckName::HolderBinding, true)),
            Err(error) => checks.push(fail_with_code(
                CredentialCheckName::HolderBinding,
                code_from_error(&error),
            )),
        },
        None if policy.require_holder_binding => {
            checks.push(indeterminate(CredentialCheckName::HolderBinding, true));
        }
        None => checks.push(skipped(CredentialCheckName::HolderBinding, false)),
    }

    complete_local_validation(
        &envelope,
        verification_context.now_unix,
        policy,
        &requested_checks,
        checks,
        issuer_verifier,
    )
}
