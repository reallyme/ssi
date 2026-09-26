// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Request for `presentations.present`.
#[derive(PartialEq)]
pub struct PresentationPresentRequest {
    /// Protocol-neutral presentation payload.
    pub presentation: Presentation,
    /// Selected wallet credential identifiers.
    pub selected_credentials: Vec<String>,
    /// Selected claim disclosures.
    pub selected_claims: Vec<PresentationDisclosureFact>,
    /// Holder binding.
    pub holder_binding: PresentationBinding,
    /// Current time as Unix seconds.
    pub now_unix: u64,
}

impl core::fmt::Debug for PresentationPresentRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PresentationPresentRequest(<redacted>)")
    }
}

impl Zeroize for PresentationPresentRequest {
    fn zeroize(&mut self) {
        self.presentation.zeroize();
        self.selected_credentials.zeroize();
        zeroize_disclosure_facts(&mut self.selected_claims);
        self.holder_binding.zeroize();
        self.now_unix.zeroize();
    }
}

impl Drop for PresentationPresentRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PresentationPresentRequest {}

/// Record returned by `presentations.present`.
#[derive(PartialEq)]
pub struct PresentationRecord {
    /// Protocol-neutral presentation payload.
    pub presentation: Presentation,
    /// Selected wallet credential identifiers.
    pub selected_credentials: Vec<String>,
    /// Selected claim disclosures.
    pub selected_claims: Vec<PresentationDisclosureFact>,
    /// Holder binding used to produce the presentation.
    pub holder_binding: PresentationBinding,
}

impl core::fmt::Debug for PresentationRecord {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PresentationRecord(<redacted>)")
    }
}

impl Zeroize for PresentationRecord {
    fn zeroize(&mut self) {
        self.presentation.zeroize();
        self.selected_credentials.zeroize();
        zeroize_disclosure_facts(&mut self.selected_claims);
        self.holder_binding.zeroize();
    }
}

impl Drop for PresentationRecord {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PresentationRecord {}

/// Request for `presentations.verify`.
#[derive(PartialEq)]
pub struct PresentationVerifyRequest {
    /// Protocol-neutral presentation payload.
    pub presentation: Presentation,
    /// Expected verifier binding values.
    pub expected: PresentationExpected,
    /// Verification time context.
    pub verification_context: PresentationVerificationContext,
    /// Verifier policy.
    pub policy: VpPolicy,
    /// Already-verified envelope/protocol facts.
    pub facts: PresentationVerificationFacts,
    /// Optional requested checks.
    pub checks: Vec<PresentationCheckName>,
}

impl core::fmt::Debug for PresentationVerifyRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PresentationVerifyRequest(<redacted>)")
    }
}

impl Zeroize for PresentationVerifyRequest {
    fn zeroize(&mut self) {
        self.presentation.zeroize();
        self.expected.zeroize();
        self.verification_context.evaluation_time_unix.zeroize();
        self.verification_context.presentation_time_unix.zeroize();
        zeroize_policy(&mut self.policy);
        self.facts.zeroize();
        self.checks.clear();
    }
}

impl Drop for PresentationVerifyRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PresentationVerifyRequest {}

/// Minimal credential result nested under a presentation result.
#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationCredentialResult {
    /// Credential claimset identifier.
    pub claimset_id: String,
    /// Whether credential-level facts satisfied presentation policy.
    pub valid: bool,
}

impl core::fmt::Debug for PresentationCredentialResult {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PresentationCredentialResult(<redacted>)")
    }
}

impl Zeroize for PresentationCredentialResult {
    fn zeroize(&mut self) {
        self.claimset_id.zeroize();
        self.valid = false;
    }
}

impl Drop for PresentationCredentialResult {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PresentationCredentialResult {}

/// Audit-safe presentation command issue.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationCommandIssue {
    /// Stable issue code.
    pub code: PresentationCheckCode,
}

/// Result for `presentations.verify`.
#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationVerificationResult {
    /// Whether all mandatory checks passed.
    pub valid: bool,
    /// Aggregate decision.
    pub decision: PresentationDecision,
    /// Presentation check rows.
    pub presentation_checks: Vec<PresentationCheckResult>,
    /// Credential-level summary rows.
    pub credential_results: Vec<PresentationCredentialResult>,
    /// Disclosed claim facts.
    pub disclosed_claims: Vec<PresentationDisclosureFact>,
    /// Stable warning codes.
    pub warnings: Vec<PresentationCommandIssue>,
    /// Stable error codes.
    pub errors: Vec<PresentationCommandIssue>,
}

impl core::fmt::Debug for PresentationVerificationResult {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PresentationVerificationResult(<redacted>)")
    }
}

impl Zeroize for PresentationVerificationResult {
    fn zeroize(&mut self) {
        self.valid = false;
        self.decision = PresentationDecision::Indeterminate;
        self.presentation_checks.clear();
        self.credential_results.zeroize();
        self.disclosed_claims.zeroize();
        self.warnings.clear();
        self.errors.clear();
    }
}

impl Drop for PresentationVerificationResult {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PresentationVerificationResult {}

/// Create a local presentation request record.
pub fn create_presentation_request(
    request: PresentationRequestCreateRequest,
    now_unix: u64,
) -> Result<PresentationRequestRecord, VpApiError> {
    if is_zero_32(&request.nonce)
        || request.state.trim().is_empty()
        || request.audience.trim().is_empty()
        || request.expires_at_unix <= now_unix
    {
        return Err(VpApiError::InvalidCommand(
            PresentationCommandReason::InvalidBinding,
        ));
    }
    if let Some(response_uri) = request.response_uri.as_deref() {
        if response_uri.trim().is_empty() {
            return Err(VpApiError::InvalidCommand(
                PresentationCommandReason::MissingField,
            ));
        }
    }
    validate_disclosures(request.required_claims.as_slice())?;

    Ok(PresentationRequestRecord {
        request,
        created_at_unix: now_unix,
    })
}

/// Validate and record a protocol-neutral presentation produced by a wallet.
pub fn present(mut request: PresentationPresentRequest) -> Result<PresentationRecord, VpApiError> {
    validate_presentation_shape(&request.presentation, request.now_unix)?;
    validate_disclosures(request.selected_claims.as_slice())?;
    validate_selected_claims(
        &request.presentation,
        request.selected_claims.as_slice(),
    )?;
    if request.selected_credentials.is_empty()
        || has_duplicate_text(request.selected_credentials.as_slice())
        || is_zero_32(&request.holder_binding.nonce)
        || is_zero_32(&request.holder_binding.audience_hash)
        || request.holder_binding.expiry_unix <= request.now_unix
    {
        return Err(VpApiError::InvalidCommand(
            PresentationCommandReason::InvalidBinding,
        ));
    }

    // The request zeroizes on drop, so replace secret-bearing fields with
    // inert sentinels before transferring their ownership to the record.
    // This avoids both unsafe extraction and a transient clone of PII/proofs.
    let presentation = core::mem::replace(
        &mut request.presentation,
        Presentation::Mdoc(Box::new(MdocPresentation {
            device_response: Vec::new(),
            envelope_hash: None,
            doc_type: None,
        })),
    );
    let selected_credentials = core::mem::take(&mut request.selected_credentials);
    let selected_claims = core::mem::take(&mut request.selected_claims);
    let holder_binding = core::mem::replace(
        &mut request.holder_binding,
        PresentationBinding {
            nonce: [0_u8; 32],
            audience_hash: [0_u8; 32],
            expiry_unix: 0,
        },
    );

    Ok(PresentationRecord {
        presentation,
        selected_credentials,
        selected_claims,
        holder_binding,
    })
}

/// Verify a presentation from already-resolved envelope/protocol facts.
pub fn verify_presentation(
    mut request: PresentationVerifyRequest,
) -> PresentationVerificationResult {
    let mut checks = Vec::new();
    let mut errors = Vec::new();

    add_expected_checks(&request, &mut checks);
    checks.push(bool_check(
        PresentationCheckName::Signature,
        request.facts.proof_verified,
        PresentationCheckCode::InvalidProof,
        true,
    ));
    checks.push(bool_check(
        PresentationCheckName::HolderBinding,
        request.facts.binding_ok,
        PresentationCheckCode::BindingMismatch,
        true,
    ));
    checks.push(optional_bool_check(
        PresentationCheckName::KeyBinding,
        request.facts.key_binding_ok,
        true,
        PresentationCheckCode::BindingMismatch,
    ));
    checks.push(disclosure_check(request.facts.disclosures.as_slice()));
    checks.push(status_check(
        request.facts.status,
        request.policy.require_status,
    ));
    checks.push(optional_bool_check(
        PresentationCheckName::IssuerTrust,
        request.facts.issuer_trust_ok,
        false,
        PresentationCheckCode::InvalidTrust,
    ));
    checks.push(optional_bool_check(
        PresentationCheckName::WalletTrust,
        request.facts.wallet_trust_ok,
        false,
        PresentationCheckCode::InvalidTrust,
    ));
    checks.push(optional_bool_check(
        PresentationCheckName::TransactionData,
        request.facts.transaction_data_ok,
        request.expected.transaction_data_hash.is_some(),
        PresentationCheckCode::BindingMismatch,
    ));
    checks.push(optional_bool_check(
        PresentationCheckName::AgeOverAttestation,
        request.facts.age_over_attestation_ok,
        false,
        PresentationCheckCode::InvalidDisclosure,
    ));

    let disclosures = extracted_disclosures(request.facts.disclosures.as_slice());
    let status = request.facts.status.map(StatusContext::from);
    let qeaa_profile = request
        .facts
        .qeaa
        .as_ref()
        .and_then(|qeaa| qeaa.profile.as_deref());
    let qeaa = request.facts.qeaa.as_ref().map(|qeaa| QeaaContext {
        verified: qeaa.verified,
        profile: qeaa_profile,
        identity_proofing_rank: qeaa.identity_proofing_rank,
    });
    let ctx = EvaluationContext {
        binding_ok: request.facts.binding_ok,
        now_unix: request.verification_context.evaluation_time_unix,
        presentation: &request.presentation,
        issuer_algorithm: request.facts.issuer_algorithm,
        holder_algorithm: request.facts.holder_algorithm,
        claimset_id: request.facts.claimset_id.as_str(),
        disclosures: disclosures.as_slice(),
        status,
        qeaa,
    };
    let policy_report = validate_vp(&request.policy, &ctx);
    if policy_report.outcome == VpVerificationOutcome::Accepted {
        checks.push(pass(PresentationCheckName::VerifierPolicy, true));
    } else {
        checks.push(fail(
            PresentationCheckName::VerifierPolicy,
            PresentationCheckCode::PolicyRejected,
            true,
        ));
        errors.push(PresentationCommandIssue {
            code: PresentationCheckCode::PolicyRejected,
        });
    }

    apply_requested_checks(&mut checks, request.checks.as_slice());
    for check in &checks {
        if check.mandatory && check.outcome == PresentationCheckOutcome::Fail {
            errors.push(PresentationCommandIssue { code: check.code });
        }
    }

    let decision = decision_from_checks(checks.as_slice());
    let claimset_id = core::mem::take(&mut request.facts.claimset_id);
    let disclosed_claims = core::mem::take(&mut request.facts.disclosures);
    PresentationVerificationResult {
        valid: decision == PresentationDecision::Allow,
        decision,
        presentation_checks: checks,
        credential_results: vec![PresentationCredentialResult {
            claimset_id,
            valid: policy_report.outcome == VpVerificationOutcome::Accepted,
        }],
        disclosed_claims,
        warnings: Vec::new(),
        errors,
    }
}

impl From<PresentationStatusFact> for StatusContext {
    fn from(value: PresentationStatusFact) -> Self {
        Self {
            checked: value.checked,
            revoked: value.revoked,
            suspended: value.suspended,
            age_seconds: value.age_seconds,
        }
    }
}
