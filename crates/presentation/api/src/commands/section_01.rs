// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;
use identity_core_primitives::Algorithm;
use reallyme_disclosure_policy::{
    EvaluationContext, ExtractedDisclosure, QeaaContext, StatusContext, VpPolicy,
};
use reallyme_vp_core::{
    ClaimDisclosure, DisclosureMode, MdocPresentation, Presentation, PresentationBinding,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{PresentationCommandReason, VpApiError};
use crate::{validate_vp, VpVerificationOutcome};

/// Taxonomy presentation verification decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationDecision {
    /// Presentation satisfies all mandatory local checks.
    Allow,
    /// Presentation failed at least one mandatory local check.
    Deny,
    /// Local evidence is insufficient to reach a terminal decision.
    Indeterminate,
    /// Caller policy requires review.
    Review,
}

/// Presentation check outcome.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationCheckOutcome {
    /// Check passed.
    Pass,
    /// Check failed.
    Fail,
    /// Check was skipped because it was not applicable or not requested.
    Skipped,
    /// Evidence was insufficient for a terminal result.
    Indeterminate,
}

/// Presentation check severity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationCheckSeverity {
    /// Informational check.
    Info,
    /// Non-fatal warning.
    Warning,
    /// Error-level validation issue.
    Error,
    /// Fatal validation issue.
    Fatal,
}

/// Presentation verification check name from the taxonomy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationCheckName {
    /// OAuth or response-mode state binding.
    State,
    /// Nonce or challenge binding.
    Nonce,
    /// Audience binding.
    Audience,
    /// Response URI binding.
    ResponseUri,
    /// Envelope/proof signature verification.
    Signature,
    /// Origin binding.
    OriginBinding,
    /// Holder binding.
    HolderBinding,
    /// Key binding.
    KeyBinding,
    /// Disclosure extraction and required-claim checks.
    Disclosures,
    /// Credential status evidence.
    CredentialStatus,
    /// Issuer trust evidence.
    IssuerTrust,
    /// Wallet trust evidence.
    WalletTrust,
    /// Verifier policy evaluation.
    VerifierPolicy,
    /// Transaction-data binding.
    TransactionData,
    /// Age-over attestation validation.
    AgeOverAttestation,
}

/// Stable non-PII presentation check code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationCheckCode {
    /// Check completed successfully.
    Ok,
    /// Required evidence is missing.
    EvidenceRequired,
    /// Expected binding value did not match.
    BindingMismatch,
    /// Presentation proof or signature failed validation.
    InvalidProof,
    /// Disclosure facts failed policy.
    InvalidDisclosure,
    /// Credential status failed policy.
    InvalidCredentialStatus,
    /// Trust evidence failed or was absent.
    InvalidTrust,
    /// Verifier policy rejected the presentation.
    PolicyRejected,
    /// Input shape was malformed.
    InvalidInput,
}

/// One presentation check result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationCheckResult {
    /// Stable check name.
    pub name: PresentationCheckName,
    /// Check outcome.
    pub outcome: PresentationCheckOutcome,
    /// Check severity.
    pub severity: PresentationCheckSeverity,
    /// Stable non-PII code.
    pub code: PresentationCheckCode,
    /// Whether this check is mandatory for the aggregate decision.
    pub mandatory: bool,
}

/// Expected presentation binding values.
#[derive(Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationExpected {
    /// Optional response state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Optional 32-byte nonce/challenge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<[u8; 32]>,
    /// Optional 32-byte audience hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience_hash: Option<[u8; 32]>,
    /// Optional response URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_uri: Option<String>,
    /// Optional transaction-data digest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_data_hash: Option<[u8; 32]>,
}

impl core::fmt::Debug for PresentationExpected {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PresentationExpected(<redacted>)")
    }
}

impl Zeroize for PresentationExpected {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.nonce.zeroize();
        self.audience_hash.zeroize();
        self.response_uri.zeroize();
        self.transaction_data_hash.zeroize();
    }
}

impl Drop for PresentationExpected {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PresentationExpected {}

/// Verification time context.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationVerificationContext {
    /// Evaluation time as Unix seconds.
    pub evaluation_time_unix: u64,
    /// Presentation receipt time as Unix seconds.
    pub presentation_time_unix: u64,
}

/// Disclosure fact supplied by an envelope-specific verifier.
#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationDisclosureFact {
    /// Canonical claim path.
    pub claim_path: String,
    /// Disclosure mode satisfied by the presentation.
    pub mode: DisclosureMode,
}

impl core::fmt::Debug for PresentationDisclosureFact {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PresentationDisclosureFact(<redacted>)")
    }
}

impl Zeroize for PresentationDisclosureFact {
    fn zeroize(&mut self) {
        self.claim_path.zeroize();
        self.mode = DisclosureMode::Unspecified;
    }
}

impl Drop for PresentationDisclosureFact {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PresentationDisclosureFact {}

/// Status fact supplied by a credential-status verifier.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationStatusFact {
    /// Whether status was checked successfully.
    pub checked: bool,
    /// Whether the credential was revoked.
    pub revoked: bool,
    /// Whether the credential was suspended.
    pub suspended: bool,
    /// Age of status material, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_seconds: Option<u64>,
}

impl Zeroize for PresentationStatusFact {
    fn zeroize(&mut self) {
        self.checked = false;
        self.revoked = false;
        self.suspended = false;
        self.age_seconds.zeroize();
    }
}

/// QEAA fact supplied by a credential/audit verifier.
#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationQeaaFact {
    /// Whether QEAA evidence was verified.
    pub verified: bool,
    /// Validated QEAA profile identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Identity proofing rank.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_proofing_rank: Option<u32>,
}

impl core::fmt::Debug for PresentationQeaaFact {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PresentationQeaaFact(<redacted>)")
    }
}

impl Zeroize for PresentationQeaaFact {
    fn zeroize(&mut self) {
        self.verified = false;
        self.profile.zeroize();
        self.identity_proofing_rank.zeroize();
    }
}

impl Drop for PresentationQeaaFact {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PresentationQeaaFact {}

/// Already-verified facts used by the aggregate presentation verifier.
#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationVerificationFacts {
    /// Whether holder binding was verified by the protocol/envelope layer.
    pub binding_ok: bool,
    /// Whether envelope proof or signature verification succeeded.
    pub proof_verified: bool,
    /// Whether key binding was verified when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_binding_ok: Option<bool>,
    /// Whether issuer trust evidence was verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_trust_ok: Option<bool>,
    /// Whether wallet trust evidence was verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_trust_ok: Option<bool>,
    /// Whether transaction data was verified when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_data_ok: Option<bool>,
    /// Whether age-over attestation was verified when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_over_attestation_ok: Option<bool>,
    /// Whether the response `state` matched the expected state.
    ///
    /// Required whenever [`PresentationExpected::state`] is set; the verifier
    /// never infers a state binding from the expected value alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_ok: Option<bool>,
    /// Whether the response was delivered to the expected response URI.
    ///
    /// Required whenever [`PresentationExpected::response_uri`] is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_uri_ok: Option<bool>,
    /// Issuer signature algorithm.
    pub issuer_algorithm: Algorithm,
    /// Holder binding algorithm.
    pub holder_algorithm: Algorithm,
    /// Credential claimset identifier.
    pub claimset_id: String,
    /// Disclosure facts extracted by the envelope verifier.
    pub disclosures: Vec<PresentationDisclosureFact>,
    /// Optional status fact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<PresentationStatusFact>,
    /// Optional QEAA fact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qeaa: Option<PresentationQeaaFact>,
}

impl core::fmt::Debug for PresentationVerificationFacts {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PresentationVerificationFacts(<redacted>)")
    }
}

impl Zeroize for PresentationVerificationFacts {
    fn zeroize(&mut self) {
        self.binding_ok = false;
        self.proof_verified = false;
        self.key_binding_ok.zeroize();
        self.issuer_trust_ok.zeroize();
        self.wallet_trust_ok.zeroize();
        self.transaction_data_ok.zeroize();
        self.age_over_attestation_ok.zeroize();
        self.state_ok.zeroize();
        self.response_uri_ok.zeroize();
        self.issuer_algorithm = Algorithm::Ed25519;
        self.holder_algorithm = Algorithm::Ed25519;
        self.claimset_id.zeroize();
        self.disclosures.zeroize();
        self.status.zeroize();
        self.qeaa.zeroize();
    }
}

impl Drop for PresentationVerificationFacts {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PresentationVerificationFacts {}

/// Request for `presentations.request`.
#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationRequestCreateRequest {
    /// Verifier nonce/challenge.
    pub nonce: [u8; 32],
    /// Response state.
    pub state: String,
    /// Audience identifier or verifier client id.
    pub audience: String,
    /// Response URI for direct-post or callback flows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_uri: Option<String>,
    /// Requested claims.
    pub required_claims: Vec<PresentationDisclosureFact>,
    /// Expiration time as Unix seconds.
    pub expires_at_unix: u64,
    /// Human-readable purpose text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

impl core::fmt::Debug for PresentationRequestCreateRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PresentationRequestCreateRequest(<redacted>)")
    }
}

impl Zeroize for PresentationRequestCreateRequest {
    fn zeroize(&mut self) {
        self.nonce.zeroize();
        self.state.zeroize();
        self.audience.zeroize();
        self.response_uri.zeroize();
        for disclosure in &mut self.required_claims {
            disclosure.claim_path.zeroize();
            disclosure.mode = DisclosureMode::Unspecified;
        }
        self.required_claims.clear();
        self.expires_at_unix.zeroize();
        self.purpose.zeroize();
    }
}

impl Drop for PresentationRequestCreateRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PresentationRequestCreateRequest {}

/// Record returned by `presentations.request`.
#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationRequestRecord {
    /// Created request.
    pub request: PresentationRequestCreateRequest,
    /// Creation time as Unix seconds.
    pub created_at_unix: u64,
}

impl core::fmt::Debug for PresentationRequestRecord {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PresentationRequestRecord(<redacted>)")
    }
}

impl Zeroize for PresentationRequestRecord {
    fn zeroize(&mut self) {
        self.request.zeroize();
        self.created_at_unix.zeroize();
    }
}

impl Drop for PresentationRequestRecord {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PresentationRequestRecord {}
