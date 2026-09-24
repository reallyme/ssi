// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_revocation_core::{StatusCheckError, StatusChecker};

use envelopes_x509::{
    policy::screen_chain_policy_only_no_path_validation, X509Certificate, X509Chain,
    MAX_X509_CHAIN_CERTIFICATES,
};

use crate::{
    validate_chain_links, CertificatePosition, CertificateStatus, CertificateStatusEvidence,
    DirectTrustEntry, SignatureVerifier, SignatureVerifyError, StatusRequirement,
    TrustAnchorEvidence, TrustAnchorKind, TrustConfig, TrustDecision, TrustError, TrustEvidence,
    TrustFailureReason, TrustOutcome, TrustResourceLimit,
};

const MAX_CANDIDATE_PATHS: usize = 64;
const MAX_PATH_SEARCH_STEPS: usize = 4_096;
/// Maximum roots accepted by the owning evaluator, independent of adapters.
pub const MAX_TRUST_ROOTS: usize = 32;
/// Maximum purpose-scoped direct end-entity entries accepted by the evaluator.
pub const MAX_DIRECT_TRUST_ENTRIES: usize = 32;

struct CandidatePath {
    chain: X509Chain,
    trust_root_index: u16,
}

struct PathSearch<'a> {
    intermediates: Vec<&'a X509Certificate>,
    root: &'a X509Certificate,
    root_index: u16,
    paths: Vec<CandidatePath>,
    work_steps: usize,
    limit_reached: bool,
}

/// Evaluate trust and return a three-state decision with audit evidence.
///
/// The first presented certificate is the leaf. Remaining certificates are an
/// unordered, attacker-controlled candidate set. Paths are built
/// deterministically and every candidate failure remains local to that path.
/// The selected leaf-to-anchor order follows the RFC 5280 §6 certification
/// path model; policy-screening and backend signature validation remain
/// separate explicit stages.
pub fn evaluate_trust_decision(
    presented: &[X509Certificate],
    cfg: &TrustConfig,
    sig_verifier: &dyn SignatureVerifier,
    status_checker: Option<&dyn StatusChecker>,
) -> Result<TrustDecision, TrustError> {
    if !cfg.evaluation.purpose_policy_is_consistent() {
        return Err(TrustError::PurposePolicyMismatch);
    }
    if presented.is_empty() || presented.len() > MAX_X509_CHAIN_CERTIFICATES {
        return Err(TrustError::NoValidPath);
    }
    if cfg.trust_roots.len() > MAX_TRUST_ROOTS {
        return Err(TrustError::ResourceLimit(
            TrustResourceLimit::TooManyTrustRoots,
        ));
    }
    if cfg.direct_trust.len() > MAX_DIRECT_TRUST_ENTRIES {
        return Err(TrustError::ResourceLimit(
            TrustResourceLimit::TooManyDirectTrustEntries,
        ));
    }

    let leaf = presented.first().ok_or(TrustError::NoValidPath)?;
    if let Some(decision) = evaluate_direct_trust(leaf, cfg, status_checker)? {
        return Ok(decision);
    }

    let (paths, path_limit_reached) = build_candidate_paths(presented, cfg)?;
    if paths.is_empty() {
        let (outcome, failure) = if path_limit_reached {
            (
                TrustOutcome::Indeterminate,
                TrustFailureReason::PathSearchLimit,
            )
        } else {
            (TrustOutcome::Rejected, TrustFailureReason::NoValidPath)
        };
        return Ok(decision(
            outcome,
            None,
            cfg,
            None,
            Vec::new(),
            vec![failure],
        ));
    }

    let mut failures = Vec::new();
    let mut saw_indeterminate = path_limit_reached;
    let mut retained_status = Vec::new();
    if path_limit_reached {
        push_failure(&mut failures, TrustFailureReason::PathSearchLimit);
    }

    for candidate in paths {
        // RFC 5280 §6 validation is anchored in trust information selected by
        // the relying party. Distinguished Names and key identifiers only
        // discover candidate issuers; they never establish trust. Recheck the
        // terminal certificate by exact DER identity so a forged certificate
        // that reuses a configured anchor's Subject DN cannot close a path
        // (CVE-2026-75522).
        if !candidate_terminates_at_configured_anchor(&candidate, cfg) {
            push_failure(&mut failures, TrustFailureReason::NoValidPath);
            continue;
        }

        if validate_chain_links(&candidate.chain, &cfg.link_policy).is_err() {
            push_failure(&mut failures, TrustFailureReason::ChainLinkPolicy);
            continue;
        }

        if screen_chain_policy_only_no_path_validation(&candidate.chain, cfg.now, &cfg.policy)
            .is_err()
        {
            push_failure(&mut failures, TrustFailureReason::Policy);
            continue;
        }

        let status = evaluate_status(&candidate.chain, cfg, status_checker)?;
        if retained_status.is_empty() || status.outcome == TrustOutcome::Indeterminate {
            retained_status.clone_from(&status.evidence);
        }
        for failure in &status.failures {
            push_failure(&mut failures, *failure);
        }
        match status.outcome {
            TrustOutcome::Trusted => {}
            TrustOutcome::Rejected => continue,
            TrustOutcome::Indeterminate => {
                saw_indeterminate = true;
                continue;
            }
        }

        match sig_verifier.verify_chain(&candidate.chain, cfg.now) {
            Ok(()) => {
                return Ok(decision(
                    TrustOutcome::Trusted,
                    Some(candidate.chain),
                    cfg,
                    Some(TrustAnchorEvidence {
                        kind: TrustAnchorKind::RootCertificate,
                        configured_index: candidate.trust_root_index,
                    }),
                    status.evidence,
                    Vec::new(),
                ));
            }
            Err(SignatureVerifyError::InvalidSignature) => {
                push_failure(&mut failures, TrustFailureReason::Signature);
            }
            Err(
                SignatureVerifyError::UnsupportedAlgorithm | SignatureVerifyError::BackendFailure,
            ) => {
                saw_indeterminate = true;
                push_failure(&mut failures, TrustFailureReason::SignatureIndeterminate);
            }
        }
    }

    if failures.is_empty() {
        failures.push(TrustFailureReason::NoValidPath);
    }
    let outcome = if saw_indeterminate {
        TrustOutcome::Indeterminate
    } else {
        TrustOutcome::Rejected
    };
    Ok(decision(
        outcome,
        None,
        cfg,
        None,
        retained_status,
        failures,
    ))
}

fn candidate_terminates_at_configured_anchor(candidate: &CandidatePath, cfg: &TrustConfig) -> bool {
    let configured = cfg.trust_roots.get(usize::from(candidate.trust_root_index));
    match (candidate.chain.certs.last(), configured) {
        (Some(terminal), Some(anchor)) => terminal.der == anchor.der,
        (None, _) | (_, None) => false,
    }
}

/// Compatibility entry point returning errors for non-trusted outcomes.
///
/// New authorization code should consume [`evaluate_trust_decision`] so an
/// unavailable verifier or status source cannot be mistaken for rejection.
pub fn evaluate_trust(
    presented: &[X509Certificate],
    cfg: &TrustConfig,
    sig_verifier: &dyn SignatureVerifier,
    status_checker: Option<&dyn StatusChecker>,
) -> Result<TrustDecision, TrustError> {
    let decision = evaluate_trust_decision(presented, cfg, sig_verifier, status_checker)?;
    match decision.outcome {
        TrustOutcome::Trusted => Ok(decision),
        TrustOutcome::Rejected => Err(legacy_rejection(&decision.failures)),
        TrustOutcome::Indeterminate => Err(TrustError::StatusFailure),
    }
}

fn legacy_rejection(failures: &[TrustFailureReason]) -> TrustError {
    if failures.contains(&TrustFailureReason::StatusRevoked) {
        TrustError::Revoked
    } else if failures.contains(&TrustFailureReason::Signature) {
        TrustError::InvalidSignature
    } else {
        TrustError::NoValidPath
    }
}

fn decision(
    outcome: TrustOutcome,
    chain: Option<X509Chain>,
    cfg: &TrustConfig,
    trust_anchor: Option<TrustAnchorEvidence>,
    certificate_status: Vec<CertificateStatusEvidence>,
    failures: Vec<TrustFailureReason>,
) -> TrustDecision {
    TrustDecision {
        outcome,
        accepted: outcome == TrustOutcome::Trusted,
        chain,
        failures,
        evidence: TrustEvidence {
            purpose: cfg.evaluation.purpose,
            policy_id: cfg.evaluation.policy_id,
            evaluated_at: cfg.now,
            source: cfg.evaluation.source,
            trust_anchor,
            certificate_status,
        },
    }
}

fn evaluate_direct_trust(
    leaf: &X509Certificate,
    cfg: &TrustConfig,
    status_checker: Option<&dyn StatusChecker>,
) -> Result<Option<TrustDecision>, TrustError> {
    for (index, entry) in cfg.direct_trust.iter().enumerate() {
        if entry.certificate.der != leaf.der || !direct_entry_matches_context(entry, cfg) {
            continue;
        }

        let chain = X509Chain {
            certs: vec![leaf.clone()],
        };
        if screen_chain_policy_only_no_path_validation(&chain, cfg.now, &cfg.policy).is_err() {
            return Ok(Some(decision(
                TrustOutcome::Rejected,
                None,
                cfg,
                None,
                Vec::new(),
                vec![TrustFailureReason::Policy],
            )));
        }

        let status = evaluate_status(&chain, cfg, status_checker)?;
        let anchor_index = u16::try_from(index).map_err(|_| TrustError::Internal)?;
        return Ok(Some(decision(
            status.outcome,
            (status.outcome == TrustOutcome::Trusted).then_some(chain),
            cfg,
            Some(TrustAnchorEvidence {
                kind: TrustAnchorKind::DirectEndEntity,
                configured_index: anchor_index,
            }),
            status.evidence,
            status.failures,
        )));
    }

    Ok(None)
}

fn direct_entry_matches_context(entry: &DirectTrustEntry, cfg: &TrustConfig) -> bool {
    entry.purpose == cfg.evaluation.purpose
        && entry.policy_id == cfg.evaluation.policy_id
        && cfg.evaluation.source == Some(entry.source)
}

struct StatusEvaluation {
    outcome: TrustOutcome,
    evidence: Vec<CertificateStatusEvidence>,
    failures: Vec<TrustFailureReason>,
}

fn evaluate_status(
    chain: &X509Chain,
    cfg: &TrustConfig,
    checker: Option<&dyn StatusChecker>,
) -> Result<StatusEvaluation, TrustError> {
    let mut evidence = Vec::with_capacity(chain.certs.len());
    let mut failures = Vec::new();
    let mut outcome = TrustOutcome::Trusted;
    let now_unix = u64::try_from(cfg.now.unix_timestamp()).ok();

    for (index, cert) in chain.certs.iter().enumerate() {
        let position = certificate_position(index, chain.certs.len())?;
        let requirement = status_requirement(position, cfg);
        let status = match (requirement, checker, now_unix) {
            (StatusRequirement::Exempt, _, _) | (StatusRequirement::Optional, None, _) => {
                CertificateStatus::Exempt
            }
            (StatusRequirement::Required, None, _) => CertificateStatus::Unavailable,
            (StatusRequirement::Required | StatusRequirement::Optional, Some(_), None) => {
                push_failure(&mut failures, TrustFailureReason::InvalidEvaluationTime);
                outcome = TrustOutcome::Indeterminate;
                CertificateStatus::Unavailable
            }
            (
                StatusRequirement::Required | StatusRequirement::Optional,
                Some(status_checker),
                Some(timestamp),
            ) => match status_checker.check(cert, timestamp) {
                Ok(()) => CertificateStatus::Good,
                Err(error) => {
                    let (mapped_status, mapped_failure, mapped_outcome) = map_status_error(error);
                    push_failure(&mut failures, mapped_failure);
                    outcome = combine_outcome(outcome, mapped_outcome);
                    mapped_status
                }
            },
        };

        if requirement == StatusRequirement::Required && checker.is_none() {
            push_failure(&mut failures, TrustFailureReason::StatusUnavailable);
            outcome = TrustOutcome::Indeterminate;
        }
        evidence.push(CertificateStatusEvidence { position, status });
    }

    Ok(StatusEvaluation {
        outcome,
        evidence,
        failures,
    })
}

fn certificate_position(index: usize, chain_len: usize) -> Result<CertificatePosition, TrustError> {
    if index == 0 {
        return Ok(CertificatePosition::Leaf);
    }
    if chain_len > 1 && index == chain_len - 1 {
        return Ok(CertificatePosition::TrustAnchor);
    }
    let intermediate_offset = index.checked_sub(1).ok_or(TrustError::Internal)?;
    let intermediate = u8::try_from(intermediate_offset).map_err(|_| TrustError::Internal)?;
    Ok(CertificatePosition::Intermediate(intermediate))
}

fn status_requirement(position: CertificatePosition, cfg: &TrustConfig) -> StatusRequirement {
    match position {
        CertificatePosition::Leaf => cfg.evaluation.status_policy.leaf,
        CertificatePosition::Intermediate(_) => cfg.evaluation.status_policy.intermediates,
        CertificatePosition::TrustAnchor => cfg.evaluation.status_policy.trust_anchor,
    }
}

fn map_status_error(
    error: StatusCheckError,
) -> (CertificateStatus, TrustFailureReason, TrustOutcome) {
    match error {
        StatusCheckError::Revoked => (
            CertificateStatus::Revoked,
            TrustFailureReason::StatusRevoked,
            TrustOutcome::Rejected,
        ),
        StatusCheckError::Suspended => (
            CertificateStatus::Suspended,
            TrustFailureReason::StatusSuspended,
            TrustOutcome::Rejected,
        ),
        StatusCheckError::Expired => (
            CertificateStatus::Stale,
            TrustFailureReason::StatusStale,
            TrustOutcome::Indeterminate,
        ),
        StatusCheckError::NotYetValid => (
            CertificateStatus::NotYetValid,
            TrustFailureReason::StatusNotYetValid,
            TrustOutcome::Indeterminate,
        ),
        StatusCheckError::InvalidIndex | StatusCheckError::InvalidList => (
            CertificateStatus::Malformed,
            TrustFailureReason::StatusMalformed,
            TrustOutcome::Indeterminate,
        ),
        StatusCheckError::InvalidSignature => (
            CertificateStatus::InvalidSignature,
            TrustFailureReason::StatusInvalidSignature,
            TrustOutcome::Indeterminate,
        ),
        StatusCheckError::Unavailable => (
            CertificateStatus::Unavailable,
            TrustFailureReason::StatusUnavailable,
            TrustOutcome::Indeterminate,
        ),
        StatusCheckError::Unknown => (
            CertificateStatus::Unknown,
            TrustFailureReason::StatusUnknown,
            TrustOutcome::Indeterminate,
        ),
        StatusCheckError::Unsupported => (
            CertificateStatus::Unsupported,
            TrustFailureReason::StatusUnsupported,
            TrustOutcome::Indeterminate,
        ),
    }
}

fn combine_outcome(current: TrustOutcome, next: TrustOutcome) -> TrustOutcome {
    match (current, next) {
        // A definitive revoked/suspended result rejects this candidate path
        // even if another position's responder was unavailable. Indeterminate
        // remains dominant only when no conclusive rejection exists.
        (TrustOutcome::Rejected, _) | (_, TrustOutcome::Rejected) => TrustOutcome::Rejected,
        (TrustOutcome::Indeterminate, _) | (_, TrustOutcome::Indeterminate) => {
            TrustOutcome::Indeterminate
        }
        _ => TrustOutcome::Trusted,
    }
}

include!("evaluate/build_paths.rs");
