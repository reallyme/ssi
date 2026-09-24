// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use envelopes_x509::policy::{screen_chain_policy_only_no_path_validation, X509Policy};
use envelopes_x509::{
    parse_cert_der, X509Certificate, MAX_X509_CERTIFICATE_DER_BYTES, MAX_X509_CHAIN_CERTIFICATES,
};
use reallyme_trust_core::{validate_chain_links, ChainLinkPolicy, MAX_TRUST_ROOTS};

use crate::dto::{TrustAnchorsDer, X509ChainDer};
use crate::{
    TrustApiError, TrustApiResult, TrustDecision, TrustDecisionEvidence, TrustDecisionFailure,
    TrustDecisionOutcome, TrustPolicyId, TrustPurpose,
};

fn parse_chain_der(chain: &X509ChainDer) -> Result<Vec<X509Certificate>, TrustApiError> {
    if chain.certs.is_empty() || chain.certs.len() > MAX_X509_CHAIN_CERTIFICATES {
        return Err(TrustApiError::InvalidInput);
    }

    let mut out = Vec::with_capacity(chain.certs.len());
    for c in &chain.certs {
        if c.der.is_empty() || c.der.len() > MAX_X509_CERTIFICATE_DER_BYTES {
            return Err(TrustApiError::InvalidInput);
        }
        let cert = parse_cert_der(&c.der).map_err(|_| TrustApiError::InvalidInput)?;
        out.push(cert);
    }
    Ok(out)
}

fn parse_roots_der(anchors: &TrustAnchorsDer) -> Result<Vec<X509Certificate>, TrustApiError> {
    if anchors.roots.is_empty() || anchors.roots.len() > MAX_TRUST_ROOTS {
        return Err(TrustApiError::InvalidInput);
    }

    let mut out = Vec::with_capacity(anchors.roots.len());
    for c in &anchors.roots {
        if c.der.is_empty() || c.der.len() > MAX_X509_CERTIFICATE_DER_BYTES {
            return Err(TrustApiError::InvalidInput);
        }
        let cert = parse_cert_der(&c.der).map_err(|_| TrustApiError::InvalidInput)?;
        out.push(cert);
    }
    Ok(out)
}

/// Screen a DER chain structurally without signature verification.
/// - checks leaf→issuer DN continuity + AKI/SKI (per ChainLinkPolicy)
/// - checks policy/time window via envelopes_x509 policy checks
///
/// This compatibility API can establish only that a candidate path is worth
/// sending to a cryptographic verifier. It never returns `Trusted`: RFC 5280
/// Section 6 requires signature validation to the exact configured anchor.
/// Call [`crate::evaluate_trust_api`] for a trust decision.
pub fn validate_certificate_chain_der(
    chain_der: &X509ChainDer,
    roots_der: &TrustAnchorsDer,
    now_unix: i64,
) -> TrustApiResult<TrustDecision> {
    let mut chain = parse_chain_der(chain_der)?;
    let trust_roots = parse_roots_der(roots_der)?;

    if chain.is_empty() || trust_roots.is_empty() {
        return Err(TrustApiError::InvalidInput);
    }

    let now = time::OffsetDateTime::from_unix_timestamp(now_unix)
        .map_err(|_| TrustApiError::InvalidInput)?;

    let link_policy = ChainLinkPolicy::default();
    let policy = X509Policy::default();

    chain
        .try_reserve_exact(1)
        .map_err(|_| TrustApiError::InvalidInput)?;

    for root in &trust_roots {
        // Reuse the parsed leaf/intermediate allocation across trust roots.
        // Only the candidate root changes, so cloning every DER certificate
        // for every root would multiply attacker-controlled work needlessly.
        chain.push(root.clone());
        let mut x509_chain = envelopes_x509::X509Chain { certs: chain };
        let accepted = validate_chain_links(&x509_chain, &link_policy).is_ok()
            && screen_chain_policy_only_no_path_validation(&x509_chain, now, &policy).is_ok();
        chain = core::mem::take(&mut x509_chain.certs);
        chain.pop().ok_or(TrustApiError::InvalidInput)?;

        if !accepted {
            continue;
        }

        // Structural linkage is not cryptographic closure. Returning Trusted
        // here would accept a forged child whose issuer fields reuse a trusted
        // anchor's Subject DN (CVE-2026-75522).
        return Ok(TrustDecision {
            accepted: false,
            outcome: TrustDecisionOutcome::Indeterminate,
            failures: vec![TrustDecisionFailure::SignatureIndeterminate],
            evidence: TrustDecisionEvidence {
                purpose: TrustPurpose::Generic,
                policy_id: TrustPolicyId::GenericX509V1,
                evaluated_at_unix: now_unix,
                source: None,
                trust_anchor: None,
                certificate_status: Vec::new(),
                selected_path_certificate_sha256: Vec::new(),
            },
        });
    }

    // No root worked
    Ok(TrustDecision {
        accepted: false,
        outcome: TrustDecisionOutcome::Rejected,
        failures: vec![TrustDecisionFailure::NoValidPath],
        evidence: TrustDecisionEvidence {
            purpose: TrustPurpose::Generic,
            policy_id: TrustPolicyId::GenericX509V1,
            evaluated_at_unix: now_unix,
            source: None,
            trust_anchor: None,
            certificate_status: Vec::new(),
            selected_path_certificate_sha256: Vec::new(),
        },
    })
}

/// “Just check trust anchor” (NO chain building, NO crypto):
/// returns Ok if the provided root DER is exactly one of the trust anchors.
///
/// Inputs are typed DER byte owners; transport encoding belongs to adapters.
pub fn validate_trust_anchor_der(
    root_cert_der: &[u8],
    trust_roots: &TrustAnchorsDer,
) -> TrustApiResult<()> {
    if root_cert_der.is_empty()
        || root_cert_der.len() > MAX_X509_CERTIFICATE_DER_BYTES
        || trust_roots.roots.is_empty()
        || trust_roots.roots.len() > MAX_TRUST_ROOTS
    {
        return Err(TrustApiError::InvalidInput);
    }

    for certificate in &trust_roots.roots {
        if certificate.der == root_cert_der {
            return Ok(());
        }
    }

    Err(TrustApiError::NotTrusted)
}
