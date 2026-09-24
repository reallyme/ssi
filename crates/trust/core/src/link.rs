// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use envelopes_x509::{X509Certificate, X509Chain};

use crate::{ChainLinkPolicy, ChainLinkPolicyViolation, TrustError};

/// Validate deterministic chain linkage (no crypto):
/// - issuer/subject DN continuity
/// - AKI/SKI linkage when present or required
///
/// Assumes chain ordering: leaf → intermediates → root
pub fn validate_chain_links(chain: &X509Chain, link: &ChainLinkPolicy) -> Result<(), TrustError> {
    if chain.certs.len() < 2 {
        return Err(TrustError::NoValidPath);
    }

    // Adjacent windows express each child→issuer hop without index arithmetic,
    // keeping this parser-adjacent path free of underflow and bounds panics.
    for hop in chain.certs.windows(2) {
        let child = hop.first().ok_or(TrustError::Internal)?;
        let issuer = hop.get(1).ok_or(TrustError::Internal)?;

        validate_certificate_link(child, issuer, link)?;
    }

    Ok(())
}

/// Validate one borrowed child-to-issuer link without cloning DER material.
pub fn validate_certificate_link(
    child: &X509Certificate,
    issuer: &X509Certificate,
    link: &ChainLinkPolicy,
) -> Result<(), TrustError> {
    if link.require_dn_continuity && child.issuer != issuer.subject {
        return Err(TrustError::ChainLinkPolicy(
            ChainLinkPolicyViolation::IssuerDistinguishedNameMismatch,
        ));
    }

    match (
        child.authority_key_identifier.as_ref(),
        issuer.subject_key_identifier.as_ref(),
    ) {
        (Some(aki), Some(ski)) => {
            if aki != ski {
                return Err(TrustError::ChainLinkPolicy(
                    ChainLinkPolicyViolation::AuthorityKeyIdentifierMismatch,
                ));
            }
        }

        (None, Some(_)) if link.require_aki_ski_when_present => {
            return Err(TrustError::ChainLinkPolicy(
                ChainLinkPolicyViolation::MissingAuthorityKeyIdentifier,
            ));
        }

        (Some(_), None) if link.require_aki_ski_when_present => {
            return Err(TrustError::ChainLinkPolicy(
                ChainLinkPolicyViolation::MissingSubjectKeyIdentifier,
            ));
        }

        (None, None) if link.require_aki_ski_when_present => {
            return Err(TrustError::ChainLinkPolicy(
                ChainLinkPolicyViolation::MissingKeyIdentifiers,
            ));
        }

        _ => {}
    }

    Ok(())
}
