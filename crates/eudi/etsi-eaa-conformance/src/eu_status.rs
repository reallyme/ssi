// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use url::Url;

use crate::{ConformanceError, Result};

const MAX_STATUS_URI_BYTES: usize = 2_048;
const MAX_STATUS_IDENTIFIER_BYTES: usize = 64;
const IDENTIFIER_LIST_CONTENT_TYPE: &str = "application/identifierlist+cwt";
const STATUS_LIST_CONTENT_TYPE: &str = "application/statuslist+cwt";

/// COSE signature algorithms permitted for an EU mdoc revocation list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EuMdocStatusAlgorithm {
    /// ECDSA with NIST P-256 and SHA-256.
    Es256,
    /// ECDSA with NIST P-384 and SHA-384.
    Es384,
    /// ECDSA with NIST P-521 and SHA-512.
    Es512,
    /// ECDSA with brainpoolP256r1 and SHA-256.
    Esb256,
    /// ECDSA with brainpoolP384r1 and SHA-384.
    Esb384,
    /// ECDSA with brainpoolP512r1 and SHA-512.
    Esb512,
}

/// Authenticated correlation key carried in an mdoc MSO status reference.
pub enum MdocStatusCorrelationKey<'a> {
    /// Status-list URI and issuer-selected bit index.
    StatusList {
        /// Absolute status-list URI.
        uri: &'a str,
        /// Status-list bit index.
        index: u64,
    },
    /// Identifier-list URI and opaque credential identifier.
    IdentifierList {
        /// Absolute identifier-list URI.
        uri: &'a str,
        /// Opaque per-MSO identifier.
        identifier: &'a [u8],
    },
}

/// Decoded EU mdoc revocation-list token fields.
pub struct EuMdocStatusTokenFacts<'a> {
    /// Correlation key authenticated in the MSO.
    pub reference: MdocStatusCorrelationKey<'a>,
    /// CWT type/media type.
    pub content_type: &'a str,
    /// Numeric `exp` claim.
    pub expires_at: u64,
    /// Current verification time.
    pub verified_at: u64,
    /// Optional positive token-status-list `ttl` claim.
    pub time_to_live: Option<u64>,
    /// Permitted COSE signature algorithm.
    pub algorithm: EuMdocStatusAlgorithm,
    /// Protected COSE header carries a non-empty `x5chain`.
    pub protected_x5chain_present: bool,
    /// COSE signature and the required certificate binding verify.
    pub signature_and_certificate_binding_valid: bool,
    /// Status-list `bits` value; required to be exactly one for index lists.
    pub bits_per_status: Option<u8>,
    /// The CWT contains a `StatusList` claim.
    pub status_list_claim_present: bool,
    /// The CWT contains the identifier-list claim at key 65530.
    pub identifier_list_claim_65530_present: bool,
    /// Decoded outcomes are restricted to valid/not-valid revocation state.
    pub binary_revocation_only: bool,
    /// Revoked entries cannot return to valid state.
    pub irreversible_revocation: bool,
}

/// Cross-component capabilities required by the EU mdoc status profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EuMdocStatusCapabilities {
    /// Wallet solution implements both list mechanisms.
    pub wallet_implements_both_mechanisms: bool,
    /// PID/EAA provider can verify both mechanisms for WIA and KA.
    pub issuer_verifies_both_for_wallet_attestations: bool,
    /// Wallet provider revokes WIA and KA through one of the two mechanisms.
    pub wallet_attestations_use_profiled_revocation: bool,
    /// A relying party that checks status supports both mechanisms.
    pub relying_party_status_check_supports_both: bool,
}

/// Validate one EU mdoc status token and its non-correlation property.
///
/// `prior_references` is the issuer's already allocated MSO-reference set. The
/// current URI/index or URI/identifier pair must not repeat, so the uniqueness
/// rule is evaluated from actual keys rather than a caller-supplied boolean.
pub fn validate_eu_mdoc_status(
    facts: &EuMdocStatusTokenFacts<'_>,
    prior_references: &[MdocStatusCorrelationKey<'_>],
) -> Result<()> {
    validate_reference(&facts.reference)?;
    if prior_references
        .iter()
        .any(|prior| references_equal(prior, &facts.reference))
    {
        return Err(ConformanceError::CorrelatableMdocStatusReference);
    }
    if facts.expires_at <= facts.verified_at
        || facts.time_to_live == Some(0)
        || !facts.protected_x5chain_present
        || !facts.signature_and_certificate_binding_valid
        || !facts.binary_revocation_only
        || !facts.irreversible_revocation
    {
        return Err(ConformanceError::InvalidEuMdocStatusProfile);
    }

    match facts.reference {
        MdocStatusCorrelationKey::StatusList { .. } => {
            if facts.content_type != STATUS_LIST_CONTENT_TYPE
                || facts.bits_per_status != Some(1)
                || !facts.status_list_claim_present
                || facts.identifier_list_claim_65530_present
            {
                return Err(ConformanceError::InvalidEuMdocStatusProfile);
            }
        }
        MdocStatusCorrelationKey::IdentifierList { .. } => {
            if facts.content_type != IDENTIFIER_LIST_CONTENT_TYPE
                || facts.bits_per_status.is_some()
                || facts.status_list_claim_present
                || !facts.identifier_list_claim_65530_present
            {
                return Err(ConformanceError::InvalidEuMdocStatusProfile);
            }
        }
    }
    Ok(())
}

/// Validate system support around EU mdoc status and wallet-attestation revocation.
pub fn validate_eu_mdoc_status_capabilities(facts: EuMdocStatusCapabilities) -> Result<()> {
    if facts.wallet_implements_both_mechanisms
        && facts.issuer_verifies_both_for_wallet_attestations
        && facts.wallet_attestations_use_profiled_revocation
        && facts.relying_party_status_check_supports_both
    {
        Ok(())
    } else {
        Err(ConformanceError::InvalidEuMdocStatusProfile)
    }
}

fn validate_reference(reference: &MdocStatusCorrelationKey<'_>) -> Result<()> {
    let (uri, identifier_valid) = match reference {
        MdocStatusCorrelationKey::StatusList { uri, .. } => (*uri, true),
        MdocStatusCorrelationKey::IdentifierList { uri, identifier } => (
            *uri,
            !identifier.is_empty() && identifier.len() <= MAX_STATUS_IDENTIFIER_BYTES,
        ),
    };
    let parsed = Url::parse(uri).map_err(|_| ConformanceError::InvalidEuMdocStatusProfile)?;
    if uri.is_empty()
        || uri.len() > MAX_STATUS_URI_BYTES
        || uri.trim() != uri
        || !matches!(parsed.scheme(), "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || !identifier_valid
    {
        return Err(ConformanceError::InvalidEuMdocStatusProfile);
    }
    Ok(())
}

fn references_equal(
    left: &MdocStatusCorrelationKey<'_>,
    right: &MdocStatusCorrelationKey<'_>,
) -> bool {
    match (left, right) {
        (
            MdocStatusCorrelationKey::StatusList {
                uri: left_uri,
                index: left_index,
            },
            MdocStatusCorrelationKey::StatusList {
                uri: right_uri,
                index: right_index,
            },
        ) => left_uri == right_uri && left_index == right_index,
        (
            MdocStatusCorrelationKey::IdentifierList {
                uri: left_uri,
                identifier: left_identifier,
            },
            MdocStatusCorrelationKey::IdentifierList {
                uri: right_uri,
                identifier: right_identifier,
            },
        ) => left_uri == right_uri && left_identifier == right_identifier,
        _ => false,
    }
}
