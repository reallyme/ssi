// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Opaque receipts binding wallet attestation trust to client proof-of-possession.

use core::fmt;

use buffa::{EnumValue, MessageField};
use reallyme_crypto::sha2::digest as digest_sha2_256;
use reallyme_ssi_proto::generated::proto::identity::trust::v1 as trust_pb;
use reallyme_trust_core::{
    CertificatePosition, CertificateStatus, TrustAnchorKind, TrustDecision, TrustEvidence,
    TrustOutcome, TrustPolicyId, TrustPurpose,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::attestation_client_auth::{AttestationPopClaims, SHA_256_BYTES};
use crate::bind_attested_client_key::AttestedClientKey;
use crate::error::{OauthError, OauthResult, Reason};
use crate::jwt::CompactJwt;

mod freshness;

const MAX_ATTESTATION_PATH_CERTIFICATES: usize = 10;

/// Verified attestation-based client authentication result.
#[derive(PartialEq, Eq)]
pub struct VerifiedAttestationClientAuthentication {
    /// Validated Client Attestation PoP claims.
    pub pop_claims: AttestationPopClaims,
    verified_attestation: VerifiedClientAttestation,
    pop_jti_sha256: [u8; SHA_256_BYTES],
}

impl fmt::Debug for VerifiedAttestationClientAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedAttestationClientAuthentication([REDACTED])")
    }
}

impl Zeroize for VerifiedAttestationClientAuthentication {
    fn zeroize(&mut self) {
        self.pop_claims.zeroize();
        self.verified_attestation.zeroize();
        self.pop_jti_sha256.zeroize();
    }
}

impl Drop for VerifiedAttestationClientAuthentication {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedAttestationClientAuthentication {}

impl VerifiedAttestationClientAuthentication {
    pub(crate) fn new(
        pop_claims: AttestationPopClaims,
        verified_attestation: VerifiedClientAttestation,
        pop_jti_sha256: [u8; SHA_256_BYTES],
    ) -> Self {
        Self {
            pop_claims,
            verified_attestation,
            pop_jti_sha256,
        }
    }

    /// RFC 7638 SHA-256 thumbprint of the attested Client Instance Key.
    #[must_use]
    pub fn client_instance_key_thumbprint(&self) -> &str {
        self.verified_attestation.attested_client_key.thumbprint()
    }

    /// SHA-256 identity of the exact accepted Client Attestation compact JWT.
    #[must_use]
    pub fn client_attestation_sha256(&self) -> &[u8; SHA_256_BYTES] {
        &self.verified_attestation.client_attestation_sha256
    }

    /// SHA-256 identity of the PoP `jti`, retained without exposing the token.
    #[must_use]
    pub fn pop_jti_sha256(&self) -> &[u8; SHA_256_BYTES] {
        &self.pop_jti_sha256
    }

    /// Wallet-provider trust evidence bound to this authentication event.
    #[must_use]
    pub fn trust_evidence(&self) -> &WalletAttestationTrustEvidence {
        &self.verified_attestation.trust_evidence
    }

    /// Projects the atomic receipt into the canonical protobuf contract.
    pub fn to_proto(&self) -> OauthResult<trust_pb::WalletAttestationClientAuthenticationReceipt> {
        Ok(trust_pb::WalletAttestationClientAuthenticationReceipt {
            client_attestation_sha256: self.client_attestation_sha256().to_vec(),
            client_instance_key_jwk_thumbprint_sha256: self
                .verified_attestation
                .attested_client_key
                .thumbprint_sha256()
                .to_vec(),
            pop_jti_sha256: self.pop_jti_sha256.to_vec(),
            pop_issued_at_unix: self.pop_claims.iat,
            trust: MessageField::some(self.trust_evidence().to_proto()?),
            ..Default::default()
        })
    }
}

/// Trust evidence for the signer of one verified wallet Client Attestation.
///
/// The constructor accepts only a trusted, purpose-scoped trust decision and
/// derives the signer fingerprint and validity limit from its selected leaf.
/// This prevents protocol adapters from assembling trust evidence from
/// unrelated ambient values.
#[derive(PartialEq, Eq)]
pub struct WalletAttestationTrustEvidence {
    evidence: TrustEvidence,
    signer_spki_sha256: [u8; SHA_256_BYTES],
    anchor_certificate_sha256: [u8; SHA_256_BYTES],
    selected_path_certificate_sha256: Vec<[u8; SHA_256_BYTES]>,
    valid_until_unix: i64,
}

impl fmt::Debug for WalletAttestationTrustEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletAttestationTrustEvidence([REDACTED])")
    }
}

impl WalletAttestationTrustEvidence {
    /// Creates evidence from a successful wallet-attestation issuer decision.
    pub fn from_trust_decision(decision: &TrustDecision) -> OauthResult<Self> {
        match decision.outcome {
            TrustOutcome::Rejected => {
                return Err(OauthError::new(Reason::AttestationTrustRejected));
            }
            TrustOutcome::Indeterminate => {
                return Err(OauthError::new(Reason::AttestationTrustIndeterminate));
            }
            TrustOutcome::Trusted => {}
        }
        if !decision.accepted
            || decision.evidence.purpose != TrustPurpose::WalletAttestationIssuer
            || decision.evidence.policy_id != TrustPolicyId::WalletAttestationIssuerV1
            || decision.evidence.source.is_none()
            || decision.evidence.trust_anchor.is_none()
            || decision.evidence.certificate_status.is_empty()
            || decision.evidence.certificate_status.len() > MAX_ATTESTATION_PATH_CERTIFICATES
            || !decision.failures.is_empty()
        {
            return Err(OauthError::new(Reason::InvalidAttestationReceipt));
        }
        let chain = decision
            .chain
            .as_ref()
            .ok_or(OauthError::new(Reason::InvalidAttestationReceipt))?;
        let signer = chain
            .certs
            .first()
            .ok_or(OauthError::new(Reason::InvalidAttestationReceipt))?;
        let anchor = chain
            .certs
            .last()
            .ok_or(OauthError::new(Reason::InvalidAttestationReceipt))?;
        let trust_anchor = decision
            .evidence
            .trust_anchor
            .ok_or(OauthError::new(Reason::InvalidAttestationReceipt))?;
        let path_shape_is_valid = match trust_anchor.kind {
            TrustAnchorKind::RootCertificate => chain.certs.len() >= 2,
            TrustAnchorKind::DirectEndEntity => chain.certs.len() == 1,
        };
        if chain.certs.len() > MAX_ATTESTATION_PATH_CERTIFICATES
            || chain.certs.iter().any(|certificate| {
                certificate.der.is_empty()
                    || certificate.not_before > decision.evidence.evaluated_at
                    || certificate.not_after < decision.evidence.evaluated_at
            })
            || signer.spki_der.is_empty()
        {
            return Err(OauthError::new(Reason::InvalidAttestationReceipt));
        }
        if !path_shape_is_valid
            || anchor.der.is_empty()
            || decision.evidence.certificate_status.len() != chain.certs.len()
        {
            return Err(OauthError::new(Reason::InvalidAttestationReceipt));
        }
        validate_trusted_status_evidence(&decision.evidence.certificate_status, chain.certs.len())?;
        let selected_path_certificate_sha256 = chain
            .certs
            .iter()
            .map(|certificate| sha256(&certificate.der))
            .collect::<Vec<_>>();
        if selected_path_has_duplicates(&selected_path_certificate_sha256) {
            return Err(OauthError::new(Reason::InvalidAttestationReceipt));
        }
        // RFC 5280 §§6.1.3 and 6.1.4 require every certificate in the
        // selected path to be valid at the evaluation time. A reusable receipt
        // therefore expires with the earliest path certificate, not merely
        // with the target certificate whose signature authenticated the JWT.
        let mut valid_until = signer.not_after;
        for certificate in &chain.certs {
            valid_until = valid_until.min(certificate.not_after);
        }
        Ok(Self {
            evidence: decision.evidence.clone(),
            // RFC 5280 §6 requires the validated path to start at the target
            // certificate. Hashing that leaf's SPKI binds this receipt to the
            // key that the attestation signature verifier must use.
            signer_spki_sha256: sha256(&signer.spki_der),
            anchor_certificate_sha256: sha256(&anchor.der),
            selected_path_certificate_sha256,
            valid_until_unix: valid_until.unix_timestamp(),
        })
    }

    /// Purpose-scoped source, anchor, status, policy, and evaluation evidence.
    #[must_use]
    pub fn decision_evidence(&self) -> &TrustEvidence {
        &self.evidence
    }

    /// SHA-256 identity of the verified attestation signer's SPKI.
    #[must_use]
    pub fn signer_spki_sha256(&self) -> &[u8; SHA_256_BYTES] {
        &self.signer_spki_sha256
    }

    /// SHA-256 identity of the exact configured anchor certificate.
    #[must_use]
    pub fn anchor_certificate_sha256(&self) -> &[u8; SHA_256_BYTES] {
        &self.anchor_certificate_sha256
    }

    /// SHA-256 identities of the selected leaf-to-anchor certificate path.
    #[must_use]
    pub fn selected_path_certificate_sha256(&self) -> &[[u8; SHA_256_BYTES]] {
        &self.selected_path_certificate_sha256
    }

    /// Last Unix second at which the signer certificate can support the receipt.
    #[must_use]
    pub const fn valid_until_unix(&self) -> i64 {
        self.valid_until_unix
    }

    fn to_proto(&self) -> OauthResult<trust_pb::WalletAttestationTrustEvidence> {
        let source = self
            .evidence
            .source
            .ok_or(OauthError::new(Reason::InvalidAttestationReceipt))?;
        let anchor = self
            .evidence
            .trust_anchor
            .ok_or(OauthError::new(Reason::InvalidAttestationReceipt))?;
        let trust_anchor_kind = match anchor.kind {
            TrustAnchorKind::RootCertificate => {
                trust_pb::TrustAnchorKind::TRUST_ANCHOR_KIND_ROOT_CERTIFICATE
            }
            TrustAnchorKind::DirectEndEntity => {
                trust_pb::TrustAnchorKind::TRUST_ANCHOR_KIND_DIRECT_END_ENTITY
            }
        };
        let certificate_status = self
            .evidence
            .certificate_status
            .iter()
            .map(|item| {
                let (position, intermediate_index) = match item.position {
                    CertificatePosition::Leaf => {
                        (trust_pb::CertificatePosition::CERTIFICATE_POSITION_LEAF, 0)
                    }
                    CertificatePosition::Intermediate(index) => (
                        trust_pb::CertificatePosition::CERTIFICATE_POSITION_INTERMEDIATE,
                        u32::from(index),
                    ),
                    CertificatePosition::TrustAnchor => (
                        trust_pb::CertificatePosition::CERTIFICATE_POSITION_TRUST_ANCHOR,
                        0,
                    ),
                };
                trust_pb::CertificateStatusEvidence {
                    position: EnumValue::from(position),
                    intermediate_index,
                    status: EnumValue::from(certificate_status_to_proto(item.status)),
                    ..Default::default()
                }
            })
            .collect();
        Ok(trust_pb::WalletAttestationTrustEvidence {
            purpose: EnumValue::from(
                trust_pb::TrustPurpose::TRUST_PURPOSE_WALLET_ATTESTATION_ISSUER,
            ),
            policy_id: EnumValue::from(
                trust_pb::TrustPolicyId::TRUST_POLICY_ID_WALLET_ATTESTATION_ISSUER_V1,
            ),
            evaluated_at_unix: self.evidence.evaluated_at.unix_timestamp(),
            valid_until_unix: self.valid_until_unix,
            signer_spki_sha256: self.signer_spki_sha256.to_vec(),
            source_id: source.source_id.to_vec(),
            snapshot_id: source.snapshot_id.to_vec(),
            trust_anchor: MessageField::some(trust_pb::TrustAnchorEvidence {
                kind: EnumValue::from(trust_anchor_kind),
                configured_index: u32::from(anchor.configured_index),
                ..Default::default()
            }),
            certificate_status,
            anchor_certificate_sha256: self.anchor_certificate_sha256.to_vec(),
            selected_path_certificate_sha256: self
                .selected_path_certificate_sha256
                .iter()
                .map(|fingerprint| fingerprint.to_vec())
                .collect(),
            ..Default::default()
        })
    }
}

fn selected_path_has_duplicates(path: &[[u8; SHA_256_BYTES]]) -> bool {
    path.iter().enumerate().any(|(index, fingerprint)| {
        index
            .checked_add(1)
            .and_then(|next| path.get(next..))
            .is_none_or(|remaining| remaining.contains(fingerprint))
    })
}

fn validate_trusted_status_evidence(
    statuses: &[reallyme_trust_core::CertificateStatusEvidence],
    path_len: usize,
) -> OauthResult<()> {
    let trust_anchor_index = path_len
        .checked_sub(1)
        .ok_or(OauthError::new(Reason::InvalidAttestationReceipt))?;
    for (index, status) in statuses.iter().enumerate() {
        let expected_position = if index == 0 {
            CertificatePosition::Leaf
        } else if index == trust_anchor_index {
            CertificatePosition::TrustAnchor
        } else {
            let intermediate_index = index
                .checked_sub(1)
                .and_then(|value| u8::try_from(value).ok())
                .ok_or(OauthError::new(Reason::InvalidAttestationReceipt))?;
            CertificatePosition::Intermediate(intermediate_index)
        };
        if status.position != expected_position
            || !matches!(
                status.status,
                CertificateStatus::Good | CertificateStatus::Exempt
            )
        {
            return Err(OauthError::new(Reason::InvalidAttestationReceipt));
        }
    }
    Ok(())
}

fn certificate_status_to_proto(status: CertificateStatus) -> trust_pb::CertificateStatus {
    match status {
        CertificateStatus::Good => trust_pb::CertificateStatus::CERTIFICATE_STATUS_GOOD,
        CertificateStatus::Revoked => trust_pb::CertificateStatus::CERTIFICATE_STATUS_REVOKED,
        CertificateStatus::Suspended => trust_pb::CertificateStatus::CERTIFICATE_STATUS_SUSPENDED,
        CertificateStatus::Unknown => trust_pb::CertificateStatus::CERTIFICATE_STATUS_UNKNOWN,
        CertificateStatus::Unavailable => {
            trust_pb::CertificateStatus::CERTIFICATE_STATUS_UNAVAILABLE
        }
        CertificateStatus::Stale => trust_pb::CertificateStatus::CERTIFICATE_STATUS_STALE,
        CertificateStatus::NotYetValid => {
            trust_pb::CertificateStatus::CERTIFICATE_STATUS_NOT_YET_VALID
        }
        CertificateStatus::Malformed => trust_pb::CertificateStatus::CERTIFICATE_STATUS_MALFORMED,
        CertificateStatus::InvalidSignature => {
            trust_pb::CertificateStatus::CERTIFICATE_STATUS_INVALID_SIGNATURE
        }
        CertificateStatus::Unsupported => {
            trust_pb::CertificateStatus::CERTIFICATE_STATUS_UNSUPPORTED
        }
        CertificateStatus::Exempt => trust_pb::CertificateStatus::CERTIFICATE_STATUS_EXEMPT,
    }
}

impl Zeroize for WalletAttestationTrustEvidence {
    fn zeroize(&mut self) {
        self.signer_spki_sha256.zeroize();
        self.anchor_certificate_sha256.zeroize();
        self.selected_path_certificate_sha256.zeroize();
        if let Some(source) = &mut self.evidence.source {
            source.source_id.zeroize();
            source.snapshot_id.zeroize();
        }
        self.evidence.certificate_status.clear();
    }
}

impl Drop for WalletAttestationTrustEvidence {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for WalletAttestationTrustEvidence {}

/// Capability minted for the exact attestation accepted by a verifier.
///
/// Its private fields ensure PoP and replay hooks can only consume the key and
/// trust receipt extracted from the same compact JWT.
#[derive(PartialEq, Eq)]
pub struct VerifiedClientAttestation {
    client_attestation_sha256: [u8; SHA_256_BYTES],
    attested_client_key: AttestedClientKey,
    trust_evidence: WalletAttestationTrustEvidence,
}

impl fmt::Debug for VerifiedClientAttestation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedClientAttestation([REDACTED])")
    }
}

impl VerifiedClientAttestation {
    /// Binds a successful signer-trust decision to this exact attestation JWT.
    pub(crate) fn bind(
        client_attestation: &CompactJwt,
        trust_evidence: WalletAttestationTrustEvidence,
    ) -> OauthResult<Self> {
        let attested_client_key = AttestedClientKey::from_client_attestation(client_attestation)?;
        Ok(Self {
            client_attestation_sha256: sha256(client_attestation.as_str().as_bytes()),
            attested_client_key,
            trust_evidence,
        })
    }

    /// Public JWK permitted by the verified attestation for PoP verification.
    #[must_use]
    pub fn attested_client_key(&self) -> &AttestedClientKey {
        &self.attested_client_key
    }

    /// SHA-256 identity used to reject a receipt minted for another JWT.
    pub(crate) fn client_attestation_sha256(&self) -> &[u8; SHA_256_BYTES] {
        &self.client_attestation_sha256
    }

    /// Wallet-provider trust receipt for the attestation signer.
    #[must_use]
    pub fn trust_evidence(&self) -> &WalletAttestationTrustEvidence {
        &self.trust_evidence
    }

    pub(crate) fn validate_trust_evidence_freshness(
        &mut self,
        current_time: i64,
        max_age_seconds: i64,
    ) -> OauthResult<()> {
        self.trust_evidence
            .validate_freshness_at(current_time, max_age_seconds)
    }
}

impl Zeroize for VerifiedClientAttestation {
    fn zeroize(&mut self) {
        self.client_attestation_sha256.zeroize();
        self.attested_client_key.zeroize();
        self.trust_evidence.zeroize();
    }
}

impl Drop for VerifiedClientAttestation {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedClientAttestation {}

fn sha256(value: &[u8]) -> [u8; SHA_256_BYTES] {
    *digest_sha2_256(value).as_bytes()
}
