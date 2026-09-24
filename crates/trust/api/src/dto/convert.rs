// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

impl From<TrustPolicyId> for trust_pb::TrustPolicyId {
    fn from(policy: TrustPolicyId) -> Self {
        match policy {
            TrustPolicyId::GenericX509V1 => Self::TRUST_POLICY_ID_GENERIC_X509_V1,
            TrustPolicyId::EuQeaaV1 => Self::TRUST_POLICY_ID_EU_QEAA_V1,
            TrustPolicyId::EuQwacV1 => Self::TRUST_POLICY_ID_EU_QWAC_V1,
            TrustPolicyId::EuQsealV1 => Self::TRUST_POLICY_ID_EU_QSEAL_V1,
            TrustPolicyId::EuTrustedListSignerV1 => Self::TRUST_POLICY_ID_EU_TRUSTED_LIST_SIGNER_V1,
            TrustPolicyId::WalletAttestationIssuerV1 => {
                Self::TRUST_POLICY_ID_WALLET_ATTESTATION_ISSUER_V1
            }
            TrustPolicyId::EtsiJadesBaselineBV1 => {
                Self::TRUST_POLICY_ID_ETSI_JADES_BASELINE_B_V1
            }
            TrustPolicyId::EtsiTs1194126PidProviderV1 => {
                Self::TRUST_POLICY_ID_ETSI_TS_119_412_6_PID_PROVIDER_V1
            }
            TrustPolicyId::EudiPidStatusV1 => Self::TRUST_POLICY_ID_EUDI_PID_STATUS_V1,
            TrustPolicyId::EtsiTs1194126WalletProviderV1 => {
                Self::TRUST_POLICY_ID_ETSI_TS_119_412_6_WALLET_PROVIDER_V1
            }
            TrustPolicyId::EudiWalletOrKeyStorageStatusV1 => {
                Self::TRUST_POLICY_ID_EUDI_WALLET_OR_KEY_STORAGE_STATUS_V1
            }
            TrustPolicyId::EtsiTs1194118WrpacV1 => {
                Self::TRUST_POLICY_ID_ETSI_TS_119_411_8_WRPAC_V1
            }
            TrustPolicyId::EtsiTs119475WrprcV1 => {
                Self::TRUST_POLICY_ID_ETSI_TS_119_475_WRPRC_V1
            }
            TrustPolicyId::EtsiTs119475WrprcStatusV1 => {
                Self::TRUST_POLICY_ID_ETSI_TS_119_475_WRPRC_STATUS_V1
            }
            TrustPolicyId::EudiTs5RegistryResponseSigningV1 => {
                Self::TRUST_POLICY_ID_EUDI_TS5_REGISTRY_RESPONSE_SIGNING_V1
            }
        }
    }
}

fn trust_policy_from_proto(
    value: EnumValue<trust_pb::TrustPolicyId>,
) -> Result<TrustPolicyId, TrustProtoError> {
    match trust_pb::TrustPolicyId::from_i32(value.to_i32()) {
        Some(trust_pb::TrustPolicyId::TRUST_POLICY_ID_GENERIC_X509_V1) => {
            Ok(TrustPolicyId::GenericX509V1)
        }
        Some(trust_pb::TrustPolicyId::TRUST_POLICY_ID_EU_QEAA_V1) => Ok(TrustPolicyId::EuQeaaV1),
        Some(trust_pb::TrustPolicyId::TRUST_POLICY_ID_EU_QWAC_V1) => Ok(TrustPolicyId::EuQwacV1),
        Some(trust_pb::TrustPolicyId::TRUST_POLICY_ID_EU_QSEAL_V1) => Ok(TrustPolicyId::EuQsealV1),
        Some(trust_pb::TrustPolicyId::TRUST_POLICY_ID_EU_TRUSTED_LIST_SIGNER_V1) => {
            Ok(TrustPolicyId::EuTrustedListSignerV1)
        }
        Some(trust_pb::TrustPolicyId::TRUST_POLICY_ID_WALLET_ATTESTATION_ISSUER_V1) => {
            Ok(TrustPolicyId::WalletAttestationIssuerV1)
        }
        Some(trust_pb::TrustPolicyId::TRUST_POLICY_ID_ETSI_JADES_BASELINE_B_V1) => {
            Ok(TrustPolicyId::EtsiJadesBaselineBV1)
        }
        Some(trust_pb::TrustPolicyId::TRUST_POLICY_ID_ETSI_TS_119_412_6_PID_PROVIDER_V1) => {
            Ok(TrustPolicyId::EtsiTs1194126PidProviderV1)
        }
        Some(trust_pb::TrustPolicyId::TRUST_POLICY_ID_EUDI_PID_STATUS_V1) => {
            Ok(TrustPolicyId::EudiPidStatusV1)
        }
        Some(
            trust_pb::TrustPolicyId::TRUST_POLICY_ID_ETSI_TS_119_412_6_WALLET_PROVIDER_V1,
        ) => Ok(TrustPolicyId::EtsiTs1194126WalletProviderV1),
        Some(trust_pb::TrustPolicyId::TRUST_POLICY_ID_EUDI_WALLET_OR_KEY_STORAGE_STATUS_V1) => {
            Ok(TrustPolicyId::EudiWalletOrKeyStorageStatusV1)
        }
        Some(trust_pb::TrustPolicyId::TRUST_POLICY_ID_ETSI_TS_119_411_8_WRPAC_V1) => {
            Ok(TrustPolicyId::EtsiTs1194118WrpacV1)
        }
        Some(trust_pb::TrustPolicyId::TRUST_POLICY_ID_ETSI_TS_119_475_WRPRC_V1) => {
            Ok(TrustPolicyId::EtsiTs119475WrprcV1)
        }
        Some(trust_pb::TrustPolicyId::TRUST_POLICY_ID_ETSI_TS_119_475_WRPRC_STATUS_V1) => {
            Ok(TrustPolicyId::EtsiTs119475WrprcStatusV1)
        }
        Some(trust_pb::TrustPolicyId::TRUST_POLICY_ID_EUDI_TS5_REGISTRY_RESPONSE_SIGNING_V1) => {
            Ok(TrustPolicyId::EudiTs5RegistryResponseSigningV1)
        }
        _ => Err(TrustProtoError::UnknownTrustPolicy),
    }
}

impl From<TrustAnchorKind> for trust_pb::TrustAnchorKind {
    fn from(kind: TrustAnchorKind) -> Self {
        match kind {
            TrustAnchorKind::RootCertificate => Self::TRUST_ANCHOR_KIND_ROOT_CERTIFICATE,
            TrustAnchorKind::DirectEndEntity => Self::TRUST_ANCHOR_KIND_DIRECT_END_ENTITY,
        }
    }
}

fn trust_anchor_kind_from_proto(
    value: EnumValue<trust_pb::TrustAnchorKind>,
) -> Result<TrustAnchorKind, TrustProtoError> {
    match trust_pb::TrustAnchorKind::from_i32(value.to_i32()) {
        Some(trust_pb::TrustAnchorKind::TRUST_ANCHOR_KIND_ROOT_CERTIFICATE) => {
            Ok(TrustAnchorKind::RootCertificate)
        }
        Some(trust_pb::TrustAnchorKind::TRUST_ANCHOR_KIND_DIRECT_END_ENTITY) => {
            Ok(TrustAnchorKind::DirectEndEntity)
        }
        _ => Err(TrustProtoError::UnknownTrustAnchorKind),
    }
}

impl From<CertificateStatus> for trust_pb::CertificateStatus {
    fn from(status: CertificateStatus) -> Self {
        match status {
            CertificateStatus::Good => Self::CERTIFICATE_STATUS_GOOD,
            CertificateStatus::Revoked => Self::CERTIFICATE_STATUS_REVOKED,
            CertificateStatus::Suspended => Self::CERTIFICATE_STATUS_SUSPENDED,
            CertificateStatus::Unknown => Self::CERTIFICATE_STATUS_UNKNOWN,
            CertificateStatus::Unavailable => Self::CERTIFICATE_STATUS_UNAVAILABLE,
            CertificateStatus::Stale => Self::CERTIFICATE_STATUS_STALE,
            CertificateStatus::NotYetValid => Self::CERTIFICATE_STATUS_NOT_YET_VALID,
            CertificateStatus::Malformed => Self::CERTIFICATE_STATUS_MALFORMED,
            CertificateStatus::InvalidSignature => Self::CERTIFICATE_STATUS_INVALID_SIGNATURE,
            CertificateStatus::Unsupported => Self::CERTIFICATE_STATUS_UNSUPPORTED,
            CertificateStatus::Exempt => Self::CERTIFICATE_STATUS_EXEMPT,
        }
    }
}

fn certificate_status_from_proto(
    value: EnumValue<trust_pb::CertificateStatus>,
) -> Result<CertificateStatus, TrustProtoError> {
    match trust_pb::CertificateStatus::from_i32(value.to_i32()) {
        Some(trust_pb::CertificateStatus::CERTIFICATE_STATUS_GOOD) => Ok(CertificateStatus::Good),
        Some(trust_pb::CertificateStatus::CERTIFICATE_STATUS_REVOKED) => {
            Ok(CertificateStatus::Revoked)
        }
        Some(trust_pb::CertificateStatus::CERTIFICATE_STATUS_SUSPENDED) => {
            Ok(CertificateStatus::Suspended)
        }
        Some(trust_pb::CertificateStatus::CERTIFICATE_STATUS_UNKNOWN) => {
            Ok(CertificateStatus::Unknown)
        }
        Some(trust_pb::CertificateStatus::CERTIFICATE_STATUS_UNAVAILABLE) => {
            Ok(CertificateStatus::Unavailable)
        }
        Some(trust_pb::CertificateStatus::CERTIFICATE_STATUS_STALE) => Ok(CertificateStatus::Stale),
        Some(trust_pb::CertificateStatus::CERTIFICATE_STATUS_NOT_YET_VALID) => {
            Ok(CertificateStatus::NotYetValid)
        }
        Some(trust_pb::CertificateStatus::CERTIFICATE_STATUS_MALFORMED) => {
            Ok(CertificateStatus::Malformed)
        }
        Some(trust_pb::CertificateStatus::CERTIFICATE_STATUS_INVALID_SIGNATURE) => {
            Ok(CertificateStatus::InvalidSignature)
        }
        Some(trust_pb::CertificateStatus::CERTIFICATE_STATUS_UNSUPPORTED) => {
            Ok(CertificateStatus::Unsupported)
        }
        Some(trust_pb::CertificateStatus::CERTIFICATE_STATUS_EXEMPT) => {
            Ok(CertificateStatus::Exempt)
        }
        _ => Err(TrustProtoError::UnknownCertificateStatus),
    }
}

fn certificate_position_to_proto(
    position: CertificatePosition,
) -> (trust_pb::CertificatePosition, u32) {
    match position {
        CertificatePosition::Leaf => (trust_pb::CertificatePosition::CERTIFICATE_POSITION_LEAF, 0),
        CertificatePosition::Intermediate(index) => (
            trust_pb::CertificatePosition::CERTIFICATE_POSITION_INTERMEDIATE,
            u32::from(index),
        ),
        CertificatePosition::TrustAnchor => (
            trust_pb::CertificatePosition::CERTIFICATE_POSITION_TRUST_ANCHOR,
            0,
        ),
    }
}

fn certificate_position_from_proto(
    value: EnumValue<trust_pb::CertificatePosition>,
    intermediate_index: u32,
) -> Result<CertificatePosition, TrustProtoError> {
    match trust_pb::CertificatePosition::from_i32(value.to_i32()) {
        Some(trust_pb::CertificatePosition::CERTIFICATE_POSITION_LEAF)
            if intermediate_index == 0 =>
        {
            Ok(CertificatePosition::Leaf)
        }
        Some(trust_pb::CertificatePosition::CERTIFICATE_POSITION_INTERMEDIATE) => {
            u8::try_from(intermediate_index)
                .map(CertificatePosition::Intermediate)
                .map_err(|_| TrustProtoError::InvalidDecisionEvidence)
        }
        Some(trust_pb::CertificatePosition::CERTIFICATE_POSITION_TRUST_ANCHOR)
            if intermediate_index == 0 =>
        {
            Ok(CertificatePosition::TrustAnchor)
        }
        _ => Err(TrustProtoError::UnknownCertificatePosition),
    }
}

/// Authorization intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationPurpose {
    /// Qualified electronic attestation issuer authorization.
    QeaaIssuer,
    /// Qualified website authentication certificate TLS server authorization.
    QwacTlsServer,
    /// Qualified electronic seal signer authorization.
    QsealSigner,
}

impl From<AuthorizationPurpose> for trust_pb::AuthorizationPurpose {
    fn from(purpose: AuthorizationPurpose) -> Self {
        match purpose {
            AuthorizationPurpose::QeaaIssuer => Self::AUTHORIZATION_PURPOSE_QEAA_ISSUER,
            AuthorizationPurpose::QwacTlsServer => Self::AUTHORIZATION_PURPOSE_QWAC_TLS_SERVER,
            AuthorizationPurpose::QsealSigner => Self::AUTHORIZATION_PURPOSE_QSEAL_SIGNER,
        }
    }
}

impl TryFrom<EnumValue<trust_pb::AuthorizationPurpose>> for AuthorizationPurpose {
    type Error = TrustProtoError;

    fn try_from(value: EnumValue<trust_pb::AuthorizationPurpose>) -> Result<Self, Self::Error> {
        match trust_pb::AuthorizationPurpose::from_i32(value.to_i32()) {
            Some(trust_pb::AuthorizationPurpose::AUTHORIZATION_PURPOSE_QEAA_ISSUER) => {
                Ok(Self::QeaaIssuer)
            }
            Some(trust_pb::AuthorizationPurpose::AUTHORIZATION_PURPOSE_QWAC_TLS_SERVER) => {
                Ok(Self::QwacTlsServer)
            }
            Some(trust_pb::AuthorizationPurpose::AUTHORIZATION_PURPOSE_QSEAL_SIGNER) => {
                Ok(Self::QsealSigner)
            }
            _ => Err(TrustProtoError::UnknownAuthorizationPurpose),
        }
    }
}

impl From<&TrustDecision> for trust_pb::TrustDecision {
    fn from(decision: &TrustDecision) -> Self {
        Self {
            accepted: decision.accepted,
            failures: decision
                .failures
                .iter()
                .copied()
                .map(trust_pb::TrustDecisionFailure::from)
                .map(EnumValue::from)
                .collect(),
            outcome: EnumValue::from(trust_pb::TrustDecisionOutcome::from(decision.outcome)),
            evidence: buffa::MessageField::some(trust_decision_evidence_to_proto(
                &decision.evidence,
            )),
            ..Self::default()
        }
    }
}

impl TryFrom<trust_pb::TrustDecision> for TrustDecision {
    type Error = TrustProtoError;

    fn try_from(decision: trust_pb::TrustDecision) -> Result<Self, Self::Error> {
        let outcome = decision_outcome_from_proto(decision.outcome)?;
        if decision.accepted != (outcome == TrustDecisionOutcome::Trusted) {
            return Err(TrustProtoError::InconsistentDecisionOutcome);
        }
        if decision.failures.len() > MAX_TRUST_DECISION_FAILURES {
            return Err(TrustProtoError::ResourceLimit);
        }
        let failures = decision
            .failures
            .into_iter()
            .map(TrustDecisionFailure::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let evidence = decision
            .evidence
            .into_option()
            .ok_or(TrustProtoError::InvalidDecisionEvidence)
            .and_then(trust_decision_evidence_from_proto)?;

        let decoded = Self {
            accepted: decision.accepted,
            outcome,
            failures,
            evidence,
        };
        validate_decision_semantics(&decoded)?;
        Ok(decoded)
    }
}

fn trust_decision_evidence_to_proto(
    evidence: &TrustDecisionEvidence,
) -> trust_pb::TrustDecisionEvidence {
    let (source_id, snapshot_id) = match evidence.source {
        Some(source) => (source.source_id.to_vec(), source.snapshot_id.to_vec()),
        None => (Vec::new(), Vec::new()),
    };
    let trust_anchor = evidence.trust_anchor.map(|anchor| {
        buffa::MessageField::some(trust_pb::TrustAnchorEvidence {
            kind: EnumValue::from(trust_pb::TrustAnchorKind::from(anchor.kind)),
            configured_index: u32::from(anchor.configured_index),
            ..Default::default()
        })
    });

    trust_pb::TrustDecisionEvidence {
        purpose: EnumValue::from(trust_pb::TrustPurpose::from(evidence.purpose)),
        policy_id: EnumValue::from(trust_pb::TrustPolicyId::from(evidence.policy_id)),
        evaluated_at_unix: evidence.evaluated_at_unix,
        source_id,
        snapshot_id,
        trust_anchor: trust_anchor.unwrap_or_else(buffa::MessageField::none),
        certificate_status: evidence
            .certificate_status
            .iter()
            .map(|item| {
                let (position, intermediate_index) = certificate_position_to_proto(item.position);
                trust_pb::CertificateStatusEvidence {
                    position: EnumValue::from(position),
                    intermediate_index,
                    status: EnumValue::from(trust_pb::CertificateStatus::from(item.status)),
                    ..Default::default()
                }
            })
            .collect(),
        selected_path_certificate_sha256: evidence
            .selected_path_certificate_sha256
            .iter()
            .map(|fingerprint| fingerprint.to_vec())
            .collect(),
        ..Default::default()
    }
}

fn trust_decision_evidence_from_proto(
    evidence: trust_pb::TrustDecisionEvidence,
) -> Result<TrustDecisionEvidence, TrustProtoError> {
    if evidence.certificate_status.len() > MAX_TRUST_DECISION_PATH_CERTIFICATES
        || evidence.selected_path_certificate_sha256.len() > MAX_TRUST_DECISION_PATH_CERTIFICATES
    {
        return Err(TrustProtoError::ResourceLimit);
    }
    let source = match (
        evidence.source_id.is_empty(),
        evidence.snapshot_id.is_empty(),
    ) {
        (true, true) => None,
        (false, false) => Some(TrustSourceEvidence {
            source_id: <[u8; 32]>::try_from(evidence.source_id)
                .map_err(|_| TrustProtoError::InvalidDecisionEvidence)?,
            snapshot_id: <[u8; 32]>::try_from(evidence.snapshot_id)
                .map_err(|_| TrustProtoError::InvalidDecisionEvidence)?,
        }),
        _ => return Err(TrustProtoError::InvalidDecisionEvidence),
    };
    let trust_anchor = evidence
        .trust_anchor
        .into_option()
        .map(|anchor| {
            Ok(TrustAnchorEvidence {
                kind: trust_anchor_kind_from_proto(anchor.kind)?,
                configured_index: u16::try_from(anchor.configured_index)
                    .map_err(|_| TrustProtoError::InvalidDecisionEvidence)?,
            })
        })
        .transpose()?;
    let certificate_status = evidence
        .certificate_status
        .into_iter()
        .map(|item| {
            Ok(CertificateStatusEvidence {
                position: certificate_position_from_proto(item.position, item.intermediate_index)?,
                status: certificate_status_from_proto(item.status)?,
            })
        })
        .collect::<Result<Vec<_>, TrustProtoError>>()?;
    let selected_path_certificate_sha256 = evidence
        .selected_path_certificate_sha256
        .into_iter()
        .map(|fingerprint| {
            <[u8; 32]>::try_from(fingerprint).map_err(|_| TrustProtoError::InvalidDecisionEvidence)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(TrustDecisionEvidence {
        purpose: trust_purpose_from_proto(evidence.purpose)?,
        policy_id: trust_policy_from_proto(evidence.policy_id)?,
        evaluated_at_unix: evidence.evaluated_at_unix,
        source,
        trust_anchor,
        certificate_status,
        selected_path_certificate_sha256,
    })
}

/// Owned DER certificate bytes that are cleared on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X509CertificateDer {
    /// Complete DER certificate bytes.
    pub der: Vec<u8>,
}

impl core::fmt::Debug for X509CertificateDer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("X509CertificateDer")
            .field("der", &"<redacted>")
            .finish()
    }
}

/// Certificate chain ordered leaf to root.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct X509ChainDer {
    /// DER certificates ordered leaf to root.
    pub certs: Vec<X509CertificateDer>,
}

/// Caller-owned root trust anchors.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct TrustAnchorsDer {
    /// DER root certificates.
    pub roots: Vec<X509CertificateDer>,
}

#[cfg(test)]
#[path = "../dto_proto_tests.rs"]
mod proto_tests;
