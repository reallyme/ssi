// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Convert generated QEAA evidence into the validated native audit model.
pub fn qeaa_compliance_from_proto(
    qeaa: &audit_pb::QeaaCompliance,
) -> Result<QeaaCompliance, CredentialError> {
    let qtsp = qeaa.qtsp.as_option().ok_or(CredentialError::Proto(
        CredentialProtoReason::MissingField(CredentialProtoField::QeaaCompliance),
    ))?;
    let policies = qeaa.policies.as_option().ok_or(CredentialError::Proto(
        CredentialProtoReason::MissingField(CredentialProtoField::QeaaCompliance),
    ))?;
    let issuer_credential = qeaa
        .issuer_credential
        .as_option()
        .ok_or(CredentialError::Proto(CredentialProtoReason::MissingField(
            CredentialProtoField::QeaaCompliance,
        )))?;
    let key_management = qeaa
        .key_management
        .as_option()
        .ok_or(CredentialError::Proto(CredentialProtoReason::MissingField(
            CredentialProtoField::QeaaCompliance,
        )))?;
    let identity_proofing = qeaa
        .identity_proofing
        .as_option()
        .ok_or(CredentialError::Proto(CredentialProtoReason::MissingField(
            CredentialProtoField::QeaaCompliance,
        )))?;
    let audit = qeaa.audit.as_option().ok_or(CredentialError::Proto(
        CredentialProtoReason::MissingField(CredentialProtoField::QeaaCompliance),
    ))?;
    let revocation = qeaa.revocation.as_option().ok_or(CredentialError::Proto(
        CredentialProtoReason::MissingField(CredentialProtoField::QeaaCompliance),
    ))?;

    Ok(QeaaCompliance {
        qtsp: QtspInfo {
            tsp_name: qtsp.tsp_name.clone(),
            tsp_id: qtsp.tsp_id.clone(),
            tsp_role: qtsp_role_from_proto(qtsp.tsp_role.to_i32())?,
        },
        policies: QeaaPolicies {
            policy_id: policies.policy_id.clone(),
            standards: policies.standards.clone(),
        },
        issuer_credential: IssuerCredential {
            kind: issuer_credential_kind_from_proto(issuer_credential.kind.to_i32())?,
            cert_fingerprint_sha256: sha256_from_slice(
                issuer_credential.cert_fingerprint_sha256.as_slice(),
                CredentialProtoField::FixedBytes,
            )?,
            cert_chain_der: issuer_credential.cert_chain_der.clone(),
            trusted_list_ref: issuer_credential.trusted_list_ref.clone(),
            policy_oids: issuer_credential.policy_oids.clone(),
            qcstatements_oids: issuer_credential.qcstatements_oids.clone(),
        },
        key_management: KeyManagement {
            signing_key_id: key_management.signing_key_id.clone(),
            protection: key_protection_from_proto(key_management.protection.to_i32())?,
        },
        identity_proofing: IdentityProofing {
            standard: identity_proofing.standard.clone(),
            loip: identity_proofing_level_from_proto(identity_proofing.loip.to_i32())?,
            evidence_ref: identity_proofing.evidence_ref.clone(),
            evidence_hash: sha256_from_slice(
                identity_proofing.evidence_hash.as_slice(),
                CredentialProtoField::FixedBytes,
            )?,
        },
        audit: AuditInfo {
            audit_standard: audit.audit_standard.clone(),
            audit_report_ref: audit.audit_report_ref.clone(),
            audit_report_hash: sha256_from_slice(
                audit.audit_report_hash.as_slice(),
                CredentialProtoField::FixedBytes,
            )?,
            period_from_unix: audit.period_from_unix,
            period_to_unix: audit.period_to_unix,
        },
        revocation: RevocationPolicy {
            status_method: status_method_from_proto(revocation.status_method.to_i32())?,
            signing_key_id: revocation.signing_key_id.clone(),
            max_status_age_seconds: revocation.max_status_age_seconds,
        },
    })
}

fn timestamp_to_proto(value: UnixSeconds) -> Timestamp {
    Timestamp {
        seconds: value,
        nanos: 0,
        ..Timestamp::default()
    }
}

fn timestamp_from_proto(
    value: &Timestamp,
    field: CredentialProtoField,
) -> Result<UnixSeconds, CredentialError> {
    if value.nanos != 0 {
        return Err(CredentialError::Proto(
            CredentialProtoReason::InvalidTimestamp(field),
        ));
    }
    Ok(value.seconds)
}

fn sha256_from_slice(
    value: &[u8],
    field: CredentialProtoField,
) -> Result<Sha256Digest, CredentialError> {
    <Sha256Digest>::try_from(value)
        .map_err(|_| CredentialError::Proto(CredentialProtoReason::InvalidFixedBytes(field)))
}

fn credential_kind_to_proto(kind: CredentialKind) -> credential_pb::CredentialKind {
    match kind {
        CredentialKind::Generic => credential_pb::CredentialKind::Generic,
        CredentialKind::Pid => credential_pb::CredentialKind::Pid,
        CredentialKind::Eaa => credential_pb::CredentialKind::Eaa,
        CredentialKind::Qeaa => credential_pb::CredentialKind::Qeaa,
    }
}

fn credential_kind_from_proto(value: i32) -> Result<CredentialKind, CredentialError> {
    match credential_pb::CredentialKind::from_i32(value).ok_or(CredentialError::Proto(
        CredentialProtoReason::InvalidEnum(CredentialProtoField::Kind),
    ))? {
        credential_pb::CredentialKind::Pid => Ok(CredentialKind::Pid),
        credential_pb::CredentialKind::Eaa => Ok(CredentialKind::Eaa),
        credential_pb::CredentialKind::Qeaa => Ok(CredentialKind::Qeaa),
        credential_pb::CredentialKind::Generic => Ok(CredentialKind::Generic),
        credential_pb::CredentialKind::Unspecified => Err(CredentialError::Proto(
            CredentialProtoReason::InvalidEnum(CredentialProtoField::Kind),
        )),
    }
}

fn assurance_level_to_proto(assurance: AssuranceLevel) -> credential_pb::AssuranceLevel {
    match assurance {
        AssuranceLevel::Basic => credential_pb::AssuranceLevel::Basic,
        AssuranceLevel::Substantial => credential_pb::AssuranceLevel::Substantial,
        AssuranceLevel::High => credential_pb::AssuranceLevel::High,
    }
}

fn assurance_level_from_proto(value: i32) -> Result<AssuranceLevel, CredentialError> {
    match credential_pb::AssuranceLevel::from_i32(value).ok_or(CredentialError::Proto(
        CredentialProtoReason::InvalidEnum(CredentialProtoField::Assurance),
    ))? {
        credential_pb::AssuranceLevel::Substantial => Ok(AssuranceLevel::Substantial),
        credential_pb::AssuranceLevel::High => Ok(AssuranceLevel::High),
        credential_pb::AssuranceLevel::Basic => Ok(AssuranceLevel::Basic),
        credential_pb::AssuranceLevel::Unspecified => Err(CredentialError::Proto(
            CredentialProtoReason::InvalidEnum(CredentialProtoField::Assurance),
        )),
    }
}

fn status_purpose_to_proto(purpose: StatusPurpose) -> credential_pb::StatusPurpose {
    match purpose {
        StatusPurpose::Revocation => credential_pb::StatusPurpose::Revocation,
        StatusPurpose::Suspension => credential_pb::StatusPurpose::Suspension,
    }
}

fn status_purpose_from_proto(value: i32) -> Result<StatusPurpose, CredentialError> {
    match credential_pb::StatusPurpose::from_i32(value).ok_or(CredentialError::Proto(
        CredentialProtoReason::InvalidEnum(CredentialProtoField::StatusPurpose),
    ))? {
        credential_pb::StatusPurpose::Revocation => Ok(StatusPurpose::Revocation),
        credential_pb::StatusPurpose::Suspension => Ok(StatusPurpose::Suspension),
        credential_pb::StatusPurpose::Unspecified => Err(CredentialError::Proto(
            CredentialProtoReason::InvalidEnum(CredentialProtoField::StatusPurpose),
        )),
    }
}

fn identity_proofing_level_to_proto(
    value: IdentityProofingLevel,
) -> audit_pb::IdentityProofingLevel {
    match value {
        IdentityProofingLevel::Unspecified => audit_pb::IdentityProofingLevel::Unspecified,
        IdentityProofingLevel::Baseline => audit_pb::IdentityProofingLevel::Baseline,
        IdentityProofingLevel::Extended => audit_pb::IdentityProofingLevel::Extended,
        IdentityProofingLevel::High => audit_pb::IdentityProofingLevel::High,
    }
}

fn identity_proofing_level_from_proto(
    value: i32,
) -> Result<IdentityProofingLevel, CredentialError> {
    match audit_pb::IdentityProofingLevel::from_i32(value).ok_or(CredentialError::Proto(
        CredentialProtoReason::InvalidEnum(CredentialProtoField::QeaaEnum),
    ))? {
        audit_pb::IdentityProofingLevel::Baseline => Ok(IdentityProofingLevel::Baseline),
        audit_pb::IdentityProofingLevel::Extended => Ok(IdentityProofingLevel::Extended),
        audit_pb::IdentityProofingLevel::High => Ok(IdentityProofingLevel::High),
        audit_pb::IdentityProofingLevel::Unspecified => Err(CredentialError::Proto(
            CredentialProtoReason::InvalidEnum(CredentialProtoField::QeaaEnum),
        )),
    }
}

fn qtsp_role_to_proto(value: QtspRole) -> audit_pb::QtspRole {
    match value {
        QtspRole::Unspecified => audit_pb::QtspRole::Unspecified,
        QtspRole::QeaaProvider => audit_pb::QtspRole::QeaaProvider,
    }
}

fn qtsp_role_from_proto(value: i32) -> Result<QtspRole, CredentialError> {
    match audit_pb::QtspRole::from_i32(value).ok_or(CredentialError::Proto(
        CredentialProtoReason::InvalidEnum(CredentialProtoField::QeaaEnum),
    ))? {
        audit_pb::QtspRole::QeaaProvider => Ok(QtspRole::QeaaProvider),
        audit_pb::QtspRole::Unspecified => Err(CredentialError::Proto(
            CredentialProtoReason::InvalidEnum(CredentialProtoField::QeaaEnum),
        )),
    }
}

fn issuer_credential_kind_to_proto(value: IssuerCredentialKind) -> audit_pb::IssuerCredentialKind {
    match value {
        IssuerCredentialKind::Unspecified => audit_pb::IssuerCredentialKind::Unspecified,
        IssuerCredentialKind::X509 => audit_pb::IssuerCredentialKind::X509,
    }
}

fn issuer_credential_kind_from_proto(value: i32) -> Result<IssuerCredentialKind, CredentialError> {
    match audit_pb::IssuerCredentialKind::from_i32(value).ok_or(CredentialError::Proto(
        CredentialProtoReason::InvalidEnum(CredentialProtoField::QeaaEnum),
    ))? {
        audit_pb::IssuerCredentialKind::X509 => Ok(IssuerCredentialKind::X509),
        audit_pb::IssuerCredentialKind::Unspecified => Err(CredentialError::Proto(
            CredentialProtoReason::InvalidEnum(CredentialProtoField::QeaaEnum),
        )),
    }
}

fn key_protection_to_proto(value: KeyProtection) -> audit_pb::KeyProtection {
    match value {
        KeyProtection::Unspecified => audit_pb::KeyProtection::Unspecified,
        KeyProtection::Hsm => audit_pb::KeyProtection::Hsm,
        KeyProtection::Qscd => audit_pb::KeyProtection::Qscd,
    }
}

fn key_protection_from_proto(value: i32) -> Result<KeyProtection, CredentialError> {
    match audit_pb::KeyProtection::from_i32(value).ok_or(CredentialError::Proto(
        CredentialProtoReason::InvalidEnum(CredentialProtoField::QeaaEnum),
    ))? {
        audit_pb::KeyProtection::Hsm => Ok(KeyProtection::Hsm),
        audit_pb::KeyProtection::Qscd => Ok(KeyProtection::Qscd),
        audit_pb::KeyProtection::Unspecified => Err(CredentialError::Proto(
            CredentialProtoReason::InvalidEnum(CredentialProtoField::QeaaEnum),
        )),
    }
}

fn status_method_to_proto(value: StatusMethod) -> audit_pb::StatusMethod {
    match value {
        StatusMethod::Unspecified => audit_pb::StatusMethod::Unspecified,
        StatusMethod::StatusList => audit_pb::StatusMethod::StatusList,
    }
}

fn status_method_from_proto(value: i32) -> Result<StatusMethod, CredentialError> {
    match audit_pb::StatusMethod::from_i32(value).ok_or(CredentialError::Proto(
        CredentialProtoReason::InvalidEnum(CredentialProtoField::QeaaEnum),
    ))? {
        audit_pb::StatusMethod::StatusList => Ok(StatusMethod::StatusList),
        audit_pb::StatusMethod::Unspecified => Err(CredentialError::Proto(
            CredentialProtoReason::InvalidEnum(CredentialProtoField::QeaaEnum),
        )),
    }
}
