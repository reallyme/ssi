// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn issuer_credential_to_cbor(issuer: &IssuerCredential) -> CborValue {
    CborValue::Map(vec![
        (
            "kind".to_owned(),
            CborValue::String(issuer_credential_kind_label(issuer.kind).to_owned()),
        ),
        (
            "certFingerprintSha256".to_owned(),
            CborValue::Bytes(issuer.cert_fingerprint_sha256.to_vec()),
        ),
        (
            "certChainDer".to_owned(),
            bytes_array_to_cbor(&issuer.cert_chain_der),
        ),
        (
            "trustedListRef".to_owned(),
            CborValue::String(issuer.trusted_list_ref.clone()),
        ),
        (
            "policyOids".to_owned(),
            string_array_to_cbor(&issuer.policy_oids),
        ),
        (
            "qcstatementsOids".to_owned(),
            string_array_to_cbor(&issuer.qcstatements_oids),
        ),
    ])
}

fn key_management_to_cbor(keys: &KeyManagement) -> CborValue {
    CborValue::Map(vec![
        (
            "signingKeyId".to_owned(),
            CborValue::String(keys.signing_key_id.clone()),
        ),
        (
            "protection".to_owned(),
            CborValue::String(key_protection_label(keys.protection).to_owned()),
        ),
    ])
}

fn identity_proofing_to_cbor(proofing: &IdentityProofing) -> CborValue {
    CborValue::Map(vec![
        (
            "standard".to_owned(),
            CborValue::String(proofing.standard.clone()),
        ),
        (
            "loip".to_owned(),
            CborValue::String(identity_proofing_level_label(proofing.loip).to_owned()),
        ),
        (
            "evidenceRef".to_owned(),
            CborValue::String(proofing.evidence_ref.clone()),
        ),
        (
            "evidenceHash".to_owned(),
            CborValue::Bytes(proofing.evidence_hash.to_vec()),
        ),
    ])
}

fn audit_info_to_cbor(audit: &AuditInfo) -> Result<CborValue, CredentialError> {
    Ok(CborValue::Map(vec![
        (
            "auditStandard".to_owned(),
            CborValue::String(audit.audit_standard.clone()),
        ),
        (
            "auditReportRef".to_owned(),
            CborValue::String(audit.audit_report_ref.clone()),
        ),
        (
            "auditReportHash".to_owned(),
            CborValue::Bytes(audit.audit_report_hash.to_vec()),
        ),
        (
            "periodFromUnix".to_owned(),
            CborValue::Int(i64::try_from(audit.period_from_unix).map_err(|_| {
                CredentialError::Canonical(CredentialCanonicalReason::IntegerOutOfRange)
            })?),
        ),
        (
            "periodToUnix".to_owned(),
            CborValue::Int(i64::try_from(audit.period_to_unix).map_err(|_| {
                CredentialError::Canonical(CredentialCanonicalReason::IntegerOutOfRange)
            })?),
        ),
    ]))
}

fn revocation_policy_to_cbor(revocation: &RevocationPolicy) -> CborValue {
    CborValue::Map(vec![
        (
            "statusMethod".to_owned(),
            CborValue::String(status_method_label(revocation.status_method).to_owned()),
        ),
        (
            "signingKeyId".to_owned(),
            CborValue::String(revocation.signing_key_id.clone()),
        ),
        (
            "maxStatusAgeSeconds".to_owned(),
            CborValue::Int(i64::from(revocation.max_status_age_seconds)),
        ),
    ])
}

fn string_array_to_cbor(values: &[String]) -> CborValue {
    CborValue::Array(values.iter().cloned().map(CborValue::String).collect())
}

fn bytes_array_to_cbor(values: &[Vec<u8>]) -> CborValue {
    CborValue::Array(values.iter().cloned().map(CborValue::Bytes).collect())
}

fn kind_label(kind: CredentialKind) -> &'static str {
    match kind {
        CredentialKind::Generic => "generic",
        CredentialKind::Pid => "pid",
        CredentialKind::Eaa => "eaa",
        CredentialKind::Qeaa => "qeaa",
    }
}

fn assurance_label(assurance: AssuranceLevel) -> &'static str {
    match assurance {
        AssuranceLevel::Basic => "basic",
        AssuranceLevel::Substantial => "substantial",
        AssuranceLevel::High => "high",
    }
}

fn status_purpose_label(purpose: StatusPurpose) -> &'static str {
    match purpose {
        StatusPurpose::Revocation => "revocation",
        StatusPurpose::Suspension => "suspension",
    }
}

fn credential_algorithm_label(algorithm: CredentialAlgorithm) -> &'static str {
    match algorithm {
        CredentialAlgorithm::Unspecified => "unspecified",
        CredentialAlgorithm::Ed25519 => "ed25519",
        CredentialAlgorithm::X25519 => "x25519",
        CredentialAlgorithm::P256 => "p-256",
        CredentialAlgorithm::Secp256k1 => "secp256k1",
        CredentialAlgorithm::Es256kRecovery => "es256k-recovery",
        CredentialAlgorithm::MlDsa65 => "ml-dsa-65",
        CredentialAlgorithm::MlDsa87 => "ml-dsa-87",
        CredentialAlgorithm::MlKem768 => "ml-kem-768",
        CredentialAlgorithm::MlKem1024 => "ml-kem-1024",
        CredentialAlgorithm::MlDsa44 => "ml-dsa-44",
    }
}

fn qtsp_role_label(role: QtspRole) -> &'static str {
    match role {
        QtspRole::Unspecified => "unspecified",
        QtspRole::QeaaProvider => "qeaa-provider",
    }
}

fn issuer_credential_kind_label(kind: IssuerCredentialKind) -> &'static str {
    match kind {
        IssuerCredentialKind::Unspecified => "unspecified",
        IssuerCredentialKind::X509 => "x509",
    }
}

fn key_protection_label(protection: KeyProtection) -> &'static str {
    match protection {
        KeyProtection::Unspecified => "unspecified",
        KeyProtection::Hsm => "hsm",
        KeyProtection::Qscd => "qscd",
    }
}

fn identity_proofing_level_label(level: IdentityProofingLevel) -> &'static str {
    match level {
        IdentityProofingLevel::Unspecified => "unspecified",
        IdentityProofingLevel::Baseline => "baseline",
        IdentityProofingLevel::Extended => "extended",
        IdentityProofingLevel::High => "high",
    }
}

fn status_method_label(method: StatusMethod) -> &'static str {
    match method {
        StatusMethod::Unspecified => "unspecified",
        StatusMethod::StatusList => "status-list",
    }
}
