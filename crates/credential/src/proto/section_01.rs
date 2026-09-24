// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    validate_credential_envelope, AssuranceLevel, CredentialEnvelope, CredentialError,
    CredentialKind, CredentialProtoField, CredentialProtoReason, CredentialStatus,
    CredentialSubject, HolderBinding, PartyReference, PublicKeyIdentity, UnixSeconds,
    X509SubjectReference,
};
use buffa::{EnumValue, Enumeration, Inline, MessageField};
use buffa_types::google::protobuf::Timestamp;
use reallyme_credential_audit::{
    AuditInfo, IdentityProofing, IdentityProofingLevel, IssuerCredential, IssuerCredentialKind,
    KeyManagement, KeyProtection, QeaaCompliance, QeaaPolicies, QtspInfo, QtspRole,
    RevocationPolicy, Sha256Digest, StatusMethod,
};
use reallyme_credential_claims::{
    claims_commitment_from_proto, claims_commitment_to_proto, public_key_material_from_proto,
    public_key_material_to_proto, public_key_ref_from_proto, public_key_ref_to_proto, Signature,
};
use reallyme_credential_status::StatusPurpose;
use reallyme_ssi_proto::generated::proto::identity::audit::v1 as audit_pb;
use reallyme_ssi_proto::generated::proto::identity::credential::v1 as credential_pb;

/// Convert a native credential envelope into the generated protobuf boundary.
pub fn credential_envelope_to_proto(
    envelope: &CredentialEnvelope,
) -> Result<credential_pb::CredentialEnvelope, CredentialError> {
    validate_credential_envelope(envelope)?;
    Ok(credential_pb::CredentialEnvelope {
        kind: EnumValue::from(credential_kind_to_proto(envelope.kind)),
        profile_id: envelope.profile_id.clone(),
        assurance: EnumValue::from(assurance_level_to_proto(envelope.assurance)),
        issuer_reference: MessageField::some(party_reference_to_proto(&envelope.issuer_reference)),
        issuer_country: envelope.issuer_country.clone(),
        valid_from: MessageField::some(timestamp_to_proto(envelope.valid_from)),
        valid_until: MessageField::some(timestamp_to_proto(envelope.valid_until)),
        status: MessageField::some(credential_status_to_proto(&envelope.status)),
        subject: MessageField::some(credential_subject_to_proto(&envelope.subject)),
        claims_commitment: MessageField::some(
            claims_commitment_to_proto(&envelope.claims_commitment)
                .map_err(CredentialError::Claims)?,
        ),
        qeaa_compliance: qeaa_compliance_to_proto_field(envelope.qeaa_compliance.as_ref())?,
        issuer_signature: MessageField::some(signature_to_proto(&envelope.issuer_signature)),
        ..credential_pb::CredentialEnvelope::default()
    })
}

/// Convert a generated protobuf credential envelope into the native semantic model.
pub fn credential_envelope_from_proto(
    envelope: &credential_pb::CredentialEnvelope,
) -> Result<CredentialEnvelope, CredentialError> {
    let status = envelope.status.as_option().ok_or(CredentialError::Proto(
        CredentialProtoReason::MissingField(CredentialProtoField::Status),
    ))?;
    let subject = envelope.subject.as_option().ok_or(CredentialError::Proto(
        CredentialProtoReason::MissingField(CredentialProtoField::Subject),
    ))?;
    let commitment = envelope
        .claims_commitment
        .as_option()
        .ok_or(CredentialError::Proto(CredentialProtoReason::MissingField(
            CredentialProtoField::ClaimsCommitment,
        )))?;
    let issuer_signature = envelope
        .issuer_signature
        .as_option()
        .ok_or(CredentialError::Proto(CredentialProtoReason::MissingField(
            CredentialProtoField::IssuerSignature,
        )))?;
    let valid_from = envelope
        .valid_from
        .as_option()
        .ok_or(CredentialError::Proto(CredentialProtoReason::MissingField(
            CredentialProtoField::ValidFrom,
        )))?;
    let valid_until = envelope
        .valid_until
        .as_option()
        .ok_or(CredentialError::Proto(CredentialProtoReason::MissingField(
            CredentialProtoField::ValidUntil,
        )))?;

    let out = CredentialEnvelope {
        kind: credential_kind_from_proto(envelope.kind.to_i32())?,
        profile_id: envelope.profile_id.clone(),
        assurance: assurance_level_from_proto(envelope.assurance.to_i32())?,
        issuer_reference: party_reference_from_proto(
            envelope
                .issuer_reference
                .as_option()
                .ok_or(CredentialError::Proto(CredentialProtoReason::MissingField(
                    CredentialProtoField::IssuerSignature,
                )))?,
        )?,
        issuer_country: envelope.issuer_country.clone(),
        valid_from: timestamp_from_proto(valid_from, CredentialProtoField::ValidFrom)?,
        valid_until: timestamp_from_proto(valid_until, CredentialProtoField::ValidUntil)?,
        status: credential_status_from_proto(status)?,
        subject: credential_subject_from_proto(subject)?,
        claims_commitment: claims_commitment_from_proto(commitment)
            .map_err(CredentialError::Claims)?,
        qeaa_compliance: qeaa_compliance_from_proto_field(&envelope.qeaa_compliance)?,
        issuer_signature: signature_from_proto(
            issuer_signature,
            CredentialProtoField::SignatureAlgorithm,
        )?,
    };
    validate_credential_envelope(&out)?;
    Ok(out)
}

fn credential_subject_to_proto(subject: &CredentialSubject) -> credential_pb::CredentialSubject {
    credential_pb::CredentialSubject {
        subject_reference: MessageField::some(party_reference_to_proto(&subject.subject_reference)),
        holder_binding: MessageField::some(holder_binding_to_proto(&subject.holder_binding)),
        ..credential_pb::CredentialSubject::default()
    }
}

fn credential_subject_from_proto(
    subject: &credential_pb::CredentialSubject,
) -> Result<CredentialSubject, CredentialError> {
    let subject_reference = subject
        .subject_reference
        .as_option()
        .ok_or(CredentialError::Proto(CredentialProtoReason::MissingField(
            CredentialProtoField::SubjectKey,
        )))?;
    let holder_binding = subject
        .holder_binding
        .as_option()
        .ok_or(CredentialError::Proto(CredentialProtoReason::MissingField(
            CredentialProtoField::SubjectKey,
        )))?;
    Ok(CredentialSubject {
        subject_reference: party_reference_from_proto(subject_reference)?,
        holder_binding: holder_binding_from_proto(holder_binding)?,
    })
}

/// Convert a native credential status reference into the generated protobuf boundary.
pub fn credential_status_to_proto(status: &CredentialStatus) -> credential_pb::CredentialStatus {
    credential_pb::CredentialStatus {
        status_list_url: status.status_list_url.clone(),
        status_list_id: status.status_list_id.to_vec(),
        status_list_index: status.status_list_index,
        purpose: EnumValue::from(status_purpose_to_proto(status.purpose)),
        ..credential_pb::CredentialStatus::default()
    }
}

/// Convert a generated credential status reference into the native semantic model.
pub fn credential_status_from_proto(
    status: &credential_pb::CredentialStatus,
) -> Result<CredentialStatus, CredentialError> {
    Ok(CredentialStatus {
        status_list_url: status.status_list_url.clone(),
        status_list_id: sha256_from_slice(
            status.status_list_id.as_slice(),
            CredentialProtoField::FixedBytes,
        )?,
        status_list_index: status.status_list_index,
        purpose: status_purpose_from_proto(status.purpose.to_i32())?,
    })
}

fn signature_to_proto(signature: &Signature) -> credential_pb::Signature {
    credential_pb::Signature {
        verification_key: MessageField::some(public_key_ref_to_proto(&signature.verification_key)),
        raw_rs: signature.raw_rs.clone(),
        ..credential_pb::Signature::default()
    }
}

fn signature_from_proto(
    signature: &credential_pb::Signature,
    field: CredentialProtoField,
) -> Result<Signature, CredentialError> {
    let verification_key = signature
        .verification_key
        .as_option()
        .ok_or(CredentialError::Proto(CredentialProtoReason::MissingField(
            field,
        )))?;
    Ok(Signature {
        verification_key: public_key_ref_from_proto(verification_key)
            .map_err(CredentialError::Claims)?,
        raw_rs: signature.raw_rs.clone(),
    })
}

/// Convert a semantic party reference into protobuf.
pub fn party_reference_to_proto(reference: &PartyReference) -> credential_pb::PartyReference {
    use credential_pb::__buffa::oneof::party_reference::Kind;

    let kind = match reference {
        PartyReference::Did(value) => Kind::Did(value.clone()),
        PartyReference::X509Subject(value) => {
            Kind::X509Subject(Box::new(x509_subject_reference_to_proto(value)))
        }
        PartyReference::PublicKey(value) => Kind::PublicKey(Box::new(
            public_key_material_to_proto(value.alg, &value.public_key),
        )),
        PartyReference::FederationEntityId(value) => Kind::FederationEntityId(value.clone()),
        PartyReference::OpaqueIdentifier(value) => Kind::OpaqueIdentifier(value.clone()),
        PartyReference::Uri(value) => Kind::Uri(value.clone()),
        PartyReference::Absent => Kind::Absent(Box::default()),
    };
    credential_pb::PartyReference {
        kind: Some(kind),
        ..credential_pb::PartyReference::default()
    }
}

/// Convert a protobuf party reference into the semantic model.
pub fn party_reference_from_proto(
    reference: &credential_pb::PartyReference,
) -> Result<PartyReference, CredentialError> {
    use credential_pb::__buffa::oneof::party_reference::Kind;

    match reference.kind.as_ref().ok_or(CredentialError::Proto(
        CredentialProtoReason::MissingField(CredentialProtoField::Subject),
    ))? {
        Kind::Did(value) => Ok(PartyReference::Did(value.clone())),
        Kind::X509Subject(value) => Ok(PartyReference::X509Subject(
            x509_subject_reference_from_proto(value)?,
        )),
        Kind::PublicKey(value) => {
            let (alg, public_key) =
                public_key_material_from_proto(value).map_err(CredentialError::Claims)?;
            Ok(PartyReference::PublicKey(PublicKeyIdentity {
                alg,
                public_key,
            }))
        }
        Kind::FederationEntityId(value) => Ok(PartyReference::FederationEntityId(value.clone())),
        Kind::OpaqueIdentifier(value) => Ok(PartyReference::OpaqueIdentifier(value.clone())),
        Kind::Uri(value) => Ok(PartyReference::Uri(value.clone())),
        Kind::Absent(_) => Ok(PartyReference::Absent),
    }
}

/// Convert an explicit holder binding into protobuf.
pub fn holder_binding_to_proto(binding: &HolderBinding) -> credential_pb::HolderBinding {
    use credential_pb::__buffa::oneof::holder_binding::Mode;

    let mode = match binding {
        HolderBinding::CryptographicKey(value) => {
            Mode::CryptographicKey(Box::new(public_key_ref_to_proto(value)))
        }
        HolderBinding::ClaimsBased(claim_ids) => {
            Mode::ClaimsBased(Box::new(credential_pb::ClaimsBasedHolderBinding {
                claim_ids: claim_ids.clone(),
                ..credential_pb::ClaimsBasedHolderBinding::default()
            }))
        }
        HolderBinding::BearerWithoutBinding => Mode::Bearer(Box::default()),
    };
    credential_pb::HolderBinding {
        mode: Some(mode),
        ..credential_pb::HolderBinding::default()
    }
}

/// Convert a protobuf holder binding into the semantic model.
pub fn holder_binding_from_proto(
    binding: &credential_pb::HolderBinding,
) -> Result<HolderBinding, CredentialError> {
    use credential_pb::__buffa::oneof::holder_binding::Mode;

    match binding.mode.as_ref().ok_or(CredentialError::Proto(
        CredentialProtoReason::MissingField(CredentialProtoField::SubjectKey),
    ))? {
        Mode::CryptographicKey(value) => Ok(HolderBinding::CryptographicKey(
            public_key_ref_from_proto(value).map_err(CredentialError::Claims)?,
        )),
        Mode::ClaimsBased(value) => Ok(HolderBinding::ClaimsBased(value.claim_ids.clone())),
        Mode::Bearer(_) => Ok(HolderBinding::BearerWithoutBinding),
    }
}

fn x509_subject_reference_to_proto(
    reference: &X509SubjectReference,
) -> credential_pb::X509SubjectReference {
    use credential_pb::__buffa::oneof::x509subject_reference::Reference;

    let reference = match reference {
        X509SubjectReference::CertificateSha256(value) => {
            Reference::CertificateSha256(value.to_vec())
        }
        X509SubjectReference::IssuerAndSerial {
            issuer_name_der,
            serial_number,
        } => Reference::IssuerAndSerial(Box::new(credential_pb::X509IssuerAndSerial {
            issuer_name_der: issuer_name_der.clone(),
            serial_number: serial_number.clone(),
            ..credential_pb::X509IssuerAndSerial::default()
        })),
        X509SubjectReference::ValidatedCertificateDer(value) => {
            Reference::ValidatedCertificateDer(value.clone())
        }
    };
    credential_pb::X509SubjectReference {
        reference: Some(reference),
        ..credential_pb::X509SubjectReference::default()
    }
}

fn x509_subject_reference_from_proto(
    reference: &credential_pb::X509SubjectReference,
) -> Result<X509SubjectReference, CredentialError> {
    use credential_pb::__buffa::oneof::x509subject_reference::Reference;

    match reference.reference.as_ref().ok_or(CredentialError::Proto(
        CredentialProtoReason::MissingField(CredentialProtoField::Subject),
    ))? {
        Reference::CertificateSha256(value) => Ok(X509SubjectReference::CertificateSha256(
            <[u8; 32]>::try_from(value.as_slice()).map_err(|_| {
                CredentialError::Proto(CredentialProtoReason::InvalidFixedBytes(
                    CredentialProtoField::FixedBytes,
                ))
            })?,
        )),
        Reference::IssuerAndSerial(value) => Ok(X509SubjectReference::IssuerAndSerial {
            issuer_name_der: value.issuer_name_der.clone(),
            serial_number: value.serial_number.clone(),
        }),
        Reference::ValidatedCertificateDer(value) => {
            Ok(X509SubjectReference::ValidatedCertificateDer(value.clone()))
        }
    }
}

fn qeaa_compliance_to_proto_field(
    qeaa: Option<&QeaaCompliance>,
) -> Result<MessageField<audit_pb::QeaaCompliance, Inline<audit_pb::QeaaCompliance>>, CredentialError>
{
    qeaa.map(qeaa_compliance_to_proto)
        .transpose()
        .map(|value| value.map_or_else(MessageField::none, MessageField::some))
}

fn qeaa_compliance_from_proto_field(
    qeaa: &MessageField<audit_pb::QeaaCompliance, Inline<audit_pb::QeaaCompliance>>,
) -> Result<Option<QeaaCompliance>, CredentialError> {
    qeaa.as_option().map(qeaa_compliance_from_proto).transpose()
}

fn qeaa_compliance_to_proto(
    qeaa: &QeaaCompliance,
) -> Result<audit_pb::QeaaCompliance, CredentialError> {
    Ok(audit_pb::QeaaCompliance {
        qtsp: MessageField::some(audit_pb::QtspInfo {
            tsp_name: qeaa.qtsp.tsp_name.clone(),
            tsp_id: qeaa.qtsp.tsp_id.clone(),
            tsp_role: EnumValue::from(qtsp_role_to_proto(qeaa.qtsp.tsp_role)),
            ..audit_pb::QtspInfo::default()
        }),
        policies: MessageField::some(audit_pb::QeaaPolicies {
            policy_id: qeaa.policies.policy_id.clone(),
            standards: qeaa.policies.standards.clone(),
            ..audit_pb::QeaaPolicies::default()
        }),
        issuer_credential: MessageField::some(audit_pb::IssuerCredential {
            kind: EnumValue::from(issuer_credential_kind_to_proto(qeaa.issuer_credential.kind)),
            cert_fingerprint_sha256: qeaa.issuer_credential.cert_fingerprint_sha256.to_vec(),
            cert_chain_der: qeaa.issuer_credential.cert_chain_der.clone(),
            trusted_list_ref: qeaa.issuer_credential.trusted_list_ref.clone(),
            policy_oids: qeaa.issuer_credential.policy_oids.clone(),
            qcstatements_oids: qeaa.issuer_credential.qcstatements_oids.clone(),
            ..audit_pb::IssuerCredential::default()
        }),
        key_management: MessageField::some(audit_pb::KeyManagement {
            signing_key_id: qeaa.key_management.signing_key_id.clone(),
            protection: EnumValue::from(key_protection_to_proto(qeaa.key_management.protection)),
            ..audit_pb::KeyManagement::default()
        }),
        identity_proofing: MessageField::some(audit_pb::IdentityProofing {
            standard: qeaa.identity_proofing.standard.clone(),
            loip: EnumValue::from(identity_proofing_level_to_proto(
                qeaa.identity_proofing.loip,
            )),
            evidence_ref: qeaa.identity_proofing.evidence_ref.clone(),
            evidence_hash: qeaa.identity_proofing.evidence_hash.to_vec(),
            ..audit_pb::IdentityProofing::default()
        }),
        audit: MessageField::some(audit_pb::AuditInfo {
            audit_standard: qeaa.audit.audit_standard.clone(),
            audit_report_ref: qeaa.audit.audit_report_ref.clone(),
            audit_report_hash: qeaa.audit.audit_report_hash.to_vec(),
            period_from_unix: qeaa.audit.period_from_unix,
            period_to_unix: qeaa.audit.period_to_unix,
            ..audit_pb::AuditInfo::default()
        }),
        revocation: MessageField::some(audit_pb::RevocationPolicy {
            status_method: EnumValue::from(status_method_to_proto(qeaa.revocation.status_method)),
            signing_key_id: qeaa.revocation.signing_key_id.clone(),
            max_status_age_seconds: qeaa.revocation.max_status_age_seconds,
            ..audit_pb::RevocationPolicy::default()
        }),
        ..audit_pb::QeaaCompliance::default()
    })
}
