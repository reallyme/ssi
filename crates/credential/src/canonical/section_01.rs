// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    validate_credential_unsigned_envelope, AssuranceLevel, CredentialCanonicalReason,
    CredentialEnvelope, CredentialError, CredentialKind, CredentialStatus, CredentialSubject,
    HolderBinding, PartyReference, PublicKeyIdentity, X509SubjectReference,
};
use reallyme_codec::cbor::{encode_dag_cbor, CborValue};
use reallyme_credential_audit::{
    AuditInfo, IdentityProofing, IdentityProofingLevel, IssuerCredential, IssuerCredentialKind,
    KeyManagement, KeyProtection, QeaaCompliance, QeaaPolicies, QtspInfo, QtspRole,
    RevocationPolicy, StatusMethod,
};
use reallyme_credential_claims::{
    ClaimsCommitment, CommitmentLimits, CredentialAlgorithm, DomainTags, KeyAssurance,
    KeyReference, PublicKeyRef, PublicKeyRepresentation, RawPublicKeySerialization,
};
use reallyme_credential_status::StatusPurpose;
use reallyme_crypto::{core::HashAlgorithm, dispatch::hash_digest};

/// Produce canonical CBOR bytes covered by the issuer signature.
///
/// The issuer signature is intentionally excluded. All other public envelope
/// fields, including QEAA evidence when present, are encoded with proto-JSON
/// field names and explicit protocol labels.
pub fn credential_signing_payload(
    envelope: &CredentialEnvelope,
) -> Result<Vec<u8>, CredentialError> {
    validate_credential_unsigned_envelope(envelope)?;
    encode_dag_cbor(&credential_envelope_to_cbor(envelope)?)
        .map_err(|_| CredentialError::Canonical(CredentialCanonicalReason::Encoding))
}

/// Compute `SHA-256(credential_signing_payload(envelope))`.
pub fn credential_envelope_hash(
    envelope: &CredentialEnvelope,
) -> Result<[u8; 32], CredentialError> {
    let payload = credential_signing_payload(envelope)?;
    let digest = hash_digest(HashAlgorithm::Sha2_256, payload.as_slice())
        .map_err(|_| CredentialError::Canonical(CredentialCanonicalReason::Hash))?;
    <[u8; 32]>::try_from(digest.as_slice())
        .map_err(|_| CredentialError::Canonical(CredentialCanonicalReason::Hash))
}

fn credential_envelope_to_cbor(
    envelope: &CredentialEnvelope,
) -> Result<CborValue, CredentialError> {
    let valid_from = envelope.valid_from;
    let valid_until = envelope.valid_until;

    let mut entries = vec![
        (
            "kind".to_owned(),
            CborValue::String(kind_label(envelope.kind).to_owned()),
        ),
        (
            "profileId".to_owned(),
            CborValue::String(envelope.profile_id.clone()),
        ),
        (
            "assurance".to_owned(),
            CborValue::String(assurance_label(envelope.assurance).to_owned()),
        ),
        (
            "issuerReference".to_owned(),
            party_reference_to_cbor(&envelope.issuer_reference),
        ),
        (
            "issuerCountry".to_owned(),
            CborValue::String(envelope.issuer_country.clone()),
        ),
        ("validFrom".to_owned(), CborValue::Int(valid_from)),
        ("validUntil".to_owned(), CborValue::Int(valid_until)),
        (
            "status".to_owned(),
            credential_status_to_cbor(&envelope.status)?,
        ),
        (
            "subject".to_owned(),
            credential_subject_to_cbor(&envelope.subject),
        ),
        (
            "claimsCommitment".to_owned(),
            claims_commitment_to_cbor(&envelope.claims_commitment),
        ),
    ];

    if let Some(qeaa) = &envelope.qeaa_compliance {
        entries.push(("qeaaCompliance".to_owned(), qeaa_compliance_to_cbor(qeaa)?));
    }

    Ok(CborValue::Map(entries))
}

fn credential_subject_to_cbor(subject: &CredentialSubject) -> CborValue {
    CborValue::Map(vec![
        (
            "subjectReference".to_owned(),
            party_reference_to_cbor(&subject.subject_reference),
        ),
        (
            "holderBinding".to_owned(),
            holder_binding_to_cbor(&subject.holder_binding),
        ),
    ])
}

fn credential_status_to_cbor(status: &CredentialStatus) -> Result<CborValue, CredentialError> {
    Ok(CborValue::Map(vec![
        (
            "statusListUrl".to_owned(),
            CborValue::String(status.status_list_url.clone()),
        ),
        (
            "statusListId".to_owned(),
            CborValue::Bytes(status.status_list_id.to_vec()),
        ),
        (
            "statusListIndex".to_owned(),
            CborValue::Int(i64::try_from(status.status_list_index).map_err(|_| {
                CredentialError::Canonical(CredentialCanonicalReason::IntegerOutOfRange)
            })?),
        ),
        (
            "purpose".to_owned(),
            CborValue::String(status_purpose_label(status.purpose).to_owned()),
        ),
    ]))
}

fn claims_commitment_to_cbor(commitment: &ClaimsCommitment) -> CborValue {
    CborValue::Map(vec![
        (
            "merkleRoot".to_owned(),
            CborValue::Bytes(commitment.merkle_root.clone()),
        ),
        (
            "claimsetId".to_owned(),
            CborValue::String(commitment.claimset_id.clone()),
        ),
        (
            "hashAlg".to_owned(),
            CborValue::String(commitment.hash_alg.clone()),
        ),
        (
            "valueEncoding".to_owned(),
            CborValue::String(commitment.value_encoding.clone()),
        ),
        (
            "domainTags".to_owned(),
            domain_tags_to_cbor(&commitment.domain_tags),
        ),
        (
            "limits".to_owned(),
            commitment_limits_to_cbor(commitment.limits),
        ),
    ])
}

fn domain_tags_to_cbor(tags: &DomainTags) -> CborValue {
    CborValue::Map(vec![
        ("clm".to_owned(), CborValue::String(tags.clm.clone())),
        ("leaf".to_owned(), CborValue::String(tags.leaf.clone())),
        ("node".to_owned(), CborValue::String(tags.node.clone())),
    ])
}

fn commitment_limits_to_cbor(limits: CommitmentLimits) -> CborValue {
    CborValue::Map(vec![
        (
            "maxValueLen".to_owned(),
            CborValue::Int(i64::from(limits.max_value_len)),
        ),
        (
            "saltLen".to_owned(),
            CborValue::Int(i64::from(limits.salt_len)),
        ),
    ])
}

fn public_key_ref_to_cbor(key: &PublicKeyRef) -> CborValue {
    CborValue::Map(vec![
        (
            "alg".to_owned(),
            CborValue::String(credential_algorithm_label(key.alg).to_owned()),
        ),
        (
            "reference".to_owned(),
            key_reference_to_cbor(&key.reference),
        ),
        (
            "publicKey".to_owned(),
            public_key_representation_to_cbor(&key.public_key),
        ),
        (
            "assurance".to_owned(),
            key_assurance_to_cbor(&key.assurance),
        ),
    ])
}

fn party_reference_to_cbor(reference: &PartyReference) -> CborValue {
    let (kind, value) = match reference {
        PartyReference::Did(value) => ("did", CborValue::String(value.clone())),
        PartyReference::X509Subject(value) => ("x509Subject", x509_subject_to_cbor(value)),
        PartyReference::PublicKey(value) => ("publicKey", public_key_identity_to_cbor(value)),
        PartyReference::FederationEntityId(value) => {
            ("federationEntityId", CborValue::String(value.clone()))
        }
        PartyReference::OpaqueIdentifier(value) => {
            ("opaqueIdentifier", CborValue::String(value.clone()))
        }
        PartyReference::Uri(value) => ("uri", CborValue::String(value.clone())),
        PartyReference::Absent => ("absent", CborValue::Bool(true)),
    };
    CborValue::Map(vec![
        ("kind".to_owned(), CborValue::String(kind.to_owned())),
        ("value".to_owned(), value),
    ])
}

fn public_key_identity_to_cbor(identity: &PublicKeyIdentity) -> CborValue {
    CborValue::Map(vec![
        (
            "alg".to_owned(),
            CborValue::String(credential_algorithm_label(identity.alg).to_owned()),
        ),
        (
            "representation".to_owned(),
            public_key_representation_to_cbor(&identity.public_key),
        ),
    ])
}

fn x509_subject_to_cbor(reference: &X509SubjectReference) -> CborValue {
    let (kind, value) = match reference {
        X509SubjectReference::CertificateSha256(value) => {
            ("certificateSha256", CborValue::Bytes(value.to_vec()))
        }
        X509SubjectReference::IssuerAndSerial {
            issuer_name_der,
            serial_number,
        } => (
            "issuerAndSerial",
            CborValue::Map(vec![
                (
                    "issuerNameDer".to_owned(),
                    CborValue::Bytes(issuer_name_der.clone()),
                ),
                (
                    "serialNumber".to_owned(),
                    CborValue::Bytes(serial_number.clone()),
                ),
            ]),
        ),
        X509SubjectReference::ValidatedCertificateDer(value) => {
            ("validatedCertificateDer", CborValue::Bytes(value.clone()))
        }
    };
    CborValue::Map(vec![
        ("kind".to_owned(), CborValue::String(kind.to_owned())),
        ("value".to_owned(), value),
    ])
}

fn holder_binding_to_cbor(binding: &HolderBinding) -> CborValue {
    match binding {
        HolderBinding::CryptographicKey(key) => CborValue::Map(vec![
            (
                "mode".to_owned(),
                CborValue::String("cryptographicKey".to_owned()),
            ),
            ("key".to_owned(), public_key_ref_to_cbor(key)),
        ]),
        HolderBinding::ClaimsBased(claims) => CborValue::Map(vec![
            (
                "mode".to_owned(),
                CborValue::String("claimsBased".to_owned()),
            ),
            ("claims".to_owned(), string_array_to_cbor(claims)),
        ]),
        HolderBinding::BearerWithoutBinding => CborValue::Map(vec![(
            "mode".to_owned(),
            CborValue::String("bearer".to_owned()),
        )]),
    }
}

fn key_reference_to_cbor(reference: &KeyReference) -> CborValue {
    match reference {
        KeyReference::DidVerificationMethod(value) => CborValue::Map(vec![
            (
                "kind".to_owned(),
                CborValue::String("didVerificationMethod".to_owned()),
            ),
            ("value".to_owned(), CborValue::String(value.clone())),
        ]),
        KeyReference::X509Certificate(value) => CborValue::Map(vec![
            (
                "kind".to_owned(),
                CborValue::String("x509Certificate".to_owned()),
            ),
            ("value".to_owned(), CborValue::Bytes(value.clone())),
        ]),
        KeyReference::DirectPublicKey => CborValue::Map(vec![(
            "kind".to_owned(),
            CborValue::String("directPublicKey".to_owned()),
        )]),
    }
}

fn public_key_representation_to_cbor(representation: &PublicKeyRepresentation) -> CborValue {
    let (kind, value) = match representation {
        PublicKeyRepresentation::JwkJson(value) => ("jwk", CborValue::Bytes(value.clone())),
        PublicKeyRepresentation::CoseKey(value) => ("coseKey", CborValue::Bytes(value.clone())),
        PublicKeyRepresentation::Multikey(value) => ("multikey", CborValue::String(value.clone())),
        PublicKeyRepresentation::SubjectPublicKeyInfoDer(value) => {
            ("spkiDer", CborValue::Bytes(value.clone()))
        }
        PublicKeyRepresentation::Raw {
            serialization,
            bytes,
        } => {
            let serialization = match serialization {
                RawPublicKeySerialization::FixedWidth => "fixedWidth",
                RawPublicKeySerialization::Sec1Compressed => "sec1Compressed",
                RawPublicKeySerialization::Sec1Uncompressed => "sec1Uncompressed",
            };
            (
                "raw",
                CborValue::Map(vec![
                    (
                        "serialization".to_owned(),
                        CborValue::String(serialization.to_owned()),
                    ),
                    ("bytes".to_owned(), CborValue::Bytes(bytes.clone())),
                ]),
            )
        }
    };
    CborValue::Map(vec![
        ("kind".to_owned(), CborValue::String(kind.to_owned())),
        ("value".to_owned(), value),
    ])
}

fn key_assurance_to_cbor(assurance: &KeyAssurance) -> CborValue {
    match assurance {
        KeyAssurance::None => CborValue::Map(vec![(
            "type".to_owned(),
            CborValue::String("none".to_owned()),
        )]),
        KeyAssurance::KeyAttestation(value) => CborValue::Map(vec![
            (
                "type".to_owned(),
                CborValue::String("keyAttestation".to_owned()),
            ),
            ("evidence".to_owned(), CborValue::Bytes(value.clone())),
        ]),
        KeyAssurance::HardwareAttestation(value) => CborValue::Map(vec![
            (
                "type".to_owned(),
                CborValue::String("hardwareAttestation".to_owned()),
            ),
            ("evidence".to_owned(), CborValue::Bytes(value.clone())),
        ]),
        KeyAssurance::X509Chain(values) => CborValue::Map(vec![
            ("type".to_owned(), CborValue::String("x509Chain".to_owned())),
            ("certificates".to_owned(), bytes_array_to_cbor(values)),
        ]),
    }
}

fn qeaa_compliance_to_cbor(qeaa: &QeaaCompliance) -> Result<CborValue, CredentialError> {
    Ok(CborValue::Map(vec![
        ("qtsp".to_owned(), qtsp_info_to_cbor(&qeaa.qtsp)),
        ("policies".to_owned(), qeaa_policies_to_cbor(&qeaa.policies)),
        (
            "issuerCredential".to_owned(),
            issuer_credential_to_cbor(&qeaa.issuer_credential),
        ),
        (
            "keyManagement".to_owned(),
            key_management_to_cbor(&qeaa.key_management),
        ),
        (
            "identityProofing".to_owned(),
            identity_proofing_to_cbor(&qeaa.identity_proofing),
        ),
        ("audit".to_owned(), audit_info_to_cbor(&qeaa.audit)?),
        (
            "revocation".to_owned(),
            revocation_policy_to_cbor(&qeaa.revocation),
        ),
    ]))
}

fn qtsp_info_to_cbor(qtsp: &QtspInfo) -> CborValue {
    CborValue::Map(vec![
        (
            "tspName".to_owned(),
            CborValue::String(qtsp.tsp_name.clone()),
        ),
        ("tspId".to_owned(), CborValue::String(qtsp.tsp_id.clone())),
        (
            "tspRole".to_owned(),
            CborValue::String(qtsp_role_label(qtsp.tsp_role).to_owned()),
        ),
    ])
}

fn qeaa_policies_to_cbor(policies: &QeaaPolicies) -> CborValue {
    CborValue::Map(vec![
        (
            "policyId".to_owned(),
            CborValue::String(policies.policy_id.clone()),
        ),
        (
            "standards".to_owned(),
            string_array_to_cbor(&policies.standards),
        ),
    ])
}
