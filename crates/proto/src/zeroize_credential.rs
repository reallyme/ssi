// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Package-owned recursive cleanup for generated credential messages.

use crate::generated::proto::identity::audit::v1 as audit_pb;
use crate::generated::proto::identity::credential::v1 as pb;
use zeroize::Zeroize;

/// Recursively clears identifying credential and audit material in place.
///
/// Buffa messages intentionally remain generator-compatible and therefore do
/// not implement `Drop`. They also implement `Clone` and ProtoJSON; callers
/// must not create unmanaged copies of holder-private material. Boundary
/// owners must call this function before the allocation graph is released.
pub fn zeroize_credential_envelope(envelope: &mut pb::CredentialEnvelope) {
    envelope.kind = Default::default();
    envelope.profile_id.zeroize();
    envelope.assurance = Default::default();
    if let Some(reference) = envelope.issuer_reference.as_option_mut() {
        zeroize_party_reference(reference);
    }
    envelope.issuer_reference = Default::default();
    envelope.issuer_country.zeroize();
    zeroize_timestamp(&mut envelope.valid_from);
    zeroize_timestamp(&mut envelope.valid_until);
    if let Some(status) = envelope.status.as_option_mut() {
        status.status_list_url.zeroize();
        status.status_list_id.zeroize();
        status.status_list_index.zeroize();
        status.purpose = Default::default();
        status.__buffa_unknown_fields.clear();
    }
    envelope.status = Default::default();
    if let Some(subject) = envelope.subject.as_option_mut() {
        if let Some(reference) = subject.subject_reference.as_option_mut() {
            zeroize_party_reference(reference);
        }
        subject.subject_reference = Default::default();
        if let Some(binding) = subject.holder_binding.as_option_mut() {
            zeroize_holder_binding(binding);
        }
        subject.holder_binding = Default::default();
        subject.__buffa_unknown_fields.clear();
    }
    envelope.subject = Default::default();
    if let Some(commitment) = envelope.claims_commitment.as_option_mut() {
        commitment.merkle_root.zeroize();
        commitment.claimset_id.zeroize();
        commitment.hash_alg.zeroize();
        commitment.value_encoding.zeroize();
        if let Some(tags) = commitment.domain_tags.as_option_mut() {
            tags.clm.zeroize();
            tags.leaf.zeroize();
            tags.node.zeroize();
            tags.__buffa_unknown_fields.clear();
        }
        commitment.domain_tags = Default::default();
        if let Some(limits) = commitment.limits.as_option_mut() {
            limits.max_value_len.zeroize();
            limits.salt_len.zeroize();
            limits.__buffa_unknown_fields.clear();
        }
        commitment.limits = Default::default();
        commitment.__buffa_unknown_fields.clear();
    }
    envelope.claims_commitment = Default::default();
    if let Some(qeaa) = envelope.qeaa_compliance.as_option_mut() {
        zeroize_qeaa_compliance(qeaa);
    }
    envelope.qeaa_compliance = Default::default();
    if let Some(signature) = envelope.issuer_signature.as_option_mut() {
        zeroize_signature(signature);
    }
    envelope.issuer_signature = Default::default();
    envelope.__buffa_unknown_fields.clear();
}

/// Clear a generated credential status reference in place.
pub fn zeroize_credential_status(status: &mut pb::CredentialStatus) {
    status.status_list_url.zeroize();
    status.status_list_id.zeroize();
    status.status_list_index.zeroize();
    status.purpose = Default::default();
    status.__buffa_unknown_fields.clear();
}

/// Recursively clear holder-private claim openings and copied signature material.
pub fn zeroize_subject_private_bundle(bundle: &mut pb::SubjectPrivateBundle) {
    if let Some(holder_key) = bundle.holder_key.as_option_mut() {
        zeroize_public_key_ref(holder_key);
    }
    bundle.holder_key = Default::default();
    bundle.envelope_hash.zeroize();
    if let Some(signature) = bundle.issuer_signature.as_option_mut() {
        zeroize_signature(signature);
    }
    bundle.issuer_signature = Default::default();
    if let Some(tree) = bundle.tree.as_option_mut() {
        tree.depth.zeroize();
        tree.count.zeroize();
        tree.__buffa_unknown_fields.clear();
    }
    bundle.tree = Default::default();
    for claim in &mut bundle.claims {
        claim.claim_path.zeroize();
        claim.salt.zeroize();
        claim.value.zeroize();
        claim.index.zeroize();
        zeroize_byte_vectors(&mut claim.merkle_path);
        claim.__buffa_unknown_fields.clear();
    }
    bundle.claims.clear();
    bundle.__buffa_unknown_fields.clear();
}

fn zeroize_timestamp(
    timestamp: &mut buffa::MessageField<
        buffa_types::google::protobuf::Timestamp,
        buffa::Inline<buffa_types::google::protobuf::Timestamp>,
    >,
) {
    if let Some(value) = timestamp.as_option_mut() {
        value.seconds.zeroize();
        value.nanos.zeroize();
        value.__buffa_unknown_fields.clear();
    }
    *timestamp = Default::default();
}

/// Recursively clear a generated public-key reference.
pub fn zeroize_public_key_ref(key: &mut pb::PublicKeyRef) {
    if let Some(reference) = key.reference.as_option_mut() {
        zeroize_key_reference(reference);
    }
    key.reference = Default::default();
    if let Some(public_key) = key.public_key.as_option_mut() {
        zeroize_public_key_material(public_key);
    }
    key.public_key = Default::default();
    if let Some(assurance) = key.assurance.as_option_mut() {
        zeroize_key_assurance(assurance);
    }
    key.assurance = Default::default();
    key.__buffa_unknown_fields.clear();
}

fn zeroize_signature(signature: &mut pb::Signature) {
    if let Some(key) = signature.verification_key.as_option_mut() {
        zeroize_public_key_ref(key);
    }
    signature.verification_key = Default::default();
    signature.raw_rs.zeroize();
    signature.__buffa_unknown_fields.clear();
}

fn zeroize_public_key_material(key: &mut pb::PublicKeyMaterial) {
    use pb::__buffa::oneof::public_key_material::Representation;

    key.alg = Default::default();
    if let Some(representation) = &mut key.representation {
        match representation {
            Representation::JwkJson(bytes)
            | Representation::CoseKey(bytes)
            | Representation::SubjectPublicKeyInfoDer(bytes) => bytes.zeroize(),
            Representation::Multikey(value) => value.zeroize(),
            Representation::Raw(raw) => {
                raw.serialization = Default::default();
                raw.bytes.zeroize();
                raw.__buffa_unknown_fields.clear();
            }
        }
    }
    key.representation = None;
    key.__buffa_unknown_fields.clear();
}

fn zeroize_key_reference(reference: &mut pb::KeyReference) {
    use pb::__buffa::oneof::key_reference::Kind;

    if let Some(kind) = &mut reference.kind {
        match kind {
            Kind::DidVerificationMethod(value) => value.zeroize(),
            Kind::X509CertificateDer(value) => value.zeroize(),
            Kind::DirectPublicKey(value) => value.__buffa_unknown_fields.clear(),
        }
    }
    reference.kind = None;
    reference.__buffa_unknown_fields.clear();
}

fn zeroize_key_assurance(assurance: &mut pb::KeyAssurance) {
    use pb::__buffa::oneof::key_assurance::Kind;

    if let Some(kind) = &mut assurance.kind {
        match kind {
            Kind::None(value) => value.__buffa_unknown_fields.clear(),
            Kind::KeyAttestation(value) | Kind::HardwareAttestation(value) => value.zeroize(),
            Kind::X509Chain(chain) => {
                zeroize_byte_vectors(&mut chain.certificates_der);
                chain.__buffa_unknown_fields.clear();
            }
        }
    }
    assurance.kind = None;
    assurance.__buffa_unknown_fields.clear();
}

/// Recursively clear a generated party reference.
pub fn zeroize_party_reference(reference: &mut pb::PartyReference) {
    use pb::__buffa::oneof::party_reference::Kind;

    if let Some(kind) = &mut reference.kind {
        match kind {
            Kind::Did(value)
            | Kind::FederationEntityId(value)
            | Kind::OpaqueIdentifier(value)
            | Kind::Uri(value) => value.zeroize(),
            Kind::X509Subject(subject) => {
                use pb::__buffa::oneof::x509subject_reference::Reference;
                if let Some(subject_reference) = &mut subject.reference {
                    match subject_reference {
                        Reference::CertificateSha256(value)
                        | Reference::ValidatedCertificateDer(value) => value.zeroize(),
                        Reference::IssuerAndSerial(value) => {
                            value.issuer_name_der.zeroize();
                            value.serial_number.zeroize();
                            value.__buffa_unknown_fields.clear();
                        }
                    }
                }
                subject.reference = None;
                subject.__buffa_unknown_fields.clear();
            }
            Kind::PublicKey(key) => zeroize_public_key_material(key),
            Kind::Absent(value) => value.__buffa_unknown_fields.clear(),
        }
    }
    reference.kind = None;
    reference.__buffa_unknown_fields.clear();
}

/// Recursively clear a generated holder binding.
pub fn zeroize_holder_binding(binding: &mut pb::HolderBinding) {
    use pb::__buffa::oneof::holder_binding::Mode;

    if let Some(mode) = &mut binding.mode {
        match mode {
            Mode::CryptographicKey(key) => zeroize_public_key_ref(key),
            Mode::ClaimsBased(value) => {
                zeroize_strings(&mut value.claim_ids);
                value.__buffa_unknown_fields.clear();
            }
            Mode::Bearer(value) => value.__buffa_unknown_fields.clear(),
        }
    }
    binding.mode = None;
    binding.__buffa_unknown_fields.clear();
}

fn zeroize_strings(values: &mut Vec<String>) {
    for value in values.iter_mut() {
        value.zeroize();
    }
    values.clear();
}

fn zeroize_byte_vectors(values: &mut Vec<Vec<u8>>) {
    for value in values.iter_mut() {
        value.zeroize();
    }
    values.clear();
}

/// Recursively clear generated QEAA audit evidence in place.
pub fn zeroize_qeaa_compliance(qeaa: &mut audit_pb::QeaaCompliance) {
    if let Some(qtsp) = qeaa.qtsp.as_option_mut() {
        qtsp.tsp_name.zeroize();
        qtsp.tsp_id.zeroize();
        qtsp.tsp_role = Default::default();
        qtsp.__buffa_unknown_fields.clear();
    }
    qeaa.qtsp = Default::default();
    if let Some(policies) = qeaa.policies.as_option_mut() {
        policies.policy_id.zeroize();
        zeroize_strings(&mut policies.standards);
        policies.__buffa_unknown_fields.clear();
    }
    qeaa.policies = Default::default();
    if let Some(credential) = qeaa.issuer_credential.as_option_mut() {
        credential.kind = Default::default();
        credential.cert_fingerprint_sha256.zeroize();
        zeroize_byte_vectors(&mut credential.cert_chain_der);
        credential.trusted_list_ref.zeroize();
        zeroize_strings(&mut credential.policy_oids);
        zeroize_strings(&mut credential.qcstatements_oids);
        credential.__buffa_unknown_fields.clear();
    }
    qeaa.issuer_credential = Default::default();
    if let Some(key_management) = qeaa.key_management.as_option_mut() {
        key_management.signing_key_id.zeroize();
        key_management.protection = Default::default();
        key_management.__buffa_unknown_fields.clear();
    }
    qeaa.key_management = Default::default();
    if let Some(proofing) = qeaa.identity_proofing.as_option_mut() {
        proofing.standard.zeroize();
        proofing.loip = Default::default();
        proofing.evidence_ref.zeroize();
        proofing.evidence_hash.zeroize();
        proofing.__buffa_unknown_fields.clear();
    }
    qeaa.identity_proofing = Default::default();
    if let Some(audit) = qeaa.audit.as_option_mut() {
        audit.audit_standard.zeroize();
        audit.audit_report_ref.zeroize();
        audit.audit_report_hash.zeroize();
        audit.period_from_unix.zeroize();
        audit.period_to_unix.zeroize();
        audit.__buffa_unknown_fields.clear();
    }
    qeaa.audit = Default::default();
    if let Some(revocation) = qeaa.revocation.as_option_mut() {
        revocation.status_method = Default::default();
        revocation.signing_key_id.zeroize();
        revocation.max_status_age_seconds.zeroize();
        revocation.__buffa_unknown_fields.clear();
    }
    qeaa.revocation = Default::default();
    qeaa.__buffa_unknown_fields.clear();
}

#[cfg(test)]
#[path = "zeroize_credential_tests.rs"]
mod tests;
