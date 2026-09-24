// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Own and zeroize decoded generated presentation messages.

use core::fmt;

use reallyme_ssi_proto::generated::proto::identity::presentation::v1 as pb;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Non-cloneable owner for a decoded generated presentation message.
///
/// Buffa messages must implement `Clone` and their generated ProtoJSON
/// deserializers are incompatible with adding `Drop` directly to each message.
/// Public decode operations return this wrapper, which recursively zeroizes all
/// schema-known presentation material. The generated message is deliberately
/// not exposed outside this crate: a borrowed generated value implements
/// `Clone` and ProtoJSON serialization, either of which could create an
/// unmanaged plaintext copy.
pub struct SensitivePresentationProto {
    inner: pb::Presentation,
}

impl SensitivePresentationProto {
    pub(crate) fn new(inner: pb::Presentation) -> Self {
        Self { inner }
    }

    /// Borrow the generated protobuf message without transferring ownership.
    pub(crate) fn as_proto(&self) -> &pb::Presentation {
        &self.inner
    }

    /// Returns whether all schema-known presentation variants have been removed.
    #[must_use]
    pub fn is_cleared(&self) -> bool {
        self.inner.kind.is_none()
    }
}

impl fmt::Debug for SensitivePresentationProto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitivePresentationProto(<redacted>)")
    }
}

impl PartialEq for SensitivePresentationProto {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Zeroize for SensitivePresentationProto {
    fn zeroize(&mut self) {
        zeroize_presentation_proto(&mut self.inner);
    }
}

impl Drop for SensitivePresentationProto {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SensitivePresentationProto {}

/// Recursively clear all schema-known material in a generated presentation.
///
/// Canonical operation owners call this helper when they embed the package's
/// generated message. Keeping cleanup here ensures a schema change cannot
/// silently diverge across operation and package boundaries.
pub fn zeroize_presentation_proto(presentation: &mut pb::Presentation) {
    if let Some(mut kind) = presentation.kind.take() {
        match &mut kind {
            pb::__buffa::oneof::presentation::Kind::Zk(value) => {
                zeroize_zk_presentation(value);
            }
            pb::__buffa::oneof::presentation::Kind::SdJwtVc(value) => {
                zeroize_sd_jwt_presentation(value);
            }
            pb::__buffa::oneof::presentation::Kind::Mdoc(value) => {
                zeroize_mdoc_presentation(value);
            }
        }
    }
    presentation.__buffa_unknown_fields.clear();
}

fn zeroize_mdoc_presentation(presentation: &mut pb::MdocPresentation) {
    presentation.device_response.zeroize();
    presentation.envelope_hash.zeroize();
    presentation.doc_type.zeroize();
    presentation.__buffa_unknown_fields.clear();
}

fn zeroize_sd_jwt_presentation(presentation: &mut pb::SdJwtVcPresentation) {
    presentation.sd_jwt.zeroize();
    presentation.disclosures.zeroize();
    presentation.kb_jwt.zeroize();
    presentation.vct.zeroize();
    presentation.envelope_hash.zeroize();
    presentation.__buffa_unknown_fields.clear();
}

fn zeroize_zk_presentation(presentation: &mut pb::ZkPresentation) {
    if let Some(freshness) = presentation.freshness.as_option_mut() {
        zeroize_freshness(freshness);
    }
    presentation.freshness = Default::default();

    if let Some(credential) = presentation.credential.as_option_mut() {
        zeroize_credential_reference(credential);
    }
    presentation.credential = Default::default();

    for disclosure in &mut presentation.disclosures {
        zeroize_claim_disclosure(disclosure);
    }
    presentation.disclosures.clear();

    if let Some(proof) = presentation.zk_proof.as_option_mut() {
        zeroize_zk_proof(proof);
    }
    presentation.zk_proof = Default::default();

    if let Some(qeaa) = presentation.qeaa.as_option_mut() {
        zeroize_qeaa_hints(qeaa);
    }
    presentation.qeaa = Default::default();
    presentation.__buffa_unknown_fields.clear();
}

fn zeroize_freshness(freshness: &mut pb::PresentationFreshness) {
    freshness.challenge.zeroize();
    freshness.audience_hash.zeroize();
    freshness.expiry_unix.zeroize();
    freshness.__buffa_unknown_fields.clear();
}

fn zeroize_credential_reference(credential: &mut pb::CredentialReference) {
    credential.envelope_hash.zeroize();
    credential.issuer_did.zeroize();
    if let Some(status) = credential.status.as_option_mut() {
        zeroize_status_reference(status);
    }
    credential.status = Default::default();
    credential.__buffa_unknown_fields.clear();
}

fn zeroize_status_reference(status: &mut pb::CredentialStatusRef) {
    status.status_list_url.zeroize();
    status.status_list_id.zeroize();
    status.status_list_index.zeroize();
    status.purpose = Default::default();
    status.__buffa_unknown_fields.clear();
}

fn zeroize_claim_disclosure(disclosure: &mut pb::ClaimDisclosure) {
    disclosure.claim_path.zeroize();
    disclosure.mode = Default::default();
    if let Some(mut value) = disclosure.value.take() {
        match &mut value {
            pb::__buffa::oneof::claim_disclosure::Value::RevealedValue(bytes) => {
                bytes.zeroize();
            }
            pb::__buffa::oneof::claim_disclosure::Value::Threshold(threshold) => {
                threshold.zeroize();
            }
            pb::__buffa::oneof::claim_disclosure::Value::Range(range) => {
                range.min.zeroize();
                range.max.zeroize();
                range.__buffa_unknown_fields.clear();
            }
            pb::__buffa::oneof::claim_disclosure::Value::Set(set) => {
                set.values.zeroize();
                set.__buffa_unknown_fields.clear();
            }
        }
    }
    disclosure.__buffa_unknown_fields.clear();
}

fn zeroize_zk_proof(proof: &mut pb::ZkProof) {
    proof.circuit_id.zeroize();
    proof.circuit_version.zeroize();
    proof.vk_id.zeroize();
    proof.proof_bytes.zeroize();
    proof.proof_suite = Default::default();
    proof.artifact_manifest_sha256.zeroize();

    let public_inputs = core::mem::take(&mut proof.public_inputs);
    for (mut name, mut value) in public_inputs {
        name.zeroize();
        value.zeroize();
    }
    proof.__buffa_unknown_fields.clear();
}

fn zeroize_qeaa_hints(hints: &mut pb::QeaaVerifierHints) {
    hints.required.zeroize();
    hints.audit_report_hash.zeroize();
    hints.max_status_age_seconds.zeroize();
    hints.__buffa_unknown_fields.clear();
}

#[cfg(test)]
#[path = "own_presentation_proto_tests.rs"]
mod tests;
