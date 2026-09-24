// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Redacted diagnostics and memory hygiene for presentation domain models.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::model::{
    ClaimDisclosure, CredentialReference, CredentialStatusRef, DisclosureMode, MdocPresentation,
    Presentation, PresentationFreshness, QeaaVerifierHints, Range, SdJwtVcPresentation,
    StatusPurpose, ValueSet, ZkPresentation, ZkProof,
};

macro_rules! impl_redacted_debug {
    ($($type:ty => $name:literal),+ $(,)?) => {
        $(
            impl fmt::Debug for $type {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str(concat!($name, "(<redacted>)"))
                }
            }
        )+
    };
}

impl_redacted_debug!(
    Presentation => "Presentation",
    MdocPresentation => "MdocPresentation",
    SdJwtVcPresentation => "SdJwtVcPresentation",
    ZkPresentation => "ZkPresentation",
    PresentationFreshness => "PresentationFreshness",
    CredentialReference => "CredentialReference",
    CredentialStatusRef => "CredentialStatusRef",
    ClaimDisclosure => "ClaimDisclosure",
    Range => "Range",
    ValueSet => "ValueSet",
    ZkProof => "ZkProof",
    QeaaVerifierHints => "QeaaVerifierHints",
);

impl Zeroize for Presentation {
    fn zeroize(&mut self) {
        match self {
            Self::Zk(presentation) => presentation.zeroize(),
            Self::SdJwtVc(presentation) => presentation.zeroize(),
            Self::Mdoc(presentation) => presentation.zeroize(),
        }
    }
}

impl Zeroize for MdocPresentation {
    fn zeroize(&mut self) {
        self.device_response.zeroize();
        self.envelope_hash.zeroize();
        self.doc_type.zeroize();
    }
}

impl Zeroize for SdJwtVcPresentation {
    fn zeroize(&mut self) {
        self.sd_jwt.zeroize();
        self.disclosures.zeroize();
        self.kb_jwt.zeroize();
        self.vct.zeroize();
        self.envelope_hash.zeroize();
    }
}

impl Zeroize for ZkPresentation {
    fn zeroize(&mut self) {
        self.freshness.zeroize();
        self.credential.zeroize();
        self.disclosures.zeroize();
        self.zk_proof.zeroize();
        self.qeaa.zeroize();
    }
}

impl Zeroize for PresentationFreshness {
    fn zeroize(&mut self) {
        self.challenge.zeroize();
        self.audience_hash.zeroize();
        self.expiry_unix.zeroize();
    }
}

impl Zeroize for CredentialReference {
    fn zeroize(&mut self) {
        self.envelope_hash.zeroize();
        self.issuer_did.zeroize();
        self.status.zeroize();
    }
}

impl Zeroize for CredentialStatusRef {
    fn zeroize(&mut self) {
        self.status_list_url.zeroize();
        self.status_list_id.zeroize();
        self.status_list_index.zeroize();
        self.purpose = StatusPurpose::Unspecified;
    }
}

impl Zeroize for ClaimDisclosure {
    fn zeroize(&mut self) {
        self.claim_path.zeroize();
        self.mode = DisclosureMode::Unspecified;
        self.revealed_value.zeroize();
        self.threshold.zeroize();
        self.range.zeroize();
        self.set.zeroize();
    }
}

impl Zeroize for Range {
    fn zeroize(&mut self) {
        self.min.zeroize();
        self.max.zeroize();
    }
}

impl Zeroize for ValueSet {
    fn zeroize(&mut self) {
        self.values.zeroize();
    }
}

impl Zeroize for ZkProof {
    fn zeroize(&mut self) {
        self.circuit_id.zeroize();
        self.circuit_version.zeroize();
        self.vk_id.zeroize();
        self.proof_bytes.zeroize();
        self.proof_suite = crate::model::ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa;
        self.artifact_manifest_sha256.zeroize();

        let public_inputs = core::mem::take(&mut self.public_inputs);
        for (mut name, mut value) in public_inputs {
            name.zeroize();
            value.zeroize();
        }
    }
}

impl Zeroize for QeaaVerifierHints {
    fn zeroize(&mut self) {
        self.required.zeroize();
        self.audit_report_hash.zeroize();
        self.max_status_age_seconds.zeroize();
    }
}

macro_rules! impl_zeroize_on_drop {
    ($($type:ty),+ $(,)?) => {
        $(
            impl Drop for $type {
                fn drop(&mut self) {
                    self.zeroize();
                }
            }


impl ZeroizeOnDrop for $type {}
        )+
    };
}

impl_zeroize_on_drop!(
    Presentation,
    MdocPresentation,
    SdJwtVcPresentation,
    ZkPresentation,
    PresentationFreshness,
    CredentialReference,
    CredentialStatusRef,
    ClaimDisclosure,
    Range,
    ValueSet,
    ZkProof,
    QeaaVerifierHints,
);
