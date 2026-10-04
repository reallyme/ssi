// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Binding and consistency checks across authenticated WRPRC representations.

use super::{
    AuthenticatedRegistrationCertificate, AuthenticatedRepresentation,
    ParsedRegistrationCertificate, RegistrationCertificateBinding, RegistrationCertificateProof,
};
use crate::{ArtifactDigest, RegistrationError, RegistrationErrorReason};

const MAX_REPRESENTATIONS: usize = 2;

/// Combines one or both proof receipts for the same WRPRC and checks the
/// local binding fields that have counterparts in the signed claims.
///
/// Each receipt already proved signature validity and that its trusted
/// evaluation time fell within the signed `iat`/`exp` period. This function
/// asserts neither issuer nor certification-path trust.
pub fn authenticate_registration_certificate(
    proofs: Vec<RegistrationCertificateProof>,
    binding: RegistrationCertificateBinding,
) -> Result<AuthenticatedRegistrationCertificate, RegistrationError> {
    if proofs.is_empty() || proofs.len() > MAX_REPRESENTATIONS {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::ResourceLimitExceeded,
        ));
    }
    let mut parsed_result: Option<ParsedRegistrationCertificate> = None;
    let mut signer_digest: Option<ArtifactDigest> = None;
    let mut presented_certificate_chain_der: Option<Vec<Vec<u8>>> = None;
    let mut representations = Vec::new();
    for mut proof in proofs {
        if representations
            .iter()
            .any(|item: &AuthenticatedRepresentation| item.format == proof.format)
        {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::InvalidField,
            ));
        }
        let parsed = proof
            .parsed
            .take()
            .ok_or_else(|| RegistrationError::from_reason(RegistrationErrorReason::MissingField))?;
        if parsed.relying_party_id() != binding.relying_party_id()
            || parsed.intermediary_id() != binding.intermediary_association_id()
            || parsed.registry_reference_digest != binding.national_register_reference_digest
        {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::SemanticBindingMismatch,
            ));
        }
        let current_signer_der =
            proof
                .presented_certificate_chain_der
                .first()
                .ok_or_else(|| {
                    RegistrationError::from_reason(
                        RegistrationErrorReason::MissingSignerCertificate,
                    )
                })?;
        let current_signer = ArtifactDigest::of(current_signer_der);
        if signer_digest.is_some_and(|existing| existing != current_signer) {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::AuthenticationReceiptMismatch,
            ));
        }
        if let Some(existing) = presented_certificate_chain_der.as_ref() {
            if existing.first() != proof.presented_certificate_chain_der.first() {
                return Err(RegistrationError::from_reason(
                    RegistrationErrorReason::AuthenticationReceiptMismatch,
                ));
            }
        } else {
            presented_certificate_chain_der = Some(proof.presented_certificate_chain_der.clone());
        }
        if let Some(existing) = parsed_result.as_ref() {
            if existing.semantic_content_digest != parsed.semantic_content_digest
                || existing.relying_party_id != parsed.relying_party_id
                || existing.intermediary_id != parsed.intermediary_id
                || existing.registry_reference_digest != parsed.registry_reference_digest
                || existing.registry_uri != parsed.registry_uri
                || existing.status_list_uri_digest != parsed.status_list_uri_digest
                || existing.status_list_uri != parsed.status_list_uri
                || existing.status_list_index != parsed.status_list_index
                || existing.issued_at != parsed.issued_at
                || existing.expires_at != parsed.expires_at
            {
                return Err(RegistrationError::from_reason(
                    RegistrationErrorReason::SemanticBindingMismatch,
                ));
            }
        } else {
            parsed_result = Some(parsed);
        }
        signer_digest = Some(current_signer);
        representations.push(AuthenticatedRepresentation {
            format: proof.format,
            digest: proof.representation_digest,
        });
    }
    let parsed = parsed_result
        .ok_or_else(|| RegistrationError::from_reason(RegistrationErrorReason::MissingField))?;
    let signer_certificate_digest = signer_digest.ok_or_else(|| {
        RegistrationError::from_reason(RegistrationErrorReason::MissingSignerCertificate)
    })?;
    let presented_certificate_chain_der = presented_certificate_chain_der.ok_or_else(|| {
        RegistrationError::from_reason(RegistrationErrorReason::MissingSignerCertificate)
    })?;
    Ok(AuthenticatedRegistrationCertificate {
        representations,
        signer_certificate_digest,
        presented_certificate_chain_der,
        parsed,
        binding,
    })
}
