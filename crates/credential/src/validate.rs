// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::model::MAX_SIGNATURE_BYTES;
use crate::{
    credential_envelope_hash, CredentialEnvelope, CredentialError, CredentialInvalidReason,
    CredentialKind, HolderBinding, PartyReference, X509SubjectReference,
    MAX_CREDENTIAL_COUNTRY_BYTES, MAX_CREDENTIAL_TEXT_BYTES, MAX_PUBLIC_KEY_BYTES,
    MAX_STATUS_LIST_URL_BYTES,
};
use reallyme_credential_audit::validate_qeaa_compliance;
use reallyme_credential_claims::{
    validate_claims_commitment, validate_public_key_ref as validate_claims_public_key_ref,
    validate_public_key_representation, verify_subject_private_bundle, PublicKeyRef, Signature,
    SubjectPrivateBundle,
};
use reallyme_trust_x509::{validate_certificate_der, validate_x509_name_der};
use std::collections::BTreeSet;

/// Validate a public credential envelope without resolving network trust data.
pub fn validate_credential_envelope(envelope: &CredentialEnvelope) -> Result<(), CredentialError> {
    validate_credential_unsigned_envelope(envelope)?;
    validate_signature(&envelope.issuer_signature)
}

/// Validate the unsigned portion of a public credential envelope.
///
/// This is the validation needed before deriving the canonical issuer signing
/// payload. The issuer signature is excluded from that payload, so issuance
/// code must be able to derive it before the signature bytes exist.
pub fn validate_credential_unsigned_envelope(
    envelope: &CredentialEnvelope,
) -> Result<(), CredentialError> {
    validate_text(
        envelope.profile_id.as_str(),
        MAX_CREDENTIAL_TEXT_BYTES,
        CredentialInvalidReason::InvalidProfileId,
    )?;
    validate_party_reference(&envelope.issuer_reference, PartyReferenceContext::Issuer)?;
    validate_text(
        envelope.issuer_country.as_str(),
        MAX_CREDENTIAL_COUNTRY_BYTES,
        CredentialInvalidReason::InvalidIssuerCountry,
    )?;
    if envelope.valid_from < 0 || envelope.valid_until <= envelope.valid_from {
        return Err(CredentialError::InvalidInput(
            CredentialInvalidReason::InvalidValidityWindow,
        ));
    }

    validate_text(
        envelope.status.status_list_url.as_str(),
        MAX_STATUS_LIST_URL_BYTES,
        CredentialInvalidReason::InvalidStatusListUrl,
    )?;
    if i64::try_from(envelope.status.status_list_index).is_err() {
        return Err(CredentialError::InvalidInput(
            CredentialInvalidReason::InvalidStatusListIndex,
        ));
    }
    validate_party_reference(
        &envelope.subject.subject_reference,
        PartyReferenceContext::CredentialSubject,
    )?;
    validate_holder_binding(&envelope.subject.holder_binding)?;
    validate_claims_commitment(&envelope.claims_commitment).map_err(CredentialError::Claims)?;
    if envelope.profile_id != envelope.claims_commitment.claimset_id {
        return Err(CredentialError::InvalidInput(
            CredentialInvalidReason::ProfileClaimsetMismatch,
        ));
    }

    match (envelope.kind, envelope.qeaa_compliance.as_ref()) {
        (CredentialKind::Qeaa, Some(qeaa)) => validate_qeaa_compliance(
            qeaa,
            u64::try_from(envelope.valid_from).map_err(|_| {
                CredentialError::InvalidInput(CredentialInvalidReason::InvalidValidityWindow)
            })?,
        )
        .map_err(|_| CredentialError::Qeaa),
        (CredentialKind::Qeaa, None) => Err(CredentialError::InvalidInput(
            CredentialInvalidReason::MissingQeaaCompliance,
        )),
        (_, Some(_)) => Err(CredentialError::InvalidInput(
            CredentialInvalidReason::UnexpectedQeaaCompliance,
        )),
        (_, None) => Ok(()),
    }
}

/// Validate the public envelope together with the holder-private claim openings.
pub fn validate_credential_with_bundle(
    envelope: &CredentialEnvelope,
    bundle: &SubjectPrivateBundle,
) -> Result<(), CredentialError> {
    validate_credential_envelope(envelope)?;
    verify_subject_private_bundle(&envelope.claims_commitment, bundle)
        .map_err(CredentialError::Claims)?;
    let envelope_hash = credential_envelope_hash(envelope)?;
    let expected_holder_key = match &envelope.subject.holder_binding {
        HolderBinding::CryptographicKey(key) => Some(key),
        HolderBinding::ClaimsBased(_) | HolderBinding::BearerWithoutBinding => None,
    };
    if bundle.envelope_hash.as_slice() != envelope_hash
        || bundle.holder_key.as_ref() != expected_holder_key
        || bundle.issuer_signature != envelope.issuer_signature
    {
        return Err(CredentialError::InvalidInput(
            CredentialInvalidReason::PrivateBundleEnvelopeMismatch,
        ));
    }
    Ok(())
}

pub(crate) fn validate_public_key_ref(key: &PublicKeyRef) -> Result<(), CredentialError> {
    validate_claims_public_key_ref(key)
        .map_err(|_| CredentialError::InvalidInput(CredentialInvalidReason::InvalidPublicKeyRef))
}

pub(crate) fn validate_signature(signature: &Signature) -> Result<(), CredentialError> {
    if signature.raw_rs.is_empty()
        || signature.raw_rs.len() > MAX_SIGNATURE_BYTES
        || validate_public_key_ref(&signature.verification_key).is_err()
    {
        return Err(CredentialError::InvalidInput(
            CredentialInvalidReason::InvalidIssuerSignature,
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum PartyReferenceContext {
    Issuer,
    CredentialSubject,
}

impl PartyReferenceContext {
    const fn allows_absent(self) -> bool {
        matches!(self, Self::CredentialSubject)
    }

    const fn invalid_reason(self) -> CredentialInvalidReason {
        match self {
            Self::Issuer => CredentialInvalidReason::InvalidIssuerId,
            Self::CredentialSubject => CredentialInvalidReason::InvalidSubjectId,
        }
    }
}

fn validate_party_reference(
    reference: &PartyReference,
    context: PartyReferenceContext,
) -> Result<(), CredentialError> {
    let valid = match reference {
        PartyReference::Did(value) => valid_reference_text(value) && value.starts_with("did:"),
        PartyReference::FederationEntityId(value) | PartyReference::OpaqueIdentifier(value) => {
            valid_reference_text(value)
        }
        PartyReference::Uri(value) => valid_reference_text(value) && value.contains(':'),
        PartyReference::X509Subject(value) => match value {
            X509SubjectReference::CertificateSha256(_) => true,
            X509SubjectReference::IssuerAndSerial {
                issuer_name_der,
                serial_number,
            } => {
                valid_x509_name(issuer_name_der)
                    && !serial_number.is_empty()
                    && serial_number.len() <= 20
                    && serial_number.first().is_some_and(|first| *first != 0)
            }
            X509SubjectReference::ValidatedCertificateDer(value) => valid_x509_certificate(value),
        },
        PartyReference::PublicKey(value) => {
            !matches!(
                value.alg,
                reallyme_credential_claims::CredentialAlgorithm::Unspecified
            ) && validate_public_key_representation(value.alg, &value.public_key).is_ok()
        }
        PartyReference::Absent => context.allows_absent(),
    };
    if valid {
        Ok(())
    } else {
        Err(CredentialError::InvalidInput(context.invalid_reason()))
    }
}

fn valid_reference_text(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_CREDENTIAL_TEXT_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_x509_name(value: &[u8]) -> bool {
    if value.is_empty() || value.len() > MAX_PUBLIC_KEY_BYTES {
        return false;
    }
    validate_x509_name_der(value)
}

fn valid_x509_certificate(value: &[u8]) -> bool {
    if value.is_empty() || value.len() > MAX_PUBLIC_KEY_BYTES {
        return false;
    }
    validate_certificate_der(value)
}

fn validate_holder_binding(binding: &HolderBinding) -> Result<(), CredentialError> {
    match binding {
        HolderBinding::CryptographicKey(key) => validate_public_key_ref(key),
        HolderBinding::ClaimsBased(claim_ids) => {
            if claim_ids.is_empty() || claim_ids.len() > 256 {
                return Err(CredentialError::InvalidInput(
                    CredentialInvalidReason::InvalidSubjectId,
                ));
            }
            let mut seen = BTreeSet::new();
            for claim_id in claim_ids {
                if claim_id.trim().is_empty()
                    || claim_id.len() > MAX_CREDENTIAL_TEXT_BYTES
                    || !seen.insert(claim_id.as_str())
                {
                    return Err(CredentialError::InvalidInput(
                        CredentialInvalidReason::InvalidSubjectId,
                    ));
                }
            }
            Ok(())
        }
        HolderBinding::BearerWithoutBinding => Ok(()),
    }
}

fn validate_text(
    value: &str,
    limit: usize,
    reason: CredentialInvalidReason,
) -> Result<(), CredentialError> {
    if value.trim().is_empty() || value.len() > limit {
        Err(CredentialError::InvalidInput(reason))
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "validate_party_reference_tests.rs"]
mod party_reference_tests;
