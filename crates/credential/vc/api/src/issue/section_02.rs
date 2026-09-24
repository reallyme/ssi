// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn prepare_issue_request(
    mut req: IssueCredentialRequest,
    now_unix: u64,
) -> Result<(CoreIssueInput, BTreeMap<String, serde_json::Value>), VcApiError> {
    if req.valid_until < req.valid_from {
        return Err(VcApiError::InvalidValidity);
    }
    if req.issuer_country.trim().is_empty() {
        return Err(VcApiError::InvalidIssuer);
    }

    let CredentialProfile::Custom(profile) = &req.profile;
    if profile.require_qeaa && req.qeaa.is_none() {
        return Err(VcApiError::QeaaRequired);
    }
    if let Some(qeaa) = &req.qeaa {
        validate_qeaa_compliance(qeaa, now_unix).map_err(|_| VcApiError::QeaaInvalid)?;
    }
    validate_claims_against_registry(&profile.registry, &profile.required_claim_ids, &req.claims)?;

    // IssueCredentialRequest zeroizes on drop. Replace each moved field with an
    // explicitly invalid empty sentinel so every success and failure path retains
    // a live owner that can wipe anything not transferred to the core operation.
    let profile = core::mem::replace(&mut req.profile, empty_profile());
    let issuer_reference = core::mem::replace(
        &mut req.issuer_reference,
        reallyme_credential::committed::model::PartyReference::Absent,
    );
    let issuer_verification_key =
        core::mem::replace(&mut req.issuer_verification_key, empty_public_key_ref());
    let issuer_country = core::mem::take(&mut req.issuer_country);
    let subject = core::mem::replace(
        &mut req.subject,
        reallyme_credential::committed::model::CredentialSubject {
            subject_reference: reallyme_credential::committed::model::PartyReference::Absent,
            holder_binding: reallyme_credential::committed::model::HolderBinding::BearerWithoutBinding,
        },
    );
    let valid_from = req.valid_from;
    let valid_until = req.valid_until;
    let status = core::mem::replace(&mut req.status, empty_credential_status());
    let claims = core::mem::take(&mut req.claims);
    let qeaa = req.qeaa.take();
    let CredentialProfile::Custom(profile) = profile;
    let CustomProfile {
        claimset_id,
        kind,
        assurance,
        domain_tags,
        limits,
        registry: _,
        require_qeaa: _,
        required_claim_ids: _,
    } = profile;

    let core = CoreIssueInput {
        kind,
        profile_id: claimset_id.clone(),
        assurance,
        issuer_reference,
        issuer_verification_key,
        issuer_country,
        valid_from,
        valid_until,
        status,
        subject,
        claimset_id,
        domain_tags,
        limits,
        qeaa_compliance: qeaa,
    };

    Ok((core, claims))
}

fn empty_profile() -> CredentialProfile {
    CredentialProfile::Custom(CustomProfile {
        claimset_id: String::new(),
        kind: reallyme_credential::committed::model::CredentialKind::Pid,
        assurance: reallyme_credential::committed::model::AssuranceLevel::Substantial,
        domain_tags: reallyme_credential::committed::model::DomainTags {
            clm: String::new(),
            leaf: String::new(),
            node: String::new(),
        },
        limits: reallyme_credential::committed::model::CommitmentLimits {
            max_value_len: 0,
            salt_len: 0,
        },
        registry: ClaimsRegistry {
            claimset_id: String::new(),
            claims: BTreeMap::new(),
        },
        require_qeaa: false,
        required_claim_ids: Vec::new(),
    })
}

fn empty_public_key_ref() -> reallyme_credential::committed::model::PublicKeyRef {
    reallyme_credential::committed::model::PublicKeyRef {
        alg: reallyme_credential::committed::model::CredentialAlgorithm::Unspecified,
        reference: reallyme_credential::committed::model::KeyReference::DirectPublicKey,
        public_key: reallyme_credential::committed::model::PublicKeyRepresentation::Raw {
            serialization:
                reallyme_credential::committed::model::RawPublicKeySerialization::FixedWidth,
            bytes: Vec::new(),
        },
        assurance: reallyme_credential::committed::model::KeyAssurance::None,
    }
}

fn empty_credential_status() -> reallyme_credential::committed::model::CredentialStatus {
    reallyme_credential::committed::model::CredentialStatus {
        status_list_url: String::new(),
        status_list_id: [0_u8; 32],
        status_list_index: 0,
        purpose: reallyme_credential::committed::model::StatusPurpose::Revocation,
    }
}

#[cfg(feature = "ietf-sd-jwt")]
fn ietf_sd_jwt_input_from_envelope(
    envelope: &reallyme_credential::committed::model::CredentialEnvelope,
    claims: &BTreeMap<String, serde_json::Value>,
    cfg: &IetfSdJwtIssuerConfig,
    now_unix: u64,
) -> Result<identity_vc_ietf_sd_jwt::IetfSdJwtIssueInput, VcApiError> {
    let issuer =
        encoded_party_reference(&envelope.issuer_reference).ok_or(VcApiError::EncodingFailed)?;
    let mut input = identity_vc_ietf_sd_jwt::IetfSdJwtIssueInput::new(issuer.to_owned());
    input.subject = encoded_party_reference(&envelope.subject.subject_reference).map(str::to_owned);
    input.issued_at_unix = Some(now_unix);
    input.not_before_unix = Some(unix_seconds_to_u64(envelope.valid_from)?);
    input.expires_at_unix = Some(unix_seconds_to_u64(envelope.valid_until)?);
    input.vct = Some(envelope.profile_id.clone());
    input.jwt_type = cfg.jwt_type;
    input.salt_len = cfg.salt_len;

    input.selective_claims = claims
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    if cfg.include_me_profile_merkle_binding {
        let merkle_root_b64u =
            codec_base64url::bytes_to_base64url(envelope.claims_commitment.merkle_root.as_slice());
        input.me_profile_merkle_binding = Some(
            identity_vc_ietf_sd_jwt::MeProfileMerkleBinding::new(
                merkle_root_b64u,
                envelope.claims_commitment.hash_alg.clone(),
            )
            .map_err(|_| VcApiError::EncodingFailed)?,
        );
    }

    Ok(input)
}

fn encoded_party_reference(
    reference: &reallyme_credential::committed::model::PartyReference,
) -> Option<&str> {
    match reference {
        reallyme_credential::committed::model::PartyReference::Did(value)
        | reallyme_credential::committed::model::PartyReference::FederationEntityId(value)
        | reallyme_credential::committed::model::PartyReference::OpaqueIdentifier(value)
        | reallyme_credential::committed::model::PartyReference::Uri(value) => Some(value.as_str()),
        reallyme_credential::committed::model::PartyReference::X509Subject(_)
        | reallyme_credential::committed::model::PartyReference::PublicKey(_)
        | reallyme_credential::committed::model::PartyReference::Absent => None,
    }
}

#[cfg(feature = "ietf-sd-jwt")]
fn unix_seconds_to_u64(value: i64) -> Result<u64, VcApiError> {
    u64::try_from(value).map_err(|_| VcApiError::InvalidValidity)
}
