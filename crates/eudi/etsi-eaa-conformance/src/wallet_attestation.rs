// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{ConformanceError, Result};

const TWENTY_FOUR_HOURS_SECONDS: u64 = 24 * 60 * 60;
const THIRTY_ONE_DAYS_SECONDS: u64 = 31 * TWENTY_FOUR_HOURS_SECONDS;
const MINIMUM_PRIVACY_STATUS_LIST_SIZE: u64 = 10_000;
const MAX_AUTHORIZATION_SERVER_BYTES: usize = 2_048;

/// Signature algorithms permitted for WIA, KA, PoP, and their Token Status Lists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletAttestationAlgorithm {
    /// ECDSA with SHA-256 and P-256.
    Es256,
    /// ECDSA with SHA-384 and P-384.
    Es384,
    /// ECDSA with SHA-512 and P-521.
    Es512,
}

/// Previously allocated WIA status index for one authorization server.
pub struct WiaIndexBinding<'a> {
    /// Authorization-server identifier.
    pub authorization_server: &'a str,
    /// Token Status List index.
    pub index: u64,
}

/// Privacy policy for wallet-instance-attestation status indices.
pub enum WiaStatusIndexPolicy<'a> {
    /// Each WIA receives a fresh index that was not used before.
    FreshUnlinkable {
        /// Candidate index.
        current_index: u64,
        /// All indexes previously allocated by this wallet unit.
        prior_indexes: &'a [u64],
    },
    /// An index may repeat only for the same authorization server.
    PerIssuerReuse {
        /// Current authorization server.
        authorization_server: &'a str,
        /// Candidate index.
        current_index: u64,
        /// Prior server/index bindings for this wallet unit.
        prior_bindings: &'a [WiaIndexBinding<'a>],
        /// Privacy policy documents the per-issuer reuse option.
        privacy_policy_discloses_reuse: bool,
    },
}

/// Key-attestation status-index strategy.
pub enum KeyAttestationIndexPolicy<'a> {
    /// One index is shared by all stores of a certified type.
    TypeShared {
        /// Revocation is restricted to a vulnerability in that store type.
        revocation_restricted_to_type_vulnerability: bool,
    },
    /// An index represents one wallet unit's WSCD or keystore.
    PerKeyAttestation {
        /// The index is pairwise unique for the credential issuer.
        pairwise_unique: bool,
        /// Number of entries in the Token Status List.
        status_list_size: u64,
        /// A smaller list is justified because 10,000 entries are not possible.
        minimum_size_exception_documented: bool,
        /// Optional per-issuer reuse state, applying the WIA reuse rules mutatis mutandis.
        per_issuer_reuse: Option<PerIssuerIndexReuse<'a>>,
    },
}

/// Per-issuer status-index reuse state shared by WIA and optional KA policy.
pub struct PerIssuerIndexReuse<'a> {
    /// Current authorization server.
    pub authorization_server: &'a str,
    /// Candidate status-list index.
    pub current_index: u64,
    /// Prior server/index bindings for this wallet unit or key store.
    pub prior_bindings: &'a [WiaIndexBinding<'a>],
    /// Privacy policy documents use of per-issuer reuse.
    pub privacy_policy_discloses_reuse: bool,
}

/// Proof container used to transport a key attestation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyAttestationProof {
    /// JWT proof signed by attested key zero and containing a current nonce.
    Jwt {
        /// Signature under key zero verified.
        signed_by_first_attested_key: bool,
        /// Nonce matches a current issuer nonce.
        nonce_valid: bool,
    },
    /// Attestation proof containing a current issuer nonce.
    Attestation {
        /// Nonce matches a current issuer nonce.
        nonce_valid: bool,
    },
}

/// Actual selection inputs for an issuer status-period preference.
///
/// The validator checks the chosen expiration against the complete candidate
/// set instead of accepting a caller assertion that minimization occurred.
pub struct StatusPeriodSelection<'a> {
    /// Issuer preference in seconds, or `None` when no preference was advertised.
    pub preferred_remaining_seconds: Option<u64>,
    /// Status expiration selected for the attestation.
    pub selected_expires_at: u64,
    /// Status expirations available to the wallet for this issuance.
    pub available_expires_at: &'a [u64],
}

/// Consolidated 2026 wallet-unit-attestation profile inputs.
pub struct WalletAttestationProfile<'a> {
    /// At least one WIA is present in the wallet-unit attestation.
    pub wallet_instance_attestation_count: u16,
    /// At least one KA is present in the wallet-unit attestation.
    pub key_attestation_count: u16,
    /// WIA is JWT plus compact JAdES baseline B and follows OID4VCI Appendix E.
    pub wallet_instance_format_valid: bool,
    /// KA is JWT plus compact JAdES baseline B and follows OID4VCI Appendix D.
    pub key_attestation_format_valid: bool,
    /// Time when wallet-instance integrity was verified.
    pub wallet_integrity_verified_at: u64,
    /// Top-level WIA expiration.
    pub wallet_instance_expires_at: u64,
    /// WIA status-maintenance expiration.
    pub wallet_instance_status_expires_at: u64,
    /// KA status-maintenance expiration.
    pub key_storage_status_expires_at: u64,
    /// Current verification time.
    pub now: u64,
    /// WIA was sent in both PAR and token request.
    pub wallet_instance_sent_in_par_and_token_request: bool,
    /// WIA PoP verifies under the `cnf` public key.
    pub wallet_instance_proof_valid: bool,
    /// WIA signature, protected x5c path, trusted-list anchor, and time checks pass.
    pub wallet_instance_signature_and_trust_valid: bool,
    /// Status-index allocation policy for this WIA.
    pub wallet_instance_index_policy: WiaStatusIndexPolicy<'a>,
    /// Status list size used for WIA revocation.
    pub wallet_instance_status_list_size: u64,
    /// A smaller WIA list is documented as unavoidable.
    pub wallet_instance_minimum_size_exception_documented: bool,
    /// A KA is present exactly when the credential is device-bound.
    pub credential_is_device_bound: bool,
    /// This credential request contains a KA.
    pub key_attestation_present: bool,
    /// WSCD and each keystore use distinct key attestations.
    pub separate_attestation_per_key_store: bool,
    /// Count of public keys in the KA.
    pub attested_key_count: u32,
    /// Issuer-advertised maximum batch size.
    pub issuer_maximum_batch_size: u32,
    /// Every attested public key is included in at most one KA.
    pub public_keys_unique_across_attestations: bool,
    /// The KA was used in at most one issuance or reissuance process.
    pub key_attestation_single_use: bool,
    /// Wallet provider verified that attested keys are held in the described store.
    pub attested_keys_in_described_store: bool,
    /// Selected proof mechanism and nonce/signature results.
    pub key_attestation_proof: Option<KeyAttestationProof>,
    /// Device-bound metadata advertises both JWT and attestation proof types.
    pub device_bound_metadata_supports_both_proof_types: bool,
    /// Non-device-bound metadata omits proof and binding parameters.
    pub non_device_bound_metadata_omits_binding_parameters: bool,
    /// KA signature and protected x5c trusted-list path verify.
    pub key_attestation_signature_and_trust_valid: bool,
    /// PID holder key originates from a KA that identifies a WSCD.
    pub pid_key_originates_from_wscd_attestation: bool,
    /// WIA mandatory wallet identity, version, certification, status, and exp claims are valid.
    pub wallet_instance_content_valid: bool,
    /// KA storage/authentication, certification, status, and exp claims are valid.
    pub key_attestation_content_valid: bool,
    /// `key_storage` and `user_authentication` are `iso_18045_high` for a WSCD.
    pub wscd_assurance_claims_valid: bool,
    /// Token Status Lists are used for WIA and KA revocation.
    pub token_status_lists_used: bool,
    /// Top-level attestation expiration is not treated as status-maintenance expiration.
    pub top_level_exp_not_used_for_status_maintenance: bool,
    /// WIA and KA status is maintained through each status-specific expiration.
    pub status_maintenance_committed_through_exp: bool,
    /// Credential Issuer Metadata was fetched during this issuance.
    pub credential_issuer_metadata_fetched: bool,
    /// Actual WIA candidates and issuer status-period preference.
    pub wallet_instance_status_period: StatusPeriodSelection<'a>,
    /// Actual KA candidates and issuer status-period preference.
    pub key_storage_status_period: StatusPeriodSelection<'a>,
    /// KA status-index strategy.
    pub key_attestation_index_policy: KeyAttestationIndexPolicy<'a>,
    /// Algorithm selected for signatures.
    pub signing_algorithm: WalletAttestationAlgorithm,
    /// Authorization server and credential issuer support ES256, ES384, and ES512.
    pub verifier_supports_all_required_algorithms: bool,
    /// Issued PID technical-validity start.
    pub pid_not_before: u64,
    /// Issued PID technical-validity end.
    pub pid_expires_at: u64,
    /// Maximum interval between WIA/KA revocation checks for long-lived PID.
    pub maximum_revocation_check_interval_seconds: Option<u64>,
}

/// Validate the wallet-unit-attestation Annex added to CIR (EU) 2024/2979 in 2026.
pub fn validate_wallet_attestation_profile(facts: &WalletAttestationProfile<'_>) -> Result<()> {
    validate_wia_index_policy(&facts.wallet_instance_index_policy)?;
    validate_key_index_policy(&facts.key_attestation_index_policy)?;
    validate_status_period_selection(
        facts.now,
        facts.wallet_instance_status_expires_at,
        &facts.wallet_instance_status_period,
    )?;
    validate_status_period_selection(
        facts.now,
        facts.key_storage_status_expires_at,
        &facts.key_storage_status_period,
    )?;

    let integrity_to_expiry = facts
        .wallet_instance_expires_at
        .checked_sub(facts.wallet_integrity_verified_at)
        .ok_or(ConformanceError::InvalidWalletAttestationProfile)?;
    let required_status_horizon = facts
        .now
        .checked_add(THIRTY_ONE_DAYS_SECONDS)
        .ok_or(ConformanceError::InvalidWalletAttestationProfile)?;
    let pid_duration = facts
        .pid_expires_at
        .checked_sub(facts.pid_not_before)
        .ok_or(ConformanceError::InvalidWalletAttestationProfile)?;
    let long_lived_monitoring_valid = if pid_duration > TWENTY_FOUR_HOURS_SECONDS {
        facts
            .maximum_revocation_check_interval_seconds
            .is_some_and(|interval| interval != 0 && interval <= TWENTY_FOUR_HOURS_SECONDS)
    } else {
        true
    };
    let key_presence_valid = facts.credential_is_device_bound == facts.key_attestation_present;
    let proof_valid = if facts.key_attestation_present {
        matches!(
            facts.key_attestation_proof,
            Some(KeyAttestationProof::Jwt {
                signed_by_first_attested_key: true,
                nonce_valid: true,
            }) | Some(KeyAttestationProof::Attestation { nonce_valid: true })
        )
    } else {
        facts.key_attestation_proof.is_none()
    };
    let metadata_valid = if facts.credential_is_device_bound {
        facts.device_bound_metadata_supports_both_proof_types
    } else {
        facts.non_device_bound_metadata_omits_binding_parameters
    };
    let wia_status_size_valid = facts.wallet_instance_status_list_size
        >= MINIMUM_PRIVACY_STATUS_LIST_SIZE
        || facts.wallet_instance_minimum_size_exception_documented;

    if facts.wallet_instance_attestation_count == 0
        || facts.key_attestation_count == 0
        || !facts.wallet_instance_format_valid
        || !facts.key_attestation_format_valid
        || integrity_to_expiry >= TWENTY_FOUR_HOURS_SECONDS
        || facts.wallet_instance_expires_at <= facts.now
        || facts.wallet_instance_status_expires_at < required_status_horizon
        || facts.key_storage_status_expires_at < required_status_horizon
        || !facts.wallet_instance_sent_in_par_and_token_request
        || !facts.wallet_instance_proof_valid
        || !facts.wallet_instance_signature_and_trust_valid
        || !wia_status_size_valid
        || !key_presence_valid
        || !facts.separate_attestation_per_key_store
        || facts.attested_key_count == 0
        || facts.attested_key_count > facts.issuer_maximum_batch_size
        || !facts.public_keys_unique_across_attestations
        || !facts.key_attestation_single_use
        || !facts.attested_keys_in_described_store
        || !proof_valid
        || !metadata_valid
        || !facts.key_attestation_signature_and_trust_valid
        || (facts.credential_is_device_bound && !facts.pid_key_originates_from_wscd_attestation)
        || !facts.wallet_instance_content_valid
        || !facts.key_attestation_content_valid
        || !facts.wscd_assurance_claims_valid
        || !facts.token_status_lists_used
        || !facts.top_level_exp_not_used_for_status_maintenance
        || !facts.status_maintenance_committed_through_exp
        || !facts.credential_issuer_metadata_fetched
        || !facts.verifier_supports_all_required_algorithms
        || facts.pid_expires_at >= facts.wallet_instance_status_expires_at
        || facts.pid_expires_at >= facts.key_storage_status_expires_at
        || !long_lived_monitoring_valid
    {
        return Err(ConformanceError::InvalidWalletAttestationProfile);
    }
    Ok(())
}

fn validate_status_period_selection(
    now: u64,
    actual_expires_at: u64,
    selection: &StatusPeriodSelection<'_>,
) -> Result<()> {
    if selection.available_expires_at.is_empty()
        || selection.selected_expires_at != actual_expires_at
        || !selection
            .available_expires_at
            .contains(&selection.selected_expires_at)
    {
        return Err(ConformanceError::InvalidWalletAttestationProfile);
    }

    for (position, candidate) in selection.available_expires_at.iter().enumerate() {
        if *candidate <= now || selection.available_expires_at[..position].contains(candidate) {
            return Err(ConformanceError::InvalidWalletAttestationProfile);
        }
    }

    let Some(preferred_seconds) = selection.preferred_remaining_seconds else {
        return Ok(());
    };
    let preferred_expires_at = now
        .checked_add(preferred_seconds)
        .ok_or(ConformanceError::InvalidWalletAttestationProfile)?;
    if selection.selected_expires_at < preferred_expires_at
        || selection.available_expires_at.iter().any(|candidate| {
            *candidate >= preferred_expires_at && *candidate < selection.selected_expires_at
        })
    {
        return Err(ConformanceError::InvalidWalletAttestationProfile);
    }
    Ok(())
}

fn validate_wia_index_policy(policy: &WiaStatusIndexPolicy<'_>) -> Result<()> {
    match policy {
        WiaStatusIndexPolicy::FreshUnlinkable {
            current_index,
            prior_indexes,
        } => {
            if prior_indexes.contains(current_index) {
                return Err(ConformanceError::InvalidWalletAttestationProfile);
            }
        }
        WiaStatusIndexPolicy::PerIssuerReuse {
            authorization_server,
            current_index,
            prior_bindings,
            privacy_policy_discloses_reuse,
        } => {
            if !valid_server_identifier(authorization_server) || !privacy_policy_discloses_reuse {
                return Err(ConformanceError::InvalidWalletAttestationProfile);
            }
            for binding in *prior_bindings {
                if !valid_server_identifier(binding.authorization_server)
                    || (binding.index == *current_index
                        && binding.authorization_server != *authorization_server)
                    || (binding.authorization_server == *authorization_server
                        && binding.index != *current_index)
                {
                    return Err(ConformanceError::InvalidWalletAttestationProfile);
                }
            }
        }
    }
    Ok(())
}

fn validate_key_index_policy(policy: &KeyAttestationIndexPolicy<'_>) -> Result<()> {
    match policy {
        KeyAttestationIndexPolicy::TypeShared {
            revocation_restricted_to_type_vulnerability: true,
        } => Ok(()),
        KeyAttestationIndexPolicy::PerKeyAttestation {
            pairwise_unique: true,
            status_list_size,
            minimum_size_exception_documented,
            per_issuer_reuse,
        } if *status_list_size >= MINIMUM_PRIVACY_STATUS_LIST_SIZE
            || *minimum_size_exception_documented =>
        {
            if let Some(reuse) = per_issuer_reuse {
                validate_per_issuer_reuse(reuse)
            } else {
                Ok(())
            }
        }
        _ => Err(ConformanceError::InvalidWalletAttestationProfile),
    }
}

fn validate_per_issuer_reuse(reuse: &PerIssuerIndexReuse<'_>) -> Result<()> {
    validate_wia_index_policy(&WiaStatusIndexPolicy::PerIssuerReuse {
        authorization_server: reuse.authorization_server,
        current_index: reuse.current_index,
        prior_bindings: reuse.prior_bindings,
        privacy_policy_discloses_reuse: reuse.privacy_policy_discloses_reuse,
    })
}

fn valid_server_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_AUTHORIZATION_SERVER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
