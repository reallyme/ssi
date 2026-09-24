// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use url::Url;

use crate::{country::is_iso_3166_alpha_2, ConformanceError, CredentialFormatSet, Result};

const MAX_TEXT_BYTES: usize = 256;
const MAX_TRANSACTION_TYPES: usize = 256;
const MAX_URI_BYTES: usize = 2_048;
const MAX_REVOCATION_NOTIFICATION_DELAY_SECONDS: u64 = 24 * 60 * 60;

/// Wallet operation subject to the CIR (EU) 2024/2979 authentication gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletOperation {
    /// Authenticate the user to unlock the wallet unit.
    AuthenticateUser,
    /// Receive PID or an electronic attestation.
    ReceiveCredential,
    /// Present PID or an electronic attestation.
    PresentCredential,
    /// Create a signature or seal.
    CreateSignatureOrSeal,
    /// Export wallet data or transaction history.
    ExportData,
    /// Manage credentials or wallet-unit state.
    ManageWallet,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WalletGateState {
    Locked,
    Authenticated,
}

/// Non-cloneable gate preventing wallet functionality before user authentication.
pub struct WalletOperationGate {
    state: WalletGateState,
}

impl WalletOperationGate {
    /// Create a locked wallet operation gate.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: WalletGateState::Locked,
        }
    }

    /// Record successful user authentication.
    pub fn record_successful_authentication(&mut self) -> Result<()> {
        if matches!(self.state, WalletGateState::Authenticated) {
            return Err(ConformanceError::InvalidWalletAuthenticationState);
        }
        self.state = WalletGateState::Authenticated;
        Ok(())
    }

    /// Relock the wallet unit and require fresh authentication.
    pub fn lock(&mut self) {
        self.state = WalletGateState::Locked;
    }

    /// Authorize one operation under the current authentication state.
    pub fn authorize(&self, operation: WalletOperation) -> Result<()> {
        if matches!(operation, WalletOperation::AuthenticateUser)
            || matches!(self.state, WalletGateState::Authenticated)
        {
            Ok(())
        } else {
            Err(ConformanceError::WalletUserAuthenticationRequired)
        }
    }
}

impl Default for WalletOperationGate {
    fn default() -> Self {
        Self::new()
    }
}

/// WSCA/WSCD capabilities required for wallet critical assets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalletCryptographicCapabilities {
    /// Critical assets are managed through at least one WSCD.
    pub wscd_present: bool,
    /// Wallet-instance/WSCA communication is integrity, authenticity, and confidentiality protected.
    pub protected_component_channel: bool,
    /// High-assurance operations satisfy Implementing Regulation (EU) 2015/1502.
    pub high_assurance_operation_profile: bool,
    /// Only the WSCA can execute high-assurance critical-asset operations.
    pub exclusive_critical_asset_execution: bool,
    /// New cryptographic keys are generated inside the protected boundary.
    pub secure_key_generation: bool,
    /// Critical assets can be securely erased.
    pub secure_erasure: bool,
    /// Proof of possession can be generated without releasing private keys.
    pub proof_of_possession: bool,
    /// Private keys remain protected throughout their lifetime.
    pub private_key_lifetime_protection: bool,
    /// The configured mechanisms are from the current ENISA agreed set.
    pub enisa_agreed_mechanisms_only: bool,
}

/// Validate the CIR wallet cryptographic boundary.
pub fn validate_wallet_cryptographic_capabilities(
    facts: WalletCryptographicCapabilities,
) -> Result<()> {
    if facts.wscd_present
        && facts.protected_component_channel
        && facts.high_assurance_operation_profile
        && facts.exclusive_critical_asset_execution
        && facts.secure_key_generation
        && facts.secure_erasure
        && facts.proof_of_possession
        && facts.private_key_lifetime_protection
        && facts.enisa_agreed_mechanisms_only
    {
        Ok(())
    } else {
        Err(ConformanceError::InvalidWalletCryptographicCapabilities)
    }
}

/// Validate support for every ETSI EAA/PID format incorporated by Annex II.
pub fn validate_wallet_format_capabilities(formats: CredentialFormatSet) -> Result<()> {
    if formats.supports_all_etsi_formats() {
        Ok(())
    } else {
        Err(ConformanceError::IncompleteWalletCredentialFormatSupport)
    }
}

/// Reason a wallet provider revoked a wallet-unit attestation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletAttestationRevocationReason {
    /// Authenticated request from the wallet user.
    WalletUserRequest,
    /// Compromise or suspected compromise of the wallet unit.
    WalletUnitCompromise,
    /// Loss, suspension, or withdrawal of wallet-solution certification.
    CertificationStatusChanged,
    /// Another condition enumerated in the provider's published policy.
    PublishedPolicyCause,
}

/// Actual wallet-unit-attestation revocation event required by Article 7.
pub struct WalletAttestationRevocationEvent<'a> {
    /// Identifier of the wallet provider that issued the attestation.
    pub wallet_provider_identifier: &'a str,
    /// Authenticated identifier of the actor performing revocation.
    pub revoking_actor_identifier: &'a str,
    /// HTTPS location of the provider's public revocation policy.
    pub public_policy_uri: &'a str,
    /// HTTPS location described in the attestation for public status checks.
    pub public_status_uri: &'a str,
    /// Closed revocation-reason category.
    pub reason: WalletAttestationRevocationReason,
    /// Unix time at which revocation became effective.
    pub revoked_at: u64,
    /// Unix time at which the affected wallet user was informed.
    pub user_notified_at: u64,
    /// Notification explains both the reason and consequences for the user.
    pub notification_included_reason_and_consequences: bool,
    /// Notification is concise, accessible, clear, and in plain language.
    pub notification_accessibility_requirements_met: bool,
    /// Public status is privacy preserving.
    pub public_status_privacy_preserving: bool,
}

/// Validate wallet-attestation revocation authority, timing, and publication.
pub fn validate_wallet_attestation_revocation(
    event: &WalletAttestationRevocationEvent<'_>,
) -> Result<()> {
    if !valid_text(event.wallet_provider_identifier)
        || event.wallet_provider_identifier != event.revoking_actor_identifier
        || !valid_https_uri(event.public_policy_uri)
        || !valid_https_uri(event.public_status_uri)
        || !event.notification_included_reason_and_consequences
        || !event.notification_accessibility_requirements_met
        || !event.public_status_privacy_preserving
    {
        return Err(ConformanceError::InvalidWalletAttestationRevocation);
    }
    let notification_delay = event
        .user_notified_at
        .checked_sub(event.revoked_at)
        .ok_or(ConformanceError::InvalidWalletAttestationRevocation)?;
    if notification_delay > MAX_REVOCATION_NOTIFICATION_DELAY_SECONDS {
        return Err(ConformanceError::InvalidWalletAttestationRevocation);
    }
    Ok(())
}

/// Existing RP-specific pseudonym allocation used for collision detection.
///
/// Values are borrowed and deliberately do not implement logging traits.
pub struct RelyingPartyPseudonymBinding<'a> {
    /// Authenticated relying-party identifier.
    pub relying_party_identifier: &'a str,
    /// Pseudonym allocated to that relying party.
    pub pseudonym: &'a [u8],
}

/// Validate a stable one-to-one pseudonym allocation for one relying party.
pub fn validate_relying_party_pseudonym(
    candidate: &RelyingPartyPseudonymBinding<'_>,
    existing: &[RelyingPartyPseudonymBinding<'_>],
) -> Result<()> {
    validate_pseudonym_binding(candidate)?;
    for binding in existing {
        validate_pseudonym_binding(binding)?;
        let same_relying_party =
            binding.relying_party_identifier == candidate.relying_party_identifier;
        let same_pseudonym = binding.pseudonym == candidate.pseudonym;
        if same_relying_party != same_pseudonym {
            return Err(ConformanceError::InvalidWalletPseudonymAllocation);
        }
    }
    Ok(())
}

/// Reason a wallet transaction did not complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionFailureReason {
    /// The wallet user declined or cancelled.
    UserDeclined,
    /// Relying-party authentication or validation failed.
    RelyingPartyValidationFailed,
    /// The request violated disclosure policy.
    DisclosurePolicyRejected,
    /// A protocol or transport operation failed.
    ProtocolFailure,
    /// A required credential was unavailable.
    CredentialUnavailable,
}

/// Completion state recorded in a transaction log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionOutcome {
    /// Transaction completed.
    Completed,
    /// Transaction did not complete and records a closed reason code.
    NotCompleted(TransactionFailureReason),
}

/// Required identifying data when a transaction involves a relying party.
///
/// Fields are borrowed so this validator never owns or retains log data.
pub struct WalletRelyingPartyLogData<'a> {
    /// Relying-party name.
    pub name: &'a str,
    /// Relying-party contact details.
    pub contact: &'a str,
    /// Unique relying-party identifier.
    pub identifier: &'a str,
    /// ISO 3166-1 alpha-2 Member State of establishment.
    pub member_state: &'a str,
}

/// Transaction classes Article 9 requires wallet instances to record.
pub enum WalletTransactionKind<'a> {
    /// PID or EAA request from an authenticated wallet-relying party.
    RelyingPartyPresentation(WalletRelyingPartyLogData<'a>),
    /// Interaction with another wallet unit.
    OtherWalletUnit {
        /// Privacy-safe identifier for the counterparty wallet unit.
        counterparty_identifier: &'a str,
    },
    /// Electronic signature creation, optionally requested by a relying party.
    ElectronicSignature {
        /// Relying-party data when the signature was requested by one.
        relying_party: Option<WalletRelyingPartyLogData<'a>>,
    },
    /// Electronic seal creation, optionally requested by a relying party.
    ElectronicSeal {
        /// Relying-party data when the seal was requested by one.
        relying_party: Option<WalletRelyingPartyLogData<'a>>,
    },
}

/// One CIR-compliant wallet transaction log record.
///
/// Fields are borrowed so this validator never owns or retains log data.
pub struct WalletTransactionLogEntry<'a> {
    /// Non-zero Unix timestamp.
    pub timestamp: u64,
    /// Class and counterparty details for the transaction.
    pub kind: WalletTransactionKind<'a>,
    /// Credential or attribute types requested.
    pub requested_types: &'a [&'a str],
    /// Credential or attribute types actually presented.
    pub presented_types: &'a [&'a str],
    /// Completion state.
    pub outcome: TransactionOutcome,
    /// Whether this record covers a portrait request or disclosure.
    pub portrait_related: bool,
}

/// Storage and access controls applied to wallet transaction logs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalletTransactionLogControls {
    /// Stored records have integrity protection.
    pub integrity_protected: bool,
    /// Stored records have authenticity protection.
    pub authenticity_protected: bool,
    /// Stored records have confidentiality protection.
    pub confidentiality_protected: bool,
    /// Reports sent to data-protection authorities are logged.
    pub authority_reports_logged: bool,
    /// Wallet-provider access is impossible without prior explicit user consent.
    pub provider_access_requires_explicit_prior_consent: bool,
    /// Retention is bounded by applicable Union or national law.
    pub legally_bounded_retention: bool,
    /// The user can export the records.
    pub user_export_supported: bool,
}

/// Validate a transaction log record and its storage/access controls.
pub fn validate_wallet_transaction_log(
    entry: &WalletTransactionLogEntry<'_>,
    controls: WalletTransactionLogControls,
) -> Result<()> {
    if entry.timestamp == 0
        || !valid_transaction_kind(&entry.kind, entry.requested_types)
        || !valid_type_set(entry.requested_types, true)
        || !valid_type_set(entry.presented_types, true)
        || entry
            .presented_types
            .iter()
            .any(|presented| !entry.requested_types.contains(presented))
        || entry.portrait_related
            != (entry.requested_types.contains(&"portrait")
                || entry.presented_types.contains(&"portrait"))
        || !controls.integrity_protected
        || !controls.authenticity_protected
        || !controls.confidentiality_protected
        || !controls.authority_reports_logged
        || !controls.provider_access_requires_explicit_prior_consent
        || !controls.legally_bounded_retention
        || !controls.user_export_supported
    {
        return Err(ConformanceError::InvalidWalletTransactionLog);
    }
    if matches!(entry.outcome, TransactionOutcome::NotCompleted(_))
        && !entry.presented_types.is_empty()
    {
        return Err(ConformanceError::InvalidWalletTransactionLog);
    }
    Ok(())
}

fn valid_transaction_kind(kind: &WalletTransactionKind<'_>, requested_types: &[&str]) -> bool {
    match kind {
        WalletTransactionKind::RelyingPartyPresentation(relying_party) => {
            !requested_types.is_empty() && valid_relying_party_log_data(relying_party)
        }
        WalletTransactionKind::OtherWalletUnit {
            counterparty_identifier,
        } => valid_text(counterparty_identifier),
        WalletTransactionKind::ElectronicSignature { relying_party }
        | WalletTransactionKind::ElectronicSeal { relying_party } => {
            requested_types.is_empty()
                && relying_party
                    .as_ref()
                    .is_none_or(valid_relying_party_log_data)
        }
    }
}

fn valid_relying_party_log_data(data: &WalletRelyingPartyLogData<'_>) -> bool {
    valid_text(data.name)
        && valid_text(data.contact)
        && valid_text(data.identifier)
        && is_iso_3166_alpha_2(data.member_state)
}

/// Common embedded disclosure policy evaluated against a concrete relying party.
pub enum WalletDisclosurePolicy<'a> {
    /// No policy applies.
    NoPolicy,
    /// Only the listed authenticated relying-party identifiers may receive the attestation.
    AuthorizedRelyingParties(&'a [&'a str]),
    /// The relying-party access certificate must terminate at one of these SHA-256 roots.
    SpecificRootsOfTrust(&'a [[u8; 32]]),
}

/// Evaluate an embedded disclosure policy using actual RP and certificate data.
pub fn evaluate_wallet_disclosure_policy(
    policy: &WalletDisclosurePolicy<'_>,
    authenticated_relying_party: &str,
    access_certificate_root_sha256: Option<&[u8; 32]>,
) -> Result<()> {
    if !valid_text(authenticated_relying_party) {
        return Err(ConformanceError::InvalidEmbeddedDisclosurePolicy);
    }
    let permitted = match policy {
        WalletDisclosurePolicy::NoPolicy => true,
        WalletDisclosurePolicy::AuthorizedRelyingParties(identifiers) => {
            !identifiers.is_empty()
                && identifiers.iter().all(|identifier| valid_text(identifier))
                && identifiers.contains(&authenticated_relying_party)
        }
        WalletDisclosurePolicy::SpecificRootsOfTrust(roots) => {
            access_certificate_root_sha256.is_some_and(|root| roots.contains(root))
        }
    };
    if permitted {
        Ok(())
    } else {
        Err(ConformanceError::InvalidEmbeddedDisclosurePolicy)
    }
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn validate_pseudonym_binding(binding: &RelyingPartyPseudonymBinding<'_>) -> Result<()> {
    if !valid_text(binding.relying_party_identifier)
        || binding.pseudonym.is_empty()
        || binding.pseudonym.len() > MAX_TEXT_BYTES
    {
        return Err(ConformanceError::InvalidWalletPseudonymAllocation);
    }
    Ok(())
}

fn valid_https_uri(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_URI_BYTES || value.trim() != value {
        return false;
    }
    let Ok(uri) = Url::parse(value) else {
        return false;
    };
    uri.scheme() == "https"
        && uri.host_str().is_some()
        && uri.username().is_empty()
        && uri.password().is_none()
        && uri.fragment().is_none()
}

fn valid_type_set(values: &[&str], allow_empty: bool) -> bool {
    if (!allow_empty && values.is_empty()) || values.len() > MAX_TRANSACTION_TYPES {
        return false;
    }
    values
        .iter()
        .enumerate()
        .all(|(index, value)| valid_text(value) && !values[..index].contains(value))
}
