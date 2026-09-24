// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{ConformanceError, Result};
use url::Url;

const MAX_NOTIFICATION_ID_BYTES: usize = 128;

/// Supported credential formats advertised by an EAA/PID issuer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialFormatSet(u8);

impl CredentialFormatSet {
    const ALL: u8 = Self::SD_JWT_VC
        | Self::MSO_MDOC
        | Self::X509_ATTRIBUTE_CERTIFICATE
        | Self::JSON_LD_JOSE
        | Self::JSON_LD_SD_JWT;

    /// SD-JWT VC (`dc+sd-jwt`).
    pub const SD_JWT_VC: u8 = 1 << 0;
    /// ISO/IEC mdoc (`mso_mdoc`).
    pub const MSO_MDOC: u8 = 1 << 1;
    /// X.509 Attribute Certificate (`x509_attr`).
    pub const X509_ATTRIBUTE_CERTIFICATE: u8 = 1 << 2;
    /// JSON-LD W3C VC secured with JOSE (`vc+jwt`).
    pub const JSON_LD_JOSE: u8 = 1 << 3;
    /// JSON-LD W3C VC secured with SD-JWT (`vc+sd-jwt`).
    pub const JSON_LD_SD_JWT: u8 = 1 << 4;

    /// Construct a format set from a validated bit mask.
    #[must_use]
    pub const fn new(mask: u8) -> Self {
        Self(mask)
    }

    /// Return whether at least one format is advertised.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Return whether the set contains an advertised format.
    #[must_use]
    pub const fn contains(self, format: u8) -> bool {
        self.0 & format == format
    }

    pub(crate) const fn is_valid(self) -> bool {
        self.0 & !Self::ALL == 0
    }

    pub(crate) const fn supports_all_etsi_formats(self) -> bool {
        self.is_valid() && self.0 == Self::ALL
    }
}

/// Reuse method listed in ARF Annex II issuer metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReuseMethod {
    /// Every credential instance is presented once.
    OnceOnly,
    /// Credential instances are reused only for a bounded lifetime.
    LimitedTime,
    /// Wallet rotates through a batch of credential instances.
    RotatingBatch,
    /// Wallet uses a stable credential instance per relying party.
    PerRelyingParty,
}

/// Credential reuse policy conveyed in issuer metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReusePolicy<'a> {
    /// Parameter omitted; ETSI defines this as unrestricted reuse.
    OmittedUnrestricted,
    /// ARF Annex II policy represented by its actual metadata values.
    ArfAnnexIi {
        /// Ordered `details` array from the policy object.
        details: &'a [ReuseMethod],
        /// Batch size, when batching is used.
        batch_size: Option<u32>,
        /// Lower bound for unused credential instances before reissuance.
        reissue_trigger_unused: Option<u32>,
        /// Seconds before credential expiry that trigger reissuance.
        reissue_trigger_lifetime_left_seconds: Option<u64>,
    },
}

/// Reuse methods implemented by a wallet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReuseMethodSet(u8);

impl ReuseMethodSet {
    const ALL: u8 =
        Self::ONCE_ONLY | Self::LIMITED_TIME | Self::ROTATING_BATCH | Self::PER_RELYING_PARTY;

    /// Once-only credential instances.
    pub const ONCE_ONLY: u8 = 1 << 0;
    /// Reuse bounded by credential lifetime.
    pub const LIMITED_TIME: u8 = 1 << 1;
    /// Rotation through a credential batch.
    pub const ROTATING_BATCH: u8 = 1 << 2;
    /// Stable credential instances scoped to a relying party.
    pub const PER_RELYING_PARTY: u8 = 1 << 3;

    /// Construct a set from a mask. Unknown bits are rejected by validation.
    #[must_use]
    pub const fn new(mask: u8) -> Self {
        Self(mask)
    }

    const fn is_valid(self) -> bool {
        self.0 & !Self::ALL == 0
    }

    const fn contains(self, method: ReuseMethod) -> bool {
        let bit = match method {
            ReuseMethod::OnceOnly => Self::ONCE_ONLY,
            ReuseMethod::LimitedTime => Self::LIMITED_TIME,
            ReuseMethod::RotatingBatch => Self::ROTATING_BATCH,
            ReuseMethod::PerRelyingParty => Self::PER_RELYING_PARTY,
        };
        self.0 & bit == bit
    }
}

/// Wallet decision produced from an issuer's ordered reuse preferences.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReusePolicyDecision {
    /// Reuse mechanisms implemented by the wallet.
    pub supported_methods: ReuseMethodSet,
    /// Selected method, or `None` when the policy parameter is absent.
    pub selected_method: Option<ReuseMethod>,
}

/// Embedded disclosure policy carried through issuer metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmbeddedDisclosurePolicy {
    /// No restrictions apply.
    NoPolicy,
    /// Only registered relying parties in the policy may receive the EAA.
    AuthorizedRelyingParties {
        /// Every relying-party identity entry is valid and unambiguous.
        entries_valid: bool,
    },
    /// RP access certificates must chain to one of the stated roots/intermediates.
    SpecificRootsOfTrust {
        /// Every trust-anchor entry is valid and non-empty.
        entries_valid: bool,
    },
}

/// Signed Credential Issuer Metadata facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IssuerMetadataFacts<'a> {
    /// Metadata is a signed JWT and its signature verifies.
    pub signed_metadata_valid: bool,
    /// The signing certificate is the issuer access certificate.
    pub access_certificate_signer: bool,
    /// Protected `x5c` begins with the signing certificate and has a valid path excluding the anchor.
    pub protected_x5c_valid: bool,
    /// At least one ETSI credential format is advertised.
    pub formats: CredentialFormatSet,
    /// `issuer_info` is top-level and structurally valid.
    pub issuer_info_valid: bool,
    /// Access-certificate and registrar data entries use their required format labels.
    pub issuer_information_entries_valid: bool,
    /// Registration-certificate `providesAttestations` data is valid.
    pub registered_attestation_types_valid: bool,
    /// At least one `issuer_info` entry contains the issuer registration certificate.
    pub registration_certificate_present: bool,
    /// OpenID4VCI batch metadata is ignored when an ETSI reuse policy is present.
    pub batch_metadata_precedence_valid: bool,
    /// Credential reuse policy.
    pub reuse_policy: ReusePolicy<'a>,
    /// Embedded disclosure policy, when one applies.
    pub disclosure_policy: Option<EmbeddedDisclosurePolicy>,
}

/// Issuance flow support and request authentication facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationEvent {
    /// Credential was accepted and stored by the wallet.
    CredentialAccepted,
    /// Credential storage or processing failed.
    CredentialFailure,
    /// Credential was deleted from the wallet.
    CredentialDeleted,
}

/// Optional OpenID4VCI notification request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationRequest<'a> {
    /// This issuance did not produce a notification identifier.
    NotUsed,
    /// A notification was sent to the authenticated issuer endpoint.
    Sent {
        /// HTTPS notification endpoint from authenticated issuer metadata.
        endpoint: &'a str,
        /// Opaque identifier issued by the credential endpoint.
        notification_id: &'a str,
        /// Closed notification event set.
        event: NotificationEvent,
    },
}

/// Issuance flow support and request authentication facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IssuanceFlow<'a> {
    /// Authorization Code Flow is supported.
    pub authorization_code_supported: bool,
    /// Pre-Authorized Code Flow is supported, when advertised.
    pub pre_authorized_code_condition_met: bool,
    /// The `eu-eaa-offer` custom URL scheme is supported.
    pub eu_eaa_offer_scheme_supported: bool,
    /// At least one required credential-offer grant is advertised.
    pub credential_offer_grant_valid: bool,
    /// PAR or token requests carry a Wallet Instance Attestation as required.
    pub wallet_instance_attestation_present: bool,
    /// Proof of possession binds the request to the WIA key.
    pub wallet_instance_proof_valid: bool,
    /// WIA signature is verified against a trusted Wallet Provider and is unexpired.
    pub wallet_instance_attestation_valid: bool,
    /// Optional notification request, validated structurally by this crate.
    pub notification: NotificationRequest<'a>,
}

/// Credential-request proof processing facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialProofFacts {
    /// A device-bound credential request uses exactly one allowed proof container.
    pub exactly_one_proof_mechanism: bool,
    /// The proof contains the nonce obtained from the issuer nonce endpoint.
    pub nonce_valid: bool,
    /// The Wallet Unit Attestation is valid and trusted.
    pub wallet_unit_attestation_valid: bool,
    /// Proof signature verifies under the first attested key where the JWT mechanism is used.
    pub proof_signature_valid: bool,
    /// Issued credential count equals the number of attested keys.
    pub credential_count_matches_keys: bool,
    /// Each credential is bound to exactly one distinct attested key.
    pub one_distinct_key_per_credential: bool,
}

/// Complete ETSI TS 119 472-3 issuance facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IssuanceFacts<'a> {
    /// Issuer metadata.
    pub metadata: IssuerMetadataFacts<'a>,
    /// Wallet selection of the first supported issuer reuse preference.
    pub reuse_decision: ReusePolicyDecision,
    /// Protocol-flow facts.
    pub flow: IssuanceFlow<'a>,
    /// Credential proof processing.
    pub proof: CredentialProofFacts,
    /// AES-128-GCM support in addition to HAIP suites.
    pub a128gcm_supported: bool,
    /// AES-256-GCM support in addition to HAIP suites.
    pub a256gcm_supported: bool,
    /// OpenID4VCI security and privacy considerations are applied by policy.
    pub openid4vci_security_policy_applied: bool,
}

/// Validate issuer metadata and an EAA/PID issuance flow.
pub fn validate_issuance(facts: &IssuanceFacts<'_>) -> Result<()> {
    validate_metadata(&facts.metadata)?;
    validate_reuse_policy(facts.metadata.reuse_policy, facts.reuse_decision)?;
    validate_flow(&facts.flow)?;
    validate_proof(&facts.proof)?;

    if !facts.a128gcm_supported || !facts.a256gcm_supported {
        return Err(ConformanceError::MissingIssuanceCryptoSuite);
    }
    if !facts.openid4vci_security_policy_applied {
        return Err(ConformanceError::InvalidIssuanceFlow);
    }

    Ok(())
}

/// Validate issuance under the 2026 EU legal incorporation of Part 3.
///
/// The EU adaptation requires a registration certificate in `issuer_info` and
/// excludes Part 3 Annex A, so X.509 Attribute Certificate issuance cannot be
/// advertised through this legal profile.
pub fn validate_eu_issuance(facts: &IssuanceFacts<'_>) -> Result<()> {
    validate_issuance(facts)?;
    if !facts.metadata.registration_certificate_present
        || facts
            .metadata
            .formats
            .contains(CredentialFormatSet::X509_ATTRIBUTE_CERTIFICATE)
    {
        return Err(ConformanceError::InvalidEuIssuanceProfile);
    }
    Ok(())
}

fn validate_metadata(metadata: &IssuerMetadataFacts<'_>) -> Result<()> {
    if !metadata.signed_metadata_valid
        || !metadata.access_certificate_signer
        || !metadata.protected_x5c_valid
        || metadata.formats.is_empty()
        || !metadata.issuer_info_valid
        || !metadata.issuer_information_entries_valid
        || !metadata.registered_attestation_types_valid
        || !metadata.batch_metadata_precedence_valid
        || !metadata.formats.is_valid()
    {
        return Err(ConformanceError::InvalidIssuerMetadata);
    }

    if let Some(policy) = metadata.disclosure_policy {
        validate_disclosure_policy(policy)?;
    }

    Ok(())
}

fn validate_reuse_policy(policy: ReusePolicy<'_>, decision: ReusePolicyDecision) -> Result<()> {
    if !decision.supported_methods.is_valid() {
        return Err(ConformanceError::InvalidReusePolicy);
    }
    match policy {
        ReusePolicy::OmittedUnrestricted if decision.selected_method.is_none() => Ok(()),
        ReusePolicy::OmittedUnrestricted => Err(ConformanceError::InvalidReusePolicy),
        ReusePolicy::ArfAnnexIi {
            details,
            batch_size,
            reissue_trigger_unused,
            reissue_trigger_lifetime_left_seconds,
        } => {
            let details_valid = !details.is_empty()
                && details.len() <= 4
                && details
                    .iter()
                    .enumerate()
                    .all(|(position, method)| !details[..position].contains(method));
            let once_only = details.contains(&ReuseMethod::OnceOnly);
            let limited_time = details.contains(&ReuseMethod::LimitedTime);
            let rotating_batch = details.contains(&ReuseMethod::RotatingBatch);
            let per_relying_party = details.contains(&ReuseMethod::PerRelyingParty);
            let base_mode_valid = once_only ^ limited_time;
            let batch_required = once_only || rotating_batch || per_relying_party;
            let batching_valid = if batch_required {
                batch_size.is_some_and(|size| size >= 2)
            } else {
                batch_size.is_none()
            };
            let unused_threshold_valid = if once_only || per_relying_party {
                matches!(
                    (reissue_trigger_unused, batch_size),
                    (Some(threshold), Some(size)) if threshold < size
                )
            } else {
                reissue_trigger_unused.is_none()
            };
            let lifetime_required = limited_time || rotating_batch || per_relying_party;
            let timing_valid = lifetime_required == reissue_trigger_lifetime_left_seconds.is_some();
            let first_supported = details
                .iter()
                .copied()
                .find(|method| decision.supported_methods.contains(*method));
            let selection_valid =
                first_supported.is_some() && decision.selected_method == first_supported;
            if details_valid
                && base_mode_valid
                && batching_valid
                && unused_threshold_valid
                && timing_valid
                && selection_valid
            {
                Ok(())
            } else {
                Err(ConformanceError::InvalidReusePolicy)
            }
        }
    }
}

fn validate_disclosure_policy(policy: EmbeddedDisclosurePolicy) -> Result<()> {
    match policy {
        EmbeddedDisclosurePolicy::NoPolicy => Ok(()),
        EmbeddedDisclosurePolicy::AuthorizedRelyingParties { entries_valid }
        | EmbeddedDisclosurePolicy::SpecificRootsOfTrust { entries_valid }
            if entries_valid =>
        {
            Ok(())
        }
        EmbeddedDisclosurePolicy::AuthorizedRelyingParties { .. }
        | EmbeddedDisclosurePolicy::SpecificRootsOfTrust { .. } => {
            Err(ConformanceError::InvalidEmbeddedDisclosurePolicy)
        }
    }
}

fn validate_flow(flow: &IssuanceFlow<'_>) -> Result<()> {
    if flow.authorization_code_supported
        && flow.pre_authorized_code_condition_met
        && flow.eu_eaa_offer_scheme_supported
        && flow.credential_offer_grant_valid
        && flow.wallet_instance_attestation_present
        && flow.wallet_instance_proof_valid
        && flow.wallet_instance_attestation_valid
    {
        validate_notification(flow.notification)
    } else {
        Err(ConformanceError::InvalidIssuanceFlow)
    }
}

fn validate_notification(notification: NotificationRequest<'_>) -> Result<()> {
    let NotificationRequest::Sent {
        endpoint,
        notification_id,
        event: _,
    } = notification
    else {
        return Ok(());
    };

    let identifier_valid = !notification_id.is_empty()
        && notification_id.len() <= MAX_NOTIFICATION_ID_BYTES
        && notification_id.trim() == notification_id
        && notification_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'));
    if !identifier_valid {
        return Err(ConformanceError::InvalidNotificationRequest);
    }

    let parsed = Url::parse(endpoint).map_err(|_| ConformanceError::InvalidNotificationRequest)?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ConformanceError::InvalidNotificationRequest);
    }

    Ok(())
}

fn validate_proof(proof: &CredentialProofFacts) -> Result<()> {
    if proof.exactly_one_proof_mechanism
        && proof.nonce_valid
        && proof.wallet_unit_attestation_valid
        && proof.proof_signature_valid
        && proof.credential_count_matches_keys
        && proof.one_distinct_key_per_credential
    {
        Ok(())
    } else {
        Err(ConformanceError::InvalidCredentialProof)
    }
}
