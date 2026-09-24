// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use crypto_core::Algorithm as CryptoAlg;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use identity_credential_claims_core::ClaimsRegistry;
use reallyme_credential::committed::model::{
    AssuranceLevel, CommitmentLimits, CredentialEnvelope, CredentialKind, CredentialStatus,
    CredentialSubject, DomainTags, PartyReference, PublicKeyRef, SubjectPrivateBundle,
};
use reallyme_credential_audit::QeaaCompliance;

/// Built-in profiles for direct use.
/// `CustomProfile` can also be used to provide a registry and policy parameters.
pub enum CredentialProfile {
    /// Use caller-provided parameters + registry.
    Custom(CustomProfile),
}

pub struct CustomProfile {
    pub claimset_id: String,
    pub kind: CredentialKind,
    pub assurance: AssuranceLevel,
    pub domain_tags: DomainTags,
    pub limits: CommitmentLimits,

    /// Registry used to validate claim ids and types.
    pub registry: ClaimsRegistry,

    /// If true, QEAA must be present and must validate.
    pub require_qeaa: bool,

    /// Required claim ids (not paths). If empty => no required set enforced here.
    pub required_claim_ids: Vec<String>,
}

/// High-level issuance request.
pub struct IssueCredentialRequest {
    pub profile: CredentialProfile,

    pub issuer_reference: PartyReference,
    pub issuer_verification_key: PublicKeyRef,
    pub issuer_country: String,

    pub subject: CredentialSubject,

    /// UTC seconds since epoch
    pub valid_from: i64,
    pub valid_until: i64,

    pub status: CredentialStatus,

    /// Claim id -> JSON value
    pub claims: BTreeMap<String, serde_json::Value>,

    /// Optional QEAA metadata (validated here if required)
    pub qeaa: Option<QeaaCompliance>,
}

/// Issuer crypto context (signing).
pub struct IssuerSigning {
    /// Signature algorithm used for the issuer key.
    pub alg: CryptoAlg,
    private_key: Zeroizing<Vec<u8>>,
}

impl IssuerSigning {
    /// Own issuer signing bytes in a zeroizing container.
    ///
    /// Direct-key integrations should keep this owner as short-lived as possible.
    /// Provider-based integrations should prefer the signer-provider functions so
    /// private key material can remain in an HSM, platform keystore, or remote
    /// signing service.
    pub fn new(alg: CryptoAlg, private_key: Vec<u8>) -> Self {
        Self {
            alg,
            private_key: Zeroizing::new(private_key),
        }
    }

    pub(crate) fn private_key_bytes(&self) -> &[u8] {
        self.private_key.as_slice()
    }
}

/// Output of issuance (canonical).
pub struct IssuedCredential {
    pub envelope: CredentialEnvelope,
    pub subject_bundle: SubjectPrivateBundle,
}

/// Public output encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicFormat {
    /// Compact JWT-VC (UTF-8 bytes)
    JwtVc,

    /// Compact IETF SD-JWT VC (UTF-8 bytes)
    IetfSdJwtVc,
}

/// Output of issue+encode.
pub struct IssuedAndEncoded {
    pub public_format: PublicFormat,
    pub public_bytes: Vec<u8>,

    pub envelope: CredentialEnvelope,
    pub subject_bundle: SubjectPrivateBundle,
}

impl core::fmt::Debug for IssuedCredential {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("IssuedCredential([REDACTED])")
    }
}

impl Zeroize for IssuedCredential {
    fn zeroize(&mut self) {
        self.envelope.zeroize();
        self.subject_bundle.zeroize();
    }
}

impl Drop for IssuedCredential {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for IssuedCredential {}

impl core::fmt::Debug for IssuedAndEncoded {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("IssuedAndEncoded")
            .field("public_format", &self.public_format)
            .field("public_bytes", &"[REDACTED]")
            .field("envelope", &"[REDACTED]")
            .field("subject_bundle", &"[REDACTED]")
            .finish()
    }
}

impl Zeroize for IssuedAndEncoded {
    fn zeroize(&mut self) {
        self.public_bytes.zeroize();
        self.envelope.zeroize();
        self.subject_bundle.zeroize();
    }
}

impl Drop for IssuedAndEncoded {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for IssuedAndEncoded {}

#[cfg(feature = "jwt")]
pub struct JwtIssuerConfig {
    pub issuer_did: String,
    pub issuer_jwk: envelopes_jwk::Jwk,
}

#[cfg(feature = "ietf-sd-jwt")]
pub struct IetfSdJwtIssuerConfig {
    pub issuer_jwk: envelopes_jwk::Jwk,
    pub jwt_type: identity_vc_ietf_sd_jwt::IetfSdJwtJwtType,
    pub include_me_profile_merkle_binding: bool,
    pub salt_len: usize,
}

impl core::fmt::Debug for CredentialProfile {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Custom(profile) => formatter.debug_tuple("Custom").field(profile).finish(),
        }
    }
}

impl core::fmt::Debug for CustomProfile {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CustomProfile")
            .field("claimset_id", &redacted_len(self.claimset_id.len()))
            .field("kind", &self.kind)
            .field("assurance", &self.assurance)
            .field("domain_tags", &self.domain_tags)
            .field("limits", &self.limits)
            .field("registry_claims", &self.registry.claims.len())
            .field("require_qeaa", &self.require_qeaa)
            .field("required_claim_ids", &self.required_claim_ids.len())
            .finish()
    }
}

impl core::fmt::Debug for IssueCredentialRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("IssueCredentialRequest")
            .field("profile", &self.profile)
            .field("issuer_reference", &self.issuer_reference)
            .field("issuer_verification_key", &self.issuer_verification_key)
            .field("issuer_country", &redacted_len(self.issuer_country.len()))
            .field("subject", &self.subject)
            .field("valid_from", &self.valid_from)
            .field("valid_until", &self.valid_until)
            .field("status", &self.status)
            .field("claims", &self.claims.len())
            .field("qeaa", &self.qeaa.is_some())
            .finish()
    }
}

impl Zeroize for IssueCredentialRequest {
    fn zeroize(&mut self) {
        zeroize_profile(&mut self.profile);
        self.issuer_reference.zeroize();
        self.issuer_verification_key.zeroize();
        self.issuer_country.zeroize();
        self.subject.zeroize();
        self.valid_from.zeroize();
        self.valid_until.zeroize();
        self.status.zeroize();
        zeroize_claims(&mut self.claims);
        if let Some(qeaa) = &mut self.qeaa {
            zeroize_qeaa(qeaa);
        }
    }
}

impl Drop for IssueCredentialRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for IssueCredentialRequest {}

#[cfg(feature = "jwt")]
impl core::fmt::Debug for JwtIssuerConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("JwtIssuerConfig")
            .field("issuer_did", &redacted_len(self.issuer_did.len()))
            .field("issuer_jwk", &"[REDACTED]")
            .finish()
    }
}

#[cfg(feature = "ietf-sd-jwt")]
impl core::fmt::Debug for IetfSdJwtIssuerConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("IetfSdJwtIssuerConfig")
            .field("issuer_jwk", &"[REDACTED]")
            .field("jwt_type", &self.jwt_type)
            .field(
                "include_me_profile_merkle_binding",
                &self.include_me_profile_merkle_binding,
            )
            .field("salt_len", &self.salt_len)
            .finish()
    }
}

fn redacted_len(len: usize) -> RedactedLen {
    RedactedLen { len }
}

struct RedactedLen {
    len: usize,
}

impl core::fmt::Debug for RedactedLen {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("redacted")
            .field("len", &self.len)
            .finish()
    }
}

fn zeroize_profile(profile: &mut CredentialProfile) {
    let CredentialProfile::Custom(custom) = profile;
    custom.claimset_id.zeroize();
    custom.kind.zeroize();
    custom.assurance.zeroize();
    custom.domain_tags.zeroize();
    custom.limits.max_value_len = 0;
    custom.limits.salt_len = 0;
    zeroize_registry(&mut custom.registry);
    custom.require_qeaa.zeroize();
    custom.required_claim_ids.zeroize();
}

fn zeroize_registry(registry: &mut ClaimsRegistry) {
    registry.claimset_id.zeroize();

    // BTreeMap keys cannot be zeroized in place. Taking ownership lets us wipe
    // both keys and values before their allocations are released.
    let claims = core::mem::take(&mut registry.claims);
    for (mut key, mut definition) in claims {
        key.zeroize();
        definition.claim_id.zeroize();
        definition.encoding.zeroize();
        definition.disclosure.predicates.clear();
        definition.disclosure.allow_reveal = false;
    }
}

fn zeroize_claims(claims: &mut BTreeMap<String, serde_json::Value>) {
    let owned = core::mem::take(claims);
    for (mut key, mut value) in owned {
        key.zeroize();
        zeroize_json_value(&mut value);
    }
}

fn zeroize_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(values) => {
            for nested in values.iter_mut() {
                zeroize_json_value(nested);
            }
            values.clear();
        }
        serde_json::Value::Object(entries) => {
            let owned = core::mem::take(entries);
            for (mut key, mut nested) in owned {
                key.zeroize();
                zeroize_json_value(&mut nested);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            *value = serde_json::Value::Null;
        }
    }
}

fn zeroize_qeaa(qeaa: &mut QeaaCompliance) {
    qeaa.qtsp.tsp_name.zeroize();
    qeaa.qtsp.tsp_id.zeroize();
    qeaa.policies.policy_id.zeroize();
    qeaa.policies.standards.zeroize();
    qeaa.issuer_credential.cert_fingerprint_sha256.zeroize();
    qeaa.issuer_credential.cert_chain_der.zeroize();
    qeaa.issuer_credential.trusted_list_ref.zeroize();
    qeaa.issuer_credential.policy_oids.zeroize();
    qeaa.issuer_credential.qcstatements_oids.zeroize();
    qeaa.key_management.signing_key_id.zeroize();
    qeaa.identity_proofing.standard.zeroize();
    qeaa.identity_proofing.evidence_ref.zeroize();
    qeaa.identity_proofing.evidence_hash.zeroize();
    qeaa.audit.audit_standard.zeroize();
    qeaa.audit.audit_report_ref.zeroize();
    qeaa.audit.audit_report_hash.zeroize();
    qeaa.revocation.signing_key_id.zeroize();
}
