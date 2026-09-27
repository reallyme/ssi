// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;
use std::collections::{BTreeSet, HashMap, HashSet};

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_crypto::core::{HashAlgorithm, RngOutputKind};
use reallyme_crypto::csprng::{generate_bytes, OsSecureRandom};
use reallyme_crypto::dispatch::hash_digest;
use reallyme_crypto::jwk::Jwk;
use reallyme_jose::jwt::{encode_signed_jwt_with_header_options, JwtHeaderEncodeOptions};
use serde_json::{Map, Value};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::disclose::{
    create_array_element_disclosure, create_object_property_disclosure, decode_disclosure,
    validate_object_claim_name, DisclosureKind, ARRAY_DIGEST_CLAIM_NAME, SD_CLAIM_NAME,
};
use crate::registered_claims::is_non_selectively_disclosable_claim;
use crate::sensitive::{zeroize_json_value, zeroize_strings};
use crate::{digest_disclosure, serialize_sd_jwt_compact, SdJwtEnvelopeError, SdJwtHashAlgorithm};

const SD_ALG_CLAIM_NAME: &str = "_sd_alg";
const DEFAULT_SALT_BYTES: usize = 16;
const DECOY_DIGEST_BYTES: usize = 32;
const DEFAULT_ISSUER_TYP: &str = "dc+sd-jwt";
const VC_ISSUER_TYP: &str = "vc+sd-jwt";
const JWT_TYP: &str = "JWT";
const DEFAULT_MAX_DEPTH: usize = 64;
const DEFAULT_MAX_NODES: usize = 16_384;
/// Hard ceiling applied to caller-supplied processing depth. Recursive
/// processing is bounded by this value regardless of policy configuration.
pub const MAX_SD_JWT_PROCESSING_DEPTH: usize = 128;
/// Hard ceiling applied to caller-supplied processing node budgets.
pub const MAX_SD_JWT_PROCESSING_NODES: usize = 131_072;

/// Entropy source used to generate disclosure salts and decoy digests.
pub trait SdJwtSaltSource {
    /// Produces the next salt for issuance.
    fn next_salt(&mut self) -> Result<String, SdJwtEnvelopeError>;
    /// Produces the next decoy digest for issuance.
    fn next_decoy_digest(&mut self) -> Result<String, SdJwtEnvelopeError>;
}

/// Operating-system random source for disclosure salts and decoy digests.
#[derive(Default)]
pub struct SecureRandomSaltSource {
    rng: OsSecureRandom,
}

impl SecureRandomSaltSource {
    /// Creates a salt source backed by the operating system CSPRNG.
    pub fn new() -> Self {
        SecureRandomSaltSource {
            rng: OsSecureRandom,
        }
    }
}

impl SdJwtSaltSource for SecureRandomSaltSource {
    fn next_salt(&mut self) -> Result<String, SdJwtEnvelopeError> {
        let random = generate_bytes::<DEFAULT_SALT_BYTES>(&mut self.rng, RngOutputKind::Generic)?;
        Ok(bytes_to_base64url(random.as_bytes()))
    }

    fn next_decoy_digest(&mut self) -> Result<String, SdJwtEnvelopeError> {
        let random = generate_bytes::<DECOY_DIGEST_BYTES>(&mut self.rng, RngOutputKind::Generic)?;
        Ok(bytes_to_base64url(&hash_digest(
            HashAlgorithm::Sha2_256,
            random.as_bytes(),
        )?))
    }
}

/// Strategy used to select selectively disclosable claims.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SdJwtDisclosureStrategy {
    /// Leaves every claim visible in the issuer payload.
    None,
    /// Makes each top-level claim selectively disclosable.
    TopLevel,
    /// Recursively makes object members and array elements selectively disclosable.
    AllLevels,
    /// Makes only the configured canonical JSON paths selectively disclosable.
    JsonPaths(BTreeSet<String>),
}

impl fmt::Debug for SdJwtDisclosureStrategy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => formatter.write_str("None"),
            Self::TopLevel => formatter.write_str("TopLevel"),
            Self::AllLevels => formatter.write_str("AllLevels"),
            Self::JsonPaths(_) => formatter.write_str("JsonPaths([REDACTED])"),
        }
    }
}

/// Controls decoy digest insertion during issuance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecoyPolicy {
    /// Number of decoy digests inserted into each selectively disclosable object.
    pub object_decoys: u8,
    /// Number of decoy digests inserted into each selectively disclosable array.
    pub array_decoys: u8,
}

impl DecoyPolicy {
    /// Constructs a policy with decoy generation disabled.
    pub const fn none() -> Self {
        DecoyPolicy {
            object_decoys: 0,
            array_decoys: 0,
        }
    }
}

/// Protected `typ` value written to the issuer-signed JWT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SdJwtIssuerType {
    /// Writes the `dc+sd-jwt` protected `typ` value from RFC 9901.
    DigitalCredentialSdJwt,
    /// Writes the legacy `vc+sd-jwt` protected `typ` value.
    VerifiableCredentialSdJwt,
    /// Generic `JWT` type for explicitly configured compatibility.
    Jwt,
    /// Omits the protected `typ` value.
    Omit,
}

impl SdJwtIssuerType {
    fn header_value(self) -> Option<String> {
        match self {
            SdJwtIssuerType::DigitalCredentialSdJwt => Some(DEFAULT_ISSUER_TYP.to_owned()),
            SdJwtIssuerType::VerifiableCredentialSdJwt => Some(VC_ISSUER_TYP.to_owned()),
            SdJwtIssuerType::Jwt => Some(JWT_TYP.to_owned()),
            SdJwtIssuerType::Omit => None,
        }
    }
}

/// Controls disclosure selection, decoys, and the issuer JWT type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdJwtIssuancePolicy {
    /// Claims converted into issuer-bound disclosures.
    pub disclosure_strategy: SdJwtDisclosureStrategy,
    /// Decoy digests inserted to obscure the number of real disclosures.
    pub decoys: DecoyPolicy,
    /// Protected `typ` value written to the issuer JWT.
    pub issuer_type: SdJwtIssuerType,
}

impl Default for SdJwtIssuancePolicy {
    fn default() -> Self {
        SdJwtIssuancePolicy {
            disclosure_strategy: SdJwtDisclosureStrategy::TopLevel,
            decoys: DecoyPolicy::none(),
            issuer_type: SdJwtIssuerType::DigitalCredentialSdJwt,
        }
    }
}

/// Inputs for creating an issuer-signed SD-JWT.
pub struct SdJwtIssuanceInput<'a> {
    /// Claims transformed according to `policy` before signing.
    pub claims: Value,
    /// Issuer public JWK whose parameters identify the signing key.
    pub issuer_jwk: &'a Jwk,
    /// Issuer private-key bytes used only to create the issuer signature.
    pub issuer_private_key: &'a [u8],
    /// Disclosure and protected-header policy for this issuance.
    pub policy: SdJwtIssuancePolicy,
}

impl fmt::Debug for SdJwtIssuanceInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SdJwtIssuanceInput([REDACTED])")
    }
}

/// Records one disclosure, its claim path, and its issuer-bound digest.
#[derive(PartialEq, Eq)]
pub struct DisclosureRecord {
    /// Canonical claim path associated with the disclosure.
    pub path: String,
    /// Base64url-encoded disclosure exactly as hashed by the issuer.
    pub encoded: String,
    /// Base64url digest that binds the encoded disclosure into the issuer payload.
    pub digest: String,
}

impl fmt::Debug for DisclosureRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DisclosureRecord([REDACTED])")
    }
}

impl Zeroize for DisclosureRecord {
    fn zeroize(&mut self) {
        self.path.zeroize();
        self.encoded.zeroize();
        self.digest.zeroize();
    }
}

impl Drop for DisclosureRecord {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DisclosureRecord {}

/// Issuance result containing the signed JWT, disclosures, and compact form.
#[derive(PartialEq)]
pub struct IssuedSdJwt {
    /// Claims written to the issuer-signed JWT before serialization.
    pub issuer_payload: Value,
    /// Compact issuer-signed JWT whose signature authenticates the SD-JWT payload.
    pub issuer_signed_jwt: String,
    /// Encoded disclosures carried by this SD-JWT value.
    pub disclosures: Vec<String>,
    /// Disclosure metadata produced during issuance.
    pub records: Vec<DisclosureRecord>,
    /// Canonical compact SD-JWT serialization produced by issuance.
    pub compact: String,
}

impl fmt::Debug for IssuedSdJwt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IssuedSdJwt([REDACTED])")
    }
}

impl Zeroize for IssuedSdJwt {
    fn zeroize(&mut self) {
        zeroize_json_value(&mut self.issuer_payload);
        self.issuer_signed_jwt.zeroize();
        zeroize_strings(&mut self.disclosures);
        for record in &mut self.records {
            record.zeroize();
        }
        self.records.clear();
        self.compact.zeroize();
    }
}

impl Drop for IssuedSdJwt {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for IssuedSdJwt {}

/// Issues an SD-JWT under the supplied disclosure and protected-header policy.
pub fn issue_sd_jwt(
    input: SdJwtIssuanceInput<'_>,
    salt_source: &mut impl SdJwtSaltSource,
) -> Result<IssuedSdJwt, SdJwtEnvelopeError> {
    if !input.claims.is_object() {
        return Err(SdJwtEnvelopeError::InvalidIssuanceInput);
    }

    validate_disclosure_strategy(&input.policy.disclosure_strategy)?;
    let mut records = Vec::new();
    let mut matched_paths = BTreeSet::new();
    let issuer_payload = transform_value(
        &input.claims,
        "$",
        true,
        &input.policy,
        salt_source,
        &mut records,
        &mut matched_paths,
    )?;
    if let SdJwtDisclosureStrategy::JsonPaths(paths) = &input.policy.disclosure_strategy {
        if matched_paths != *paths {
            return Err(SdJwtEnvelopeError::DisclosurePathNotFound);
        }
    }
    let issuer_signed_jwt = encode_signed_jwt_with_header_options(
        &issuer_payload,
        input.issuer_jwk,
        input.issuer_private_key,
        &JwtHeaderEncodeOptions::new(input.policy.issuer_type.header_value()),
    )?;
    let disclosures = records
        .iter()
        .map(|record| record.encoded.clone())
        .collect::<Vec<String>>();
    let compact = serialize_sd_jwt_compact(&issuer_signed_jwt, &disclosures)?;

    Ok(IssuedSdJwt {
        issuer_payload,
        issuer_signed_jwt,
        disclosures,
        records,
        compact,
    })
}
