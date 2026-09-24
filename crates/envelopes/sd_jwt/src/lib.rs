// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// This crate exposes a deliberately bounded protocol surface. The remaining
// module-level allowance is temporary technical debt, not an indication that
// the package is internal or unsupported.
#![allow(missing_docs)]

//! SD-JWT envelope formats.
//!
//! This crate implements RFC 9901 SD-JWT issuance and verifier-side helpers:
//! compact serialization, JWS JSON Serialization, disclosure encoding,
//! recursive disclosure processing, issuer signature verification, and optional
//! key-binding JWT validation.

mod compact;
mod disclose;
mod error;
mod hash_algorithm;
mod holder_binding;
mod json_serialization;
mod present;
mod select_disclosures;
mod sensitive;
mod verify;
mod verify_receipt;

pub use compact::{
    parse_sd_jwt_compact, parse_sd_jwt_or_kb_compact, serialize_sd_jwt_compact,
    serialize_sd_jwt_kb_compact, SdJwtCompact, SdJwtOrKbCompact, SdJwtWithKbCompact,
    MAX_SD_JWT_COMPACT_BYTES, MAX_SD_JWT_DISCLOSURES, MAX_SD_JWT_DISCLOSURE_BYTES,
};
pub use disclose::{
    create_array_element_disclosure, create_object_property_disclosure, decode_disclosure,
    digest_disclosure, Disclosure, DisclosureKind,
};
pub use error::SdJwtEnvelopeError;
pub use hash_algorithm::SdJwtHashAlgorithm;
pub use holder_binding::{
    build_key_binding_jwt, KeyBindingJwtBuildOptions, KeyBindingVerificationOptions,
};
pub use json_serialization::{
    parse_sd_jwt_json_serialization, SdJwtJsonSerialization, SdJwtJsonSerializationSet,
    MAX_SD_JWT_JSON_BYTES, MAX_SD_JWT_JSON_SIGNATURES,
};
pub use present::{
    issue_sd_jwt, process_sd_jwt_payload, DecoyPolicy, DisclosureRecord, IssuedSdJwt,
    SdJwtDisclosureStrategy, SdJwtIssuanceInput, SdJwtIssuancePolicy, SdJwtIssuerType,
    SdJwtProcessingPolicy, SdJwtSaltSource, SecureRandomSaltSource,
};
/// Exact JWK type accepted by issuance-receipt holder-binding policy.
pub use reallyme_crypto::jwk::EcJwk as SdJwtReceiptEcJwk;
pub use reallyme_crypto::jwk::Jwk as SdJwtReceiptJwk;
pub use select_disclosures::{
    select_sd_jwt_disclosures, SdJwtClaimPathComponent, SelectedSdJwtDisclosures,
};
pub use verify::{
    verify_sd_jwt, verify_sd_jwt_json_serialization, SdJwtVerificationOptions, VerifiedSdJwt,
};
pub use verify_receipt::{
    parse_sd_jwt_issuer_x5c, verify_sd_jwt_receipt, verify_sd_jwt_receipt_with_x5c,
    SdJwtReceiptVerificationPolicy, ValidatedSdJwtHolderBinding, VerifiedSdJwtReceipt,
    MAX_SD_JWT_EXPECTED_CLAIM_BYTES,
};
