// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OAuth substrate for ReallyMe protocol layers.
//!
//! This crate owns RFC 9126 PAR, RFC 9449 DPoP, RFC 7636 PKCE, RFC 8414
//! Authorization Server metadata, and attestation-based client authentication
//! draft support. Client Attestation PoP validation is inseparable from the
//! verified attestation's `cnf.jwk` binding. OpenID4VCI issuance, wallet, and
//! HTTP adapters consume these modules instead of duplicating OAuth logic.

pub mod attestation_client_auth;
mod attestation_trust_receipt;
mod bind_attested_client_key;
pub mod dpop;
pub mod error;
pub mod jwt;
pub mod metadata;
mod metadata_url;
#[cfg(test)]
mod metadata_url_tests;
pub mod par;
pub mod pkce;
mod sensitive;
mod strict_json;
pub mod validation;

pub use attestation_client_auth::{
    validate_attestation_client_authentication, AttestationClientAuthentication,
    AttestationClientAuthenticationValidationContext, AttestationClientAuthenticationVerifier,
    AttestationPopClaims, AttestationPopRequest, AttestedClientKey,
    VerifiedAttestationClientAuthentication, VerifiedClientAttestation,
    WalletAttestationTrustEvidence, MAX_ATTESTATION_TRUST_EVIDENCE_AGE_SECONDS,
    OAUTH_CLIENT_ATTESTATION_HEADER, OAUTH_CLIENT_ATTESTATION_POP_HEADER,
};
pub use dpop::{
    jwk_thumbprint, DpopClaims, DpopHeader, DpopProof, DpopProofRequest, DpopValidationContext,
    DpopVerifier,
};
pub use error::{OauthError, OauthResult, Reason};
pub use jwt::{CompactJwt, JwtSigner, JwtVerifier};
pub use metadata::{
    fetch_authorization_server_metadata, AuthorizationServerMetadata, MetadataFetcher,
};
pub use metadata_url::authorization_server_metadata_url;
pub use par::{GrantType, ParRequest, ParResponse};
pub use pkce::{CodeChallengeMethod, PkceChallenge, PkceVerifier};
