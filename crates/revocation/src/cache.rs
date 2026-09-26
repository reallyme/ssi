// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

use reallyme_trust_x509::X509Certificate;

use crate::{RevocationCacheError, RevocationEvidenceMeta, StatusCheckError};

/// Cache for validated revocation evidence outcomes.
pub trait RevocationEvidenceCache {
    /// Retrieve a fresh cached outcome for a certificate, when available.
    fn lookup(&self, cert: &X509Certificate, now_unix: u64)
        -> Result<Option<()>, StatusCheckError>;

    /// Store a validated evidence outcome.
    ///
    /// Evidence without an expiry bound, or whose expiry does not follow its
    /// fetch time, is rejected rather than cached indefinitely.
    fn store(
        &mut self,
        cert: &X509Certificate,
        meta: RevocationEvidenceMeta,
        result: Result<(), StatusCheckError>,
    ) -> Result<(), RevocationCacheError>;
}

/// Certificate identity used as the cache key.
///
/// Serial numbers are only unique per issuer (RFC 5280 Section 4.1.2.2), so the
/// key binds the exact certificate and encoded issuer name as well as the
/// authority key identifier and canonical serial. Display names and absent AKIs
/// cannot uniquely identify an issuer. Owned certificate data is scrubbed on drop.
#[derive(Eq, Ord, PartialEq, PartialOrd, Zeroize, ZeroizeOnDrop)]
struct CacheKey {
    certificate_der: Vec<u8>,
    issuer_der: Vec<u8>,
    issuer: String,
    authority_key_identifier: Option<Vec<u8>>,
    serial: Vec<u8>,
}

impl CacheKey {
    fn for_certificate(cert: &X509Certificate) -> Self {
        Self {
            certificate_der: cert.der.clone(),
            issuer_der: cert.issuer_der.clone(),
            issuer: cert.issuer.clone(),
            authority_key_identifier: cert.authority_key_identifier.clone(),
            serial: canonical_serial(&cert.serial).to_vec(),
        }
    }
}

fn canonical_serial(serial: &[u8]) -> &[u8] {
    let start = serial
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(serial.len());
    serial.get(start..).unwrap_or_default()
}

struct CachedOutcome {
    expires_at_unix: u64,
    result: Result<(), StatusCheckError>,
}

/// Deterministic in-memory revocation evidence cache for tests and short-lived processes.
#[derive(Default)]
pub struct InMemoryRevocationCache {
    entries: BTreeMap<CacheKey, CachedOutcome>,
}

impl InMemoryRevocationCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self::default()
    }
}

impl RevocationEvidenceCache for InMemoryRevocationCache {
    fn lookup(
        &self,
        cert: &X509Certificate,
        now_unix: u64,
    ) -> Result<Option<()>, StatusCheckError> {
        let Some(outcome) = self.entries.get(&CacheKey::for_certificate(cert)) else {
            return Ok(None);
        };
        if now_unix > outcome.expires_at_unix {
            return Ok(None);
        }

        match outcome.result {
            Ok(()) => Ok(Some(())),
            Err(StatusCheckError::Revoked) => Err(StatusCheckError::Revoked),
            Err(StatusCheckError::Suspended) => Err(StatusCheckError::Suspended),
            Err(_) => Ok(None),
        }
    }

    fn store(
        &mut self,
        cert: &X509Certificate,
        meta: RevocationEvidenceMeta,
        result: Result<(), StatusCheckError>,
    ) -> Result<(), RevocationCacheError> {
        let expires_at_unix = meta
            .expires_at_unix
            .ok_or(RevocationCacheError::MissingExpiry)?;
        if expires_at_unix <= meta.fetched_at_unix {
            return Err(RevocationCacheError::InvalidExpiry);
        }
        self.entries.insert(
            CacheKey::for_certificate(cert),
            CachedOutcome {
                expires_at_unix,
                result,
            },
        );
        Ok(())
    }
}
