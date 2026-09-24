// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use reallyme_trust_x509::X509Certificate;

use crate::{RevocationEvidenceMeta, StatusCheckError};

/// Cache for validated revocation evidence outcomes.
pub trait RevocationEvidenceCache {
    /// Retrieve a fresh cached outcome for a certificate, when available.
    fn lookup(&self, cert: &X509Certificate, now_unix: u64)
        -> Result<Option<()>, StatusCheckError>;

    /// Store a validated evidence outcome.
    fn store(
        &mut self,
        cert: &X509Certificate,
        meta: RevocationEvidenceMeta,
        result: Result<(), StatusCheckError>,
    );
}

/// Deterministic in-memory revocation evidence cache for tests and short-lived processes.
#[derive(Default)]
pub struct InMemoryRevocationCache {
    entries: BTreeMap<Vec<u8>, (RevocationEvidenceMeta, Result<(), StatusCheckError>)>,
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
        let Some((meta, result)) = self.entries.get(&cert.serial) else {
            return Ok(None);
        };
        if let Some(expires_at_unix) = meta.expires_at_unix {
            if now_unix > expires_at_unix {
                return Ok(None);
            }
        }

        match result {
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
    ) {
        self.entries.insert(cert.serial.clone(), (meta, result));
    }
}
