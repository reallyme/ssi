// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_trust_x509::X509Certificate;

use crate::{
    CompositeRevocationPolicy, OcspStatusChecker, SoftFailMode, StatusCheckError, StatusChecker,
};

/// Composite checker that evaluates every configured X.509 revocation source.
///
/// A successful source does not mask a later authoritative revocation. The
/// credential status-list leg is intentionally not part of this checker: it
/// concerns a credential identifier rather than an X.509 certificate and is
/// evaluated by the credential verification boundary.
pub struct CompositeStatusChecker<'a> {
    /// Evaluation policy.
    pub policy: CompositeRevocationPolicy,

    /// Optional OCSP checker.
    pub ocsp: Option<&'a dyn OcspStatusChecker>,

    /// Optional CRL checker.
    pub crl: Option<&'a dyn StatusChecker>,
}

impl StatusChecker for CompositeStatusChecker<'_> {
    fn check(&self, cert: &X509Certificate, now_unix: u64) -> Result<(), StatusCheckError> {
        if now_unix == 0 || now_unix != self.policy.now_unix {
            return Err(StatusCheckError::InvalidList);
        }
        let mut last_non_terminal_error = None;
        let mut source_was_configured = false;
        let mut source_succeeded = false;
        if self.policy.prefer_ocsp {
            if let Some(checker) = self.ocsp {
                source_was_configured = true;
                match checker.check_with_policy(cert, now_unix, self.policy.ocsp) {
                    Ok(()) => source_succeeded = true,
                    Err(StatusCheckError::Revoked) => return Err(StatusCheckError::Revoked),
                    Err(StatusCheckError::Suspended) => return Err(StatusCheckError::Suspended),
                    Err(error) => handle_non_terminal(
                        self.policy.soft_fail,
                        error,
                        &mut last_non_terminal_error,
                    )?,
                }
            }
        }

        for (enabled, checker) in [(self.policy.prefer_crl, self.crl)] {
            if !enabled {
                continue;
            }
            let Some(checker) = checker else {
                continue;
            };
            source_was_configured = true;
            match checker.check(cert, now_unix) {
                Ok(()) => source_succeeded = true,
                Err(StatusCheckError::Revoked) => return Err(StatusCheckError::Revoked),
                Err(StatusCheckError::Suspended) => return Err(StatusCheckError::Suspended),
                Err(error) => {
                    handle_non_terminal(self.policy.soft_fail, error, &mut last_non_terminal_error)?
                }
            }
        }

        if source_succeeded {
            Ok(())
        } else if source_was_configured {
            Err(last_non_terminal_error.unwrap_or(StatusCheckError::Unavailable))
        } else {
            Err(StatusCheckError::Unsupported)
        }
    }
}

fn handle_non_terminal(
    mode: SoftFailMode,
    error: StatusCheckError,
    last_error: &mut Option<StatusCheckError>,
) -> Result<(), StatusCheckError> {
    match mode {
        SoftFailMode::Strict => Err(error),
        SoftFailMode::FallbackOnUnavailable if error != StatusCheckError::Unavailable => Err(error),
        SoftFailMode::FallbackOnUnavailable | SoftFailMode::Fallback => {
            *last_error = Some(error);
            Ok(())
        }
    }
}
