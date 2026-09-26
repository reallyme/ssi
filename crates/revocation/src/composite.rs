// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_trust_x509::X509Certificate;

use crate::{CompositeRevocationPolicy, SoftFailMode, StatusCheckError, StatusChecker};

/// Composite checker that delegates to OCSP, CRL, and StatusList sources in policy order.
pub struct CompositeStatusChecker<'a> {
    /// Evaluation policy.
    pub policy: CompositeRevocationPolicy,

    /// Optional OCSP checker.
    pub ocsp: Option<&'a dyn StatusChecker>,

    /// Optional CRL checker.
    pub crl: Option<&'a dyn StatusChecker>,

    /// Optional credential status-list checker.
    pub statuslist: Option<&'a dyn StatusChecker>,
}

impl StatusChecker for CompositeStatusChecker<'_> {
    fn check(&self, cert: &X509Certificate, now_unix: u64) -> Result<(), StatusCheckError> {
        let attempts = [
            (self.policy.prefer_ocsp, self.ocsp),
            (self.policy.prefer_crl, self.crl),
            (self.policy.prefer_statuslist, self.statuslist),
        ];

        let mut last_non_terminal_error = None;
        for (enabled, checker) in attempts {
            if !enabled {
                continue;
            }
            let Some(checker) = checker else {
                continue;
            };
            match checker.check(cert, now_unix) {
                Ok(()) => return Ok(()),
                Err(StatusCheckError::Revoked) => return Err(StatusCheckError::Revoked),
                Err(StatusCheckError::Suspended) => return Err(StatusCheckError::Suspended),
                Err(error) => match self.policy.soft_fail {
                    SoftFailMode::Strict => return Err(error),
                    SoftFailMode::FallbackOnUnavailable => {
                        if error != StatusCheckError::Unavailable {
                            return Err(error);
                        }
                        last_non_terminal_error = Some(error);
                    }
                    SoftFailMode::Fallback => last_non_terminal_error = Some(error),
                },
            }
        }

        Err(last_non_terminal_error.unwrap_or(StatusCheckError::Unavailable))
    }
}
