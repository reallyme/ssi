// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::update::error::UpdateError;
use reallyme_did_types::{DNSBinding, DomainVerification, Service, WellKnownBinding};

/// Merge services:
/// - `None` → inherit old services
/// - `Some([])` → explicitly clear services
/// - `Some(v)` → replace services
pub fn merge_services(old: &[Service], new: Option<Vec<Service>>) -> Vec<Service> {
    match new {
        Some(v) => v,
        None => old.to_vec(),
    }
}

/// Merge domain verification:
/// - `None` → inherit old
/// - `Some(v)` → replace + rebind to DID
pub fn merge_domain_verification(
    did: &str,
    old: &[DomainVerification],
    new: Option<&[DomainVerification]>,
) -> Result<Vec<DomainVerification>, UpdateError> {
    let src = match new {
        None => old,
        Some(v) => v,
    };

    let mut out = Vec::new();

    for dv in src {
        match dv.method.as_str() {
            "dns" => {
                out.push(DomainVerification {
                    verification_type: "DnsTxtVerification".into(),
                    method: "dns".into(),
                    domain: dv.domain.clone(),
                    dns: Some(DNSBinding {
                        record_name: "_did".into(),
                        txt_value: did.into(),
                    }),
                    wellknown: None,
                });
            }
            "wellknown" => {
                out.push(DomainVerification {
                    verification_type: "HttpsWellKnownVerification".into(),
                    method: "wellknown".into(),
                    domain: dv.domain.clone(),
                    dns: None,
                    wellknown: Some(WellKnownBinding {
                        uri: "/.well-known/did-configuration.json".into(),
                        content: did.into(),
                    }),
                });
            }
            _ => return Err(UpdateError::InvalidDomainVerification),
        }
    }

    Ok(out)
}
