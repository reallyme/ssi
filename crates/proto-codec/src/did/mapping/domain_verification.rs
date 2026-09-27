// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_did_types::{DNSBinding, DomainVerification, WellKnownBinding};
use reallyme_ssi_proto::generated::proto::meid::did::v1::{
    domain_verification::Binding, DNSBinding as PbDnsBinding,
    DomainVerification as PbDomainVerification, WellKnownBinding as PbWellKnownBinding,
};

use crate::did::DidProtoCodecError;

/// JSON-domain domain verification to did:me protobuf.
pub fn domain_to_proto(d: &DomainVerification) -> Result<PbDomainVerification, DidProtoCodecError> {
    let binding = match d.method.as_str() {
        "dns" => d
            .dns
            .as_ref()
            .filter(|_| d.wellknown.is_none())
            .map(|dns| {
                Binding::Dns(Box::new(PbDnsBinding {
                    record_name: dns.record_name.clone(),
                    txt_value: dns.txt_value.clone(),
                    ..PbDnsBinding::default()
                }))
            })
            .ok_or(DidProtoCodecError::InvalidDomainVerification)?,
        "wellknown" => d
            .wellknown
            .as_ref()
            .filter(|_| d.dns.is_none())
            .map(|wellknown| {
                Binding::WellKnown(Box::new(PbWellKnownBinding {
                    uri: wellknown.uri.clone(),
                    content: wellknown.content.clone(),
                    ..PbWellKnownBinding::default()
                }))
            })
            .ok_or(DidProtoCodecError::InvalidDomainVerification)?,
        _ => return Err(DidProtoCodecError::InvalidDomainVerification),
    };

    Ok(PbDomainVerification {
        r#type: d.verification_type.clone(),
        domain: d.domain.clone(),
        method: d.method.clone(),
        binding: Some(binding),
        ..PbDomainVerification::default()
    })
}

/// did:me protobuf domain verification to JSON-domain model.
pub fn domain_from_proto(
    p: &PbDomainVerification,
) -> Result<DomainVerification, DidProtoCodecError> {
    let (dns, wellknown) = match (p.method.as_str(), p.binding.as_ref()) {
        ("dns", Some(Binding::Dns(dns))) => (
            Some(DNSBinding {
                record_name: dns.record_name.clone(),
                txt_value: dns.txt_value.clone(),
            }),
            None,
        ),
        ("wellknown", Some(Binding::WellKnown(wellknown))) => (
            None,
            Some(WellKnownBinding {
                uri: wellknown.uri.clone(),
                content: wellknown.content.clone(),
            }),
        ),
        _ => return Err(DidProtoCodecError::InvalidDomainVerification),
    };

    Ok(DomainVerification {
        verification_type: p.r#type.clone(),
        method: p.method.clone(),
        domain: p.domain.clone(),
        dns,
        wellknown,
    })
}
