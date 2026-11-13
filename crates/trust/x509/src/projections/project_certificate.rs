// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::project_extensions::{alternative_names, crl_points};
use super::project_name::{name, Budget};
use super::read_der::{finish, invalid, oid, one, require, take, validate_tree_with_budget};
use super::{Asn1Class, CertificateProjections, ProjectionError, ProjectionErrorReason};
use crate::{MAX_X509_CERTIFICATE_DER_BYTES, MAX_X509_EXTENSIONS};
use x509_parser::{nom::Parser, prelude::X509CertificateParser};

/// Projects exact certificate syntax without authenticating it or imposing an
/// ISO, AAMVA, IACA, OCSP-service, or other relying-party profile.
///
/// Input and all borrowed values remain tied to the caller's DER owner. For an
/// owned certificate, use [`crate::X509Certificate::projections`]; that owner
/// zeroizes its storage on drop. Only decoded BMP/Universal strings allocate
/// identifying data here, and those owners zeroize on drop as well.
pub fn project_certificate(der: &[u8]) -> Result<CertificateProjections<'_>, ProjectionError> {
    if der.len() > MAX_X509_CERTIFICATE_DER_BYTES {
        return Err(ProjectionErrorReason::CertificateTooLarge.into());
    }
    let mut budget = Budget::default();
    validate_tree_with_budget(der, &mut budget.der_elements)?;
    let source = one(der)?;
    require(&source, Asn1Class::Universal, 16, true)?;
    let mut outer = source.content;
    let tbs = take(&mut outer)?;
    require(&tbs, Asn1Class::Universal, 16, true)?;
    let _algorithm = take(&mut outer)?;
    let _signature = take(&mut outer)?;
    finish(outer)?;
    let mut fields = tbs.content;
    let first = take(&mut fields)?;
    if first.encoding.class == Asn1Class::ContextSpecific && first.encoding.tag_number == 0 {
        require(&first, Asn1Class::ContextSpecific, 0, true)?;
        let version = one(first.content)?;
        require(&version, Asn1Class::Universal, 2, false)?;
        if !matches!(version.content, [1] | [2]) {
            return Err(invalid());
        }
        let _serial = take(&mut fields)?;
    }
    let _algorithm = take(&mut fields)?;
    let issuer_der = take(&mut fields)?;
    let _validity = take(&mut fields)?;
    let subject_der = take(&mut fields)?;
    let _spki = take(&mut fields)?;
    let subject = name(subject_der.der, &mut budget)?;
    let issuer = name(issuer_der.der, &mut budget)?;
    let mut result = CertificateProjections {
        source,
        subject,
        issuer,
        san: None,
        ian: None,
        crl: None,
    };

    // Read the wrappers ourselves: a DEFAULT FALSE encoded explicitly is not
    // DER, and extension identity must be checked even for unknown extensions.
    let mut extension_sequence = None;
    while !fields.is_empty() {
        let field = take(&mut fields)?;
        if field.encoding.class == Asn1Class::ContextSpecific && field.encoding.tag_number == 3 {
            if extension_sequence.is_some() || !fields.is_empty() {
                return Err(invalid());
            }
            require(&field, Asn1Class::ContextSpecific, 3, true)?;
            let sequence = one(field.content)?;
            require(&sequence, Asn1Class::Universal, 16, true)?;
            if sequence.content.is_empty() {
                return Err(invalid());
            }
            extension_sequence = Some(sequence);
        }
    }
    let mut content = match extension_sequence {
        Some(sequence) => sequence.content,
        None => &[],
    };
    let mut seen = Vec::<&[u8]>::new();
    while !content.is_empty() {
        if seen.len() >= MAX_X509_EXTENSIONS {
            return Err(ProjectionErrorReason::TooManyExtensions.into());
        }
        let extension = take(&mut content)?;
        require(&extension, Asn1Class::Universal, 16, true)?;
        let mut fields = extension.content;
        let identifier = take(&mut fields)?;
        require(&identifier, Asn1Class::Universal, 6, false)?;
        oid(identifier.content)?;
        if seen.contains(&identifier.content) {
            return Err(ProjectionErrorReason::DuplicateExtension.into());
        }
        seen.push(identifier.content);
        let mut value = take(&mut fields)?;
        let critical =
            if value.encoding.class == Asn1Class::Universal && value.encoding.tag_number == 1 {
                require(&value, Asn1Class::Universal, 1, false)?;
                if value.content != [0xff] {
                    return Err(invalid());
                }
                value = take(&mut fields)?;
                true
            } else {
                false
            };
        require(&value, Asn1Class::Universal, 4, false)?;
        finish(fields)?;
        match identifier.content {
            [0x55, 0x1d, 0x11] => {
                result.san = Some(alternative_names(value.content, critical, &mut budget)?)
            }
            [0x55, 0x1d, 0x12] => {
                result.ian = Some(alternative_names(value.content, critical, &mut budget)?)
            }
            [0x55, 0x1d, 0x1f] => {
                result.crl = Some(crl_points(value.content, critical, &mut budget)?)
            }
            _ => {}
        }
    }
    // Schema parsing runs after the tighter projection budgets, so it cannot
    // allocate unbounded extension or name collections first.
    let (rest, _certificate) = X509CertificateParser::new()
        .with_deep_parse_extensions(false)
        .parse(der)
        .map_err(|_| invalid())?;
    finish(rest)?;
    Ok(result)
}
