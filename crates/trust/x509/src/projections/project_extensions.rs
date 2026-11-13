// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::project_name::{name, relative_name, Budget};
use super::read_der::{
    bit_string, finish, invalid, oid, one, require, take, validate_tree_with_budget,
};
use super::{
    AlternativeNamesProjection, Asn1Class, CrlDistributionPointProjection,
    CrlDistributionPointsProjection, DistributionPointNameProjection, EncodedValue,
    GeneralNameProjection, GeneralNameValue, ProjectionError, ProjectionErrorReason,
    ReasonFlagsProjection, RedactedIa5, MAX_PROJECTION_DISTRIBUTION_POINTS,
    MAX_PROJECTION_GENERAL_NAMES,
};

pub(super) fn alternative_names<'a>(
    der: &'a [u8],
    critical: bool,
    budget: &mut Budget,
) -> Result<AlternativeNamesProjection<'a>, ProjectionError> {
    validate_tree_with_budget(der, &mut budget.der_elements)?;
    let sequence = one(der)?;
    require(&sequence, Asn1Class::Universal, 16, true)?;
    Ok(AlternativeNamesProjection {
        critical,
        names: general_names(sequence.content, budget)?,
    })
}

fn general_names<'a>(
    mut content: &'a [u8],
    budget: &mut Budget,
) -> Result<Vec<GeneralNameProjection<'a>>, ProjectionError> {
    if content.is_empty() {
        return Err(invalid());
    }
    let mut names = Vec::new();
    while !content.is_empty() {
        budget.general_names = budget
            .general_names
            .checked_add(1)
            .ok_or(ProjectionErrorReason::TooManyGeneralNames)?;
        if budget.general_names > MAX_PROJECTION_GENERAL_NAMES {
            return Err(ProjectionErrorReason::TooManyGeneralNames.into());
        }
        let encoded = take(&mut content)?;
        if encoded.encoding.class != Asn1Class::ContextSpecific {
            return Err(invalid());
        }
        let tag = encoded.encoding.tag_number;
        let constructed = matches!(tag, 0 | 3 | 4 | 5);
        require(&encoded, Asn1Class::ContextSpecific, tag, constructed)?;
        let value = match tag {
            0 => {
                let mut fields = encoded.content;
                let type_id = take(&mut fields)?;
                require(&type_id, Asn1Class::Universal, 6, false)?;
                oid(type_id.content)?;
                let value = take(&mut fields)?;
                require(&value, Asn1Class::ContextSpecific, 0, true)?;
                let _ = one(value.content)?;
                finish(fields)?;
                GeneralNameValue::OtherName { type_id, value }
            }
            1 => GeneralNameValue::Rfc822Name(ia5(&encoded)?),
            2 => GeneralNameValue::DnsName(ia5(&encoded)?),
            // These ASN.1 structures remain explicit unsupported alternatives.
            // Their original DER is retained; no policy claim is derived.
            3 => GeneralNameValue::UnsupportedX400Address,
            4 => GeneralNameValue::DirectoryName(name(encoded.content, budget)?),
            5 => GeneralNameValue::UnsupportedEdiPartyName,
            6 => GeneralNameValue::UniformResourceIdentifier(ia5(&encoded)?),
            7 => GeneralNameValue::IpAddress(one(encoded.der)?),
            8 => {
                oid(encoded.content)?;
                GeneralNameValue::RegisteredId(one(encoded.der)?)
            }
            _ => return Err(invalid()),
        };
        names.push(GeneralNameProjection { encoded, value });
    }
    Ok(names)
}

fn ia5<'a>(encoded: &EncodedValue<'a>) -> Result<RedactedIa5<'a>, ProjectionError> {
    if !encoded.content.is_ascii() {
        return Err(ProjectionErrorReason::InvalidStringEncoding.into());
    }
    let text = core::str::from_utf8(encoded.content)
        .map_err(|_| ProjectionErrorReason::InvalidStringEncoding)?;
    Ok(RedactedIa5(text))
}

pub(super) fn crl_points<'a>(
    der: &'a [u8],
    critical: bool,
    budget: &mut Budget,
) -> Result<CrlDistributionPointsProjection<'a>, ProjectionError> {
    validate_tree_with_budget(der, &mut budget.der_elements)?;
    let sequence = one(der)?;
    require(&sequence, Asn1Class::Universal, 16, true)?;
    if sequence.content.is_empty() {
        return Err(invalid());
    }
    let mut content = sequence.content;
    let mut points = Vec::new();
    while !content.is_empty() {
        if points.len() >= MAX_PROJECTION_DISTRIBUTION_POINTS {
            return Err(ProjectionErrorReason::TooManyDistributionPoints.into());
        }
        let encoded = take(&mut content)?;
        require(&encoded, Asn1Class::Universal, 16, true)?;
        let mut fields = encoded.content;
        let mut name = None;
        let mut reasons = None;
        let mut issuer = None;
        let mut previous = None;
        while !fields.is_empty() {
            let field = take(&mut fields)?;
            let tag = field.encoding.tag_number;
            // SEQUENCE components must be ordered and unique even though all
            // three are OPTIONAL. Presence must never be collapsed to a value.
            if previous.is_some_and(|previous| previous >= tag) {
                return Err(invalid());
            }
            previous = Some(tag);
            match tag {
                0 => {
                    require(&field, Asn1Class::ContextSpecific, 0, true)?;
                    let choice = one(field.content)?;
                    let choice_tag = choice.encoding.tag_number;
                    require(&choice, Asn1Class::ContextSpecific, choice_tag, true)?;
                    name = Some(match choice_tag {
                        0 => DistributionPointNameProjection::FullName(general_names(
                            choice.content,
                            budget,
                        )?),
                        1 => DistributionPointNameProjection::RelativeName(relative_name(
                            choice, budget,
                        )?),
                        _ => return Err(invalid()),
                    });
                }
                1 => {
                    require(&field, Asn1Class::ContextSpecific, 1, false)?;
                    bit_string(field.content)?;
                    // A named BIT STRING has no implicit SIZE constraint.
                    // Keep unknown bit positions for the caller's profile to
                    // reject, while enforcing DER's trailing-zero removal.
                    // The empty value remains distinct from an absent field.
                    let (&unused, bytes) = field.content.split_first().ok_or_else(invalid)?;
                    if bytes.last().is_some_and(|last| {
                        *last == 0 || last.trailing_zeros() != u32::from(unused)
                    }) {
                        return Err(invalid());
                    }
                    reasons = Some(ReasonFlagsProjection { encoded: field });
                }
                2 => {
                    require(&field, Asn1Class::ContextSpecific, 2, true)?;
                    issuer = Some(general_names(field.content, budget)?);
                }
                _ => return Err(invalid()),
            }
        }
        // A reasons-only point is syntactically representable. Retain it so
        // applications can apply their own RFC/profile conformance policy.
        points.push(CrlDistributionPointProjection {
            encoded,
            name,
            reasons,
            issuer,
        });
    }
    Ok(CrlDistributionPointsProjection { critical, points })
}
