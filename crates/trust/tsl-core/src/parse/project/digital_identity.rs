// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

struct ParsedDigitalRepresentations {
    certificates_der: Vec<Vec<u8>>,
    subject_name: Option<String>,
    key_value: Option<XmlDsigKeyValue>,
    subject_key_identifier: Option<Vec<u8>>,
    non_pki_identifiers: Vec<TslNonPkiIdentifier>,
    structured_other_present: bool,
}
fn parse_current_digital_identity(
    identity: RawServiceDigitalIdentity,
) -> Result<ServiceDigitalIdentity, TslError> {
    let mut parsed = parse_digital_representations(identity)?;
    if !parsed.certificates_der.is_empty() {
        let mut facts = validate_current_pki_representations(&parsed)?;
        if parsed.subject_key_identifier.is_none() {
            parsed.subject_key_identifier = Some(
                facts
                    .subject_key_identifier
                    .clone()
                    .unwrap_or_else(|| facts.derived_subject_key_identifier.to_vec()),
            );
        }
        let certificates = core::mem::take(&mut parsed.certificates_der);
        merge_unique(&mut parsed.certificates_der, certificates);
        return Ok(ServiceDigitalIdentity::Pki(Box::new(
            PkiServiceDigitalIdentity {
                certificates_der: parsed.certificates_der,
                subject_name: parsed.subject_name,
                key_value: parsed.key_value,
                subject_key_identifier: parsed.subject_key_identifier,
                subject_public_key_info_der: core::mem::take(
                    &mut facts.subject_public_key_info_der,
                ),
                certificate_authority: facts.certificate_authority,
            },
        )));
    }
    if parsed.subject_name.is_some()
        || parsed.key_value.is_some()
        || parsed.subject_key_identifier.is_some()
        || parsed.structured_other_present
    {
        return Err(TslError::DigitalIdentity(
            TslDigitalIdentityFailure::MissingCertificate,
        ));
    }
    let non_pki_identifier = one_non_pki_identifier(parsed.non_pki_identifiers)?;
    Ok(ServiceDigitalIdentity::NonPki(non_pki_identifier))
}

fn parse_historical_digital_identity(
    identity: RawServiceDigitalIdentity,
) -> Result<Option<ServiceDigitalIdentity>, TslError> {
    if identity.ids.is_empty() {
        return Ok(None);
    }
    let mut parsed = parse_digital_representations(identity)?;
    // History that cannot identify a prior PKI key cannot authorize any
    // retrospective trust decision. Omit it conservatively while retaining
    // the authenticated current service state.
    if parsed.subject_key_identifier.is_none() {
        return Ok(None);
    }
    if !parsed.certificates_der.is_empty() {
        // Some deployed lists redundantly retain a certificate in history.
        // Prove that every representation names the same key before dropping
        // the forbidden certificate representation from the normalized model.
        if let Err(error) = validate_historical_certificates(&parsed) {
            if error
                == TslError::DigitalIdentity(
                    TslDigitalIdentityFailure::SubjectKeyIdentifierMismatch,
                )
            {
                // An inconsistent historical row cannot authorize a current
                // key. Omit that row instead of rejecting the independently
                // authenticated current service state.
                return Ok(None);
            }
            return Err(error);
        }
        parsed.certificates_der.clear();
    }
    Ok(Some(ServiceDigitalIdentity::Pki(Box::new(
        PkiServiceDigitalIdentity {
            certificates_der: Vec::new(),
            subject_name: parsed.subject_name,
            key_value: parsed.key_value,
            subject_key_identifier: parsed.subject_key_identifier,
            subject_public_key_info_der: Vec::new(),
            certificate_authority: false,
        },
    ))))
}

fn validate_historical_certificates(
    identity: &ParsedDigitalRepresentations,
) -> Result<(), TslError> {
    let expected = identity.subject_key_identifier.as_deref().ok_or(
        TslError::DigitalIdentity(
            TslDigitalIdentityFailure::MissingHistoricalSubjectKeyIdentifier,
        ),
    )?;
    for certificate_der in &identity.certificates_der {
        let facts = parse_certificate_identity_facts(certificate_der)?;
        if !certificate_subject_key_identifier_matches(&facts, expected) {
            return Err(TslError::DigitalIdentity(
                TslDigitalIdentityFailure::SubjectKeyIdentifierMismatch,
            ));
        }
    }
    Ok(())
}

fn parse_digital_representations(
    identity: RawServiceDigitalIdentity,
) -> Result<ParsedDigitalRepresentations, TslError> {
    if identity.ids.is_empty() {
        return Err(TslError::DigitalIdentity(
            TslDigitalIdentityFailure::Empty,
        ));
    }
    if identity.ids.len() > MAX_DIGITAL_IDENTITIES {
        return Err(TslError::DigitalIdentity(
            TslDigitalIdentityFailure::RepresentationLimit,
        ));
    }
    let mut parsed = ParsedDigitalRepresentations {
        certificates_der: Vec::new(),
        subject_name: None,
        key_value: None,
        subject_key_identifier: None,
        non_pki_identifiers: Vec::new(),
        structured_other_present: false,
    };
    for digital_id in identity.ids {
        let representation_count = usize::from(digital_id.certificate.is_some())
            .checked_add(usize::from(digital_id.subject_name.is_some()))
            .and_then(|count| count.checked_add(usize::from(digital_id.key_value.is_some())))
            .and_then(|count| {
                count.checked_add(usize::from(digital_id.subject_key_identifier.is_some()))
            })
            .and_then(|count| count.checked_add(usize::from(digital_id.other.is_some())))
            .ok_or(TslError::DigitalIdentity(
                TslDigitalIdentityFailure::RepresentationLimit,
            ))?;
        if representation_count != 1 {
            return Err(TslError::DigitalIdentity(
                TslDigitalIdentityFailure::MalformedRepresentation,
            ));
        }
        if let Some(certificate) = digital_id.certificate {
            if parsed.certificates_der.len() >= MAX_CERTIFICATES_PER_IDENTITY {
                return Err(TslError::ResourceLimit(TslResourceLimit::Certificates));
            }
            parsed.certificates_der.push(decode_base64_binary(
                certificate,
                MAX_CERTIFICATE_BASE64_BYTES,
                TslError::InvalidCertificate,
            )?);
        }
        if let Some(subject_name) = digital_id.subject_name {
            merge_identity_representation(
                &mut parsed.subject_name,
                bounded_text(subject_name)?,
            )?;
        }
        if let Some(key_value) = digital_id.key_value {
            merge_identity_representation(&mut parsed.key_value, parse_key_value(key_value)?)?;
        }
        if let Some(subject_key_identifier) = digital_id.subject_key_identifier {
            let value = decode_base64_binary(
                subject_key_identifier,
                MAX_KEY_COMPONENT_BASE64_BYTES,
                TslError::DigitalIdentity(TslDigitalIdentityFailure::MalformedRepresentation),
            )?;
            merge_identity_representation(&mut parsed.subject_key_identifier, value)?;
        }
        if let Some(other) = digital_id.other {
            match other.value {
                Some(value) => parsed
                    .non_pki_identifiers
                    .push(parse_non_pki_identifier(value)?),
                None => parsed.structured_other_present = true,
            }
        }
    }
    Ok(parsed)
}

fn merge_identity_representation<T: PartialEq>(
    slot: &mut Option<T>,
    value: T,
) -> Result<(), TslError> {
    if slot.as_ref().is_some_and(|existing| existing == &value) {
        return Ok(());
    }
    if slot.is_some() {
        return Err(TslError::DigitalIdentity(
            TslDigitalIdentityFailure::DuplicateRepresentation,
        ));
    }
    *slot = Some(value);
    Ok(())
}

fn parse_non_pki_identifier(value: String) -> Result<TslNonPkiIdentifier, TslError> {
    let value = bounded_text(value)?;
    if value.len() > MAX_TSL_URI_BYTES || value.trim().is_empty() {
        return Err(TslError::DigitalIdentity(
            TslDigitalIdentityFailure::InvalidNonPkiIdentifier,
        ));
    }
    Ok(TslNonPkiIdentifier::new(value))
}

fn one_non_pki_identifier(
    values: Vec<TslNonPkiIdentifier>,
) -> Result<TslNonPkiIdentifier, TslError> {
    let mut values = values.into_iter();
    let first = values.next().ok_or(TslError::DigitalIdentity(
        TslDigitalIdentityFailure::Empty,
    ))?;
    if values.any(|value| value != first) {
        return Err(TslError::DigitalIdentity(
            TslDigitalIdentityFailure::DuplicateRepresentation,
        ));
    }
    Ok(first)
}

fn parse_key_value(raw: RawKeyValue) -> Result<XmlDsigKeyValue, TslError> {
    match (raw.rsa, raw.dsa, raw.ec) {
        (Some(rsa), None, None) => Ok(XmlDsigKeyValue::Rsa {
            modulus: decode_required_key_component(rsa.modulus)?,
            exponent: decode_required_key_component(rsa.exponent)?,
        }),
        (None, Some(dsa), None) => {
            if dsa.p.is_some() != dsa.q.is_some()
                || dsa.seed.is_some() != dsa.pgen_counter.is_some()
            {
                return Err(TslError::DigitalIdentity(
                    TslDigitalIdentityFailure::MalformedRepresentation,
                ));
            }
            Ok(XmlDsigKeyValue::Dsa {
                p: dsa.p.map(decode_key_component).transpose()?,
                q: dsa.q.map(decode_key_component).transpose()?,
                g: dsa.g.map(decode_key_component).transpose()?,
                y: decode_required_key_component(dsa.y)?,
                j: dsa.j.map(decode_key_component).transpose()?,
                seed: dsa.seed.map(decode_key_component).transpose()?,
                pgen_counter: dsa.pgen_counter.map(decode_key_component).transpose()?,
            })
        }
        (None, None, Some(ec)) => {
            let named_curve = ec
                .named_curve
                .and_then(|curve| curve.uri)
                .and_then(|uri| uri.strip_prefix("urn:oid:").map(str::to_owned))
                .ok_or(TslError::DigitalIdentity(
                    TslDigitalIdentityFailure::MalformedRepresentation,
                ))?;
            let named_curve = TslObjectIdentifier::parse(&named_curve).map_err(|_| {
                TslError::DigitalIdentity(TslDigitalIdentityFailure::MalformedRepresentation)
            })?;
            let public_key = decode_required_key_component(ec.public_key)?;
            if !matches!(public_key.first(), Some(0x02..=0x04)) {
                return Err(TslError::DigitalIdentity(
                    TslDigitalIdentityFailure::MalformedRepresentation,
                ));
            }
            Ok(XmlDsigKeyValue::Ec {
                named_curve,
                public_key,
            })
        }
        _ => Err(TslError::DigitalIdentity(
            TslDigitalIdentityFailure::UnsupportedKeyValue,
        )),
    }
}

fn decode_required_key_component(value: Option<String>) -> Result<Vec<u8>, TslError> {
    decode_key_component(value.ok_or(TslError::DigitalIdentity(
        TslDigitalIdentityFailure::MalformedRepresentation,
    ))?)
}

fn decode_key_component(value: String) -> Result<Vec<u8>, TslError> {
    decode_base64_binary(
        value,
        MAX_KEY_COMPONENT_BASE64_BYTES,
        TslError::DigitalIdentity(TslDigitalIdentityFailure::MalformedRepresentation),
    )
}

fn decode_base64_binary(
    value: String,
    maximum_source_bytes: usize,
    invalid_error: TslError,
) -> Result<Vec<u8>, TslError> {
    let compact: String = value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if compact.is_empty() || compact.len() > maximum_source_bytes {
        return Err(invalid_error);
    }
    let decoded = base64_to_bytes(&compact).map_err(|_| invalid_error)?;
    if decoded.is_empty() {
        return Err(invalid_error);
    }
    Ok(decoded)
}

include!("digital_identity/certificate_support.rs");

fn validate_current_pki_representations(
    identity: &ParsedDigitalRepresentations,
) -> Result<CertificateIdentityFacts, TslError> {
    let mut first: Option<CertificateIdentityFacts> = None;
    let mut subject_key_identifier_matches = identity.subject_key_identifier.is_none();
    for certificate_der in &identity.certificates_der {
        let facts = parse_certificate_identity_facts(certificate_der)?;
        if identity.subject_key_identifier.as_deref().is_some_and(|expected| {
            certificate_subject_key_identifier_matches(&facts, expected)
        }) {
            subject_key_identifier_matches = true;
        }
        if let Some(first) = &first {
            if first.subject_public_key_info_der != facts.subject_public_key_info_der {
                return Err(TslError::DigitalIdentity(
                    TslDigitalIdentityFailure::PublicKeyMismatch,
                ));
            }
        } else {
            first = Some(facts);
        }
    }
    let first = first.ok_or(TslError::DigitalIdentity(
        TslDigitalIdentityFailure::MissingCertificate,
    ))?;
    if !subject_key_identifier_matches {
        return Err(TslError::DigitalIdentity(
            TslDigitalIdentityFailure::SubjectKeyIdentifierMismatch,
        ));
    }
    if let Some(key_value) = &identity.key_value {
        let matches = match key_value {
            XmlDsigKeyValue::Rsa { modulus, exponent } => {
                first.rsa_modulus.as_deref().is_some_and(|value| {
                    unsigned_integer_equal(value, modulus)
                }) && first.rsa_exponent.as_deref().is_some_and(|value| {
                    unsigned_integer_equal(value, exponent)
                })
            }
            XmlDsigKeyValue::Dsa { p, q, g, y, .. } => {
                optional_unsigned_integer_matches(first.dsa_p.as_deref(), p.as_deref())
                    && optional_unsigned_integer_matches(first.dsa_q.as_deref(), q.as_deref())
                    && optional_unsigned_integer_matches(first.dsa_g.as_deref(), g.as_deref())
                    && first
                        .dsa_y
                        .as_deref()
                        .is_some_and(|value| unsigned_integer_equal(value, y))
            }
            XmlDsigKeyValue::Ec {
                named_curve,
                public_key,
            } => {
                first.ec_curve_oid.as_deref() == Some(named_curve.as_str())
                    && first.ec_public_key.as_deref() == Some(public_key.as_slice())
            }
        };
        if !matches {
            return Err(TslError::DigitalIdentity(
                TslDigitalIdentityFailure::PublicKeyMismatch,
            ));
        }
    }
    Ok(first)
}

fn parse_certificate_identity_facts(
    certificate_der: &[u8],
) -> Result<CertificateIdentityFacts, TslError> {
    let mut facts = reallyme_trust_x509::certificate_identity_facts(certificate_der)
        .map_err(|_| TslError::InvalidCertificate)?;
    let organization_identifiers = core::mem::take(&mut facts.organization_identifiers)
        .into_iter()
        .map(bounded_text)
        .collect::<Result<Vec<_>, TslError>>()?;
    facts.organization_identifiers = organization_identifiers;
    Ok(facts)
}
