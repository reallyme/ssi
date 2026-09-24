// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn parse_extensions(
    raw: Option<RawExtensions>,
    service_type: &TrustServiceType,
) -> Result<(Vec<ServiceQualification>, Vec<AdditionalServiceInformation>), TslError> {
    let mut qualifications = Vec::new();
    let mut additional = Vec::new();
    for extension in raw.map(|value| value.extensions).unwrap_or_default() {
        let critical = extension.critical.ok_or(TslError::InvalidStructure(
            TslStructureFailure::Extension,
        ))?;
        let known_child_count = usize::from(extension.additional.is_some())
            .checked_add(usize::from(extension.qualifications.is_some()))
            .and_then(|count| count.checked_add(usize::from(extension.taken_over_by.is_some())))
            .ok_or(TslError::ResourceLimit(TslResourceLimit::XmlElements))?;
        if known_child_count == 0 {
            if critical {
                return Err(TslError::UnsupportedCriticalExtension);
            }
            continue;
        }
        if known_child_count != 1 {
            return Err(TslError::InvalidStructure(
                TslStructureFailure::Extension,
            ));
        }
        if let Some(value) = extension.additional {
            if critical && value.other_information.is_some() {
                return Err(TslError::UnsupportedCriticalExtension);
            }
            let uri_text = value
                .uri
                .and_then(|uri| uri.value)
                .ok_or(TslError::InvalidUri)?;
            let uri = parse_uri(uri_text)?;
            let kind = parse_additional_service_information_kind(uri, critical)?;
            additional.push(AdditionalServiceInformation {
                kind,
                information_value: value.information_value.map(bounded_text).transpose()?,
            });
        }
        if let Some(value) = extension.qualifications {
            match parse_qualifications(value, service_type, critical) {
                Ok(mut parsed) => qualifications.append(&mut parsed),
                Err(TslError::Qualification(TslQualificationFailure::PolicyIdentifier))
                    if !critical =>
                {
                    // A non-critical extension with a malformed policy claim
                    // is not authoritative. Ignore the complete extension so
                    // no partial qualifier can influence trust evaluation.
                }
                Err(error) => return Err(error),
            }
        }
        if let Some(value) = extension.taken_over_by {
            parse_taken_over_by(value, critical)?;
        }
    }
    Ok((qualifications, additional))
}

fn parse_qualifications(
    value: RawQualifications,
    service_type: &TrustServiceType,
    critical: bool,
) -> Result<Vec<ServiceQualification>, TslError> {
    let is_certificate_authority = service_type == &TrustServiceType::CaQualifiedCertificates
        || matches!(
            service_type,
            TrustServiceType::Other(uri)
                if uri.as_str() == "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC"
        );
    if !is_certificate_authority {
        return Err(TslError::Qualification(
            TslQualificationFailure::WrongServiceType,
        ));
    }
    if value.elements.is_empty() || value.elements.len() > MAX_QUALIFICATION_ELEMENTS {
        return Err(TslError::Qualification(
            TslQualificationFailure::ElementCount,
        ));
    }
    let mut parsed = Vec::new();
    let mut criteria_count = 0_usize;
    for element in value.elements {
        let raw_qualifiers = element.qualifiers.ok_or(TslError::Qualification(
            TslQualificationFailure::Qualifiers,
        ))?;
        if raw_qualifiers.qualifiers.is_empty() {
            return Err(TslError::Qualification(
                TslQualificationFailure::Qualifiers,
            ));
        }
        if raw_qualifiers.qualifiers.len() > MAX_QUALIFIERS_PER_ELEMENT {
            return Err(TslError::ResourceLimit(TslResourceLimit::XmlElements));
        }
        let qualifiers = raw_qualifiers
            .qualifiers
            .into_iter()
            .map(|qualifier| {
                let uri = parse_uri(qualifier.uri.ok_or(TslError::InvalidUri)?)?;
                Ok(ServiceQualifier {
                    kind: parse_service_qualifier_kind(uri, critical)?,
                })
            })
            .collect::<Result<Vec<_>, TslError>>()?;
        let criteria = parse_qualification_criteria(
            element.criteria.ok_or(TslError::Qualification(
                TslQualificationFailure::MissingCriteria,
            ))?,
            1,
            &mut criteria_count,
        )?;
        parsed.push(ServiceQualification {
            qualifiers,
            criteria,
        });
    }
    Ok(parsed)
}

fn parse_taken_over_by(value: RawTakenOverBy, _critical: bool) -> Result<(), TslError> {
    let uri = value.uri.ok_or(TslError::InvalidStructure(
        TslStructureFailure::Extension,
    ))?;
    parse_pointer_language_tag(uri.language.ok_or(TslError::InvalidStructure(
        TslStructureFailure::Extension,
    ))?)
    .map_err(|_| TslError::InvalidStructure(TslStructureFailure::Extension))?;
    parse_uri(uri.value.ok_or(TslError::InvalidStructure(
        TslStructureFailure::Extension,
    ))?)
    .map_err(|_| TslError::InvalidStructure(TslStructureFailure::Extension))?;
    parse_names(value.tsp_name.ok_or(TslError::InvalidStructure(
        TslStructureFailure::Extension,
    ))?)?;
    parse_names(
        value
            .scheme_operator_name
            .ok_or(TslError::InvalidStructure(
                TslStructureFailure::Extension,
            ))?,
    )?;
    bounded_text(
        value
            .scheme_territory
            .ok_or(TslError::InvalidStructure(
                TslStructureFailure::Extension,
            ))?,
    )
    .map_err(|_| TslError::InvalidStructure(TslStructureFailure::Extension))?;
    // Clause 5.5.9.3 explicitly permits an optional scheme-specific
    // OtherQualifier and states that TakenOverBy does not enforce validation
    // action. The streaming boundary has already bounded and structurally
    // isolated this opaque subtree; the core takeover identity above remains
    // fully parsed even when the qualifier is present.
    let _other_qualifier = value.other_qualifier;
    Ok(())
}
fn parse_additional_service_information_kind(
    uri: TslUri,
    critical: bool,
) -> Result<AdditionalServiceInformationKind, TslError> {
    let kind = match uri.as_str() {
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures" => {
            AdditionalServiceInformationKind::ForElectronicSignatures
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals" => {
            AdditionalServiceInformationKind::ForElectronicSeals
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication" => {
            AdditionalServiceInformationKind::ForWebsiteAuthentication
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/RootCA-QC" => {
            AdditionalServiceInformationKind::RootCaQualifiedCertificates
        }
        _ if critical => return Err(TslError::UnsupportedCriticalExtension),
        _ => AdditionalServiceInformationKind::Other(uri),
    };
    Ok(kind)
}

fn parse_service_qualifier_kind(
    uri: TslUri,
    critical: bool,
) -> Result<ServiceQualifierKind, TslError> {
    let kind = match uri.as_str() {
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD" => {
            ServiceQualifierKind::QualifiedCertificateWithSscd
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoSSCD" => {
            ServiceQualifierKind::QualifiedCertificateWithoutSscd
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCSSCDStatusAsInCert" => {
            ServiceQualifierKind::SscdStatusAsInCertificate
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD" => {
            ServiceQualifierKind::QualifiedCertificateWithQscd
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoQSCD" => {
            ServiceQualifierKind::QualifiedCertificateWithoutQscd
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDStatusAsInCert" => {
            ServiceQualifierKind::QscdStatusAsInCertificate
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDManagedOnBehalf" => {
            ServiceQualifierKind::QscdManagedOnBehalf
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForLegalPerson" => {
            ServiceQualifierKind::QualifiedCertificateForLegalPerson
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig" => {
            ServiceQualifierKind::QualifiedCertificateForElectronicSignature
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESeal" => {
            ServiceQualifierKind::QualifiedCertificateForElectronicSeal
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForWSA" => {
            ServiceQualifierKind::QualifiedCertificateForWebsiteAuthentication
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/NotQualified" => {
            ServiceQualifierKind::NotQualified
        }
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement" => {
            ServiceQualifierKind::QualifiedCertificateStatement
        }
        _ if critical => {
            return Err(TslError::Qualification(
                TslQualificationFailure::UnsupportedSemantics,
            ))
        }
        _ => ServiceQualifierKind::Other(uri),
    };
    Ok(kind)
}

fn parse_qualification_criteria(
    raw: RawCriteriaList,
    depth: usize,
    criteria_count: &mut usize,
) -> Result<QualificationCriteria, TslError> {
    if depth > MAX_QUALIFICATION_CRITERIA_DEPTH {
        return Err(TslError::ResourceLimit(TslResourceLimit::XmlDepth));
    }
    *criteria_count = criteria_count
        .checked_add(1)
        .ok_or(TslError::ResourceLimit(TslResourceLimit::XmlElements))?;
    if *criteria_count > MAX_QUALIFICATION_CRITERIA {
        return Err(TslError::ResourceLimit(TslResourceLimit::XmlElements));
    }
    let assertion = match raw.assertion.as_deref() {
        Some("all") => QualificationAssertion::All,
        Some("atLeastOne") => QualificationAssertion::AtLeastOne,
        Some("none") => QualificationAssertion::None,
        _ => {
            return Err(TslError::Qualification(
                TslQualificationFailure::InvalidAssertion,
            ))
        }
    };
    let mut criteria = Vec::new();
    for key_usage in raw.key_usage {
        if key_usage.bits.is_empty() || key_usage.bits.len() > MAX_KEY_USAGE_ASSERTIONS {
            return Err(TslError::Qualification(
                TslQualificationFailure::KeyUsage,
            ));
        }
        let mut assertions = Vec::new();
        for raw_bit in key_usage.bits {
            let expected = raw_bit
                .expected
                .ok_or(TslError::Qualification(
                    TslQualificationFailure::KeyUsage,
                ))?;
            let bit = match raw_bit.name.as_deref() {
                Some("digitalSignature") => QualificationKeyUsageBit::DigitalSignature,
                Some("nonRepudiation") => QualificationKeyUsageBit::NonRepudiation,
                Some("keyEncipherment") => QualificationKeyUsageBit::KeyEncipherment,
                Some("dataEncipherment") => QualificationKeyUsageBit::DataEncipherment,
                Some("keyAgreement") => QualificationKeyUsageBit::KeyAgreement,
                Some("keyCertSign") => QualificationKeyUsageBit::KeyCertSign,
                Some("crlSign") => QualificationKeyUsageBit::CrlSign,
                Some("encipherOnly") => QualificationKeyUsageBit::EncipherOnly,
                Some("decipherOnly") => QualificationKeyUsageBit::DecipherOnly,
                _ => {
                    return Err(TslError::Qualification(
                        TslQualificationFailure::UnsupportedSemantics,
                    ))
                }
            };
            if assertions
                .iter()
                .any(|existing: &QualificationKeyUsage| existing.bit == bit)
            {
                return Err(TslError::Qualification(
                    TslQualificationFailure::DuplicateKeyUsage,
                ));
            }
            assertions.push(QualificationKeyUsage {
                bit,
                expected,
            });
        }
        criteria.push(QualificationCriterion::KeyUsage(assertions));
    }
    for policy_set in raw.policy_sets {
        criteria.push(QualificationCriterion::CertificatePolicies(
            parse_policy_set(policy_set)?,
        ));
    }
    let next_depth = depth
        .checked_add(1)
        .ok_or(TslError::ResourceLimit(TslResourceLimit::XmlDepth))?;
    for nested in raw.nested {
        criteria.push(QualificationCriterion::Nested(parse_qualification_criteria(
            nested,
            next_depth,
            criteria_count,
        )?));
    }
    if let Some(other) = raw.other {
        let other_count = usize::from(other.extended_key_usage.is_some())
            .checked_add(usize::from(other.subject_dn_attributes.is_some()))
            .ok_or(TslError::ResourceLimit(TslResourceLimit::XmlElements))?;
        if other_count == 0 {
            return Err(TslError::Qualification(
                TslQualificationFailure::UnsupportedSemantics,
            ));
        }
        if let Some(extended_key_usage) = other.extended_key_usage {
            criteria.push(QualificationCriterion::ExtendedKeyUsage(
                parse_object_identifier_list(extended_key_usage.identifiers)?,
            ));
        }
        if let Some(subject_dn_attributes) = other.subject_dn_attributes {
            criteria.push(QualificationCriterion::SubjectDistinguishedNameAttributes(
                parse_object_identifier_list(subject_dn_attributes.identifiers)?,
            ));
        }
    }
    if criteria.is_empty() {
        return Err(TslError::Qualification(
            TslQualificationFailure::EmptyCriteria,
        ));
    }
    let criterion_count = criteria.len();
    *criteria_count = criteria_count
        .checked_add(criterion_count)
        .ok_or(TslError::ResourceLimit(TslResourceLimit::XmlElements))?;
    if *criteria_count > MAX_QUALIFICATION_CRITERIA {
        return Err(TslError::ResourceLimit(TslResourceLimit::XmlElements));
    }
    Ok(QualificationCriteria {
        assertion,
        criteria,
        description: raw
            .description
            .map(bounded_optional_xml_string)
            .transpose()?
            .flatten(),
    })
}

fn parse_policy_set(raw: RawPolicySet) -> Result<Vec<TslObjectIdentifier>, TslError> {
    if raw.policies.is_empty() || raw.policies.len() > MAX_OBJECT_IDENTIFIERS_PER_ASSERTION {
        return Err(TslError::Qualification(
            TslQualificationFailure::IdentifierCount,
        ));
    }
    raw.policies
        .into_iter()
        .map(parse_policy_identifier)
        .collect()
}

fn parse_object_identifier_list(
    values: Vec<RawPolicyIdentifier>,
) -> Result<Vec<TslObjectIdentifier>, TslError> {
    if values.is_empty() || values.len() > MAX_OBJECT_IDENTIFIERS_PER_ASSERTION {
        return Err(TslError::Qualification(
            TslQualificationFailure::IdentifierCount,
        ));
    }
    values
        .into_iter()
        .map(parse_policy_identifier)
        .collect()
}

fn parse_policy_identifier(value: RawPolicyIdentifier) -> Result<TslObjectIdentifier, TslError> {
    if let Some(description) = value.description {
        bounded_optional_xml_string(description)
            .map_err(|_| {
                TslError::Qualification(TslQualificationFailure::DescriptiveMetadata)
            })?;
    }
    if let Some(documentation) = value.documentation_references {
        if documentation.references.is_empty()
            || documentation.references.len() > MAX_OBJECT_IDENTIFIERS_PER_ASSERTION
        {
            return Err(TslError::Qualification(
                TslQualificationFailure::DescriptiveMetadata,
            ));
        }
        for reference in documentation.references {
            parse_uri(reference)
                .map_err(|_| {
                    TslError::Qualification(TslQualificationFailure::DescriptiveMetadata)
                })?;
        }
    }
    parse_object_identifier(value.identifier.ok_or(TslError::Qualification(
        TslQualificationFailure::PolicyIdentifier,
    ))?)
}

fn parse_object_identifier(value: RawXadesIdentifier) -> Result<TslObjectIdentifier, TslError> {
    let qualifier = value.qualifier;
    let value = value.value.ok_or(TslError::Qualification(
        TslQualificationFailure::PolicyIdentifier,
    ))?;
    // xsd:anyURI has whiteSpace="collapse". Apply that normalization before
    // enforcing the stricter Object Identifier grammar required by clause
    // 5.5.9.2.2.2. Internal whitespace can never occur in an OID.
    let value = value.trim();
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return Err(TslError::Qualification(
            TslQualificationFailure::PolicyIdentifier,
        ));
    }
    let dotted_decimal = match qualifier.as_deref() {
        None | Some("OIDAsURI") | Some("OIDAsURN") => value
            .strip_prefix("urn:oid:")
            .or_else(|| value.strip_prefix("oid:"))
            .unwrap_or(value),
        _ => {
            return Err(TslError::Qualification(
                TslQualificationFailure::UnsupportedSemantics,
            ))
        }
    };
    // Some deployed EU TLs serialize an otherwise valid dotted-decimal OID
    // with one terminal separator. The separator carries no arc and its
    // removal is unambiguous; every other malformed form remains rejected.
    let dotted_decimal = dotted_decimal.strip_suffix('.').unwrap_or(dotted_decimal);
    TslObjectIdentifier::parse(dotted_decimal)
        .map_err(|_| TslError::Qualification(TslQualificationFailure::PolicyIdentifier))
}
