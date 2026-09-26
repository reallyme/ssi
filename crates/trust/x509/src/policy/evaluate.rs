// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Screen a presented chain for per-certificate time and policy requirements.
///
/// This is intentionally not complete X.509 path validation: it does not
/// verify signatures, issuer/subject linkage, revocation, exact configured
/// anchor identity, or path-building semantics. It does enforce bounded
/// per-certificate and path constraints for a candidate path. Call a real
/// path validator before treating the presented chain as trusted.
pub fn screen_chain_policy_only_no_path_validation(
    chain: &X509Chain,
    now: OffsetDateTime,
    policy: &X509Policy,
) -> Result<(), X509Error> {
    if chain.certs.len() > MAX_X509_CHAIN_CERTIFICATES {
        return Err(X509Error::ResourceLimitExceeded(
            X509ResourceLimit::CertificateChainTooLong,
        ));
    }

    let leaf = chain
        .leaf()
        .ok_or(X509Error::MissingField(X509MissingField::Leaf))?;

    if policy.require_v3 && leaf.profile.version != CertificateVersion::V3 {
        return Err(X509Error::PolicyFailed(X509PolicyFailure::LeafMustBeV3));
    }
    if policy.reject_unknown_critical_extensions
        && chain.certs.iter().any(|certificate| {
            certificate.profile.extensions.iter().any(|extension| {
                extension.critical && matches!(&extension.kind, CertificateExtensionKind::Other(_))
            })
        })
    {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::UnknownCriticalExtension,
        ));
    }

    for required in &policy.required_leaf_extensions {
        let extension = leaf
            .profile
            .extensions
            .iter()
            .find(|extension| known_extension_matches(&extension.kind, required.kind))
            .ok_or(X509Error::PolicyFailed(
                X509PolicyFailure::MissingRequiredExtension,
            ))?;
        let criticality_matches = match required.criticality {
            ExtensionCriticality::Either => true,
            ExtensionCriticality::Critical => extension.critical,
            ExtensionCriticality::NonCritical => !extension.critical,
        };
        if !criticality_matches {
            return Err(X509Error::PolicyFailed(
                X509PolicyFailure::ExtensionCriticality,
            ));
        }
    }

    // ------------------------------------------------------------
    // Time validity (all certs in presented chain)
    // ------------------------------------------------------------
    for c in &chain.certs {
        if now < c.not_before || now > c.not_after {
            return Err(X509Error::PolicyFailed(
                X509PolicyFailure::CertificateNotValidAtTime,
            ));
        }
    }

    // ------------------------------------------------------------
    // Leaf constraints
    // ------------------------------------------------------------
    if policy.require_leaf_not_ca {
        if let Some(bc) = &leaf.basic_constraints {
            if bc.ca {
                return Err(X509Error::PolicyFailed(X509PolicyFailure::LeafMustNotBeCa));
            }
        }
    }

    if policy.require_leaf_digital_signature {
        let ku = leaf.key_usage.as_ref().ok_or(X509Error::PolicyFailed(
            X509PolicyFailure::MissingLeafKeyUsage,
        ))?;
        if !ku.digital_signature {
            return Err(X509Error::PolicyFailed(
                X509PolicyFailure::LeafMissingDigitalSignature,
            ));
        }
    }

    if !leaf_key_usage_matches(leaf.key_usage.as_ref(), policy.leaf_key_usage_requirement) {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::LeafKeyUsageProfile,
        ));
    }

    if !distinguished_name_matches(&leaf.profile.subject, policy.leaf_subject_name_requirement) {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::LeafSubjectNameProfile,
        ));
    }
    let issuer_name_matches = if policy.leaf_issuer_name_requirement
        == DistinguishedNameRequirement::IssuingAuthorityOrSelfIssued
        && leaf.profile.subject == leaf.profile.issuer
    {
        true
    } else {
        distinguished_name_matches(&leaf.profile.issuer, policy.leaf_issuer_name_requirement)
    };
    if !issuer_name_matches {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::LeafIssuerNameProfile,
        ));
    }
    let leaf_is_self_issued = leaf.profile.subject == leaf.profile.issuer;
    if policy.require_leaf_not_self_issued && leaf_is_self_issued {
        return Err(X509Error::PolicyFailed(X509PolicyFailure::LeafSelfIssued));
    }

    if !policy.required_leaf_eku_any_of.is_empty() {
        let eku = &leaf.profile.extended_key_usage;
        if eku.is_empty() {
            return Err(X509Error::PolicyFailed(
                X509PolicyFailure::MissingLeafExtendedKeyUsage,
            ));
        }

        let ok = policy
            .required_leaf_eku_any_of
            .iter()
            .any(|need| eku.iter().any(|got| got == need));

        if !ok {
            return Err(X509Error::PolicyFailed(
                X509PolicyFailure::LeafExtendedKeyUsageMismatch,
            ));
        }
    }

    // ------------------------------------------------------------
    // EU / ETSI: CertificatePolicies
    // ------------------------------------------------------------
    if !policy.required_policy_any_of.is_empty() {
        let ok = policy.required_policy_any_of.iter().any(|need| {
            leaf.profile
                .certificate_policies
                .iter()
                .any(|got| got == need)
        });

        if !ok {
            return Err(X509Error::PolicyFailed(
                X509PolicyFailure::LeafCertificatePolicyMismatch,
            ));
        }
    }

    // ------------------------------------------------------------
    // EU / ETSI: qcStatements
    // ------------------------------------------------------------
    if !policy.required_qc_statement_ids.is_empty() {
        let has_all = policy
            .required_qc_statement_ids
            .iter()
            .all(|need| leaf.profile.qc_statement_ids.iter().any(|got| got == need));

        if !has_all {
            return Err(X509Error::PolicyFailed(
                X509PolicyFailure::LeafMissingRequiredQcStatement,
            ));
        }
    }

    if !policy.required_qc_type_any_of.is_empty() {
        let ok = policy
            .required_qc_type_any_of
            .iter()
            .any(|need| leaf.profile.qc_types.iter().any(|got| got == need));

        if !ok {
            return Err(X509Error::PolicyFailed(
                X509PolicyFailure::LeafQcTypeMismatch,
            ));
        }
    }

    if !public_key_meets_minimums(leaf, policy) {
        return Err(X509Error::PolicyFailed(X509PolicyFailure::WeakPublicKey));
    }
    if !policy.allowed_public_key_algorithms.is_empty()
        && !policy
            .allowed_public_key_algorithms
            .contains(&leaf.profile.public_key.algorithm())
    {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::PublicKeyAlgorithmNotAllowed,
        ));
    }
    if !policy.allowed_signature_algorithms.is_empty()
        && !policy
            .allowed_signature_algorithms
            .contains(&leaf.profile.signature_algorithm)
    {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::SignatureAlgorithmNotAllowed,
        ));
    }
    if policy.etsi_algorithm_policy == EtsiAlgorithmPolicy::Ts119312V211
        && (!etsi_ts_119_312_v2_1_1_key_allowed(leaf, now)
            || !etsi_ts_119_312_v2_1_1_signature_parameters_allowed(leaf))
    {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::AlgorithmParametersNotAllowed,
        ));
    }

    let name_requirement_satisfied = match policy.leaf_name_requirement {
        LeafNameRequirement::None => true,
        LeafNameRequirement::DnsOrIp => !leaf.san_dns.is_empty() || !leaf.san_ip.is_empty(),
        LeafNameRequirement::Uri => !leaf.profile.subject_alternative_names.uris.is_empty(),
        LeafNameRequirement::Email => !leaf
            .profile
            .subject_alternative_names
            .email_addresses
            .is_empty(),
        LeafNameRequirement::UriEmailOrTelephone => {
            leaf.profile
                .subject_alternative_names
                .uris
                .iter()
                .any(|uri| !uri.is_empty())
                || leaf
                    .profile
                    .subject_alternative_names
                    .email_addresses
                    .iter()
                    .any(|email| !email.is_empty())
                || leaf
                    .profile
                    .subject_alternative_names
                    .other_names
                    .iter()
                    .any(telephone_other_name_is_valid)
        }
    };
    if !name_requirement_satisfied {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::LeafNameRequirement,
        ));
    }

    let key_identifiers_satisfied = match policy.leaf_key_identifier_requirement {
        LeafKeyIdentifierRequirement::None => true,
        LeafKeyIdentifierRequirement::Subject => leaf.subject_key_identifier.is_some(),
        LeafKeyIdentifierRequirement::Authority => leaf.authority_key_identifier.is_some(),
        LeafKeyIdentifierRequirement::SubjectAndAuthority => {
            leaf.subject_key_identifier.is_some() && leaf.authority_key_identifier.is_some()
        }
    };
    if !key_identifiers_satisfied {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::LeafKeyIdentifierRequirement,
        ));
    }

    // RFC 5280 §4.2.2.1 gives id-ad-ocsp and id-ad-caIssuers different
    // semantics. A CA certificate retrieval URI is not revocation evidence.
    let has_ocsp_aia = leaf
        .profile
        .authority_information_access
        .iter()
        .any(|description| matches!(description.method, crate::AuthorityAccessMethod::Ocsp));
    let has_ca_issuers_aia = leaf
        .profile
        .authority_information_access
        .iter()
        .any(|description| matches!(description.method, crate::AuthorityAccessMethod::CaIssuers));
    let aia_requirement_satisfied = match policy.authority_information_access_requirement {
        AuthorityInformationAccessRequirement::None => true,
        AuthorityInformationAccessRequirement::Ocsp => has_ocsp_aia,
        AuthorityInformationAccessRequirement::CaIssuers => has_ca_issuers_aia,
        AuthorityInformationAccessRequirement::OcspAndCaIssuers => {
            has_ocsp_aia && has_ca_issuers_aia
        }
        AuthorityInformationAccessRequirement::CaIssuersUnlessSelfIssued => {
            leaf_is_self_issued || has_ca_issuers_aia
        }
    };
    if !aia_requirement_satisfied {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::LeafAuthorityInformationAccessRequirement,
        ));
    }

    // ETSI EN 319 412-5 conditions QcSSCD on the certificate's qualified
    // device policy; the typed policy makes that dependency explicit.
    let has_qscd_policy = leaf
        .profile
        .certificate_policies
        .iter()
        .any(|certificate_policy| {
            matches!(
                certificate_policy,
                CertificatePolicyId::QcpNaturalPersonQscd | CertificatePolicyId::QcpLegalPersonQscd
            )
        });
    if policy.qscd_statement_requirement == QscdStatementRequirement::WhenQscdPolicy
        && has_qscd_policy
        && !leaf
            .profile
            .qc_statement_ids
            .contains(&QcStatementId::QcSscd)
    {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::LeafMissingQscdStatement,
        ));
    }

    let has_revocation_pointer =
        has_ocsp_aia || !leaf.profile.crl_distribution_point_uris.is_empty();
    let revocation_requirement_satisfied = match policy.revocation_pointer_requirement {
        RevocationPointerRequirement::None => true,
        RevocationPointerRequirement::OcspOrCrl => has_revocation_pointer,
        RevocationPointerRequirement::ExplicitNoRevAvail => leaf.profile.no_rev_avail,
    };
    if !revocation_requirement_satisfied {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::RevocationPointerMissing,
        ));
    }
    if policy.forbid_no_rev_avail && leaf.profile.no_rev_avail {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::LeafForbiddenNoRevAvail,
        ));
    }
    if policy.require_certificate_policy_cps_uri
        && !leaf
            .profile
            .certificate_policy_cps_uris
            .iter()
            .any(|uri| absolute_uri_syntax(uri))
    {
        return Err(X509Error::PolicyFailed(
            X509PolicyFailure::LeafMissingPolicyCpsUri,
        ));
    }

    if policy.wrpac_profile_requirement == WrpacProfileRequirement::Version1 {
        validate_wrpac_profile(leaf)?;
    }

    // ------------------------------------------------------------
    // Intermediates
    // ------------------------------------------------------------
    if policy.require_intermediate_ca {
        for c in chain.intermediates() {
            let bc = c.basic_constraints.as_ref().ok_or(X509Error::PolicyFailed(
                X509PolicyFailure::IntermediateMissingBasicConstraints,
            ))?;
            if !bc.ca {
                return Err(X509Error::PolicyFailed(
                    X509PolicyFailure::IntermediateNotCa,
                ));
            }

            let ku = c.key_usage.as_ref().ok_or(X509Error::PolicyFailed(
                X509PolicyFailure::IntermediateMissingKeyUsage,
            ))?;
            if !ku.key_cert_sign {
                return Err(X509Error::PolicyFailed(
                    X509PolicyFailure::IntermediateMissingKeyCertSign,
                ));
            }
        }
    }

    validate_path_length_constraints(chain)?;

    // This model accepts certificate-valued trust anchors, not bare names or
    // public keys. Strict anchor profiles therefore require a CA certificate
    // authorized for certificate signing. The higher trust evaluator
    // establishes exact DER anchor identity before this policy stage; these
    // checks prevent a configured end-entity key from silently becoming an
    // unconstrained issuer.
    if chain.certs.len() > 1
        && matches!(
            policy.trust_anchor_requirement,
            TrustAnchorRequirement::Rfc5280Ca | TrustAnchorRequirement::EudiProviderCa
        )
    {
        let anchor = chain
            .trust_anchor()
            .ok_or(X509Error::MissingField(X509MissingField::Leaf))?;
        let basic_constraints =
            anchor
                .basic_constraints
                .as_ref()
                .ok_or(X509Error::PolicyFailed(
                    X509PolicyFailure::TrustAnchorMissingBasicConstraints,
                ))?;
        if !basic_constraints.ca {
            return Err(X509Error::PolicyFailed(X509PolicyFailure::TrustAnchorNotCa));
        }
        let key_usage = anchor.key_usage.as_ref().ok_or(X509Error::PolicyFailed(
            X509PolicyFailure::TrustAnchorMissingKeyUsage,
        ))?;
        if !key_usage.key_cert_sign {
            return Err(X509Error::PolicyFailed(
                X509PolicyFailure::TrustAnchorMissingKeyCertSign,
            ));
        }
    }

    if policy.trust_anchor_requirement == TrustAnchorRequirement::EudiProviderCa {
        let anchor = chain
            .trust_anchor()
            .ok_or(X509Error::MissingField(X509MissingField::Leaf))?;
        if anchor.profile.certificate_policies.is_empty() {
            return Err(X509Error::PolicyFailed(
                X509PolicyFailure::TrustAnchorMissingCertificatePolicy,
            ));
        }
        // RFC 5280 Section 6.1 treats the trust anchor as an input to path
        // validation rather than as an ordinary self-signed chain member. Its
        // public key still has to satisfy the selected ETSI cryptographic
        // policy; accepting a weak configured anchor would bypass the same
        // controls that protect the end-entity certificate.
        if !public_key_meets_minimums(anchor, policy) {
            return Err(X509Error::PolicyFailed(X509PolicyFailure::WeakPublicKey));
        }
        if !policy.allowed_public_key_algorithms.is_empty()
            && !policy
                .allowed_public_key_algorithms
                .contains(&anchor.profile.public_key.algorithm())
        {
            return Err(X509Error::PolicyFailed(
                X509PolicyFailure::PublicKeyAlgorithmNotAllowed,
            ));
        }
        if policy.etsi_algorithm_policy == EtsiAlgorithmPolicy::Ts119312V211
            && !etsi_ts_119_312_v2_1_1_key_allowed(anchor, now)
        {
            return Err(X509Error::PolicyFailed(
                X509PolicyFailure::AlgorithmParametersNotAllowed,
            ));
        }
    }

    Ok(())
}

fn validate_path_length_constraints(chain: &X509Chain) -> Result<(), X509Error> {
    for (issuer_index, issuer) in chain.certs.iter().enumerate().skip(1) {
        let Some(path_length_constraint) = issuer
            .basic_constraints
            .as_ref()
            .and_then(|constraints| constraints.path_len_constraint)
        else {
            continue;
        };

        let mut subordinate_non_self_issued_ca_count = 0_u32;
        for certificate in chain.certs.iter().take(issuer_index).skip(1) {
            let is_ca = certificate
                .basic_constraints
                .as_ref()
                .is_some_and(|constraints| constraints.ca);
            let is_self_issued = certificate.subject_der == certificate.issuer_der;
            if is_ca && !is_self_issued {
                subordinate_non_self_issued_ca_count = subordinate_non_self_issued_ca_count
                    .checked_add(1)
                    .ok_or(X509Error::PolicyFailed(
                        X509PolicyFailure::PathLengthConstraintExceeded,
                    ))?;
            }
        }

        if subordinate_non_self_issued_ca_count > path_length_constraint {
            return Err(X509Error::PolicyFailed(
                X509PolicyFailure::PathLengthConstraintExceeded,
            ));
        }
    }

    Ok(())
}
