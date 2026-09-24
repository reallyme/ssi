// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_trust_x509::{
    eudi_policy, parse_cert_der, screen_chain_policy_only_no_path_validation,
    EudiCertificateProfile, NameAttributeKind, NameAttributeValue, TrustAnchorRequirement,
    X509Chain,
};
use time::OffsetDateTime;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{ArtifactDigest, BoundedText, RegistrationError, RegistrationErrorReason};

/// Issuance binding for one exact WRPAC leaf artifact.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AccessCertificateBinding {
    expected_leaf_digest: ArtifactDigest,
    holder_relying_party_id: BoundedText,
    holder_service_id: BoundedText,
    intermediary_association_id: Option<BoundedText>,
    national_register_reference_digest: ArtifactDigest,
}

impl AccessCertificateBinding {
    /// Creates an issuance binding for one exact leaf certificate.
    pub fn try_new(
        expected_leaf_digest: ArtifactDigest,
        holder_relying_party_id: &str,
        holder_service_id: &str,
        intermediary_association_id: Option<&str>,
        national_register_reference_digest: ArtifactDigest,
    ) -> Result<Self, RegistrationError> {
        Ok(Self {
            expected_leaf_digest,
            holder_relying_party_id: BoundedText::try_new(holder_relying_party_id)?,
            holder_service_id: BoundedText::try_new(holder_service_id)?,
            intermediary_association_id: intermediary_association_id
                .map(BoundedText::try_new)
                .transpose()?,
            national_register_reference_digest,
        })
    }
}

/// ETSI TS 119 411-8 profile-authenticated WRPAC association.
///
/// This result deliberately does not assert path trust. The holder WRP is read
/// from the standardized `organizationIdentifier`; local service and customer
/// association values remain bound to the exact issuance artifact rather than
/// being projected from non-standard certificate attributes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AuthenticatedAccessCertificateAssociation {
    leaf_certificate_digest: ArtifactDigest,
    binding: AccessCertificateBinding,
    valid_from_unix_seconds: i64,
    valid_until_unix_seconds: i64,
}

impl AuthenticatedAccessCertificateAssociation {
    /// Returns the exact leaf certificate digest.
    #[must_use]
    pub const fn leaf_certificate_digest(&self) -> ArtifactDigest {
        self.leaf_certificate_digest
    }

    /// Returns the standardized organization identifier.
    #[must_use]
    pub fn holder_relying_party_id(&self) -> &str {
        self.binding.holder_relying_party_id.expose()
    }

    /// Returns the locally bound holder service.
    #[must_use]
    pub fn holder_service_id(&self) -> &str {
        self.binding.holder_service_id.expose()
    }

    /// Returns the optional locally bound customer association.
    #[must_use]
    pub fn intermediary_association_id(&self) -> Option<&str> {
        self.binding
            .intermediary_association_id
            .as_ref()
            .map(BoundedText::expose)
    }

    /// Returns the bound national-register reference digest.
    #[must_use]
    pub const fn national_register_reference_digest(&self) -> ArtifactDigest {
        self.binding.national_register_reference_digest
    }

    /// Returns the certificate not-before time.
    #[must_use]
    pub const fn valid_from_unix_seconds(&self) -> i64 {
        self.valid_from_unix_seconds
    }

    /// Returns the certificate not-after time.
    #[must_use]
    pub const fn valid_until_unix_seconds(&self) -> i64 {
        self.valid_until_unix_seconds
    }
}

/// Validates the WRPAC v1 leaf profile and binds it to the reviewed issuance
/// association without performing certificate-path trust evaluation.
pub fn authenticate_access_certificate_association(
    leaf_der: &[u8],
    evaluation_time: OffsetDateTime,
    binding: AccessCertificateBinding,
) -> Result<AuthenticatedAccessCertificateAssociation, RegistrationError> {
    let leaf_digest = ArtifactDigest::of(leaf_der);
    if leaf_digest != binding.expected_leaf_digest {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::AuthenticationReceiptMismatch,
        ));
    }
    let certificate = parse_cert_der(leaf_der).map_err(|_error| {
        RegistrationError::from_reason(RegistrationErrorReason::InvalidCertificate)
    })?;
    let organization_identifier =
        exactly_one_subject_text(&certificate, NameAttributeKind::OrganizationIdentifier)?;
    if organization_identifier != binding.holder_relying_party_id.expose() {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::SemanticBindingMismatch,
        ));
    }
    let valid_from = certificate.not_before.unix_timestamp();
    let valid_until = certificate.not_after.unix_timestamp();
    if valid_from >= valid_until {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidValidityInterval,
        ));
    }
    let chain = X509Chain {
        certs: vec![certificate],
    };
    let mut policy = eudi_policy(EudiCertificateProfile::WrpacLeafV1);
    // Path discovery and trust-anchor evaluation belong to eudi-trust. All
    // leaf and algorithm profile predicates remain enabled here.
    policy.trust_anchor_requirement = TrustAnchorRequirement::None;
    screen_chain_policy_only_no_path_validation(&chain, evaluation_time, &policy).map_err(
        |_error| {
            RegistrationError::from_reason(RegistrationErrorReason::CertificateProfileMismatch)
        },
    )?;
    Ok(AuthenticatedAccessCertificateAssociation {
        leaf_certificate_digest: leaf_digest,
        binding,
        valid_from_unix_seconds: valid_from,
        valid_until_unix_seconds: valid_until,
    })
}

fn exactly_one_subject_text(
    certificate: &reallyme_trust_x509::X509Certificate,
    kind: NameAttributeKind,
) -> Result<&str, RegistrationError> {
    let mut matching = certificate
        .profile
        .subject
        .rdns
        .iter()
        .flat_map(|rdn| rdn.attributes.iter())
        .filter(|attribute| attribute.kind == kind);
    let first = matching
        .next()
        .ok_or_else(|| RegistrationError::from_reason(RegistrationErrorReason::MissingField))?;
    if matching.next().is_some() {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidField,
        ));
    }
    match &first.value {
        NameAttributeValue::Text(value) => Ok(value),
        NameAttributeValue::Binary(_) => Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidField,
        )),
    }
}
