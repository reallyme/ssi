// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::XmlDsigKeyValue;

/// PKI representations of the single service identifier required by clause 5.5.3.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PkiServiceDigitalIdentity {
    pub certificates_der: Vec<Vec<u8>>,
    pub subject_name: Option<String>,
    pub key_value: Option<XmlDsigKeyValue>,
    pub subject_key_identifier: Option<Vec<u8>>,
    pub(crate) subject_public_key_info_der: Vec<u8>,
    pub(crate) certificate_authority: bool,
}

impl PkiServiceDigitalIdentity {
    /// Canonical DER SubjectPublicKeyInfo for a current certificate identity.
    pub fn subject_public_key_info_der(&self) -> Option<&[u8]> {
        (!self.subject_public_key_info_der.is_empty())
            .then_some(self.subject_public_key_info_der.as_slice())
    }

    /// Whether the current service certificate asserts CA basic constraints.
    pub const fn is_certificate_authority(&self) -> bool {
        self.certificate_authority
    }
}

impl core::fmt::Debug for PkiServiceDigitalIdentity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PkiServiceDigitalIdentity")
            .field("certificates_der", &"<redacted>")
            .field("subject_name", &"<redacted>")
            .field("key_value", &"<redacted>")
            .field("subject_key_identifier", &"<redacted>")
            .field("subject_public_key_info_der", &"<redacted>")
            .field("certificate_authority", &self.certificate_authority)
            .finish()
    }
}

/// Bounded scheme-defined identifier for a service that does not use PKI.
///
/// Clause 5.5.3 specifies a URI, while deployed lists also carry opaque local
/// identifiers in the schema's `Other` representation. Consumers must treat
/// this value only as an identifier; it is never a network location.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Zeroize, ZeroizeOnDrop)]
pub struct TslNonPkiIdentifier(String);

impl TslNonPkiIdentifier {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    /// Borrows the authenticated identifier source form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for TslNonPkiIdentifier {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("TslNonPkiIdentifier(<redacted>)")
    }
}

/// The one logical service identifier, represented by PKI data or a bounded
/// scheme-defined non-PKI value.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum ServiceDigitalIdentity {
    Pki(Box<PkiServiceDigitalIdentity>),
    NonPki(TslNonPkiIdentifier),
}

impl core::fmt::Debug for ServiceDigitalIdentity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Pki(_) => formatter.write_str("ServiceDigitalIdentity::Pki(<redacted>)"),
            Self::NonPki(_) => formatter.write_str("ServiceDigitalIdentity::NonPki(<redacted>)"),
        }
    }
}

impl ServiceDigitalIdentity {
    /// Certificate representations retained for current PKI service identities.
    pub fn certificates_der(&self) -> &[Vec<u8>] {
        match self {
            Self::Pki(identity) => &identity.certificates_der,
            Self::NonPki(_) => &[],
        }
    }

    /// Subject key identifier retained for current or historical PKI identity matching.
    pub fn subject_key_identifier(&self) -> Option<&[u8]> {
        match self {
            Self::Pki(identity) => identity.subject_key_identifier.as_deref(),
            Self::NonPki(_) => None,
        }
    }
}
