// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use time::OffsetDateTime;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{BasicConstraints, CertificateProfile, KeyUsage, QcStatements};

/// Parsed certificate projection used by chain, profile, and revocation policy.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct X509Certificate {
    /// Original DER encoding.
    pub der: Vec<u8>,
    /// Display-only subject Name; use [`X509Certificate::subject_der`] for identity and chaining.
    pub subject: String,
    /// Display-only rendering of the issuer Name. Never compare it for
    /// chaining or identity; use [`X509Certificate::issuer_der`].
    pub issuer: String,
    /// Exact DER encoding of the subject Name (RFC 5280 Section 4.1.2.6).
    ///
    /// Chaining compares these bytes for exact equality. RFC 5280 Section 7.1
    /// permits a relying party to match names after internationalized
    /// normalization; exact DER equality is the conservative subset of that
    /// rule and never treats two distinct encodings as the same name.
    pub subject_der: Vec<u8>,
    /// Exact DER encoding of the issuer Name (RFC 5280 Section 4.1.2.4).
    pub issuer_der: Vec<u8>,
    /// Canonical positive certificate serial-number bytes.
    pub serial: Vec<u8>,
    /// First instant at which the certificate is valid.
    #[zeroize(skip)]
    pub not_before: OffsetDateTime,
    /// Last instant at which the certificate is valid.
    #[zeroize(skip)]
    pub not_after: OffsetDateTime,
    /// DER-encoded SubjectPublicKeyInfo covered by the certificate.
    pub spki_der: Vec<u8>,
    /// Signature-algorithm object identifier encoded by the certificate.
    pub signature_algorithm_oid: String,
    /// Parsed Basic Constraints extension.
    pub basic_constraints: Option<BasicConstraints>,
    /// Parsed Key Usage extension.
    pub key_usage: Option<KeyUsage>,
    /// Extended Key Usage object identifiers.
    pub extended_key_usage: Option<Vec<String>>,
    /// Subject Key Identifier extension bytes when the certificate carries one.
    pub subject_key_identifier: Option<Vec<u8>>,
    /// Authority Key Identifier bytes when present.
    pub authority_key_identifier: Option<Vec<u8>>,
    /// DNS names carried in the Subject Alternative Name extension.
    pub san_dns: Vec<String>,
    /// IP-address octets carried in the Subject Alternative Name extension.
    pub san_ip: Vec<Vec<u8>>,
    /// Certificate-policy object identifiers asserted by the certificate.
    pub certificate_policies: Vec<String>,
    /// Parsed ETSI QCStatements extension.
    pub qc_statements: QcStatements,
    /// Lossless, typed projection used by audit-facing profile evaluation.
    pub profile: CertificateProfile,
}

impl core::fmt::Debug for X509Certificate {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("X509Certificate")
            .field("der", &"<redacted>")
            .field("subject", &"<redacted>")
            .field("issuer", &"<redacted>")
            .field("subject_der", &"<redacted>")
            .field("issuer_der", &"<redacted>")
            .field("serial", &"<redacted>")
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("spki_der", &"<redacted>")
            .field("signature_algorithm_oid", &self.signature_algorithm_oid)
            .field("basic_constraints", &self.basic_constraints)
            .field("key_usage", &self.key_usage)
            .field("extended_key_usage", &"<redacted>")
            .field("subject_key_identifier", &"<redacted>")
            .field("authority_key_identifier", &"<redacted>")
            .field("san_dns", &"<redacted>")
            .field("san_ip", &"<redacted>")
            .field("certificate_policies", &"<redacted>")
            .field("qc_statements", &"<redacted>")
            .field("profile", &self.profile)
            .finish()
    }
}
