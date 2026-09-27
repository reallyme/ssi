// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Boolean composition mode for one TS 119 612 `CriteriaList`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum QualificationAssertion {
    /// Every criterion must match.
    All,
    /// At least one criterion must match.
    AtLeastOne,
    /// No criteria are asserted.
    None,
}

/// X.509 key-usage bit named by a qualification assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum QualificationKeyUsageBit {
    /// `digitalSignature` bit.
    DigitalSignature,
    /// `nonRepudiation` or `contentCommitment` bit.
    NonRepudiation,
    /// `keyEncipherment` bit.
    KeyEncipherment,
    /// `dataEncipherment` bit.
    DataEncipherment,
    /// `keyAgreement` bit.
    KeyAgreement,
    /// `keyCertSign` bit.
    KeyCertSign,
    /// `cRLSign` bit.
    CrlSign,
    /// `encipherOnly` bit.
    EncipherOnly,
    /// `decipherOnly` bit.
    DecipherOnly,
}

/// Expected value for one X.509 key-usage bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub struct QualificationKeyUsage {
    /// Key-usage bit tested by the criterion.
    pub bit: QualificationKeyUsageBit,
    /// Required value of the selected key-usage bit.
    pub expected: bool,
}

/// Length-bounded, syntactically validated object identifier.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Zeroize, ZeroizeOnDrop)]
pub struct TslObjectIdentifier(String);

/// Maximum dotted-decimal OID length retained from a qualification.
pub const MAX_TSL_OBJECT_IDENTIFIER_BYTES: usize = 128;

/// Fixed reason for rejecting a dotted-decimal qualification OID.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum TslObjectIdentifierError {
    /// Object identifier is not canonical dotted-decimal syntax.
    #[error("object identifier is not canonical dotted-decimal syntax")]
    InvalidSyntax,
}

impl TslObjectIdentifier {
    /// Parses a bounded, canonical dotted-decimal object identifier.
    pub fn parse(value: &str) -> Result<Self, TslObjectIdentifierError> {
        if value.is_empty() || value.len() > MAX_TSL_OBJECT_IDENTIFIER_BYTES {
            return Err(TslObjectIdentifierError::InvalidSyntax);
        }
        let mut arcs = value.split('.');
        let first = arcs.next().ok_or(TslObjectIdentifierError::InvalidSyntax)?;
        let second = arcs.next().ok_or(TslObjectIdentifierError::InvalidSyntax)?;
        if !matches!(first, "0" | "1" | "2")
            || !valid_object_identifier_arc(second)
            || !arcs.all(valid_object_identifier_arc)
        {
            return Err(TslObjectIdentifierError::InvalidSyntax);
        }
        if matches!(first, "0" | "1")
            && second
                .parse::<u32>()
                .map_or(true, |second_arc| second_arc > 39)
        {
            return Err(TslObjectIdentifierError::InvalidSyntax);
        }
        Ok(Self(value.to_owned()))
    }

    /// Borrows the canonical dotted-decimal form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_object_identifier_arc(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|character| character.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

impl core::fmt::Debug for TslObjectIdentifier {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("TslObjectIdentifier(<redacted>)")
    }
}

/// One certificate assertion contained in a qualification criteria list.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum QualificationCriterion {
    /// Required X.509 key-usage bits.
    KeyUsage(Vec<QualificationKeyUsage>),
    /// Accepted certificate-policy object identifiers.
    CertificatePolicies(Vec<TslObjectIdentifier>),
    /// Accepted extended-key-usage object identifiers.
    ExtendedKeyUsage(Vec<TslObjectIdentifier>),
    /// Required subject distinguished-name attribute identifiers.
    SubjectDistinguishedNameAttributes(Vec<TslObjectIdentifier>),
    /// Nested criteria list.
    Nested(QualificationCriteria),
}

/// Recursively composed, bounded certificate-filter criteria.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct QualificationCriteria {
    /// Boolean composition applied to `criteria`.
    pub assertion: QualificationAssertion,
    /// Certificate predicates in this criteria list.
    pub criteria: Vec<QualificationCriterion>,
    /// Human-readable description supplied by the trusted list.
    pub description: Option<String>,
}

/// One complete qualification element: filters plus resulting qualifiers.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ServiceQualification {
    /// Qualifiers granted when `criteria` match.
    pub qualifiers: Vec<ServiceQualifier>,
    /// Certificate predicates controlling the qualification.
    pub criteria: QualificationCriteria,
}
