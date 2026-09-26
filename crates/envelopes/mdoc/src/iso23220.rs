// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded ISO/IEC TS 23220-2 relationship attribute handling.
//!
//! Edition 2 clause 6.3.2.3 defines relationship values structurally as a
//! non-empty array of `PersonalData` maps. The accompanying table has a
//! conflicting text-array notation, so this boundary deliberately implements
//! the clause CDDL shape and rejects a bare array of text strings. It validates
//! structure only: individual PersonalData values remain governed by their
//! registered data-element definitions and extensions.

use std::collections::BTreeSet;

use crate::cbor::cbor_bytes_to_value;
#[cfg(feature = "mdoc-crypto")]
use crate::MdocElement;
use crate::{MdocEnvelopeError, MdocInvalidInputReason};
use ciborium::value::Value;
use zeroize::Zeroize;

/// Namespace assigned to the ISO 23220 generic eID data model.
pub const ISO_23220_NAMESPACE: &str = "org.iso.23220.1";

/// Relationship identifiers defined by ISO/IEC TS 23220-2:2026 clause 6.3.2.3.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Iso23220RelationshipKind {
    /// Father.
    Father,
    /// Mother.
    Mother,
    /// Parent without a more specific relationship.
    Parent,
    /// Son.
    Son,
    /// Daughter.
    Daughter,
    /// Child without a more specific relationship.
    Child,
    /// Brother.
    Brother,
    /// Sister.
    Sister,
    /// Sibling without a more specific relationship.
    Sibling,
    /// Spouse.
    Spouse,
    /// Father-in-law.
    FatherInLaw,
    /// Mother-in-law.
    MotherInLaw,
    /// Parent-in-law without a more specific relationship.
    ParentInLaw,
    /// Son-in-law.
    SonInLaw,
    /// Daughter-in-law.
    DaughterInLaw,
    /// Child-in-law without a more specific relationship.
    ChildInLaw,
    /// Person holding parental authority.
    ParentalAuthority,
    /// Legal representative.
    LegalRepresentative,
    /// Agent.
    Agent,
}

impl Iso23220RelationshipKind {
    /// Return the exact case-sensitive ISO data-element identifier.
    #[must_use]
    pub const fn identifier(self) -> &'static str {
        match self {
            Self::Father => "father",
            Self::Mother => "mother",
            Self::Parent => "parent",
            Self::Son => "son",
            Self::Daughter => "daughter",
            Self::Child => "child",
            Self::Brother => "brother",
            Self::Sister => "sister",
            Self::Sibling => "sibling",
            Self::Spouse => "spouse",
            Self::FatherInLaw => "father_in_law",
            Self::MotherInLaw => "mother_in_law",
            Self::ParentInLaw => "parent_in_law",
            Self::SonInLaw => "son_in_law",
            Self::DaughterInLaw => "daughter_in_law",
            Self::ChildInLaw => "child_in_law",
            Self::ParentalAuthority => "parental_authority",
            Self::LegalRepresentative => "legal_representative",
            Self::Agent => "agent",
        }
    }
}

/// Validated encoded relationship value.
///
/// The bytes can contain names and other PII, so owned storage is scrubbed on
/// drop. The original caller-owned input cannot be scrubbed by this type.
#[derive(Eq, PartialEq, zeroize::Zeroize)]
#[zeroize(drop)]
pub struct Iso23220RelationshipValue {
    encoded_cbor: Vec<u8>,
    #[zeroize(skip)]
    relationship_count: usize,
}

impl Iso23220RelationshipValue {
    /// Borrow the validated encoded CBOR value.
    #[must_use]
    pub fn as_cbor(&self) -> &[u8] {
        &self.encoded_cbor
    }

    /// Number of PersonalData relationship entries in the outer array.
    #[must_use]
    pub const fn relationship_count(&self) -> usize {
        self.relationship_count
    }

    #[cfg(feature = "mdoc-crypto")]
    fn take_encoded_cbor(mut self) -> Vec<u8> {
        std::mem::take(&mut self.encoded_cbor)
    }
}

/// Parse and structurally validate an ISO 23220 relationship value.
pub fn parse_iso23220_relationship_value(
    encoded_cbor: &[u8],
) -> Result<Iso23220RelationshipValue, MdocEnvelopeError> {
    let value = cbor_bytes_to_value(encoded_cbor)?;
    let result = validate_relationship_value(&value);
    let relationship_count = result?;

    Ok(Iso23220RelationshipValue {
        encoded_cbor: encoded_cbor.to_vec(),
        relationship_count,
    })
}

/// Build an issuer-signed relationship element from a validated value.
#[cfg(feature = "mdoc-crypto")]
pub fn iso23220_relationship_element(
    kind: Iso23220RelationshipKind,
    value: Iso23220RelationshipValue,
    random: Vec<u8>,
) -> Result<MdocElement, MdocEnvelopeError> {
    crate::validate_item_random::validate_issuance_item_random(&random)?;

    Ok(MdocElement {
        namespace: ISO_23220_NAMESPACE.to_owned(),
        element_identifier: kind.identifier().to_owned(),
        element_value_cbor: value.take_encoded_cbor(),
        random,
    })
}

fn validate_relationship_value(value: &Value) -> Result<usize, MdocEnvelopeError> {
    let Value::Array(relationships) = value else {
        return Err(malformed_relationship());
    };
    if relationships.is_empty() {
        return Err(malformed_relationship());
    }

    for relationship in relationships {
        let Value::Map(personal_data) = relationship else {
            return Err(malformed_relationship());
        };
        let mut identifiers = BTreeSet::new();
        for (identifier, _) in personal_data {
            let Value::Text(identifier) = identifier else {
                return Err(malformed_relationship());
            };
            if identifier.is_empty() {
                return Err(malformed_relationship());
            }
            if !identifiers.insert(identifier.as_str()) {
                return Err(MdocEnvelopeError::InvalidInput(
                    MdocInvalidInputReason::DuplicateIso23220PersonalDataIdentifier,
                ));
            }
        }
    }

    Ok(relationships.len())
}

fn malformed_relationship() -> MdocEnvelopeError {
    MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedIso23220Relationship)
}
