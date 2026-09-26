// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Element kinds admitted inside a TS 119 612 `Qualifications` subtree.
///
/// The typed projection deserializes qualification criteria by local name and
/// silently ignores unknown children. An ignored criterion would change the
/// meaning of a `CriteriaList` (for example, removing a restriction from an
/// `assert="all"` list), so every child is validated against its parent here
/// before deserialization. This applies to non-critical extensions as well:
/// a recognized `Qualifications` extension is processed, and processing only
/// part of it is not the "ignore" option permitted by clause B.0.
#[derive(Clone, Copy, PartialEq, Eq)]
enum QualificationNode {
    Qualifications,
    QualificationElement,
    Qualifiers,
    Qualifier,
    CriteriaList,
    CriteriaDescription,
    KeyUsage,
    KeyUsageBit,
    PolicySet,
    ObjectIdentifier,
    XadesLeaf,
    DocumentationReferences,
    OtherCriteriaList,
    ExtendedKeyUsage,
    CertSubjectDnAttribute,
}

/// Validate one qualification-subtree child against its parent.
///
/// Returns the child's node kind so the caller can track the open path.
fn classify_qualification_child(
    parent: Option<QualificationNode>,
    namespace: &ResolveResult<'_>,
    local_name: &str,
    critical: bool,
) -> Result<QualificationNode, TslError> {
    let unsupported = if critical {
        TslError::UnsupportedCriticalExtension
    } else {
        TslError::Qualification(TslQualificationFailure::UnsupportedSemantics)
    };
    let ResolveResult::Bound(namespace) = namespace else {
        return Err(unsupported);
    };
    let namespace = namespace.as_ref();
    let qualifications_namespace = namespace == TSL_QUALIFICATIONS_NAMESPACE;
    let additional_types_namespace = namespace == TSL_ADDITIONAL_TYPES_NAMESPACE;
    let xades_namespace = namespace == XADES_132_NAMESPACE;
    let child = match (parent, local_name) {
        (Some(QualificationNode::Qualifications), "QualificationElement")
            if qualifications_namespace =>
        {
            QualificationNode::QualificationElement
        }
        (Some(QualificationNode::QualificationElement), "Qualifiers")
            if qualifications_namespace =>
        {
            QualificationNode::Qualifiers
        }
        (
            Some(QualificationNode::QualificationElement | QualificationNode::CriteriaList),
            "CriteriaList",
        ) if qualifications_namespace => QualificationNode::CriteriaList,
        (Some(QualificationNode::Qualifiers), "Qualifier") if qualifications_namespace => {
            QualificationNode::Qualifier
        }
        (Some(QualificationNode::CriteriaList), "KeyUsage") if qualifications_namespace => {
            QualificationNode::KeyUsage
        }
        (Some(QualificationNode::CriteriaList), "PolicySet") if qualifications_namespace => {
            QualificationNode::PolicySet
        }
        (Some(QualificationNode::CriteriaList), "Description") if qualifications_namespace => {
            QualificationNode::CriteriaDescription
        }
        (Some(QualificationNode::CriteriaList), "otherCriteriaList")
            if qualifications_namespace =>
        {
            QualificationNode::OtherCriteriaList
        }
        (Some(QualificationNode::KeyUsage), "KeyUsageBit") if qualifications_namespace => {
            QualificationNode::KeyUsageBit
        }
        (Some(QualificationNode::PolicySet), "PolicyIdentifier") if qualifications_namespace => {
            QualificationNode::ObjectIdentifier
        }
        (Some(QualificationNode::OtherCriteriaList), "ExtendedKeyUsage")
            if additional_types_namespace =>
        {
            QualificationNode::ExtendedKeyUsage
        }
        (Some(QualificationNode::OtherCriteriaList), "CertSubjectDNAttribute")
            if additional_types_namespace =>
        {
            QualificationNode::CertSubjectDnAttribute
        }
        (Some(QualificationNode::ExtendedKeyUsage), "KeyPurposeId")
            if additional_types_namespace =>
        {
            QualificationNode::ObjectIdentifier
        }
        (Some(QualificationNode::CertSubjectDnAttribute), "AttributeOID")
            if additional_types_namespace =>
        {
            QualificationNode::ObjectIdentifier
        }
        (Some(QualificationNode::ObjectIdentifier), "Identifier" | "Description")
            if xades_namespace =>
        {
            QualificationNode::XadesLeaf
        }
        (Some(QualificationNode::ObjectIdentifier), "DocumentationReferences")
            if xades_namespace =>
        {
            QualificationNode::DocumentationReferences
        }
        (Some(QualificationNode::DocumentationReferences), "DocumentationReference")
            if xades_namespace =>
        {
            QualificationNode::XadesLeaf
        }
        _ => return Err(unsupported),
    };
    Ok(child)
}
