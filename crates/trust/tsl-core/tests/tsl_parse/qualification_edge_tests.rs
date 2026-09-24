// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn parses_complete_critical_qualification_criteria_shape() {
    let extension = r#"<Extension Critical="true"><q:Qualifications xmlns:q="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"><q:QualificationElement><q:Qualifiers><q:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD"/></q:Qualifiers><q:CriteriaList assert="all"><q:KeyUsage><q:KeyUsageBit name="digitalSignature">true</q:KeyUsageBit></q:KeyUsage><q:PolicySet><q:PolicyIdentifier><xades:Identifier>1.2.3.4</xades:Identifier></q:PolicyIdentifier></q:PolicySet><q:otherCriteriaList><at:ExtendedKeyUsage><at:KeyPurposeId><xades:Identifier>1.3.6.1.5.5.7.3.3</xades:Identifier></at:KeyPurposeId></at:ExtendedKeyUsage></q:otherCriteriaList></q:CriteriaList></q:QualificationElement></q:Qualifications></Extension>"#;
    let parsed = parse_tsl_xml(&document_with_qualification_extension(extension)).unwrap();
    let qualification = &parsed.services().next().unwrap().qualifications[0];

    assert_eq!(qualification.criteria.criteria.len(), 3);
    assert!(matches!(
        qualification.criteria.criteria[1],
        QualificationCriterion::CertificatePolicies(_)
    ));
    assert!(matches!(
        qualification.criteria.criteria[2],
        QualificationCriterion::ExtendedKeyUsage(_)
    ));
}

#[test]
fn qualification_failures_are_typed_and_critical_scheme_extensions_fail_closed() {
    let unsupported_qualifier = r#"<Extension Critical="true"><q:Qualifications xmlns:q="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#"><q:QualificationElement><q:Qualifiers><q:Qualifier uri="https://future.example/qualifier"/></q:Qualifiers><q:CriteriaList assert="all"><q:KeyUsage><q:KeyUsageBit name="digitalSignature">true</q:KeyUsageBit></q:KeyUsage></q:CriteriaList></q:QualificationElement></q:Qualifications></Extension>"#;
    assert_eq!(
        parse_tsl_xml(&document_with_qualification_extension(
            unsupported_qualifier
        ))
        .unwrap_err(),
        TslError::Qualification(TslQualificationFailure::UnsupportedSemantics)
    );

    let unknown_scheme_extension = document("").replace(
        "</SchemeInformation>",
        "<SchemeExtensions><Extension Critical=\"true\"><FutureSemantics/></Extension></SchemeExtensions></SchemeInformation>",
    );
    assert_eq!(
        parse_tsl_xml(&unknown_scheme_extension).unwrap_err(),
        TslError::UnsupportedCriticalExtension
    );
}

#[test]
fn rejects_unknown_semantics_nested_in_a_known_critical_extension() {
    let additional = document_with_service_extension(
        r#"<Extension Critical="true"><AdditionalServiceInformation><URI xml:lang="en">http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures</URI><FutureSemantics/></AdditionalServiceInformation></Extension>"#,
    );
    assert_eq!(
        parse_tsl_xml(&additional).unwrap_err(),
        TslError::UnsupportedCriticalExtension
    );

    let qualification = document_with_qualification_extension(
        r#"<Extension Critical="true"><q:Qualifications xmlns:q="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#"><q:QualificationElement><q:Qualifiers><q:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD"/></q:Qualifiers><q:CriteriaList assert="all"><q:FutureCriterion/></q:CriteriaList></q:QualificationElement></q:Qualifications></Extension>"#,
    );
    assert_eq!(
        parse_tsl_xml(&qualification).unwrap_err(),
        TslError::UnsupportedCriticalExtension
    );
}

#[test]
fn rejects_qualification_semantics_on_a_non_ca_qc_service() {
    let qualification = document_with_service_extension(
        r#"<Extension Critical="false"><q:Qualifications xmlns:q="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#"><q:QualificationElement><q:Qualifiers><q:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement"/></q:Qualifiers><q:CriteriaList assert="all"><q:KeyUsage><q:KeyUsageBit name="digitalSignature">true</q:KeyUsageBit></q:KeyUsage></q:CriteriaList></q:QualificationElement></q:Qualifications></Extension>"#,
    );

    assert_eq!(
        parse_tsl_xml(&qualification).unwrap_err(),
        TslError::Qualification(TslQualificationFailure::WrongServiceType)
    );
}
