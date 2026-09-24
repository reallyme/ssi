// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn is_supported_qualification_element(local_name: &str) -> bool {
    matches!(
        local_name,
        "Qualifications"
            | "QualificationElement"
            | "Qualifiers"
            | "Qualifier"
            | "CriteriaList"
            | "KeyUsage"
            | "KeyUsageBit"
            | "PolicySet"
            | "PolicyIdentifier"
            | "Description"
            | "otherCriteriaList"
    )
}

fn is_xml_dsig_key_value_element(local_name: &str) -> bool {
    matches!(
        local_name,
        "KeyValue"
            | "RSAKeyValue"
            | "Modulus"
            | "Exponent"
            | "DSAKeyValue"
            | "P"
            | "Q"
            | "G"
            | "Y"
            | "J"
            | "Seed"
            | "PgenCounter"
    )
}
