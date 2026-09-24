// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

type CertificateIdentityFacts = reallyme_trust_x509::CertificateIdentityFacts;

fn certificate_subject_key_identifier_matches(
    facts: &CertificateIdentityFacts,
    expected: &[u8],
) -> bool {
    facts.subject_key_identifier.as_deref().map_or_else(
        || facts.derived_subject_key_identifier.as_slice() == expected,
        |identifier| identifier == expected,
    )
}

fn optional_unsigned_integer_matches(
    certificate: Option<&[u8]>,
    represented: Option<&[u8]>,
) -> bool {
    represented.is_none_or(|represented| {
        certificate.is_some_and(|certificate| unsigned_integer_equal(certificate, represented))
    })
}

fn unsigned_integer_equal(left: &[u8], right: &[u8]) -> bool {
    trim_unsigned_integer(left) == trim_unsigned_integer(right)
}

fn trim_unsigned_integer(value: &[u8]) -> &[u8] {
    let first_non_zero = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    &value[first_non_zero..]
}
