// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use x509_parser::certificate::X509Certificate as ParsedCertificate;

use crate::{X509Error, X509SignatureFailure};

/// RFC 5280 Section 4.2.1.10 id-ce-nameConstraints.
const OID_NAME_CONSTRAINTS: &str = "2.5.29.30";
/// RFC 5280 Section 4.2.1.11 id-ce-policyConstraints.
const OID_POLICY_CONSTRAINTS: &str = "2.5.29.36";
/// RFC 5280 Section 4.2.1.14 id-ce-inhibitAnyPolicy.
const OID_INHIBIT_ANY_POLICY: &str = "2.5.29.54";

/// Path-constraint extensions this lane does not process.
const UNPROCESSED_PATH_CONSTRAINT_OIDS: [&str; 3] = [
    OID_NAME_CONSTRAINTS,
    OID_POLICY_CONSTRAINTS,
    OID_INHIBIT_ANY_POLICY,
];

/// Reject certificates whose path constraints the pure-Rust lane cannot apply.
///
/// RFC 5280 Section 6.1 path validation narrows the permitted name space and
/// the valid policy tree from these extensions. This lane implements neither
/// name-constraint nor policy-tree processing, so honoring a path that carries
/// them would silently widen what the issuing CA authorized. The check applies
/// whether or not the extension is marked critical: a non-critical
/// constraint still expresses a restriction the issuer intended.
pub(super) fn reject_unprocessed_path_constraints(
    certificate: &ParsedCertificate<'_>,
) -> Result<(), X509Error> {
    let carries_unprocessed_constraint = certificate.extensions().iter().any(|extension| {
        let oid = extension.oid.to_id_string();
        UNPROCESSED_PATH_CONSTRAINT_OIDS.contains(&oid.as_str())
    });
    if carries_unprocessed_constraint {
        return Err(X509Error::SignatureFailed(
            X509SignatureFailure::UnsupportedPathConstraint,
        ));
    }
    Ok(())
}
