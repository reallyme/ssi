// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn status_policy_matches_id(
    policy_id: TrustPolicyId,
    status: crate::CertificateStatusPolicy,
) -> bool {
    match policy_id {
        TrustPolicyId::GenericX509V1 => true,
        _ => {
            status.leaf == StatusRequirement::Required
                && status.intermediates == StatusRequirement::Required
        }
    }
}
