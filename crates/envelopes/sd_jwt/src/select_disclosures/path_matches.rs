// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn disclosure_is_required(
    disclosure_path: &[SdJwtClaimPathComponent],
    requested_path: &[SdJwtClaimPathComponent],
) -> bool {
    disclosure_path.len() <= requested_path.len()
        && disclosure_path
            .iter()
            .zip(requested_path)
            .all(|(disclosure, requested)| match (disclosure, requested) {
                (SdJwtClaimPathComponent::Index(_), SdJwtClaimPathComponent::All) => true,
                (left, right) => left == right,
            })
}

fn path_is_prefix(prefix: &[SdJwtClaimPathComponent], full: &[SdJwtClaimPathComponent]) -> bool {
    prefix.len() <= full.len()
        && prefix
            .iter()
            .zip(full)
            .all(|(left, right)| match (left, right) {
                (SdJwtClaimPathComponent::Index(_), SdJwtClaimPathComponent::All)
                | (SdJwtClaimPathComponent::All, SdJwtClaimPathComponent::Index(_)) => true,
                (left, right) => left == right,
            })
}
