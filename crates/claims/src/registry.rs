// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{claim_id_from_path, claim_path, ClaimDefinition, ClaimsRegistry};

impl ClaimsRegistry {
    /// Return the canonical disclosure path for a claim id.
    pub fn claim_path(claim_id: &str) -> Option<String> {
        claim_path(claim_id)
    }

    /// Lookup a claim definition by claim id.
    pub fn get(&self, claim_id: &str) -> Option<&ClaimDefinition> {
        self.claims.get(claim_id)
    }

    /// Lookup a claim definition by canonical claim path.
    pub fn get_by_path(&self, path: &str) -> Option<&ClaimDefinition> {
        let claim_id = claim_id_from_path(path)?;
        self.claims.get(claim_id)
    }
}
