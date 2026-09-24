// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::ClaimsRegistry;

use super::pid::eu_pid_v1;

/// Built-in eIDAS VID claim identifiers.
///
/// eIDAS VID is the identity-verification view over PID. It intentionally
/// shares the EU PID catalog so verifiers do not learn a second spelling for
/// the same natural-person identity claims.
pub const EU_EIDAS_VID_V1_CLAIM_IDS: &[&str] = super::pid::EU_PID_V1_CLAIM_IDS;

/// EU eIDAS VID registry backed by the EU PID claim catalog.
pub fn eu_eidas_vid_v1() -> ClaimsRegistry {
    let mut registry = eu_pid_v1();
    registry.claimset_id = "eu.eidas-vid.v1".to_owned();
    registry
}
