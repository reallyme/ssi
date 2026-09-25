// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared profile identity tests.

use reallyme_openid4vc_profiles::{Profile, HAIP_PROFILE_NAME, HAIP_VERSION};

#[test]
fn haip_identity_is_stable_and_eidas_relevant() {
    assert_eq!(Profile::Haip.display_name(), HAIP_PROFILE_NAME);
    assert_eq!(Profile::Haip.short_name(), "HAIP");
    assert_eq!(HAIP_VERSION, "1.0");
    assert!(Profile::Haip.is_eidas_relevant());
}

#[test]
fn eudi_pid_identity_is_eidas_relevant() {
    assert_eq!(Profile::EudiPid.display_name(), "EUDI PID Profile");
    assert!(Profile::EudiPid.is_eidas_relevant());
}
