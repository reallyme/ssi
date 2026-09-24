// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};

/// Canonical HAIP profile name.
pub const HAIP_PROFILE_NAME: &str = "OpenID4VC High Assurance Interoperability Profile";

/// Stable HAIP short name used in documentation and diagnostics.
pub const HAIP_SHORT_NAME: &str = "HAIP";

/// HAIP profile version implemented across the workspace.
pub const HAIP_VERSION: &str = "1.0";

/// EUDI PID profile name.
pub const EUDI_PID_PROFILE_NAME: &str = "EUDI PID Profile";

/// A well-known interoperability profile shared across protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Profile {
    /// HAIP: OpenID4VC High Assurance Interoperability Profile.
    Haip,
    /// EUDI Personal Identification Data profile.
    EudiPid,
}

impl Profile {
    /// Returns the canonical, human-readable profile name.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Haip => HAIP_PROFILE_NAME,
            Self::EudiPid => EUDI_PID_PROFILE_NAME,
        }
    }

    /// Returns the stable short name.
    #[must_use]
    pub const fn short_name(self) -> &'static str {
        match self {
            Self::Haip => HAIP_SHORT_NAME,
            Self::EudiPid => "EUDI-PID",
        }
    }

    /// Returns true when the profile is part of the eIDAS high-assurance path.
    #[must_use]
    pub const fn is_eidas_relevant(self) -> bool {
        match self {
            Self::Haip | Self::EudiPid => true,
        }
    }
}
