// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SDK-facing presentation commands backed by the VP policy engine.

include!("commands/section_01.rs");
include!("commands/section_02.rs");
mod decision;
use decision::decision_from_checks;
include!("commands/section_03.rs");
