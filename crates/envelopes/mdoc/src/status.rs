// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::MdocEnvelopeStatus;

/// Return the current implementation status for the mdoc envelope family.
pub const fn mdoc_envelope_status() -> MdocEnvelopeStatus {
    if cfg!(feature = "mdoc-crypto") {
        MdocEnvelopeStatus::PresentationReady
    } else {
        MdocEnvelopeStatus::StructureReady
    }
}
