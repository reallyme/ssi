// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{X509Error, X509SignatureFailure};

pub fn verify_tsl_xml_dsig_wasm_unavailable() -> Result<(), X509Error> {
    Err(X509Error::SignatureFailed(
        X509SignatureFailure::XmlDsigUnavailable,
    ))
}
