// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! TS 119 475 WRPRC-specific protected JAdES header policy.

use serde::de::IgnoredAny;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{RegistrationError, RegistrationErrorReason};

const WRPRC_JWT_TYPE: &str = "rc-wrp+jwt";

#[derive(Deserialize)]
struct WrprcJadesHeader {
    typ: Option<String>,
    x5c: Option<IgnoredAny>,
}

pub(super) fn validate_wrprc_jades_header(compact: &str) -> Result<(), RegistrationError> {
    let protected_segment = compact
        .split('.')
        .next()
        .ok_or_else(|| invalid(RegistrationErrorReason::InvalidCompactJws))?;
    let protected_header = Zeroizing::new(
        reallyme_codec::base64url::base64url_to_bytes(protected_segment)
            .map_err(|_error| invalid(RegistrationErrorReason::InvalidCompactJws))?,
    );
    let header: WrprcJadesHeader = serde_json::from_slice(protected_header.as_slice())
        .map_err(|_error| invalid(RegistrationErrorReason::InvalidCompactJws))?;
    // ETSI TS 119 475 V1.2.1 GEN-5.2.2-01 and Table 5 make both
    // explicit typing and the embedded x5c chain mandatory for WRPRC JWTs.
    match header.typ.as_deref() {
        Some(WRPRC_JWT_TYPE) => {}
        Some(_) => return Err(invalid(RegistrationErrorReason::UnsupportedProfile)),
        None => return Err(invalid(RegistrationErrorReason::MissingField)),
    }
    if header.x5c.is_none() {
        return Err(invalid(RegistrationErrorReason::MissingSignerCertificate));
    }
    Ok(())
}

const fn invalid(reason: RegistrationErrorReason) -> RegistrationError {
    RegistrationError::from_reason(reason)
}
