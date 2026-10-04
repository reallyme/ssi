// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! TS 119 475 WRPRC-specific protected JAdES header policy.

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{RegistrationError, RegistrationErrorReason};

const WRPRC_JWT_TYPE: &str = "rc-wrp+jwt";

#[derive(Deserialize)]
struct WrprcJadesHeader {
    typ: Option<String>,
    x5c: Option<Vec<String>>,
}

const MAX_X5C_CERTIFICATES: usize = 10;
const MAX_X5C_CERTIFICATE_BASE64_BYTES: usize = 87_384;

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
    if header.x5c.as_ref().is_none_or(Vec::is_empty) {
        return Err(invalid(RegistrationErrorReason::MissingSignerCertificate));
    }
    Ok(())
}

pub(super) fn presented_signer_certificate(
    compact: &str,
) -> Result<Zeroizing<Vec<u8>>, RegistrationError> {
    if compact.len() > super::super::MAX_REPRESENTATION_BYTES {
        return Err(invalid(RegistrationErrorReason::InputTooLarge));
    }
    validate_wrprc_jades_header(compact)?;
    let protected_segment = compact
        .split('.')
        .next()
        .ok_or_else(|| invalid(RegistrationErrorReason::InvalidCompactJws))?;
    let protected_header = Zeroizing::new(
        reallyme_codec::base64url::base64url_to_bytes(protected_segment)
            .map_err(|_| invalid(RegistrationErrorReason::InvalidCompactJws))?,
    );
    let header: WrprcJadesHeader = serde_json::from_slice(&protected_header)
        .map_err(|_| invalid(RegistrationErrorReason::InvalidCompactJws))?;
    let chain = header
        .x5c
        .ok_or_else(|| invalid(RegistrationErrorReason::MissingSignerCertificate))?;
    if chain.is_empty() || chain.len() > MAX_X5C_CERTIFICATES {
        return Err(invalid(RegistrationErrorReason::ResourceLimitExceeded));
    }
    let encoded = chain
        .first()
        .ok_or_else(|| invalid(RegistrationErrorReason::MissingSignerCertificate))?;
    if encoded.is_empty() || encoded.len() > MAX_X5C_CERTIFICATE_BASE64_BYTES {
        return Err(invalid(RegistrationErrorReason::ResourceLimitExceeded));
    }
    let der = Zeroizing::new(
        reallyme_codec::base64::base64_to_bytes(encoded)
            .map_err(|_| invalid(RegistrationErrorReason::InvalidCertificate))?,
    );
    if reallyme_codec::base64::bytes_to_base64(&der) != *encoded
        || der.is_empty()
        || der.len() > super::super::MAX_SIGNER_CERTIFICATE_BYTES
        || !reallyme_trust_x509::validate_certificate_der(&der)
    {
        return Err(invalid(RegistrationErrorReason::InvalidCertificate));
    }
    Ok(der)
}

const fn invalid(reason: RegistrationErrorReason) -> RegistrationError {
    RegistrationError::from_reason(reason)
}
