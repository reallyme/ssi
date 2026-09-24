// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Identity envelope profile policy.
//!
//! This crate validates protocol-neutral metadata attached to credential
//! envelopes. It does not parse OpenID requests, fetch status lists, verify TSLs,
//! or evaluate presentation sessions; those checks belong in the protocol and
//! trust layers that call into these constraints.

mod profile;

pub use profile::{
    did_me, enforce_did_me_profile, enforce_eu_pid_profile, enforce_openid4vc_profile, eu_pid,
    openid4vc, CredentialProfile, EnvelopeFormat, EnvelopeProfile, EnvelopeProfileError,
    EnvelopeProfileInput, EnvelopeProfileInvalidReason,
};

pub(crate) use profile::{
    invalid, require_status, require_validity_window, require_vct_for_sd_jwt, validate_common,
    Result, DID_ME_CRYPTOSUITE, DID_ME_METHOD, EU_AGE_CLAIMSET, EU_PASSPORT_CLAIMSET,
    EU_PID_CLAIMSET, EU_TAX_CLAIMSET,
};
