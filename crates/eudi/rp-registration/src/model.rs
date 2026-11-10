// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

mod authorize_request;
mod describe_intended_use;
mod describe_service;
mod parse_date;
mod parse_relying_party;
mod payload;
mod protocol;
mod raw;
mod raw_v1_6;
mod validate_text;
mod validation;

pub use authorize_request::CredentialRequest;
pub use describe_intended_use::IntendedUse;
pub use describe_service::WalletRelyingPartyService;
pub(crate) use parse_date::{parse_iso_calendar_date, parse_registration_date};
pub use parse_relying_party::WalletRelyingParty;
pub use payload::{
    ClaimPath, CredentialMetadata, DcSdJwtMetadata, LocalizedText, MsoMdocMetadata,
    PolicyReference, ProvidedAttestation, RegistryPagination, RegistryPayload,
    SupervisoryAuthority,
};
pub use protocol::{ProtocolProfile, RegistryPayloadShape, WrpEntitlement};
pub(crate) use raw::RawWalletRelyingParty;
pub(crate) use raw_v1_6::RawWalletRelyingPartyV1_6;
pub use validate_text::BoundedText;

#[cfg(test)]
#[path = "model/v1_6_tests.rs"]
mod v1_6_tests;
