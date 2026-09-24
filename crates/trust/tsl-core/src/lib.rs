// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

//! QTSP Trusted List (TSL) ingestion (portable core).
//!
//! Parses EU LOTL + national TSLs into a normalized model.
//! Signature verification is handled by a backend crate (e.g. `*-openssl`).
//!
mod effective;
/// Typed errors for portable TSL parsing.
pub mod error;
/// Normalized TSL and trust-service models.
pub mod model;
/// Portable XML parser for LOTL and national TSL documents.
pub mod parse;
/// Bounded app-owned LOTL pointer traversal checks.
pub mod pointer;

pub use effective::select_effective_service_states;
pub use error::{
    TslAddressContext, TslAddressFailure, TslDigitalIdentityFailure, TslError,
    TslPointerPolicyFailure, TslPointerQualifierFailure, TslProviderFailure,
    TslQualificationFailure, TslRequiredField, TslResourceLimit, TslStructureFailure,
    TslXmlFailure,
};
pub use model::{
    AdditionalServiceInformation, AdditionalServiceInformationKind, LocalizedText, LocalizedUri,
    PkiServiceDigitalIdentity, PointerTraversalContext, PointerTraversalPolicy,
    QualificationAssertion, QualificationCriteria, QualificationCriterion, QualificationKeyUsage,
    QualificationKeyUsageBit, ServiceDigitalIdentity, ServiceQualification, ServiceQualifier,
    ServiceQualifierKind, TrustService, TrustServiceHistoryEntry, TrustServiceProvider,
    TrustServiceStatus, TrustServiceType, TrustedList, TslAddress, TslMediaType,
    TslNonPkiIdentifier, TslObjectIdentifier, TslObjectIdentifierError, TslOrigin, TslPointer,
    TslPostalAddress, TslTimestamp, TslUri, TslVersion, TspRegistrationIdentifier,
    TspRegistrationIdentifierKind, XmlDsigKeyValue, EU_LOTL_URL, MAX_TSL_OBJECT_IDENTIFIER_BYTES,
    MAX_TSL_URI_BYTES,
};
pub use parse::{parse_tsl_xml, validate_tsl_freshness, MAX_TSL_XML_BYTES};
pub use pointer::{validate_pointer_target, validate_pointer_traversal};
