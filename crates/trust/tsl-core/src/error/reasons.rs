// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Non-sensitive reason the streaming XML boundary rejected a document.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslXmlFailure {
    #[error("root element or namespace is invalid")]
    Root,
    #[error("element appears in an unsupported namespace or context")]
    ElementNamespace,
    #[error("extension nesting is invalid")]
    ExtensionNesting,
    #[error("extension Critical attribute is malformed")]
    CriticalAttribute,
    #[error("document type declarations are prohibited")]
    DocumentType,
    #[error("XML element nesting is unbalanced")]
    Unbalanced,
    #[error("XML syntax is malformed")]
    Syntax,
}

/// Non-sensitive location of a schema or prose-level structural failure.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslStructureFailure {
    #[error("XML could not be projected into the trusted-list schema")]
    Deserialization,
    #[error("multilingual name sequence is malformed")]
    MultilingualName,
    #[error("text field is empty, oversized, or contains prohibited characters")]
    Text,
    #[error("trusted-list sequence number is zero")]
    SequenceNumber,
    #[error("historical-information period is not the required value")]
    HistoricalInformationPeriod,
    #[error("policy or legal-notice choice is malformed")]
    PolicyOrLegalNotice,
    #[error("extension criticality or child choice is malformed")]
    Extension,
}

/// Location of an address whose TS 119 612 structure failed validation.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslAddressContext {
    #[error("scheme operator")]
    SchemeOperator,
    #[error("trust service provider")]
    Provider,
}

/// Non-sensitive reason an address failed clauses 5.3.5 or 5.4.3.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslAddressFailure {
    #[error("postal-address list is empty or exceeds its bound")]
    PostalAddressCount,
    #[error("postal-address language is missing or invalid")]
    PostalLanguage,
    #[error("postal street address is missing or invalid")]
    PostalStreet,
    #[error("postal locality is missing or invalid")]
    PostalLocality,
    #[error("postal state or province is invalid")]
    PostalStateOrProvince,
    #[error("postal code is invalid")]
    PostalCode,
    #[error("postal country code is missing or invalid")]
    PostalCountryCode,
    #[error("electronic-address list is empty or exceeds its bound")]
    ElectronicAddressCount,
    #[error("electronic-address language is missing or invalid")]
    ElectronicLanguage,
    #[error("electronic-address URI is invalid")]
    ElectronicUri,
    #[error("electronic-address URI scheme is unsupported")]
    ElectronicScheme,
    #[error("electronic address has no e-mail URI")]
    MissingEmail,
    #[error("electronic address has no web-site URI")]
    MissingWebsite,
}
