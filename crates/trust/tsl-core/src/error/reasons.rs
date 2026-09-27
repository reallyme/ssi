// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Non-sensitive reason the streaming XML boundary rejected a document.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslXmlFailure {
    /// Root element or namespace is invalid.
    #[error("root element or namespace is invalid")]
    Root,
    /// Element appears in an unsupported namespace or context.
    #[error("element appears in an unsupported namespace or context")]
    ElementNamespace,
    /// Extension nesting is invalid.
    #[error("extension nesting is invalid")]
    ExtensionNesting,
    /// Extension Critical attribute is malformed.
    #[error("extension Critical attribute is malformed")]
    CriticalAttribute,
    /// Document type declarations are prohibited.
    #[error("document type declarations are prohibited")]
    DocumentType,
    /// XML element nesting is unbalanced.
    #[error("XML element nesting is unbalanced")]
    Unbalanced,
    /// XML syntax is malformed.
    #[error("XML syntax is malformed")]
    Syntax,
}

/// Non-sensitive location of a schema or prose-level structural failure.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslStructureFailure {
    /// XML could not be projected into the trusted-list schema.
    #[error("XML could not be projected into the trusted-list schema")]
    Deserialization,
    /// Multilingual name sequence is malformed.
    #[error("multilingual name sequence is malformed")]
    MultilingualName,
    /// Text field is empty, oversized, or contains prohibited characters.
    #[error("text field is empty, oversized, or contains prohibited characters")]
    Text,
    /// Trusted-list sequence number is zero.
    #[error("trusted-list sequence number is zero")]
    SequenceNumber,
    /// Historical-information period is not the required value.
    #[error("historical-information period is not the required value")]
    HistoricalInformationPeriod,
    /// Policy or legal-notice choice is malformed.
    #[error("policy or legal-notice choice is malformed")]
    PolicyOrLegalNotice,
    /// Extension criticality or child choice is malformed.
    #[error("extension criticality or child choice is malformed")]
    Extension,
    /// A service history row is not older than the current service state.
    #[error("service history is not strictly older than the current state")]
    ServiceHistoryOrder,
}

/// Location of an address whose TS 119 612 structure failed validation.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslAddressContext {
    /// Scheme operator.
    #[error("scheme operator")]
    SchemeOperator,
    /// Trust service provider.
    #[error("trust service provider")]
    Provider,
}

/// Non-sensitive reason an address failed clauses 5.3.5 or 5.4.3.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslAddressFailure {
    /// Postal-address list is empty or exceeds its bound.
    #[error("postal-address list is empty or exceeds its bound")]
    PostalAddressCount,
    /// Postal-address language is missing or invalid.
    #[error("postal-address language is missing or invalid")]
    PostalLanguage,
    /// Postal street address is missing or invalid.
    #[error("postal street address is missing or invalid")]
    PostalStreet,
    /// Postal locality is missing or invalid.
    #[error("postal locality is missing or invalid")]
    PostalLocality,
    /// Postal state or province is invalid.
    #[error("postal state or province is invalid")]
    PostalStateOrProvince,
    /// Postal code is invalid.
    #[error("postal code is invalid")]
    PostalCode,
    /// Postal country code is missing or invalid.
    #[error("postal country code is missing or invalid")]
    PostalCountryCode,
    /// Electronic-address list is empty or exceeds its bound.
    #[error("electronic-address list is empty or exceeds its bound")]
    ElectronicAddressCount,
    /// Electronic-address language is missing or invalid.
    #[error("electronic-address language is missing or invalid")]
    ElectronicLanguage,
    /// Electronic-address URI is invalid.
    #[error("electronic-address URI is invalid")]
    ElectronicUri,
    /// Electronic-address URI scheme is unsupported.
    #[error("electronic-address URI scheme is unsupported")]
    ElectronicScheme,
    /// Electronic address has no e-mail URI.
    #[error("electronic address has no e-mail URI")]
    MissingEmail,
    /// Electronic address has no web-site URI.
    #[error("electronic address has no web-site URI")]
    MissingWebsite,
}
