// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Emit machine-readable evidence from the compiled SSI production models.

use std::io::{self, Write};

use reallyme_credential_claims::profiles::{eu_driving_license_v1, eu_pid_v1};
use reallyme_credential_claims::{ClaimType, ClaimsRegistry};
use reallyme_mdoc::{
    iso23220_relationship_element, parse_iso23220_relationship_value, DeviceKeyInfo,
    Iso23220RelationshipKind, Iso23220RelationshipValue, IssuerSigned, IssuerSignedItem,
    MdocDeviceDocument, MdocDeviceResponse, MdocDeviceSigned, MdocElement, MdocEnvelopeError,
    MdocIssuerSignedDocument, MobileSecurityObject, ValidityInfo, ISO_23220_NAMESPACE,
    MAX_MDOC_CBOR_INPUT_BYTES, MAX_MDOC_ELEMENTS_PER_NAMESPACE, MAX_MDOC_ELEMENT_VALUE_BYTES,
    MAX_MDOC_ISSUER_ELEMENTS, MAX_MDOC_NAMESPACES, MAX_MDOC_TOTAL_ELEMENT_VALUE_BYTES,
};
use reallyme_ssi_proto::generated::proto::identity::presentation::v1::MdocPresentation;
use reallyme_ssi_proto_codec::presentation::{
    MAX_MDOC_DEVICE_RESPONSE_BYTES, MAX_PRESENTATION_PROTO_MESSAGE_BYTES,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
enum EvidenceError {
    #[error("ISO model evidence serialization failed")]
    Serialize,
    #[error("ISO model evidence output failed")]
    Output,
}

#[derive(Serialize)]
struct Evidence {
    schema: &'static str,
    producer: Producer,
    mdoc_element_carrier: MdocElementCarrier,
    iso23220_relationship: Iso23220RelationshipEvidence,
    claim_registries: Vec<RegistryEvidence>,
    protocol_models: Vec<ProtocolModelEvidence>,
    protobuf_api: ProtobufApiEvidence,
}

#[derive(Serialize)]
struct Producer {
    repository: &'static str,
    artifact: &'static str,
}

#[derive(Serialize)]
struct MdocElementCarrier {
    rust_type: &'static str,
    namespace_field: &'static str,
    identifier_field: &'static str,
    value_field: &'static str,
    value_encoding: &'static str,
    namespace_semantics: &'static str,
    schema_validation: &'static str,
    max_elements: usize,
    max_namespaces: usize,
    max_elements_per_namespace: usize,
    max_cbor_input_bytes: usize,
    max_element_value_bytes: usize,
    max_total_element_value_bytes: usize,
}

#[derive(Serialize)]
struct Iso23220RelationshipEvidence {
    namespace: &'static str,
    rust_type: &'static str,
    identifiers: Vec<&'static str>,
    encoding: &'static str,
    validation_scope: &'static str,
    rejected_equivalence: &'static str,
}

#[derive(Serialize)]
struct RegistryEvidence {
    claimset_id: String,
    claims: Vec<ClaimEvidence>,
}

#[derive(Serialize)]
struct ClaimEvidence {
    identifier: String,
    semantic_type: &'static str,
    commitment_encoding: String,
}

#[derive(Serialize)]
struct ProtocolModelEvidence {
    iso_object: &'static str,
    rust_type: &'static str,
    implemented_fields: Vec<&'static str>,
    unsupported_fields: Vec<&'static str>,
    representation: &'static str,
}

#[derive(Serialize)]
struct ProtobufApiEvidence {
    message: &'static str,
    fields: Vec<ProtobufFieldEvidence>,
    iso_payload_semantics: &'static str,
    size_limit: ProtobufSizeLimitEvidence,
}

#[derive(Serialize)]
struct ProtobufSizeLimitEvidence {
    generated_model: &'static str,
    production_codec: &'static str,
    max_message_bytes: usize,
    max_device_response_bytes: usize,
}

#[derive(Serialize)]
struct ProtobufFieldEvidence {
    name: &'static str,
    number: u32,
    wire_type: &'static str,
    cardinality: &'static str,
}

fn claim_type_name(claim_type: ClaimType) -> &'static str {
    match claim_type {
        ClaimType::Unspecified => "unspecified",
        ClaimType::String => "string",
        ClaimType::Boolean => "boolean",
        ClaimType::Integer => "integer",
        ClaimType::SignedInteger => "signed_integer",
        ClaimType::UnsignedInteger => "unsigned_integer",
        ClaimType::Number => "number",
        ClaimType::Decimal => "decimal",
        ClaimType::Bytes => "bytes",
        ClaimType::Date => "date",
        ClaimType::DateTime => "date_time",
        ClaimType::Null => "null",
        ClaimType::Object => "object",
        ClaimType::Array => "array",
    }
}

fn registry_evidence(registry: ClaimsRegistry) -> RegistryEvidence {
    let claims = registry
        .claims
        .values()
        .map(|claim| ClaimEvidence {
            identifier: claim.claim_id.clone(),
            semantic_type: claim_type_name(claim.claim_type),
            commitment_encoding: claim.encoding.clone(),
        })
        .collect();
    RegistryEvidence {
        claimset_id: registry.claimset_id.clone(),
        claims,
    }
}

#[allow(dead_code)]
fn bind_core_protocol_model_fields(
    item: &IssuerSignedItem,
    validity: &ValidityInfo,
    device_key: &DeviceKeyInfo,
    mso: &MobileSecurityObject,
) {
    let _compiled_fields = (
        &item.digest_id,
        &item.random,
        &item.element_identifier,
        &item.element_value_cbor,
        &validity.signed,
        &validity.valid_from,
        &validity.valid_until,
        &device_key.device_key_cose_key_cbor,
        &mso.version,
        &mso.digest_algorithm,
        &mso.doc_type,
        &mso.validity_info,
        &mso.device_key_info,
        &mso.value_digests,
    );
}

#[allow(dead_code)]
fn bind_envelope_protocol_model_fields(
    issuer_signed: &IssuerSigned,
    issuer_document: &MdocIssuerSignedDocument,
    response: &MdocDeviceResponse,
    document: &MdocDeviceDocument,
) {
    let _compiled_fields = (
        &issuer_signed.name_spaces,
        &issuer_signed.issuer_auth,
        &issuer_document.doc_type,
        &issuer_document.issuer_signed,
        &response.version,
        &response.documents,
        &response.status,
        &document.doc_type,
        &document.issuer_signed,
        &document.device_signed,
    );
}

#[allow(dead_code)]
fn bind_device_protocol_model_fields(device_signed: &MdocDeviceSigned) {
    let _compiled_fields = (&device_signed.name_spaces_cbor, &device_signed.device_auth);
}

fn build_evidence() -> Evidence {
    // These assignments deliberately bind the evidence generator to the
    // compiled production field names. A model rename makes this generator
    // fail to compile instead of silently emitting stale evidence.
    let carrier = MdocElement {
        namespace: String::new(),
        element_identifier: String::new(),
        element_value_cbor: Vec::new(),
        random: Vec::new(),
    };
    let protobuf = MdocPresentation::default();
    let _relationship_parser: fn(&[u8]) -> Result<Iso23220RelationshipValue, MdocEnvelopeError> =
        parse_iso23220_relationship_value;
    let _relationship_builder: fn(
        Iso23220RelationshipKind,
        Iso23220RelationshipValue,
        Vec<u8>,
    ) -> Result<MdocElement, MdocEnvelopeError> = iso23220_relationship_element;
    let _compiled_fields = (
        &carrier.namespace,
        &carrier.element_identifier,
        &carrier.element_value_cbor,
        &protobuf.device_response,
        &protobuf.envelope_hash,
        &protobuf.doc_type,
    );

    Evidence {
        schema: "reallyme.identity.iso_model_evidence.v1",
        producer: Producer {
            repository: "reallyme/ssi",
            artifact: "compiled-rust-models",
        },
        mdoc_element_carrier: MdocElementCarrier {
            rust_type: "reallyme_mdoc::MdocElement",
            namespace_field: "namespace",
            identifier_field: "element_identifier",
            value_field: "element_value_cbor",
            value_encoding: "canonical_cbor_data_item",
            namespace_semantics: "exact_case_sensitive_literal",
            schema_validation: "delegated_to_profile_layer",
            max_elements: MAX_MDOC_ISSUER_ELEMENTS,
            max_namespaces: MAX_MDOC_NAMESPACES,
            max_elements_per_namespace: MAX_MDOC_ELEMENTS_PER_NAMESPACE,
            max_cbor_input_bytes: MAX_MDOC_CBOR_INPUT_BYTES,
            max_element_value_bytes: MAX_MDOC_ELEMENT_VALUE_BYTES,
            max_total_element_value_bytes: MAX_MDOC_TOTAL_ELEMENT_VALUE_BYTES,
        },
        iso23220_relationship: Iso23220RelationshipEvidence {
            namespace: ISO_23220_NAMESPACE,
            rust_type: "reallyme_mdoc::Iso23220RelationshipValue",
            identifiers: vec![
                Iso23220RelationshipKind::Father.identifier(),
                Iso23220RelationshipKind::Mother.identifier(),
                Iso23220RelationshipKind::Parent.identifier(),
                Iso23220RelationshipKind::Son.identifier(),
                Iso23220RelationshipKind::Daughter.identifier(),
                Iso23220RelationshipKind::Child.identifier(),
                Iso23220RelationshipKind::Brother.identifier(),
                Iso23220RelationshipKind::Sister.identifier(),
                Iso23220RelationshipKind::Sibling.identifier(),
                Iso23220RelationshipKind::Spouse.identifier(),
                Iso23220RelationshipKind::FatherInLaw.identifier(),
                Iso23220RelationshipKind::MotherInLaw.identifier(),
                Iso23220RelationshipKind::ParentInLaw.identifier(),
                Iso23220RelationshipKind::SonInLaw.identifier(),
                Iso23220RelationshipKind::DaughterInLaw.identifier(),
                Iso23220RelationshipKind::ChildInLaw.identifier(),
                Iso23220RelationshipKind::ParentalAuthority.identifier(),
                Iso23220RelationshipKind::LegalRepresentative.identifier(),
                Iso23220RelationshipKind::Agent.identifier(),
            ],
            encoding: "non_empty_array_of_personal_data_maps",
            validation_scope: "structural_cddl_not_personal_data_value_semantics",
            rejected_equivalence: "non_empty_array_of_text_strings",
        },
        claim_registries: vec![
            registry_evidence(eu_driving_license_v1()),
            registry_evidence(eu_pid_v1()),
        ],
        protocol_models: vec![
            ProtocolModelEvidence {
                iso_object: "IssuerSignedItem",
                rust_type: "reallyme_mdoc::IssuerSignedItem",
                implemented_fields: vec!["digestID", "random", "elementIdentifier", "elementValue"],
                unsupported_fields: vec![],
                representation: "typed_structure_with_opaque_cbor_element_value",
            },
            ProtocolModelEvidence {
                iso_object: "ValidityInfo",
                rust_type: "reallyme_mdoc::ValidityInfo",
                implemented_fields: vec!["signed", "validFrom", "validUntil"],
                unsupported_fields: vec!["expectedUpdate"],
                representation: "typed_structure",
            },
            ProtocolModelEvidence {
                iso_object: "DeviceKeyInfo",
                rust_type: "reallyme_mdoc::DeviceKeyInfo",
                implemented_fields: vec!["deviceKey"],
                unsupported_fields: vec!["keyAuthorizations", "keyInfo"],
                representation: "typed_structure_with_opaque_cose_key",
            },
            ProtocolModelEvidence {
                iso_object: "MobileSecurityObject",
                rust_type: "reallyme_mdoc::MobileSecurityObject",
                implemented_fields: vec![
                    "version",
                    "digestAlgorithm",
                    "valueDigests",
                    "deviceKeyInfo",
                    "docType",
                    "validityInfo",
                ],
                unsupported_fields: vec![],
                representation: "typed_structure",
            },
            ProtocolModelEvidence {
                iso_object: "IssuerSigned",
                rust_type: "reallyme_mdoc::IssuerSigned",
                implemented_fields: vec!["nameSpaces", "issuerAuth"],
                unsupported_fields: vec![],
                representation: "typed_structure",
            },
            ProtocolModelEvidence {
                iso_object: "DeviceResponse",
                rust_type: "reallyme_mdoc::MdocDeviceResponse",
                implemented_fields: vec!["version", "documents", "status"],
                unsupported_fields: vec!["documentErrors"],
                representation: "typed_structure",
            },
            ProtocolModelEvidence {
                iso_object: "Document",
                rust_type: "reallyme_mdoc::MdocDeviceDocument",
                implemented_fields: vec!["docType", "issuerSigned", "deviceSigned"],
                unsupported_fields: vec!["errors"],
                representation: "typed_structure",
            },
            ProtocolModelEvidence {
                iso_object: "DeviceSigned",
                rust_type: "reallyme_mdoc::MdocDeviceSigned",
                implemented_fields: vec!["nameSpaces", "deviceAuth.deviceSignature"],
                unsupported_fields: vec!["deviceAuth.deviceMac"],
                representation: "typed_structure_signature_profile_only",
            },
            ProtocolModelEvidence {
                iso_object: "DeviceAuth",
                rust_type: "reallyme_mdoc::MdocDeviceSigned",
                implemented_fields: vec!["deviceSignature"],
                unsupported_fields: vec!["deviceMac"],
                representation: "exactly_one_choice_signature_only",
            },
            ProtocolModelEvidence {
                iso_object: "SessionTranscript",
                rust_type: "reallyme_mdoc::DeviceAuthenticationInput",
                implemented_fields: vec![
                    "device_engagement_bytes",
                    "e_reader_key_bytes",
                    "handover",
                ],
                unsupported_fields: vec![],
                representation: "opaque_caller_supplied_cbor_validated_and_bound",
            },
        ],
        protobuf_api: ProtobufApiEvidence {
            message: "identity.presentation.v1.MdocPresentation",
            fields: vec![
                ProtobufFieldEvidence {
                    name: "device_response",
                    number: 1,
                    wire_type: "bytes",
                    cardinality: "required_by_domain",
                },
                ProtobufFieldEvidence {
                    name: "envelope_hash",
                    number: 2,
                    wire_type: "bytes",
                    cardinality: "optional",
                },
                ProtobufFieldEvidence {
                    name: "doc_type",
                    number: 3,
                    wire_type: "string",
                    cardinality: "optional",
                },
            ],
            iso_payload_semantics: "opaque_device_response_cbor",
            size_limit: ProtobufSizeLimitEvidence {
                generated_model: "none_at_generated_model_layer",
                production_codec: "reallyme_ssi_proto_codec::presentation",
                max_message_bytes: MAX_PRESENTATION_PROTO_MESSAGE_BYTES,
                max_device_response_bytes: MAX_MDOC_DEVICE_RESPONSE_BYTES,
            },
        },
    }
}

fn main() -> Result<(), EvidenceError> {
    let encoded =
        serde_json::to_vec_pretty(&build_evidence()).map_err(|_| EvidenceError::Serialize)?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    output
        .write_all(&encoded)
        .and_then(|()| output.write_all(b"\n"))
        .map_err(|_| EvidenceError::Output)
}
