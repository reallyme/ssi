// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Package-owned memory cleanup for generated did:me document messages.

use buffa_types::google::protobuf::{value::Kind, Value};
use zeroize::Zeroize;

use crate::generated::proto::meid::did::v1 as pb;

impl Zeroize for pb::DIDDocument {
    fn zeroize(&mut self) {
        self.id.zeroize();
        if let Some(controller) = self.controller.as_option_mut() {
            zeroize_value(controller);
        }
        self.controller = Default::default();
        zeroize_strings(&mut self.context);
        zeroize_strings(&mut self.also_known_as);
        self.biometric_protected = None;
        self.hardware_bound = None;
        self.device_model.zeroize();
        self.user_verification_method.zeroize();
        self.sequence = 0;
        self.prev.zeroize();
        self.current_core.zeroize();
        self.core_cbor.zeroize();
        zeroize_strings(&mut self.key_history);
        zeroize_messages(&mut self.verification_method);
        zeroize_strings(&mut self.authentication);
        zeroize_strings(&mut self.assertion_method);
        zeroize_strings(&mut self.capability_invocation);
        zeroize_strings(&mut self.key_agreement);
        zeroize_messages(&mut self.service);
        if let Some(policy) = self.update_policy.as_option_mut() {
            policy.zeroize();
        }
        self.update_policy = Default::default();
        zeroize_messages(&mut self.attestations);
        if let Some(proof) = self.proof.as_option_mut() {
            proof.zeroize();
        }
        self.proof = Default::default();
        zeroize_messages(&mut self.domain_verification);
        self.nonce.zeroize();
        self.eudi_level_of_assurance.zeroize();
        self.eudi_schema_version.zeroize();
        self.__buffa_unknown_fields.clear();
    }
}

impl Zeroize for pb::VerificationMethod {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.r#type.zeroize();
        self.controller.zeroize();
        self.public_key_multibase.zeroize();
        self.algorithm = Default::default();
        self.__buffa_unknown_fields.clear();
    }
}

impl Zeroize for pb::Service {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.r#type.zeroize();
        if let Some(endpoint) = self.service_endpoint.as_option_mut() {
            zeroize_value(endpoint);
        }
        self.service_endpoint = Default::default();
        self.__buffa_unknown_fields.clear();
    }
}

impl Zeroize for pb::UpdatePolicy {
    fn zeroize(&mut self) {
        zeroize_strings(&mut self.allowed_verification_methods);
        self.threshold = None;
        self.__buffa_unknown_fields.clear();
    }
}

impl Zeroize for pb::Attestation {
    fn zeroize(&mut self) {
        self.alg = Default::default();
        self.vm.zeroize();
        self.sig.zeroize();
        self.__buffa_unknown_fields.clear();
    }
}

impl Zeroize for pb::DataIntegrityProof {
    fn zeroize(&mut self) {
        self.r#type.zeroize();
        self.cryptosuite.zeroize();
        self.verification_method.zeroize();
        self.created.zeroize();
        self.jws.zeroize();
        self.proof_purpose.zeroize();
        self.__buffa_unknown_fields.clear();
    }
}

impl Zeroize for pb::DomainVerification {
    fn zeroize(&mut self) {
        self.r#type.zeroize();
        self.domain.zeroize();
        self.method.zeroize();
        if let Some(binding) = self.binding.take() {
            match binding {
                pb::domain_verification::Binding::Dns(mut dns) => dns.zeroize(),
                pb::domain_verification::Binding::WellKnown(mut well_known) => {
                    well_known.zeroize();
                }
            }
        }
        self.__buffa_unknown_fields.clear();
    }
}

impl Zeroize for pb::DNSBinding {
    fn zeroize(&mut self) {
        self.record_name.zeroize();
        self.txt_value.zeroize();
        self.__buffa_unknown_fields.clear();
    }
}

impl Zeroize for pb::WellKnownBinding {
    fn zeroize(&mut self) {
        self.uri.zeroize();
        self.content.zeroize();
        self.__buffa_unknown_fields.clear();
    }
}

fn zeroize_value(value: &mut Value) {
    if let Some(kind) = value.kind.take() {
        match kind {
            Kind::StringValue(mut text) => text.zeroize(),
            Kind::StructValue(mut object) => {
                for (mut key, mut child) in core::mem::take(&mut object.fields) {
                    key.zeroize();
                    zeroize_value(&mut child);
                }
                object.__buffa_unknown_fields.clear();
            }
            Kind::ListValue(mut list) => {
                for child in &mut list.values {
                    zeroize_value(child);
                }
                list.values.clear();
                list.__buffa_unknown_fields.clear();
            }
            Kind::NullValue(_) | Kind::NumberValue(_) | Kind::BoolValue(_) => {}
        }
    }
    value.__buffa_unknown_fields.clear();
}

fn zeroize_strings(values: &mut Vec<String>) {
    for value in values.iter_mut() {
        value.zeroize();
    }
    values.clear();
}

fn zeroize_messages<T: Zeroize>(values: &mut Vec<T>) {
    for value in values.iter_mut() {
        value.zeroize();
    }
    values.clear();
}
