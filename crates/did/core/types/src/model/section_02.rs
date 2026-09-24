// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

impl Zeroize for DomainVerification {
    fn zeroize(&mut self) {
        self.verification_type.zeroize();
        self.method.zeroize();
        self.domain.zeroize();
        if let Some(dns) = &mut self.dns {
            dns.zeroize();
        }
        self.dns = None;
        if let Some(well_known) = &mut self.wellknown {
            well_known.zeroize();
        }
        self.wellknown = None;
    }
}

impl Zeroize for DNSBinding {
    fn zeroize(&mut self) {
        self.record_name.zeroize();
        self.txt_value.zeroize();
    }
}

impl Zeroize for WellKnownBinding {
    fn zeroize(&mut self) {
        self.uri.zeroize();
        self.content.zeroize();
    }
}

macro_rules! impl_sensitive_owner {
    ($($type_name:ty),+ $(,)?) => {
        $(
            impl fmt::Debug for $type_name {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter
                        .debug_tuple(stringify!($type_name))
                        .field(&"[REDACTED]")
                        .finish()
                }
            }

            impl Drop for $type_name {
                fn drop(&mut self) {
                    self.zeroize();
                }
            }

            impl ZeroizeOnDrop for $type_name {}
        )+
    };
}

impl_sensitive_owner!(
    DIDDocument,
    Controller,
    VerificationMethod,
    Service,
    UpdatePolicy,
    Attestation,
    DataIntegrityProof,
    DomainVerification,
    DNSBinding,
    WellKnownBinding,
);

fn zeroize_json(value: &mut JsonValue) {
    match core::mem::replace(value, JsonValue::Null) {
        JsonValue::String(mut text) => text.zeroize(),
        JsonValue::Array(mut values) => {
            for child in &mut values {
                zeroize_json(child);
            }
        }
        JsonValue::Object(object) => {
            for (mut key, mut child) in object {
                key.zeroize();
                zeroize_json(&mut child);
            }
        }
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => {}
    }
}

fn zeroize_strings(values: &mut Vec<String>) {
    for value in values.iter_mut() {
        value.zeroize();
    }
    values.clear();
}

#[cfg(test)]
#[path = "../lib_tests.rs"]
mod tests;
