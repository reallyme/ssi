// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs)]
#![allow(clippy::print_stdout)]

use reallyme_did_api::validate::DomainVerificationEnv;
use reallyme_did_api::{
    create_did, update_did, validate_did, CreateConfig, DidProfile, UpdateConfig,
};
use reallyme_did_types::DIDDocument;

use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
enum DemoError {
    #[error("DID creation failed")]
    Create,
    #[error("DID serialization failed")]
    Serialize,
    #[error("DID output failed")]
    Write,
    #[error("DID validation failed")]
    Validate,
    #[error("DID update failed")]
    Update,
}

/// --------------------------------------------------
/// Write DID Document as pretty JSON
/// --------------------------------------------------
fn write_did_json<P: AsRef<Path>>(path: P, doc: &DIDDocument) -> Result<(), DemoError> {
    let json = serde_json::to_string_pretty(doc).map_err(|_| DemoError::Serialize)?;

    fs::write(path, json).map_err(|_| DemoError::Write)
}

fn main() -> Result<(), DemoError> {
    // --------------------------------------------------
    // 1. CREATE DID
    // --------------------------------------------------
    let (doc, keyset) = create_did(
        CreateConfig {
            profile: Some(DidProfile::CoreIdentity),
            also_known_as: None,
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            services: None,
            update_policy: None,
            domain_verification: None,
            verification_methods: None,
            authentication: None,
            assertion: None,
            invocation: None,
            key_agreement: None,
            created: Some("2025-01-01T00:00:00Z".into()),
        },
        "did:me:demo",
    )
    .map_err(|_| DemoError::Create)?;

    println!("Created DID");
    write_did_json("did.json", &doc)?;

    // --------------------------------------------------
    // 2. VALIDATE DID
    // --------------------------------------------------
    let validation = validate_did(
        &doc,
        DomainVerificationEnv {
            resolve_txt: None,
            fetch_url: None,
        },
    );

    println!("Validation result:\n{:#?}", validation);
    if !validation.ok {
        return Err(DemoError::Validate);
    }

    // --------------------------------------------------
    // 3. UPDATE DID (no-op update)
    // --------------------------------------------------
    let (updated_doc, _) = update_did(
        &doc,
        &keyset,
        UpdateConfig {
            services: None,
            also_known_as: None,
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            allowed: None,
            threshold: None,
            deactivate: false,
            domain_verification: None,
            rotate_vms: None,
            authentication: None,
            assertion: None,
            invocation: None,
            key_agreement: None,
            created: Some("2025-01-01T00:00:00Z".into()),
        },
    )
    .map_err(|_| DemoError::Update)?;

    println!("Updated DID");
    write_did_json("did.updated.json", &updated_doc)
}
