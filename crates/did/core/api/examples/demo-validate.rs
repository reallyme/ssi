// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs)]
#![allow(clippy::print_stdout)]

use std::fs;
use std::path::Path;

use reallyme_did_core::validate::validate_did_document;
use reallyme_did_core::validate::DomainVerificationEnv;
use reallyme_did_types::DIDDocument;
use thiserror::Error;

#[derive(Debug, Error)]
enum DemoValidationError {
    #[error("failed to read the DID document")]
    ReadInput,
    #[error("failed to parse the DID document")]
    ParseInput,
    #[error("the DID document is invalid")]
    Invalid,
}

fn main() -> Result<(), DemoValidationError> {
    // --------------------------------------------------
    // 1. Read DID JSON
    // --------------------------------------------------
    let path = Path::new("did.json");
    let json = fs::read_to_string(path).map_err(|_| DemoValidationError::ReadInput)?;

    // --------------------------------------------------
    // 2. Parse DID Document
    // --------------------------------------------------
    let doc: DIDDocument =
        serde_json::from_str(&json).map_err(|_| DemoValidationError::ParseInput)?;

    println!("Loaded DID: {}", doc.id);

    // --------------------------------------------------
    // 3. Validate DID (offline / deterministic)
    // --------------------------------------------------
    let result = validate_did_document(
        &doc,
        DomainVerificationEnv {
            resolve_txt: None,
            fetch_url: None,
        },
    );

    // --------------------------------------------------
    // 4. Print result
    // --------------------------------------------------
    if result.ok {
        println!("✅ DID is valid");
    } else {
        println!("❌ DID is INVALID");
    }

    println!("\nValidation result:");
    println!("{:#?}", result);

    // --------------------------------------------------
    // 5. Exit code for CI / scripts
    // --------------------------------------------------
    if result.ok {
        Ok(())
    } else {
        Err(DemoValidationError::Invalid)
    }
}
