// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration coverage for DID protobuf conversion and bounded transport.

#[path = "did/attestation_tests.rs"]
mod attestation_tests;
#[path = "did/codec_invariants_tests.rs"]
mod codec_invariants_tests;
#[path = "did/data_integrity_proof_tests.rs"]
mod data_integrity_proof_tests;
#[path = "did/domain_verification_tests.rs"]
mod domain_verification_tests;
#[path = "did/roundtrip_tests.rs"]
mod roundtrip_tests;
#[path = "did/service_tests.rs"]
mod service_tests;
#[path = "did/update_policy_tests.rs"]
mod update_policy_tests;
#[path = "did/verification_method_tests.rs"]
mod verification_method_tests;
