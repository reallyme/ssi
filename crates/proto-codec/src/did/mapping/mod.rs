// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Attestation JSON/protobuf mappings.
pub mod attestation;
/// Data Integrity proof JSON/protobuf mappings.
pub mod data_integrity_proof;
/// Domain verification JSON/protobuf mappings.
pub mod domain_verification;
/// Service endpoint JSON/protobuf mappings.
pub mod service;
/// Update policy JSON/protobuf mappings.
pub mod update_policy;
/// Verification method JSON/protobuf mappings.
pub mod verification_method;

pub use attestation::{attestation_from_proto, attestation_to_proto};
pub use data_integrity_proof::{di_proof_from_proto, di_proof_to_proto};
pub use domain_verification::{domain_from_proto, domain_to_proto};
pub use service::{service_from_proto, service_to_proto};
pub use update_policy::{policy_to_proto, update_policy_from_proto};
pub use verification_method::{vm_from_proto, vm_to_proto};
