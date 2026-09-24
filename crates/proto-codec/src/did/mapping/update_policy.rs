// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_did_types::UpdatePolicy as JsonPolicy;
use reallyme_ssi_proto::generated::proto::meid::did::v1::UpdatePolicy as PbPolicy;

/// JSON-domain update policy to did:me protobuf.
pub fn policy_to_proto(p: &JsonPolicy) -> PbPolicy {
    PbPolicy {
        allowed_verification_methods: p.allowed_verification_methods.clone(),
        threshold: p.threshold,
        ..PbPolicy::default()
    }
}

/// did:me protobuf update policy to JSON-domain model.
pub fn update_policy_from_proto(p: &PbPolicy) -> JsonPolicy {
    JsonPolicy {
        allowed_verification_methods: p.allowed_verification_methods.clone(),
        threshold: p.threshold,
    }
}
