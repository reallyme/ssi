// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_did_types::DataIntegrityProof as JsonProof;
use reallyme_ssi_proto::generated::proto::meid::did::v1::DataIntegrityProof as PbProof;

/// JSON-domain Data Integrity proof to did:me protobuf.
pub fn di_proof_to_proto(p: &JsonProof) -> PbProof {
    PbProof {
        r#type: p.proof_type.clone(),
        cryptosuite: option_or_empty(&p.cryptosuite),
        verification_method: option_or_empty(&p.verification_method),
        created: option_or_empty(&p.created),
        jws: option_or_empty(&p.jws),
        proof_purpose: option_or_empty(&p.proof_purpose),
        ..PbProof::default()
    }
}

/// did:me protobuf Data Integrity proof to JSON-domain model.
pub fn di_proof_from_proto(p: &PbProof) -> JsonProof {
    JsonProof {
        proof_type: p.r#type.clone(),
        cryptosuite: non_empty(&p.cryptosuite),
        verification_method: non_empty(&p.verification_method),
        created: non_empty(&p.created),
        jws: non_empty(&p.jws),
        proof_purpose: non_empty(&p.proof_purpose),
    }
}

fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

fn option_or_empty(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}
