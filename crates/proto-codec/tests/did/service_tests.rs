// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_types::Service;
use reallyme_ssi_proto_codec::did::mapping::service::{service_from_proto, service_to_proto};
use serde_json::json;

#[test]
fn service_json_to_proto_and_back() {
    let svc = Service {
        id: "svc1".into(),
        service_type: "LinkedDomains".into(),
        service_endpoint: json!({"origins": ["https://example.com"]}),
    };

    let proto = service_to_proto(&svc).unwrap();
    let back = service_from_proto(&proto).unwrap();

    assert_eq!(svc.id, back.id);
    assert_eq!(svc.service_type, back.service_type);
    assert_eq!(svc.service_endpoint, back.service_endpoint);
}
