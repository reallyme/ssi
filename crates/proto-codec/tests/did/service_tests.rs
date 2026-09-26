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
use reallyme_ssi_proto_codec::did::DidProtoCodecError;
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

#[test]
fn service_endpoint_integers_round_trip_exactly() {
    let svc = Service {
        id: "svc-int".into(),
        service_type: "LinkedDomains".into(),
        service_endpoint: json!({
            "priority": 1,
            "negative": -7,
            "max_exact": 9_007_199_254_740_991_u64,
            "ratio": 0.5
        }),
    };

    let back = service_from_proto(&service_to_proto(&svc).unwrap()).unwrap();

    assert_eq!(back.service_endpoint, svc.service_endpoint);
    assert!(
        back.service_endpoint["priority"].is_i64() || back.service_endpoint["priority"].is_u64()
    );
    assert!(back.service_endpoint["ratio"].is_f64());
}

#[test]
fn service_endpoint_rejects_integers_beyond_exact_double_range() {
    for endpoint in [
        json!({"value": 9_007_199_254_740_992_u64}),
        json!({"value": u64::MAX}),
        json!({"value": i64::MIN}),
    ] {
        let svc = Service {
            id: "svc-big".into(),
            service_type: "LinkedDomains".into(),
            service_endpoint: endpoint,
        };

        assert_eq!(
            service_to_proto(&svc).unwrap_err(),
            DidProtoCodecError::InvalidServiceEndpoint
        );
    }
}
