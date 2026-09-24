// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_mdoc::{MdocIdentifierList, MdocStatus, MdocStatusList};
use envelopes_x509::{parse_cert_der, verify_chain_signatures_pure_rust, X509Chain};

const SYNTHETIC_STATUS_URI: &str = "https://issuer.example/revocation/status-list";
const STATUS_CERTIFICATE_DER: &[u8] =
    include_bytes!("../../../../revocation/ocsp/openssl/tests/fixtures/leaf.der");
const STATUS_ISSUER_DER: &[u8] =
    include_bytes!("../../../../revocation/ocsp/openssl/tests/fixtures/issuer.der");
const STATUS_ROOT_DER: &[u8] =
    include_bytes!("../../../../revocation/ocsp/openssl/tests/fixtures/root.der");

#[test]
fn signed_mso_status_list_interoperates_with_verification() {
    let (issuer_public_key, issuer_private_key) = issuer_keys();
    let kid = b"status-list-issuer".to_vec();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };
    let status = MdocStatus::status_list(
        MdocStatusList::new(
            42,
            SYNTHETIC_STATUS_URI.to_owned(),
            Some(STATUS_CERTIFICATE_DER.to_vec()),
        )
        .unwrap(),
    );
    let config = valid_config().with_status(status.clone());
    let (document, issued_mso) = build_mso_mdoc(&config, &sample_elements(), &signer).unwrap();

    let verified = verify_issuer_signed_mdoc(
        &document,
        resolver_for_kid(kid, issuer_public_key),
        1_700_000_001,
    )
    .unwrap();

    assert!(issued_mso.status.as_ref() == Some(&status));
    assert!(verified.mobile_security_object.status.as_ref() == Some(&status));
    let certificate = verified
        .mobile_security_object
        .status
        .as_ref()
        .and_then(MdocStatus::status_list_ref)
        .and_then(MdocStatusList::certificate_der)
        .unwrap();
    let chain = X509Chain {
        certs: vec![
            parse_cert_der(certificate).unwrap(),
            parse_cert_der(STATUS_ISSUER_DER).unwrap(),
            parse_cert_der(STATUS_ROOT_DER).unwrap(),
        ],
    };
    verify_chain_signatures_pure_rust(&chain).unwrap();
}

#[test]
fn signed_mso_identifier_list_interoperates_with_verification() {
    let (issuer_public_key, issuer_private_key) = issuer_keys();
    let kid = b"identifier-list-issuer".to_vec();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };
    let status = MdocStatus::identifier_list(
        MdocIdentifierList::new(
            vec![1, 2, 3, 4, 5, 6, 7, 8],
            SYNTHETIC_STATUS_URI.to_owned(),
            None,
        )
        .unwrap(),
    );
    let config = valid_config().with_status(status.clone());
    let (document, issued_mso) = build_mso_mdoc(&config, &sample_elements(), &signer).unwrap();

    let verified = verify_issuer_signed_mdoc(
        &document,
        resolver_for_kid(kid, issuer_public_key),
        1_700_000_001,
    )
    .unwrap();

    assert!(issued_mso.status.as_ref() == Some(&status));
    assert!(verified.mobile_security_object.status.as_ref() == Some(&status));
}
