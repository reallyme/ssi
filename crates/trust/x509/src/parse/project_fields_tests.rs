// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use super::{
    rsa_pss_parameters, AlgorithmIdentifier, FromDer, RsaPssHashAlgorithm,
    RsaPssMaskGenerationAlgorithm, RsaPssParameters, X509Error,
};

const RSA_PSS_SHA256_DER: &[u8] = &[
    0x30, 0x41, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x34, 0xa0,
    0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
    0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30,
    0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa2, 0x03,
    0x02, 0x01, 0x20,
];
const RSA_PSS_WITHOUT_PARAMETERS_DER: &[u8] = &[
    0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
];

#[test]
fn projects_rsa_pss_parameters_and_rejects_missing_parameter_sequence() {
    let (remaining, algorithm) = AlgorithmIdentifier::from_der(RSA_PSS_SHA256_DER)
        .expect("valid RSA-PSS AlgorithmIdentifier fixture");
    assert!(remaining.is_empty());
    assert_eq!(
        rsa_pss_parameters(&algorithm),
        Ok(Some(RsaPssParameters {
            hash_algorithm: RsaPssHashAlgorithm::Sha256,
            mask_generation_algorithm: RsaPssMaskGenerationAlgorithm::Mgf1(
                RsaPssHashAlgorithm::Sha256,
            ),
            salt_length: 32,
            trailer_field: 1,
        }))
    );

    let (remaining, missing_parameters) =
        AlgorithmIdentifier::from_der(RSA_PSS_WITHOUT_PARAMETERS_DER)
            .expect("valid parameterless AlgorithmIdentifier fixture");
    assert!(remaining.is_empty());
    assert_eq!(
        rsa_pss_parameters(&missing_parameters),
        Err(X509Error::ParseError)
    );
}
