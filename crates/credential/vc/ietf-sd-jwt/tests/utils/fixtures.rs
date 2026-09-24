// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
// SPDX-FileCopyrightText: Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
//
// SPDX-License-Identifier: Apache-2.0
//! Test coverage for this crate.

pub const ADDRESS_CLAIMS: &str = r#"{
    "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
    "iss": "https://example.com/issuer",
    "iat": 1683000000,
    "exp": 1883000000,
    "address": {
        "street_address": "Schulstr. 12",
        "locality": "Schulpforta",
        "region": "Sachsen-Anhalt",
        "country": "DE"
  }
}"#;
pub const ADDRESS_ONLY_STRUCTURED_JSONPATH: [&str; 4] = [
    "$.address.street_address",
    "$.address.locality",
    "$.address.region",
    "$.address.country",
];
pub const ADDRESS_ONLY_STRUCTURED_ONE_OPEN_JSONPATH: [&str; 3] = [
    "$.address.street_address",
    "$.address.locality",
    "$.address.region",
];
pub const ARRAYED_CLAIMS: &str = r#"
{
  "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
  "iss": "https://example.com/issuer",
  "iat": 1683000000,
  "exp": 1883000000,
  "addresses": [
    {
    "street_address": "Schulstr. 12",
    "locality": "Schulpforta",
    "region": "Sachsen-Anhalt",
    "country": "DE"
    },
    {
    "street_address": "456 Main St",
    "locality": "Anytown",
    "region": "NY",
    "country": "US"
    }
  ],
  "nationalities": [
    "US",
    "CA"
  ]
}"#;
pub const ARRAYED_CLAIMS_JSONPATH: [&str; 3] = [
    "$.addresses[1]",
    "$.addresses[1].country",
    "$.nationalities[0]",
];
pub const NESTED_ARRAY_CLAIMS: &str = r#"{
  "iss": "https://example.com/issuer",
  "iat": 1683000000,
  "exp": 1883000000,
  "nationalities": [
    ["IT", "UZ"],
    ["DE", "US"]
   ]
}"#;
pub const NESTED_ARRAY_JSONPATH: [&str; 3] = [
    "$.nationalities[0]",
    "$.nationalities[0][0]",
    "$.nationalities[0][1]",
];
pub const COMPLEX_EIDAS_CLAIMS: &str = r#"{
  "iss": "https://example.com/issuer",
  "iat": 1683000000,
  "exp": 1883000000,
  "verified_claims": {
    "verification": {
      "trust_framework": "eidas",
      "assurance_level": "high",
      "evidence": [
        {
          "type": "document",
          "time": "2022-04-22T11:30Z",
          "document": {
            "type": "idcard",
            "issuer": {
              "name": "c_d612",
              "country": "IT"
            },
            "number": "154554",
            "date_of_issuance": "2021-03-23",
            "date_of_expiry": "2031-03-22"
          }
        }
      ]
    },
    "claims": {
      "person_unique_identifier":
        "TINIT-fc0d9684-1bf0-4220-9642-8fe652c8c040",
      "given_name": "Raffaello",
      "family_name": "Mascetti",
      "date_of_birth": "1922-03-13",
      "gender": "M",
      "place_of_birth": {
        "country": "IT",
        "locality": "Firenze"
      },
      "nationalities": [
        "IT"
      ]
    }
  },
  "birth_middle_name": "Lello"
}"#;
pub const COMPLEX_EIDAS_JSONPATH: [&str; 7] = [
    "$.verified_claims.verification.evidence[0].document.issuer",
    "$.verified_claims.verification.evidence[0].document",
    "$.verified_claims.verification.evidence",
    "$.verified_claims.claims.date_of_birth",
    "$.verified_claims.claims.gender",
    "$.verified_claims.claims.place_of_birth",
    "$.verified_claims.claims.nationalities",
];
pub const COMPLEX_EKYC_CLAIMS: &str = r#"{
  "iss": "https://example.com/issuer",
  "iat": 1683000000,
  "exp": 1883000000,
  "verified_claims": {
    "verification": {
      "trust_framework": "de_aml",
      "time": "2012-04-23T18:25Z",
      "verification_process": "f24c6f-6d3f-4ec5-973e-b0d8506f3bc7",
      "evidence": [
        {
          "type": "document",
          "method": "pipp",
          "time": "2012-04-22T11:30Z",
          "document": {
            "type": "idcard",
            "issuer": {
              "name": "Stadt Augsburg",
              "country": "DE"
            },
            "number": "53554554",
            "date_of_issuance": "2010-03-23",
            "date_of_expiry": "2020-03-22"
          }
        }
      ]
    },
    "claims": {
      "given_name": "Max",
      "family_name": "Müller",
      "nationalities": ["DE"],
      "birthdate": "1956-01-28",
      "place_of_birth": {
        "country": "IS",
        "locality": "Þykkvabæjarklaustur"
      },
      "address": {
        "locality": "Maxstadt",
        "postal_code": "12344",
        "country": "DE",
        "street_address": "Weidenstraße 22"
      }
    }
  },
  "birth_middle_name": "Timotheus",
  "salutation": "Dr.",
  "msisdn": "49123456789"
}"#;
pub const COMPLEX_EKYC_JSONPATH: [&str; 5] = [
    "$.verified_claims.verification.time",
    "$.verified_claims.verification.evidence[0].method",
    "$.verified_claims.claims.given_name",
    "$.verified_claims.claims.family_name",
    "$.verified_claims.claims.address",
];
pub const W3C_VC_CLAIMS: &str = r#"{
  "iss": "https://example.com",
  "jti": "http://example.com/credentials/3732",
  "iat": 1683000000,
  "exp": 1883000000,
  "vct": "IdentityCredential",
  "credentialSubject": {
    "given_name": "John",
    "family_name": "Doe",
    "email": "johndoe@example.com",
    "phone_number": "+1-202-555-0101",
    "address": {
      "street_address": "123 Main St",
      "locality": "Anytown",
      "region": "Anystate",
      "country": "US"
    },
    "birthdate": "1940-01-01",
    "is_over_18": true,
    "is_over_21": true,
    "is_over_65": true
  }
}"#;
pub const W3C_VC_JSONPATH: [&str; 9] = [
    "$.credentialSubject.given_name",
    "$.credentialSubject.family_name",
    "$.credentialSubject.email",
    "$.credentialSubject.phone_number",
    "$.credentialSubject.address",
    "$.credentialSubject.birthdate",
    "$.credentialSubject.is_over_18",
    "$.credentialSubject.is_over_21",
    "$.credentialSubject.is_over_65",
];
