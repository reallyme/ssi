// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

const MAX_JWK_MEMBER_COUNT: usize = 16;
const MAX_JWK_KEY_OPERATIONS: usize = 8;

struct ParsedPublicJwk {
    members: BTreeMap<String, serde_json::Value>,
    key_operations: Option<Vec<String>>,
}

struct PublicJwkVisitor;

impl<'de> serde::de::Visitor<'de> for PublicJwkVisitor {
    type Value = ParsedPublicJwk;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a bounded public JWK object")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: serde::de::MapAccess<'de>,
    {
        let mut members = BTreeMap::new();
        let mut key_operations = None;
        let mut member_count = 0_usize;

        while let Some(name) = map.next_key::<String>()? {
            member_count = member_count
                .checked_add(1)
                .ok_or_else(|| serde::de::Error::custom("invalid public JWK"))?;
            if member_count > MAX_JWK_MEMBER_COUNT
                || members.contains_key(&name)
                || (name == "key_ops" && key_operations.is_some())
            {
                return Err(serde::de::Error::custom("invalid public JWK"));
            }
            if is_private_or_symmetric_jwk_member(name.as_str()) {
                let _: serde::de::IgnoredAny = map.next_value()?;
                return Err(serde::de::Error::custom("prohibited JWK material"));
            }
            if name == "key_ops" {
                let operations = map.next_value::<Vec<String>>()?;
                if operations.is_empty() || operations.len() > MAX_JWK_KEY_OPERATIONS {
                    return Err(serde::de::Error::custom("invalid public JWK"));
                }
                key_operations = Some(operations);
                continue;
            }
            if !is_supported_public_jwk_member(name.as_str()) {
                let _: serde::de::IgnoredAny = map.next_value()?;
                return Err(serde::de::Error::custom("unsupported public JWK member"));
            }
            members.insert(name, map.next_value::<serde_json::Value>()?);
        }

        Ok(ParsedPublicJwk {
            members,
            key_operations,
        })
    }
}

fn parse_public_jwk(value: &[u8]) -> Result<ParsedPublicJwk, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(value);
    let parsed = serde::de::Deserializer::deserialize_map(&mut deserializer, PublicJwkVisitor)?;
    deserializer.end()?;
    Ok(parsed)
}

fn is_private_or_symmetric_jwk_member(name: &str) -> bool {
    matches!(
        name,
        "d" | "p" | "q" | "dp" | "dq" | "qi" | "oth" | "k" | "priv" | "privateKey"
            | "secretKey"
    )
}

fn is_supported_public_jwk_member(name: &str) -> bool {
    matches!(name, "kty" | "crv" | "x" | "y" | "alg" | "use" | "kid" | "pub")
}

fn valid_jwk_key_operations(
    algorithm: CredentialAlgorithm,
    operations: Option<&[String]>,
) -> bool {
    let Some(operations) = operations else {
        return true;
    };
    let mut seen = BTreeSet::new();
    operations.iter().all(|operation| {
        seen.insert(operation.as_str())
            && match algorithm {
                CredentialAlgorithm::Ed25519
                | CredentialAlgorithm::P256
                | CredentialAlgorithm::Secp256k1
                | CredentialAlgorithm::Es256kRecovery
                | CredentialAlgorithm::MlDsa44
                | CredentialAlgorithm::MlDsa65
                | CredentialAlgorithm::MlDsa87 => operation == "verify",
                CredentialAlgorithm::X25519 => {
                    operation == "deriveKey" || operation == "deriveBits"
                }
                CredentialAlgorithm::MlKem768 | CredentialAlgorithm::MlKem1024 => {
                    operation == "encapsulateKey"
                }
                CredentialAlgorithm::Unspecified => false,
            }
    })
}
