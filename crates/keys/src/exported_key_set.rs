// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;
use std::fmt;

use serde::de::Error as _;
use serde::de::{self, DeserializeSeed, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

mod serialize;

const MAX_EXPORTED_KEY_ENTRIES: usize = 4_096;
const MAX_EXPORTED_PRIVATE_KEY_BYTES: usize = 21_848;
const MAX_EXPORTED_PUBLIC_KEY_BYTES: usize = 32 * 1_024;
const MAX_VERIFICATION_METHOD_ID_BYTES: usize = 1_024;

/// Base64-encoded private key material for JSON import/export.
///
/// This wrapper preserves the external JSON shape as a string while keeping the
/// in-memory export value redacted in debug output and zeroized on drop.
pub struct ExportedPrivateKey {
    encoded: Zeroizing<String>,
}

impl ExportedPrivateKey {
    /// Wrap an encoded private key string.
    ///
    /// The caller is responsible for passing an already validated encoding;
    /// import validation happens when an `ExportedKeySet` is consumed.
    #[must_use]
    pub fn new(encoded: String) -> Self {
        Self {
            encoded: Zeroizing::new(encoded),
        }
    }

    /// Borrow the encoded private key string for serialization or import.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.encoded.as_str()
    }
}

impl fmt::Debug for ExportedPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl<'de> Deserialize<'de> for ExportedPrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PrivateKeyVisitor;

        impl Visitor<'_> for PrivateKeyVisitor {
            type Value = ExportedPrivateKey;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("bounded base64 private key material")
            }

            fn visit_borrowed_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() > MAX_EXPORTED_PRIVATE_KEY_BYTES {
                    return Err(E::custom("private key encoding exceeds limit"));
                }
                Ok(ExportedPrivateKey::new(value.to_owned()))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_borrowed_str(value)
            }

            fn visit_string<E>(self, mut value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() > MAX_EXPORTED_PRIVATE_KEY_BYTES {
                    value.zeroize();
                    return Err(E::custom("private key encoding exceeds limit"));
                }
                Ok(ExportedPrivateKey::new(value))
            }
        }

        deserializer.deserialize_string(PrivateKeyVisitor)
    }
}

/// JSON-compatible key-set representation.
///
/// Private values are base64-encoded secret key material. `Debug` is redacted so
/// accidental assertion or tracing output cannot leak the encoded private keys.
pub struct ExportedKeySet {
    /// Base64-encoded private key material keyed by verification method id.
    pub private: BTreeMap<String, ExportedPrivateKey>,

    /// Multibase/multikey public key material keyed by verification method id.
    pub public: BTreeMap<String, String>,
}

impl ExportedKeySet {
    /// Serialize this key set into owned zeroizing JSON storage.
    ///
    /// Generic `Serialize` is intentionally not implemented: a caller-chosen
    /// serializer could grow ordinary heap buffers containing base64 private
    /// keys without any cleanup guarantee.
    pub fn to_json(&self) -> Result<Zeroizing<String>, crate::KeySetError> {
        serialize::to_json(self)
    }
}

struct BoundedIdentifier(String);

impl<'de> Deserialize<'de> for BoundedIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IdentifierVisitor;

        impl Visitor<'_> for IdentifierVisitor {
            type Value = BoundedIdentifier;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("bounded verification method identifier")
            }

            fn visit_borrowed_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() > MAX_VERIFICATION_METHOD_ID_BYTES {
                    return Err(E::custom("verification method identifier exceeds limit"));
                }
                Ok(BoundedIdentifier(value.to_owned()))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_borrowed_str(value)
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() > MAX_VERIFICATION_METHOD_ID_BYTES {
                    return Err(E::custom("verification method identifier exceeds limit"));
                }
                Ok(BoundedIdentifier(value))
            }
        }

        deserializer.deserialize_string(IdentifierVisitor)
    }
}

struct BoundedPublicKey(String);

impl<'de> Deserialize<'de> for BoundedPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PublicKeyVisitor;

        impl Visitor<'_> for PublicKeyVisitor {
            type Value = BoundedPublicKey;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("bounded public Multikey")
            }

            fn visit_borrowed_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() > MAX_EXPORTED_PUBLIC_KEY_BYTES {
                    return Err(E::custom("public key encoding exceeds limit"));
                }
                Ok(BoundedPublicKey(value.to_owned()))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_borrowed_str(value)
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() > MAX_EXPORTED_PUBLIC_KEY_BYTES {
                    return Err(E::custom("public key encoding exceeds limit"));
                }
                Ok(BoundedPublicKey(value))
            }
        }

        deserializer.deserialize_string(PublicKeyVisitor)
    }
}

struct PrivateMapSeed;

impl<'de> DeserializeSeed<'de> for PrivateMapSeed {
    type Value = BTreeMap<String, ExportedPrivateKey>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PrivateMapVisitor;

        impl<'de> Visitor<'de> for PrivateMapVisitor {
            type Value = BTreeMap<String, ExportedPrivateKey>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("bounded private key map without duplicate identifiers")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut result = BTreeMap::new();
                while let Some(BoundedIdentifier(id)) = map.next_key()? {
                    if result.len() >= MAX_EXPORTED_KEY_ENTRIES {
                        return Err(A::Error::custom("private key entry count exceeds limit"));
                    }
                    let value = map.next_value::<ExportedPrivateKey>()?;
                    if result.insert(id, value).is_some() {
                        return Err(A::Error::custom("duplicate private key identifier"));
                    }
                }
                Ok(result)
            }
        }

        deserializer.deserialize_map(PrivateMapVisitor)
    }
}

struct PublicMapSeed;

impl<'de> DeserializeSeed<'de> for PublicMapSeed {
    type Value = BTreeMap<String, String>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PublicMapVisitor;

        impl<'de> Visitor<'de> for PublicMapVisitor {
            type Value = BTreeMap<String, String>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("bounded public key map without duplicate identifiers")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut result = BTreeMap::new();
                while let Some(BoundedIdentifier(id)) = map.next_key()? {
                    if result.len() >= MAX_EXPORTED_KEY_ENTRIES {
                        return Err(A::Error::custom("public key entry count exceeds limit"));
                    }
                    let BoundedPublicKey(value) = map.next_value()?;
                    if result.insert(id, value).is_some() {
                        return Err(A::Error::custom("duplicate public key identifier"));
                    }
                }
                Ok(result)
            }
        }

        deserializer.deserialize_map(PublicMapVisitor)
    }
}

impl<'de> Deserialize<'de> for ExportedKeySet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            Private,
            Public,
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl Visitor<'_> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("private or public")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "private" => Ok(Field::Private),
                            "public" => Ok(Field::Public),
                            _ => Err(E::unknown_field(value, &["private", "public"])),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct KeySetVisitor;

        impl<'de> Visitor<'de> for KeySetVisitor {
            type Value = ExportedKeySet;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("exported key set")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut private = None;
                let mut public = None;
                while let Some(field) = map.next_key()? {
                    match field {
                        Field::Private => {
                            if private.is_some() {
                                return Err(A::Error::duplicate_field("private"));
                            }
                            private = Some(map.next_value_seed(PrivateMapSeed)?);
                        }
                        Field::Public => {
                            if public.is_some() {
                                return Err(A::Error::duplicate_field("public"));
                            }
                            public = Some(map.next_value_seed(PublicMapSeed)?);
                        }
                    }
                }

                Ok(ExportedKeySet {
                    private: private.ok_or_else(|| A::Error::missing_field("private"))?,
                    public: public.ok_or_else(|| A::Error::missing_field("public"))?,
                })
            }
        }

        deserializer.deserialize_struct("ExportedKeySet", &["private", "public"], KeySetVisitor)
    }
}

impl fmt::Debug for ExportedKeySet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExportedKeySet")
            .field("private_key_count", &self.private.len())
            .field("public_key_count", &self.public.len())
            .finish()
    }
}

impl Zeroize for ExportedKeySet {
    fn zeroize(&mut self) {
        for (mut id, private_key) in core::mem::take(&mut self.private) {
            id.zeroize();
            drop(private_key);
        }
        for (mut id, mut public_key) in core::mem::take(&mut self.public) {
            id.zeroize();
            public_key.zeroize();
        }
    }
}

impl Drop for ExportedKeySet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ExportedKeySet {}
