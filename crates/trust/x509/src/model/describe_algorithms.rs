// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Public-key algorithm and measured strength.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub enum PublicKeyProfile {
    /// RSA public key.
    Rsa {
        /// RSA modulus size in bits.
        bits: u16,
    },
    /// Elliptic-curve public key.
    Ec {
        /// Curve-group size in bits.
        bits: u16,
        /// Named-curve object identifier when available.
        curve: Option<ObjectIdentifier>,
    },
    /// Ed25519 public key.
    Ed25519,
    /// Ed448 public key.
    Ed448,
    /// DSA public key.
    Dsa {
        /// DSA parameter size in bits.
        bits: u16,
    },
    /// Unrecognized public-key algorithm.
    Other {
        /// Algorithm object identifier.
        algorithm: ObjectIdentifier,
        /// Measured key strength in bits.
        bits: u16,
    },
}

/// Closed public-key algorithm family used by versioned profile policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
#[non_exhaustive]
pub enum PublicKeyAlgorithm {
    /// Uses the RSA algorithm.
    Rsa,
    /// Uses the EC algorithm.
    Ec,
    /// Uses the Ed25519 algorithm.
    Ed25519,
    /// Uses the Ed448 algorithm.
    Ed448,
    /// Uses the DSA algorithm.
    Dsa,
    /// Unrecognized algorithm family.
    Other,
}

impl PublicKeyProfile {
    /// Returns the typed algorithm family without reparsing an OID.
    pub const fn algorithm(&self) -> PublicKeyAlgorithm {
        match self {
            Self::Rsa { .. } => PublicKeyAlgorithm::Rsa,
            Self::Ec { .. } => PublicKeyAlgorithm::Ec,
            Self::Ed25519 => PublicKeyAlgorithm::Ed25519,
            Self::Ed448 => PublicKeyAlgorithm::Ed448,
            Self::Dsa { .. } => PublicKeyAlgorithm::Dsa,
            Self::Other { .. } => PublicKeyAlgorithm::Other,
        }
    }
}

impl Default for PublicKeyProfile {
    fn default() -> Self {
        Self::Other {
            algorithm: ObjectIdentifier("0.0".to_owned()),
            bits: 0,
        }
    }
}

/// Typed certificate-signature algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RsaPkcs1Sha256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    RsaPkcs1Sha384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    RsaPkcs1Sha512,
    /// RSASSA-PSS with separately parsed parameters.
    RsaPss,
    /// ECDSA with SHA-256.
    EcdsaSha256,
    /// ECDSA with SHA-384.
    EcdsaSha384,
    /// ECDSA with SHA-512.
    EcdsaSha512,
    /// Uses the Ed25519 algorithm.
    Ed25519,
    /// Uses the Ed448 algorithm.
    Ed448,
    /// Unrecognized signature algorithm retained by object identifier.
    Other(ObjectIdentifier),
}

/// Hash algorithm carried by an RSA-PSS algorithm identifier.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub enum RsaPssHashAlgorithm {
    /// Uses the SHA-1 algorithm.
    Sha1,
    /// Uses the SHA-256 algorithm.
    Sha256,
    /// Uses the SHA-384 algorithm.
    Sha384,
    /// Uses the SHA-512 algorithm.
    Sha512,
    /// SHA3-256.
    Sha3_256,
    /// SHA3-384.
    Sha3_384,
    /// SHA3-512.
    Sha3_512,
    /// Unrecognized hash algorithm retained by object identifier.
    Other(ObjectIdentifier),
}

/// Mask-generation algorithm carried by RSA-PSS parameters.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub enum RsaPssMaskGenerationAlgorithm {
    /// MGF1 with the selected hash algorithm.
    Mgf1(RsaPssHashAlgorithm),
    /// Unrecognized mask-generation algorithm retained by object identifier.
    Other(ObjectIdentifier),
}

/// Lossless security-relevant projection of RFC 4055 RSA-PSS parameters.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RsaPssParameters {
    /// Message hash algorithm.
    pub hash_algorithm: RsaPssHashAlgorithm,
    /// Mask-generation algorithm.
    pub mask_generation_algorithm: RsaPssMaskGenerationAlgorithm,
    /// Salt length in octets.
    pub salt_length: u32,
    /// RFC 4055 trailer-field value.
    pub trailer_field: u32,
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        Self::Other(ObjectIdentifier("0.0".to_owned()))
    }
}
