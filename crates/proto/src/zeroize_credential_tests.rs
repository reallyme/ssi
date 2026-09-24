// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{EnumValue, MessageField};

use super::{pb, zeroize_credential_envelope, zeroize_subject_private_bundle};

fn key(did_url: &str, marker: u8) -> pb::PublicKeyRef {
    pb::PublicKeyRef {
        reference: MessageField::some(pb::KeyReference {
            kind: Some(
                pb::__buffa::oneof::key_reference::Kind::DidVerificationMethod(did_url.to_owned()),
            ),
            ..Default::default()
        }),
        public_key: MessageField::some(pb::PublicKeyMaterial {
            alg: EnumValue::from(pb::Algorithm::Ed25519),
            representation: Some(
                pb::__buffa::oneof::public_key_material::Representation::Raw(Box::new(
                    pb::RawPublicKey {
                        serialization: EnumValue::from(pb::RawPublicKeySerialization::FixedWidth),
                        bytes: vec![marker; 32],
                        ..Default::default()
                    },
                )),
            ),
            ..Default::default()
        }),
        assurance: MessageField::some(pb::KeyAssurance {
            kind: Some(pb::__buffa::oneof::key_assurance::Kind::None(Box::default())),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn party(kind: pb::__buffa::oneof::party_reference::Kind) -> pb::PartyReference {
    pb::PartyReference {
        kind: Some(kind),
        ..Default::default()
    }
}

#[test]
fn credential_cleanup_recursively_clears_identifying_and_signature_material() {
    let mut envelope = pb::CredentialEnvelope {
        profile_id: "sensitive-profile".to_owned(),
        issuer_reference: MessageField::some(party(
            pb::__buffa::oneof::party_reference::Kind::Did(
                "did:example:sensitive-issuer".to_owned(),
            ),
        )),
        issuer_country: "GB".to_owned(),
        status: MessageField::some(pb::CredentialStatus {
            status_list_url: "https://private.example/status".to_owned(),
            status_list_id: vec![4; 32],
            status_list_index: 7,
            ..Default::default()
        }),
        subject: MessageField::some(pb::CredentialSubject {
            subject_reference: MessageField::some(party(
                pb::__buffa::oneof::party_reference::Kind::OpaqueIdentifier(
                    "sensitive-subject".to_owned(),
                ),
            )),
            holder_binding: MessageField::some(pb::HolderBinding {
                mode: Some(pb::__buffa::oneof::holder_binding::Mode::CryptographicKey(
                    Box::new(key("did:example:sensitive-subject#key-1", 5)),
                )),
                ..Default::default()
            }),
            ..Default::default()
        }),
        issuer_signature: MessageField::some(pb::Signature {
            verification_key: MessageField::some(key("did:example:sensitive-issuer#key-1", 6)),
            raw_rs: vec![6; 64],
            ..Default::default()
        }),
        ..Default::default()
    };

    zeroize_credential_envelope(&mut envelope);

    assert!(envelope.profile_id.is_empty());
    assert!(envelope.issuer_reference.as_option().is_none());
    assert!(envelope.issuer_country.is_empty());
    assert!(envelope.status.as_option().is_none());
    assert!(envelope.subject.as_option().is_none());
    assert!(envelope.issuer_signature.as_option().is_none());
}

#[test]
fn subject_bundle_cleanup_clears_private_openings_and_signatures() {
    let mut bundle = pb::SubjectPrivateBundle {
        holder_key: MessageField::some(key("did:example:holder#key-1", 3)),
        envelope_hash: vec![4; 32],
        issuer_signature: MessageField::some(pb::Signature {
            verification_key: MessageField::some(key("did:example:issuer#key-1", 4)),
            raw_rs: vec![5; 64],
            ..Default::default()
        }),
        tree: MessageField::some(pb::MerkleTreeInfo {
            depth: 1,
            count: 1,
            ..Default::default()
        }),
        claims: vec![pb::ClaimOpening {
            claim_path: "/claims/name".to_owned(),
            salt: vec![6; 16],
            value: b"private".to_vec(),
            index: 0,
            merkle_path: vec![vec![7; 32]],
            ..Default::default()
        }],
        ..Default::default()
    };

    zeroize_subject_private_bundle(&mut bundle);

    assert!(bundle.holder_key.as_option().is_none());
    assert!(bundle.envelope_hash.is_empty());
    assert!(bundle.issuer_signature.as_option().is_none());
    assert!(bundle.tree.as_option().is_none());
    assert!(bundle.claims.is_empty());
}
