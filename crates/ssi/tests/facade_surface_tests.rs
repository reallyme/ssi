// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.

fn assert_type_is_reachable<T>() {
    let _ = core::any::type_name::<T>();
}

#[test]
fn ssi_facade_exposes_composable_identity_surfaces() {
    assert_type_is_reachable::<reallyme_ssi::audit::core::QeaaCompliance>();
    assert_type_is_reachable::<
        reallyme_ssi::audit::proto::generated::proto::identity::audit::v1::QeaaCompliance,
    >();

    assert_type_is_reachable::<reallyme_ssi::claims::core::ClaimsRegistry>();
    assert_type_is_reachable::<
        reallyme_ssi::claims::proto::generated::proto::identity::credential::v1::ClaimsRegistry,
    >();

    assert_type_is_reachable::<
        reallyme_ssi::common::proto::generated::proto::reallyme::identity::common::v1::IdentityStackError,
    >();

    assert_type_is_reachable::<reallyme_ssi::credential::CredentialEnvelope>();
    assert_type_is_reachable::<reallyme_ssi::credential::api::IssueCredentialRequest>();
    assert_type_is_reachable::<reallyme_ssi::credential::committed::model::CredentialEnvelope>();

    assert_type_is_reachable::<reallyme_ssi::delivery::core::DeliveryEnvelope>();
    assert_type_is_reachable::<reallyme_ssi::delivery::contact::api::BuildContactMessageInput>();
    assert_type_is_reachable::<reallyme_ssi::delivery::contact::core::ContactFrame>();
    assert_type_is_reachable::<reallyme_ssi::delivery::contact::validator::ValidatedContactEnvelope>(
    );
    assert_type_is_reachable::<reallyme_ssi::delivery::siop::api::SiopAuthenticationRequest>();
    assert_type_is_reachable::<reallyme_ssi::delivery::siop::core::SiopAuthenticationRequest>();
    assert_type_is_reachable::<reallyme_ssi::delivery::siop::verifier::VerifiedSiopIdToken>();
    assert_type_is_reachable::<reallyme_ssi::delivery::web::core::QrPayload>();
    assert_type_is_reachable::<reallyme_ssi::delivery::web::validator::WebValidationInput<'static>>(
    );

    assert_type_is_reachable::<reallyme_ssi::did::api::CreateConfig>();
    assert_type_is_reachable::<reallyme_ssi::did::core::DidCore>();
    assert_type_is_reachable::<
        reallyme_ssi::did::generated_proto::generated::proto::identity::did::me::v1::DidMeRecord,
    >();
    assert_type_is_reachable::<reallyme_ssi::did::types::DIDDocument>();
    assert_type_is_reachable::<reallyme_ssi::did::methods::cheqd::CheqdDidIdentifier<'static>>();
    assert_type_is_reachable::<reallyme_ssi::did::methods::ebsi::EbsiDidIdentifier>();
    assert_type_is_reachable::<reallyme_ssi::did::methods::ion::IonDidIdentifier<'static>>();
    assert_type_is_reachable::<reallyme_ssi::did::methods::jwk::DidJwkIdentifier>();
    assert_type_is_reachable::<reallyme_ssi::did::methods::key::DidKeyIdentifier>();
    assert_type_is_reachable::<reallyme_ssi::did::methods::me::DidMeIdentifier>();
    assert_type_is_reachable::<reallyme_ssi::did::methods::web::WebDidInput<'static>>();

    assert_type_is_reachable::<
        reallyme_ssi::identity_core::proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason,
    >();
    assert_type_is_reachable::<reallyme_ssi::keys::KeySet>();
    assert_type_is_reachable::<reallyme_ssi::oauth::ParRequest>();
    assert_type_is_reachable::<reallyme_ssi::profiles::Profile>();
    assert_type_is_reachable::<reallyme_ssi::revocation::RevocationSource>();
    assert_type_is_reachable::<reallyme_ssi::single_use::InMemorySingleUseStore>();
    assert_type_is_reachable::<reallyme_ssi::status::core::StatusList>();
    assert_type_is_reachable::<
        reallyme_ssi::status::proto::generated::proto::identity::status::v1::StatusList,
    >();

    assert_type_is_reachable::<reallyme_ssi::trust::api::TrustDecision>();
    assert_type_is_reachable::<reallyme_ssi::trust::core::TrustConfig>();
    assert_type_is_reachable::<
        reallyme_ssi::trust::proto::generated::proto::identity::trust::v1::TrustDecision,
    >();
    assert_type_is_reachable::<reallyme_ssi::trust::wasm::WasmSignatureVerifier>();
    assert_type_is_reachable::<reallyme_ssi::trust::x509::X509Certificate>();

    assert_type_is_reachable::<reallyme_ssi::presentation::api::VpVerificationReport>();
    assert_type_is_reachable::<reallyme_ssi::presentation::core::Presentation>();
    assert_type_is_reachable::<reallyme_ssi::presentation::policy::VpPolicy>();
    assert_type_is_reachable::<
        reallyme_ssi::presentation::generated_proto::generated::proto::identity::presentation::v1::Presentation,
    >();
    assert_type_is_reachable::<reallyme_ssi::presentation::sd_jwt::VerifiedDisclosure>();
    assert_type_is_reachable::<reallyme_ssi::presentation::validator::VpValidationInput<'static>>();
}
