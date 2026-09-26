// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;
use zeroize::Zeroize;

use crate::{RegistrationError, RegistrationErrorReason};

/// Closed ETSI TS 119 475 Annex A.2 WRP entitlement registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Zeroize)]
pub enum WrpEntitlement {
    /// General service provider.
    #[serde(rename = "https://uri.etsi.org/19475/Entitlement/Service_Provider")]
    ServiceProvider,
    /// Qualified EAA provider.
    #[serde(rename = "https://uri.etsi.org/19475/Entitlement/QEAA_Provider")]
    QualifiedEaaProvider,
    /// Non-qualified EAA provider.
    #[serde(rename = "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider")]
    NonQualifiedEaaProvider,
    /// Public-sector EAA provider.
    #[serde(rename = "https://uri.etsi.org/19475/Entitlement/PUB_EAA_Provider")]
    PublicSectorEaaProvider,
    /// Person-identification-data provider.
    #[serde(rename = "https://uri.etsi.org/19475/Entitlement/PID_Provider")]
    PidProvider,
    /// Qualified electronic-seal certificate provider.
    #[serde(rename = "https://uri.etsi.org/19475/Entitlement/QCert_for_ESeal_Provider")]
    QualifiedEsealCertificateProvider,
    /// Qualified electronic-signature certificate provider.
    #[serde(rename = "https://uri.etsi.org/19475/Entitlement/QCert_for_ESig_Provider")]
    QualifiedEsignatureCertificateProvider,
    /// Remote qualified electronic-seal creation-device provider.
    #[serde(rename = "https://uri.etsi.org/19475/Entitlement/rQSealCDs_Provider")]
    RemoteQualifiedEsealDeviceProvider,
    /// Remote qualified electronic-signature creation-device provider.
    #[serde(rename = "https://uri.etsi.org/19475/Entitlement/rQSigCDs_Provider")]
    RemoteQualifiedEsignatureDeviceProvider,
    /// Non-qualified remote electronic-signature or seal creation provider.
    #[serde(rename = "https://uri.etsi.org/19475/Entitlement/ESig_ESeal_Creation_Provider")]
    EsignatureEsealCreationProvider,
}

impl WrpEntitlement {
    pub(crate) fn parse(value: &str) -> Result<Self, RegistrationError> {
        match value {
            "https://uri.etsi.org/19475/Entitlement/Service_Provider" => Ok(Self::ServiceProvider),
            "https://uri.etsi.org/19475/Entitlement/QEAA_Provider" => {
                Ok(Self::QualifiedEaaProvider)
            }
            "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider" => {
                Ok(Self::NonQualifiedEaaProvider)
            }
            "https://uri.etsi.org/19475/Entitlement/PUB_EAA_Provider" => {
                Ok(Self::PublicSectorEaaProvider)
            }
            "https://uri.etsi.org/19475/Entitlement/PID_Provider" => Ok(Self::PidProvider),
            "https://uri.etsi.org/19475/Entitlement/QCert_for_ESeal_Provider" => {
                Ok(Self::QualifiedEsealCertificateProvider)
            }
            "https://uri.etsi.org/19475/Entitlement/QCert_for_ESig_Provider" => {
                Ok(Self::QualifiedEsignatureCertificateProvider)
            }
            "https://uri.etsi.org/19475/Entitlement/rQSealCDs_Provider" => {
                Ok(Self::RemoteQualifiedEsealDeviceProvider)
            }
            "https://uri.etsi.org/19475/Entitlement/rQSigCDs_Provider" => {
                Ok(Self::RemoteQualifiedEsignatureDeviceProvider)
            }
            "https://uri.etsi.org/19475/Entitlement/ESig_ESeal_Creation_Provider" => {
                Ok(Self::EsignatureEsealCreationProvider)
            }
            _ => Err(RegistrationError::from_reason(
                RegistrationErrorReason::InvalidField,
            )),
        }
    }

    pub(crate) const fn provides_wallet_attestations(self) -> bool {
        matches!(
            self,
            Self::QualifiedEaaProvider
                | Self::NonQualifiedEaaProvider
                | Self::PublicSectorEaaProvider
                | Self::PidProvider
        )
    }
}

/// Pinned registration protocol profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Zeroize)]
pub enum ProtocolProfile {
    /// EUDI TS5 registrar API v1.5.
    Ts5V1_5,
    /// Explicit compatibility profile for the pinned v0.2.2 reference service.
    EuReferenceLegacyV0_2_2,
}

/// Caller-selected authenticated payload shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub enum RegistryPayloadShape {
    /// Current `SignedWRPArray` response.
    Ts5SignedWrpArray,
    /// Current `SignedWRP` response.
    Ts5SignedWrp,
    /// Current signed intended-use-check response.
    Ts5SignedIntendedUseCheck,
    /// Explicit legacy raw WRP array.
    LegacyRawWrpArray,
    /// Explicit legacy raw WRP object.
    LegacyRawWrp,
    /// Explicit legacy raw Boolean.
    ///
    /// The legacy Boolean has no authenticated issuer, issue time, or query
    /// binding. Authentication parses it strictly and then always fails closed
    /// with [`crate::RegistrationErrorReason::UnboundLegacyAnswer`].
    LegacyRawBoolean,
}
