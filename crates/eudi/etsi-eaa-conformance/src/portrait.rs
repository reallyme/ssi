// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{ConformanceError, Result};

const MAX_DISCLOSURE_IDENTIFIER_BYTES: usize = 256;

/// Transaction-specific portrait disclosure request.
///
/// Construction rejects empty, unbounded, or control-bearing identifiers so a
/// confirmation cannot be detached from a concrete relying party transaction.
pub struct PortraitDisclosureRequest<'a> {
    relying_party_id: &'a str,
    transaction_id: &'a str,
}

impl<'a> PortraitDisclosureRequest<'a> {
    /// Construct a request bound to one relying party and transaction.
    pub fn new(relying_party_id: &'a str, transaction_id: &'a str) -> Result<Self> {
        if valid_identifier(relying_party_id) && valid_identifier(transaction_id) {
            Ok(Self {
                relying_party_id,
                transaction_id,
            })
        } else {
            Err(ConformanceError::InvalidPortraitConfirmation)
        }
    }
}

/// User decision made after the portrait-specific warning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortraitDisclosureDecision {
    /// The user explicitly confirms this relying party transaction.
    Confirmed,
    /// The user declines portrait disclosure.
    Rejected,
}

/// Events accepted by the portrait disclosure gate.
pub enum PortraitDisclosureEvent<'a> {
    /// The mandatory portrait-specific warning was displayed to the user.
    WarningDisplayed,
    /// A decision was collected for the named relying party transaction.
    Decision {
        /// Relying-party identifier shown during confirmation.
        relying_party_id: &'a str,
        /// Transaction identifier shown during confirmation.
        transaction_id: &'a str,
        /// Explicit user decision.
        decision: PortraitDisclosureDecision,
    },
    /// The wallet is about to release the portrait.
    Disclose,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DisclosureState {
    WarningRequired,
    ConfirmationRequired,
    Authorized,
    Rejected,
    Disclosed,
}

/// Stateful enforcement of CIR (EU) 2024/2977 portrait warning and consent.
///
/// The gate is intentionally non-cloneable. One instance authorizes at most one
/// disclosure for exactly the request supplied at construction.
pub struct PortraitDisclosureGate<'a> {
    request: PortraitDisclosureRequest<'a>,
    state: DisclosureState,
}

impl<'a> PortraitDisclosureGate<'a> {
    /// Create a gate that initially requires the portrait warning.
    #[must_use]
    pub const fn new(request: PortraitDisclosureRequest<'a>) -> Self {
        Self {
            request,
            state: DisclosureState::WarningRequired,
        }
    }

    /// Apply the next wallet UI event.
    ///
    /// `Ok(true)` is returned only when the single authorized disclosure event
    /// is consumed. All earlier events return `Ok(false)`.
    pub fn apply(&mut self, event: PortraitDisclosureEvent<'_>) -> Result<bool> {
        match (self.state, event) {
            (DisclosureState::WarningRequired, PortraitDisclosureEvent::WarningDisplayed) => {
                self.state = DisclosureState::ConfirmationRequired;
                Ok(false)
            }
            (
                DisclosureState::ConfirmationRequired,
                PortraitDisclosureEvent::Decision {
                    relying_party_id,
                    transaction_id,
                    decision,
                },
            ) => {
                if relying_party_id != self.request.relying_party_id
                    || transaction_id != self.request.transaction_id
                {
                    return Err(ConformanceError::InvalidPortraitConfirmation);
                }
                self.state = match decision {
                    PortraitDisclosureDecision::Confirmed => DisclosureState::Authorized,
                    PortraitDisclosureDecision::Rejected => DisclosureState::Rejected,
                };
                Ok(false)
            }
            (DisclosureState::Authorized, PortraitDisclosureEvent::Disclose) => {
                self.state = DisclosureState::Disclosed;
                Ok(true)
            }
            (DisclosureState::WarningRequired, PortraitDisclosureEvent::Disclose) => {
                Err(ConformanceError::PortraitWarningRequired)
            }
            (DisclosureState::ConfirmationRequired, PortraitDisclosureEvent::Disclose) => {
                Err(ConformanceError::PortraitConfirmationRequired)
            }
            (DisclosureState::Rejected, PortraitDisclosureEvent::Disclose)
            | (DisclosureState::Disclosed, PortraitDisclosureEvent::Disclose) => {
                Err(ConformanceError::PortraitDisclosureDenied)
            }
            _ => Err(ConformanceError::InvalidPortraitConfirmation),
        }
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DISCLOSURE_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
