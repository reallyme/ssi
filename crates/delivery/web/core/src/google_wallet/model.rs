// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Minimal Google Wallet object model (Generic-style).
///
/// This is intentionally small and stable.
/// Extend with additional fields as more Google Wallet capabilities are supported.
#[derive(Serialize, Deserialize)]
pub struct GoogleWalletObject {
    /// Google Wallet object identifier.
    pub id: String,
    /// Google Wallet class identifier.
    pub class_id: String,
    /// Wallet object lifecycle state.
    pub state: String,

    /// Object header shown by wallet surfaces.
    pub header: Header,

    /// Optional text modules attached to the object.
    #[serde(default)]
    pub text_modules: Vec<TextModule>,
}

impl fmt::Debug for GoogleWalletObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GoogleWalletObject([REDACTED])")
    }
}

impl Zeroize for GoogleWalletObject {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.class_id.zeroize();
        self.state.zeroize();
        self.header.zeroize();
        for module in &mut self.text_modules {
            module.zeroize();
        }
        self.text_modules.clear();
    }
}

impl Drop for GoogleWalletObject {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for GoogleWalletObject {}

/// Header text shown for a Google Wallet object.
#[derive(Serialize, Deserialize)]
pub struct Header {
    /// Primary title.
    pub title: String,
    /// Optional subtitle.
    pub subtitle: Option<String>,
}

impl fmt::Debug for Header {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Header([REDACTED])")
    }
}

impl Zeroize for Header {
    fn zeroize(&mut self) {
        self.title.zeroize();
        self.subtitle.zeroize();
    }
}

impl Drop for Header {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Header {}

/// Text module attached to a Google Wallet object.
#[derive(Serialize, Deserialize)]
pub struct TextModule {
    /// Module identifier.
    pub id: String,
    /// Module heading.
    pub header: String,
    /// Module body text.
    pub body: String,
}

impl fmt::Debug for TextModule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TextModule([REDACTED])")
    }
}

impl Zeroize for TextModule {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.header.zeroize();
        self.body.zeroize();
    }
}

impl Drop for TextModule {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for TextModule {}
