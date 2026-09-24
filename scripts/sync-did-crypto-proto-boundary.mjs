#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { unlinkSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const identityRoot = dirname(scriptDir);
const generatedRoot = join(
  identityRoot,
  "crates/proto/src/generated/buffa",
);
const generatedMod = join(generatedRoot, "mod.rs");
const didOneof = join(
  generatedRoot,
  "identity.did.v1.did.__oneof.rs",
);
const cryptoGeneratedFiles = [
  "reallyme.crypto.v1.crypto.rs",
  "reallyme.crypto.v1.crypto.__oneof.rs",
  "reallyme.crypto.v1.crypto.__view.rs",
  "reallyme.crypto.v1.crypto.__view_oneof.rs",
  "reallyme.crypto.v1.mod.rs",
];
const cryptoReexport =
  "    pub use reallyme_crypto_proto::generated::proto::reallyme::crypto;\n";
const orphanExternalJwkConversion = `    impl From<super::super::super::super::super::super::reallyme::crypto::v1::JsonWebKey>
    for ::core::option::Option<PublicKey> {
        fn from(
            v: super::super::super::super::super::super::reallyme::crypto::v1::JsonWebKey,
        ) -> Self {
            Self::Some(PublicKey::from(v))
        }
    }
`;

for (const file of cryptoGeneratedFiles) {
  const path = join(generatedRoot, file);
  if (existsSync(path)) {
    unlinkSync(path);
  }
}

// Buffa emits this convenience conversion while JsonWebKey is generated into
// the same crate. Once the DID package reuses Crypto's package-owned binding,
// both the input type and Option target are external and Rust's coherence
// rules reject the implementation. PublicKey's direct conversion remains and
// callers can wrap it in Some explicitly.
const oneofSource = readFileSync(didOneof, "utf8");
if (oneofSource.includes(orphanExternalJwkConversion)) {
  writeFileSync(
    didOneof,
    oneofSource.replace(orphanExternalJwkConversion, ""),
  );
}

const source = readFileSync(generatedMod, "utf8");
if (source.includes(cryptoReexport)) {
  process.exit(0);
}

const reallyMeModule = "pub mod reallyme {\n";
if (!source.includes(reallyMeModule)) {
  process.exit(1);
}

writeFileSync(
  generatedMod,
  source.replace(reallyMeModule, `${reallyMeModule}${cryptoReexport}`),
);
