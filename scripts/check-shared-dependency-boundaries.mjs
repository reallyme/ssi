#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const failures = [];

function read(path) {
  return readFileSync(resolve(root, path), "utf8");
}

function filesBelow(directory, predicate) {
  const result = [];
  const visit = (relative) => {
    for (const entry of readdirSync(resolve(root, relative))) {
      if ([".git", "target"].includes(entry)) {
        continue;
      }
      const path = relative === "." ? entry : `${relative}/${entry}`;
      const metadata = statSync(resolve(root, path));
      if (metadata.isDirectory()) {
        visit(path);
      } else if (predicate(path)) {
        result.push(path);
      }
    }
  };
  visit(directory);
  return result;
}

function requireText(path, needle) {
  if (!read(path).includes(needle)) {
    failures.push(`${path}: missing ${JSON.stringify(needle)}`);
  }
}

const forbiddenDirectDependencies = [
  "base64",
  "coset",
  "der-parser",
  "getrandom",
  "getrandom02",
  "k256",
  "num-bigint",
  "p256",
  "rand_core",
  "sha2",
];

const narrowlyOwnedDependencies = new Map([
  ["asn1-rs", new Set(["Cargo.toml", "crates/trust/x509/Cargo.toml"])],
  ["brotli", new Set(["Cargo.toml", "crates/compression/brotli/Cargo.toml"])],
  ["foreign-types", new Set(["crates/revocation/ocsp/openssl/Cargo.toml"])],
  ["oid-registry", new Set(["Cargo.toml", "crates/trust/x509/Cargo.toml"])],
  ["pem", new Set(["Cargo.toml", "crates/trust/x509/Cargo.toml"])],
  ["x509-parser", new Set(["Cargo.toml", "crates/trust/x509/Cargo.toml"])],
]);

// These ownership rules are the durable policy. Transitive version selection
// belongs to Cargo.lock and upstream manifests rather than a manually
// maintained public document that can drift from the resolved graph.

for (const manifest of filesBelow(".", (path) => path.endsWith("Cargo.toml"))) {
  const contents = read(manifest);
  for (const dependency of forbiddenDirectDependencies) {
    const pattern = new RegExp(`^${dependency}\\s*[.=]`, "mu");
    if (pattern.test(contents)) {
      failures.push(
        `${manifest}: ${dependency} must be consumed through reallyme/codec, crypto, cose, or jose`,
      );
    }
  }
  if (manifest !== "Cargo.toml" && /^thiserror\s*=\s*"/mu.test(contents)) {
    failures.push(`${manifest}: thiserror must inherit the audited workspace version`);
  }
  for (const [dependency, owners] of narrowlyOwnedDependencies) {
    const pattern = new RegExp(`^${dependency}\\s*[.=]`, "mu");
    if (pattern.test(contents) && !owners.has(manifest)) {
      failures.push(`${manifest}: ${dependency} is outside its narrow parser/backend owner`);
    }
  }
}

const forbiddenProductionImports = [
  /^use base64::/mu,
  /^use der_parser::/mu,
  /^use k256::/mu,
  /^use num_bigint::/mu,
  /^use p256::/mu,
  /^use rand_core::/mu,
  /^use sha2::/mu,
];

for (const source of filesBelow("crates", (path) => path.includes("/src/") && path.endsWith(".rs"))) {
  const contents = read(source);
  for (const pattern of forbiddenProductionImports) {
    if (pattern.test(contents)) {
      failures.push(`${source}: imports a primitive owned by a shared ReallyMe package`);
    }
  }
}

requireText("crates/trust/x509/src/signature.rs", "reallyme_crypto");
requireText("crates/trust/x509/src/signature.rs", "verify_rsa_pkcs1v15");
requireText("crates/trust/x509/src/signature.rs", "verify_p256_der_prehash");
requireText("crates/trust/wasm/src/verifier.rs", "verify_chain_signatures_pure_rust");
requireText("crates/envelopes/mdoc/Cargo.toml", "reallyme-cose");
requireText("crates/envelopes/jwt_vc/Cargo.toml", "reallyme-jose");
requireText("crates/envelopes/sd_jwt/Cargo.toml", "reallyme-jose");

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`shared dependency boundary check failed: ${failure}`);
  }
  process.exit(1);
}

console.log("shared dependency boundary checks passed");
