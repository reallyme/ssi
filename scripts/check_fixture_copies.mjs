#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readdirSync, readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const copies = [
  ["vectors/claims/catalog-sources.json", "crates/claims/tests/fixtures/catalog-sources.json"],
  ["vectors/claims/normalization.json", "crates/claims/tests/fixtures/normalization.json"],
  ["vectors/claims/predefined-credentials.json", "crates/claims/tests/fixtures/predefined-credentials.json"],
  ["vectors/manifest.json", "crates/claims/tests/fixtures/vector-manifest.json"],
  ["vectors/credential/canonical.json", "crates/credential/tests/fixtures/canonical.json"],
  ["vectors/mdoc-issuer-signed.json", "crates/envelopes/mdoc/tests/fixtures/mdoc-issuer-signed.json"],
  ["vectors/jwk-thumbprint.json", "crates/oauth/tests/fixtures/jwk-thumbprint.json"],
  ["vectors/status-list.json", "crates/status/tests/fixtures/status-list.json"],
  ["vectors/x509-trust-policy.json", "crates/trust/x509/tests/fixtures/package/x509-trust-policy.json"],
  ["crates/revocation/ocsp/openssl/tests/fixtures/leaf.der", "crates/envelopes/mdoc/src/fixtures/ocsp-leaf.der"],
  ["crates/revocation/ocsp/openssl/tests/fixtures/leaf.der", "crates/envelopes/mdoc/tests/fixtures/ocsp-leaf.der"],
  ["crates/revocation/ocsp/openssl/tests/fixtures/issuer.der", "crates/envelopes/mdoc/tests/fixtures/ocsp-issuer.der"],
  ["crates/revocation/ocsp/openssl/tests/fixtures/root.der", "crates/envelopes/mdoc/tests/fixtures/ocsp-root.der"],
];

const fail = (canonical, copy) => {
  process.stderr.write(
    `fixture copy drift: ${copy} must be regenerated from ${canonical}\n`,
  );
  process.exitCode = 1;
};

const treeFiles = (directory) =>
  readdirSync(resolve(root, directory), { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) =>
      relative(resolve(root, directory), resolve(entry.parentPath, entry.name)).replaceAll(
        "\\",
        "/",
      ),
    )
    .sort();

for (const name of ["ietf-sd-jwt", "sd-jwt-rfc9901"]) {
  const canonicalRoot = `vectors/${name}`;
  const copyRoot = `crates/envelopes/sd_jwt/tests/vectors/${name}`;
  const canonicalFiles = treeFiles(canonicalRoot);
  const copyFiles = treeFiles(copyRoot);
  if (canonicalFiles.join("\0") !== copyFiles.join("\0")) {
    fail(canonicalRoot, copyRoot);
    continue;
  }
  for (const path of canonicalFiles) {
    copies.push([`${canonicalRoot}/${path}`, `${copyRoot}/${path}`]);
  }
}

for (const [canonical, copy] of copies) {
  const canonicalBytes = readFileSync(resolve(root, canonical));
  const copyBytes = readFileSync(resolve(root, copy));
  if (!canonicalBytes.equals(copyBytes)) {
    fail(canonical, copy);
  }
}

if (process.exitCode !== 1) {
  process.stdout.write(`verified ${copies.length} fixture copies\n`);
}
