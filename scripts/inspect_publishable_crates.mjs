#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const approvedPublicPackages = new Set([
  "reallyme-mdoc",
  "reallyme-sd-jwt",
  "reallyme-trust-core",
  "reallyme-compression-brotli",
  "reallyme-credential-audit",
  "reallyme-credential-claims",
  "reallyme-credential-status",
  "reallyme-disclosure-policy",
  "reallyme-credential",
  "reallyme-ssi-core",
  "reallyme-did-types",
  "reallyme-ssi-proto",
  "reallyme-vp-core",
  "reallyme-openid-oauth",
  "reallyme-revocation",
  "reallyme-ssi-proto-codec",
  "reallyme-trust-x509",
]);
const requiredContractPackages = new Map([
  [
    "reallyme-ssi-proto",
    {
      manifestPath: "crates/proto/Cargo.toml",
      requiredEntries: [
        "proto/identity/audit/v1/audit.proto",
        "proto/identity/credential/v1/claims.proto",
        "proto/identity/credential/v1/credential.proto",
        "proto/identity/credential/v1/subject_bundle.proto",
        "proto/identity/did/me/v1/did_me.proto",
        "proto/identity/did/v1/did.proto",
        "proto/identity/presentation/v1/presentation.proto",
        "proto/identity/status/v1/status_list.proto",
        "proto/identity/trust/v1/trust.proto",
        "proto/reallyme/identity/common/v1/errors.proto",
        "proto/reallyme/identity_core/v1/errors.proto",
      ],
    },
  ],
]);

const fail = (message) => {
  console.error(`publishable crate inspection failed: ${message}`);
  process.exit(1);
};

const readText = (path) => readFileSync(resolve(root, path), "utf8");

const findCargoManifests = (relativeDir) => {
  const absoluteDir = resolve(root, relativeDir);
  if (!existsSync(absoluteDir)) {
    return [];
  }

  const manifests = [];
  for (const entry of readdirSync(absoluteDir)) {
    const relativeEntry = `${relativeDir}/${entry}`;
    const absoluteEntry = resolve(root, relativeEntry);
    if (statSync(absoluteEntry).isDirectory()) {
      manifests.push(...findCargoManifests(relativeEntry));
    } else if (entry === "Cargo.toml") {
      manifests.push(relativeEntry);
    }
  }

  return manifests;
};

const parsePackageName = (manifestPath) => {
  const match = readText(manifestPath).match(/^name = "([^"]+)"$/m);
  if (!match) {
    fail(`${manifestPath} is missing a package name`);
  }
  return match[1];
};

const isPublishable = (manifestPath) =>
  /^publish = true$/m.test(readText(manifestPath));

// The repository root is intentionally a virtual workspace. Only member
// manifests can define packages or participate in publication policy.
const manifests = findCargoManifests("crates").sort();
const publishable = manifests
  .filter((manifestPath) => isPublishable(manifestPath))
  .map((manifestPath) => ({
    manifestPath,
    name: parsePackageName(manifestPath),
  }));

for (const crate of publishable) {
  if (!approvedPublicPackages.has(crate.name)) {
    fail(`${crate.name} is publishable but is not approved for this repository`);
  }
}

for (const name of approvedPublicPackages) {
  if (!publishable.some((crate) => crate.name === name)) {
    fail(`${name} is approved but not currently publishable`);
  }
}

for (const crate of publishable) {
  console.log(`checking package contents for ${crate.name}`);
  execFileSync(
    "cargo",
    [
      "package",
      "--manifest-path",
      crate.manifestPath,
      "--allow-dirty",
      "--list",
    ],
    {
      cwd: root,
      stdio: "inherit",
    },
  );
}

for (const [name, contractPackage] of requiredContractPackages) {
  console.log(`checking contract package contents for ${name}`);
  const output = execFileSync(
    "cargo",
    [
      "package",
      "--manifest-path",
      contractPackage.manifestPath,
      "--allow-dirty",
      "--list",
    ],
    {
      cwd: root,
      encoding: "utf8",
    },
  );
  const entries = new Set(output.split("\n").filter((entry) => entry.length > 0));
  for (const requiredEntry of contractPackage.requiredEntries) {
    if (!entries.has(requiredEntry)) {
      fail(`${name} package omits required contract artifact ${requiredEntry}`);
    }
  }
}

console.log(
  `package inspection passed for ${publishable.length} public and ${requiredContractPackages.size} contract crate(s)`,
);
