#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const failures = [];

function absolute(path) {
  return resolve(root, path);
}

function read(path) {
  return readFileSync(absolute(path), "utf8");
}

function requirePath(path) {
  if (!existsSync(absolute(path))) {
    failures.push(`${path}: required proto-first path is missing`);
  }
}

function rejectPath(path) {
  if (existsSync(absolute(path))) {
    failures.push(`${path}: forbidden legacy or misplaced path exists`);
  }
}

function requireText(path, needle) {
  if (!read(path).includes(needle)) {
    failures.push(`${path}: missing ${JSON.stringify(needle)}`);
  }
}

function requireTextBelow(directory, needle) {
  const sourceFiles = filesBelow(directory, (path) => path.endsWith(".rs"));
  if (!sourceFiles.some((path) => read(path).includes(needle))) {
    failures.push(`${directory}: missing ${JSON.stringify(needle)}`);
  }
}

function rejectText(path, needle) {
  if (read(path).includes(needle)) {
    failures.push(`${path}: contains forbidden ${JSON.stringify(needle)}`);
  }
}

function rejectPattern(path, pattern, description) {
  if (pattern.test(read(path))) {
    failures.push(`${path}: contains forbidden ${description}`);
  }
}

function requireMaximumLines(path, maximum) {
  const lineCount = read(path).split("\n").length;
  if (lineCount > maximum) {
    failures.push(`${path}: source has ${lineCount} lines; maximum is ${maximum}`);
  }
}

function filesBelow(directory, predicate) {
  const result = [];
  const visit = (relative) => {
    for (const entry of readdirSync(absolute(relative))) {
      const path = `${relative}/${entry}`;
      const metadata = statSync(absolute(path));
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

const schemaPackages = [
  "identity/audit/v1",
  "identity/credential/v1",
  "identity/did/me/v1",
  "identity/did/v1",
  "identity/eudi/v1",
  "identity/presentation/v1",
  "identity/status/v1",
  "identity/trust/v1",
  "reallyme/identity/common/v1",
  "reallyme/identity_core/v1",
];
const forbiddenCompatibilityCrates = [
  "crates/proto-audit",
  "crates/proto-common",
  "crates/proto-credential",
  "crates/proto-did",
  "crates/proto-identity-core",
  "crates/proto-presentation",
  "crates/proto-status",
  "crates/proto-trust",
];

requirePath("crates/ssi/Cargo.toml");
requirePath("crates/proto-codec/Cargo.toml");
requirePath("docs/ARCHITECTURE.md");
requireText("crates/ssi/Cargo.toml", 'name = "reallyme-ssi"');
requireText("crates/proto-codec/Cargo.toml", 'name = "reallyme-ssi-proto-codec"');
requireText("docs/ARCHITECTURE.md", "proto_layout: canonical");
requirePath("crates/proto/Cargo.toml");
rejectPath("crates/identity-core");
rejectPath("crates/vp");
rejectPath("crates/proto/identity-codec");
rejectPath("crates/did/core/proto");
rejectPath("crates/presentation/proto");

for (const packagePath of schemaPackages) {
  requirePath(`crates/proto/proto/${packagePath}`);
}
requirePath("crates/proto/src/generated.rs");
for (const cratePath of forbiddenCompatibilityCrates) {
  rejectPath(cratePath);
}

rejectPath("crates/proto/proto/reallyme/identity/v1");
rejectPath("crates/proto-codec/src/operation");
rejectPath("crates/dispatch");
rejectPath("crates/provider");
rejectPath("protos");
rejectPath("proto");
rejectPath("crates/proto-codec/vectors");
rejectPath("crates/proto/src/generated/connect");
rejectPath("packages/swift");
rejectPath("packages/kotlin");
rejectPath("packages/wasm");
rejectPath("bindings");
rejectPath("gen");
rejectPath("examples");

for (const proto of filesBelow(
  "crates/proto",
  (path) => path.includes("/proto/") && path.endsWith(".proto"),
)) {
  rejectPattern(proto, /^\s*(service|rpc)\s/m, "service declaration");
}

// One generated directory owns every SSI protobuf package. The external crypto
// package is referenced through its source crate and must never be regenerated
// into this repository.
const generatedPackagePrefixes = [
  "identity.audit.",
  "identity.credential.",
  "identity.did.",
  "identity.eudi.",
  "identity.presentation.",
  "identity.status.",
  "identity.trust.",
  "meid.did.",
  "reallyme.identity.",
  "reallyme.identity_core.",
];

for (const path of filesBelow(
  "crates/proto/src/generated/buffa",
  (candidate) => candidate.endsWith(".rs"),
)) {
  const fileName = path.slice(path.lastIndexOf("/") + 1);
  if (
    fileName !== "mod.rs" &&
    !generatedPackagePrefixes.some((prefix) => fileName.startsWith(prefix))
  ) {
    failures.push(`${path}: generated package is outside canonical proto ownership`);
  }
}

for (const manifest of [
  "Cargo.toml",
  "crates/proto/Cargo.toml",
  "crates/proto-codec/Cargo.toml",
]) {
  rejectText(manifest, "connectrpc");
}

requireText("buf.gen.yaml", "clean: true");
requireText("buf.gen.yaml", "strategy: all");
requireText("buf.gen.yaml", "views=true");
requireText("buf.gen.yaml", "json=true");
requireText("crates/proto/Cargo.toml", '"/proto/**/*.proto"');
requireText("crates/proto/Cargo.toml", '"/tests/**/*"');
rejectText("crates/proto/Cargo.toml", "reallyme-ssi-proto-codec");
rejectText("crates/proto/Cargo.toml", "reallyme-identity-dispatch");
requireText("crates/proto-codec/Cargo.toml", "reallyme-ssi-proto =");
requireMaximumLines("crates/proto-codec/src/lib.rs", 100);
for (const path of [
  ...filesBelow("crates/proto-codec/src", (candidate) => candidate.endsWith(".rs")),
]) {
  requireMaximumLines(path, 500);
}
rejectPattern(
  "crates/proto-codec/src/lib.rs",
  /^\s*(pub\s+)?(async\s+)?fn\s/m,
  "function implementation in thin crate root",
);
requireText("scripts/check-protos-fresh.sh", "git -C");
requireText("docs/ARCHITECTURE.md", "reallyme/identity");
requireText(
  "crates/ssi/tests/facade_surface_tests.rs",
  "generated::proto::reallyme::identity::common::v1::IdentityStackError",
);
requireText(
  "crates/ssi/tests/facade_surface_tests.rs",
  "generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason",
);
rejectText(
  "crates/ssi/tests/facade_surface_tests.rs",
  "generated::proto::reallyme_identity_core",
);

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`proto-first boundary check failed: ${failure}`);
  }
  process.exit(1);
}

console.log("proto-first boundary checks passed");
