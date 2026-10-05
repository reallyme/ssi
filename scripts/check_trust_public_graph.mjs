#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const facadeManifest = fileURLToPath(
  new URL("../crates/trust/facade/Cargo.toml", import.meta.url),
);
const fail = (reason) => {
  console.error(`trust public graph check failed: ${reason}`);
  process.exit(1);
};

let metadata;
try {
  metadata = JSON.parse(
    execFileSync("cargo", ["metadata", "--locked", "--all-features", "--format-version", "1"], {
      encoding: "utf8",
      maxBuffer: 32_000_000,
      stdio: ["ignore", "pipe", "inherit"],
    }),
  );
} catch {
  fail("cargo metadata could not resolve the locked package graph");
}

const packages = new Map(metadata.packages.map((pkg) => [pkg.id, pkg]));
const nodes = new Map(metadata.resolve.nodes.map((node) => [node.id, node]));
const facade = metadata.packages.find(
  (pkg) => pkg.name === "reallyme-trust" && pkg.manifest_path === facadeManifest,
);
if (facade === undefined) {
  fail("public facade is absent from the workspace graph");
}

const visited = new Set();
const pending = [facade.id];
while (pending.length !== 0) {
  const id = pending.pop();
  if (visited.has(id)) continue;
  visited.add(id);
  const node = nodes.get(id);
  if (node === undefined) fail("resolved dependency node is missing");
  for (const dependency of node.deps) {
    if (dependency.dep_kinds.some((kind) => kind.kind !== "dev")) {
      pending.push(dependency.pkg);
    }
  }
}

const graph = [...visited].map((id) => packages.get(id));
if (graph.some((pkg) => pkg === undefined)) {
  fail("resolved package metadata is missing");
}
for (const pkg of graph) {
  if (pkg.id !== facade.id && !pkg.source?.startsWith("registry+")) {
    fail(`${pkg.name} is not registry sourced`);
  }
}
for (const name of ["reallyme-trust-core", "reallyme-trust-x509"]) {
  const matches = graph.filter((pkg) => pkg.name === name);
  if (matches.length !== 1 || matches[0].version !== "0.4.0") {
    fail(`${name} does not resolve to one released 0.4.0 package`);
  }
}

console.log("trust public graph contains one registry-sourced trust core and X.509 type");
