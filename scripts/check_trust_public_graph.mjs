#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const facadeManifest = fileURLToPath(
  new URL("../crates/trust/facade/Cargo.toml", import.meta.url),
);
const workspaceRoot = fileURLToPath(new URL("../", import.meta.url));
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
const credential = metadata.packages.find(
  (pkg) =>
    pkg.name === "reallyme-credential" &&
    pkg.manifest_path.startsWith(workspaceRoot) &&
    pkg.publish === null,
);
if (credential === undefined) {
  fail("public credential peer is absent from the workspace graph");
}
const peerVersion = credential.version;
const sameRelease = facade.version === peerVersion;
const publicPeerNames = new Set(
  metadata.packages
    .filter(
      (pkg) =>
        pkg.manifest_path.startsWith(workspaceRoot) &&
        pkg.publish === null &&
        pkg.name !== facade.name,
    )
    .map((pkg) => pkg.name),
);

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
  if (pkg.id === facade.id) continue;
  if (publicPeerNames.has(pkg.name)) {
    const expectedLocal = sameRelease;
    const isLocal = pkg.manifest_path.startsWith(workspaceRoot) && pkg.source === null;
    if (isLocal !== expectedLocal) {
      fail(`${pkg.name} has the wrong source for the ${peerVersion} release graph`);
    }
  } else if (pkg.source === null && !pkg.manifest_path.startsWith(workspaceRoot)) {
    fail(`${pkg.name} comes from an unexpected local path`);
  }
}
for (const name of [
  "reallyme-trust-core",
  "reallyme-trust-x509",
  "reallyme-revocation",
  "reallyme-ssi-proto",
  "reallyme-credential-status",
]) {
  const matches = graph.filter((pkg) => pkg.name === name);
  if (matches.length !== 1 || matches[0].version !== peerVersion) {
    fail(`${name} does not resolve to one ${peerVersion} package`);
  }
}
for (const pkg of graph) {
  if (pkg.id !== facade.id && publicPeerNames.has(pkg.name) && pkg.version !== peerVersion) {
    fail(`${pkg.name} resolves outside the released ${peerVersion} peer graph`);
  }
}

console.log(`trust public graph contains one ${peerVersion} trust type graph`);
