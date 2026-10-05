// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { publicReleaseGraphFailures } from "./public_release_graph_core.mjs";

const registry = "registry+https://github.com/rust-lang/crates.io-index";
const releasedPeer = (name, dependencies = []) => ({
  name,
  version: "0.4.1",
  publish: null,
  dependencies,
});
const dependency = (name, req = "=0.4.1") => ({
  name,
  req,
  source: null,
  path: `/workspace/${name}`,
});
const fixture = () => ({
  packages: [
    releasedPeer("reallyme-credential", [dependency("reallyme-trust-x509", "^0.4.1")]),
    releasedPeer("reallyme-trust-x509"),
    releasedPeer("reallyme-trust-core", [dependency("reallyme-trust-x509", "^0.4.1")]),
    releasedPeer("reallyme-revocation"),
    releasedPeer("reallyme-ssi-proto"),
    {
      name: "reallyme-trust",
      version: "0.4.1",
      publish: null,
      dependencies: [
        dependency("reallyme-trust-x509"),
        dependency("reallyme-trust-core"),
        dependency("reallyme-revocation"),
        dependency("reallyme-ssi-proto"),
      ],
    },
  ],
});
test("accepts a unified public SSI release", () => {
  assert.deepEqual(publicReleaseGraphFailures(fixture()), []);
});

test("rejects a facade-only patch unsupported by the release workflow", () => {
  const graph = fixture();
  graph.packages.at(-1).version = "0.4.2";
  assert.match(publicReleaseGraphFailures(graph).join("; "), /trust facade must share/u);
});

test("rejects a released peer in a unified workspace release", () => {
  const graph = fixture();
  graph.packages.at(-1).dependencies[0].source = registry;
  graph.packages.at(-1).dependencies[0].path = null;
  assert.match(publicReleaseGraphFailures(graph).join("; "), /workspace reallyme-trust-x509/u);
});

test("rejects a registry copy in a private workspace crate", () => {
  const graph = fixture();
  graph.packages.push({
    name: "identity-credential-trust-api",
    version: "0.4.1",
    publish: [],
    dependencies: [{ ...dependency("reallyme-trust-core"), source: registry, path: null }],
  });
  assert.match(publicReleaseGraphFailures(graph).join("; "), /identity-credential-trust-api must consume the 0\.4\.1 workspace reallyme-trust-core/u);
});

test("rejects the stale 0.4.0 facade pin that escaped the 0.4.1 release", () => {
  const graph = fixture();
  graph.packages.at(-1).dependencies[0].req = "=0.4.0";
  assert.match(publicReleaseGraphFailures(graph).join("; "), /reallyme-trust-x509.*0\.4\.0/u);
});

test("rejects stale pins in other public SSI packages", () => {
  const graph = fixture();
  graph.packages[0].dependencies[0].req = "^0.4.0";
  assert.match(publicReleaseGraphFailures(graph).join("; "), /reallyme-credential.*0\.4\.0/u);
});

test("rejects stale public-package pins from source-only SSI crates", () => {
  const graph = fixture();
  graph.packages.push({
    name: "identity-credential-trust-api",
    version: "0.4.1",
    publish: [],
    dependencies: [dependency("reallyme-trust-core", "^0.4.0")],
  });
  assert.match(publicReleaseGraphFailures(graph).join("; "), /identity-credential-trust-api.*0\.4\.0/u);
});

test("rejects a local copy of a facade dependency", () => {
  const graph = fixture();
  graph.packages.at(-1).dependencies[0].source = registry;
  graph.packages.at(-1).dependencies[0].path = null;
  assert.match(publicReleaseGraphFailures(graph).join("; "), /workspace reallyme-trust-x509/u);
});

test("rejects a missing public facade dependency", () => {
  const graph = fixture();
  graph.packages.at(-1).dependencies.pop();
  assert.match(publicReleaseGraphFailures(graph).join("; "), /missing required public peer reallyme-ssi-proto/u);
});

test("rejects a version split among public SSI peer packages", () => {
  const graph = fixture();
  graph.packages[1].version = "0.4.0";
  assert.match(publicReleaseGraphFailures(graph).join("; "), /reallyme-trust-x509 is 0\.4\.0/u);
});
