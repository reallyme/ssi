// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

const root = new URL("../", import.meta.url);
const identityPackages = [
  "reallyme-data-integrity",
  "reallyme-vp-policy",
  "reallyme-did-core",
  "reallyme-did-method-cheqd",
  "reallyme-did-method-jwk",
  "reallyme-did-method-ebsi",
  "reallyme-did-method-ion",
  "reallyme-did-method-key",
  "reallyme-did-method-me",
  "reallyme-did-method-web",
  "reallyme-keys",
  "reallyme-did-api",
  "reallyme-vp-api",
];
const metadata = JSON.parse(execFileSync(
  "cargo", ["metadata", "--locked", "--no-deps", "--format-version", "1"],
  { cwd: root, encoding: "utf8" },
));
const byName = new Map(metadata.packages.map((pkg) => [pkg.name, pkg]));
const publicPackages = metadata.packages.filter((pkg) => pkg.publish === null);

test("the thirteen Identity dependencies join the public release without a version split", () => {
  assert.equal(publicPackages.length, 33);
  for (const pkg of publicPackages) {
    assert.ok(pkg.name.startsWith("reallyme-"), pkg.name);
    assert.equal(pkg.version, "0.6.2", pkg.name);
  }
  for (const pkg of metadata.packages) {
    assert.equal(pkg.version, "0.6.2", pkg.name);
  }
  const version = byName.get("reallyme-credential").version;
  for (const name of identityPackages) {
    const pkg = byName.get(name);
    assert.ok(pkg, name);
    assert.equal(pkg.publish, null, name);
    assert.equal(pkg.version, version, name);
  }
  for (const name of ["identity-trust-jades", "reallyme-eudi-rp-registration", "reallyme-ssi"]) {
    assert.deepEqual(byName.get(name).publish, [], name);
  }
});

test("all public dependencies precede their consumers", () => {
  const output = execFileSync(process.execPath, ["scripts/publish_crates_in_order.mjs", "order"], {
    cwd: root, encoding: "utf8",
  });
  const ordered = [...output.matchAll(/^- (\S+) \S+$/gmu)].map((match) => match[1]);
  assert.equal(ordered.length, publicPackages.length);
  assert.deepEqual(ordered.filter((name) => identityPackages.includes(name)).sort(), [...identityPackages].sort());
  const positions = new Map(ordered.map((name, index) => [name, index]));
  for (const pkg of publicPackages) {
    for (const dependency of pkg.dependencies) {
      if (dependency.path == null || !positions.has(dependency.name)) continue;
      assert.ok(positions.get(dependency.name) < positions.get(pkg.name),
        `${dependency.name} before ${pkg.name}`);
    }
  }
});

test("release archive verification requires the complete approved public set", () => {
  const workflow = readFileSync(new URL(".github/workflows/crates-release.yml", root), "utf8");
  const count = /test "\$archive_count" -eq ([0-9]+)/u.exec(workflow);
  assert.ok(count);
  assert.equal(Number(count[1]), publicPackages.length);
  assert.match(workflow, /for \(const crate of ledger\.crates\)/u);
});

test("manual publication instructions cover the full current release in dependency order", () => {
  const instructions = readFileSync(new URL("docs/CRATES_RELEASE.md", root), "utf8");
  const loop = /for package in \\\n([\s\S]+?)\n  do/u.exec(instructions);
  assert.ok(loop);
  const packages = loop[1].split("\n").map((line) => line.replace(/\\$/u, "").trim());
  assert.deepEqual([...packages].sort(), publicPackages.map((pkg) => pkg.name).sort());
  const positions = new Map(packages.map((name, index) => [name, index]));
  for (const pkg of publicPackages) {
    for (const dependency of pkg.dependencies) {
      if (dependency.path == null || !positions.has(dependency.name)) continue;
      assert.ok(positions.get(dependency.name) < positions.get(pkg.name),
        `${dependency.name} before ${pkg.name}`);
    }
  }
  assert.match(instructions, /RELEASE_VERSION=0\.6\.2/u);
  assert.match(instructions, /cargo publish --locked --registry crates-io -p "\$package"/u);
});

test("preflight uploads archives only for its certified release version", () => {
  const workflow = readFileSync(new URL(".github/workflows/crates-package-preflight.yml", root), "utf8");
  assert.ok(workflow.includes("target/package/*-${{ needs.verify-source-sha.outputs.release_version }}.crate"));
});
