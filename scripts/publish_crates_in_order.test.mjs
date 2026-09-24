// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const script = fileURLToPath(new URL("./publish_crates_in_order.mjs", import.meta.url));

function runFixture({ mode = "publish", scenario = "success", requirement = "^0.1.0", version = "0.1.0" } = {}) {
  const directory = mkdtempSync(join(tmpdir(), "ssi-publish-test-"));
  try {
    const callsPath = join(directory, "calls.json");
    const preload = join(directory, "mock.mjs");
    // Intercept every child process: these tests must never invoke Cargo,
    // access a registry, publish a crate, or perform real retry waits.
    writeFileSync(preload, `
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { writeFileSync } from "node:fs";
const calls = [];
const scenario = ${JSON.stringify(scenario)};
let attempts = 0;
Atomics.wait = (_array, _index, _value, delay) => {
  calls.push(["wait", delay]);
  writeFileSync(${JSON.stringify(callsPath)}, JSON.stringify(calls));
  return "timed-out";
};
childProcess.spawnSync = (command, args) => {
  calls.push([command, ...args]);
  writeFileSync(${JSON.stringify(callsPath)}, JSON.stringify(calls));
  const ok = { status: 0, stdout: "", stderr: "" };
  if (command !== "cargo") return { ...ok, status: 99 };
  if (args[0] === "metadata") return { ...ok, stdout: JSON.stringify({
    target_directory: ${JSON.stringify(directory)},
    packages: [
      { name: "reallyme-ssi-proto-codec", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [
          { name: "reallyme-compression-brotli", source: null, path: "crates/compression/brotli", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-ssi-core", source: null, path: "crates/did/core/common", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-did-types", source: null, path: "crates/did/core/types", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-vp-core", source: null, path: "crates/presentation/core", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-ssi-proto", source: null, path: "crates/proto", kind: null, req: ${JSON.stringify(requirement)} },
        ] },
      { name: "reallyme-compression-brotli", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [] },
      { name: "reallyme-ssi-core", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-ssi-proto", source: null, path: "crates/proto", kind: null, req: ${JSON.stringify(requirement)} }] },
      { name: "reallyme-did-types", version: ${JSON.stringify(version)}, publish: null, dependencies: [] },
      { name: "reallyme-vp-core", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-ssi-proto", source: null, path: "crates/proto", kind: null, req: ${JSON.stringify(requirement)} }] },
      { name: "reallyme-ssi-proto", version: ${JSON.stringify(version)}, publish: null, dependencies: [] },
      { name: "reallyme-trust-x509", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-ssi-proto", source: null, path: "crates/proto", kind: null, req: ${JSON.stringify(requirement)} }] },
      { name: "reallyme-credential-status", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-ssi-proto", source: null, path: "crates/proto", kind: null, req: ${JSON.stringify(requirement)} }] },
      { name: "reallyme-credential-audit", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-ssi-proto", source: null, path: "crates/proto", kind: null, req: ${JSON.stringify(requirement)} }] },
      { name: "reallyme-credential-claims", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [
          { name: "reallyme-ssi-proto", source: null, path: "crates/proto", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-trust-x509", source: null, path: "crates/trust/x509", kind: null, req: ${JSON.stringify(requirement)} },
        ] },
      { name: "reallyme-revocation", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [
          { name: "reallyme-credential-status", source: null, path: "crates/status", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-ssi-proto", source: null, path: "crates/proto", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-trust-x509", source: null, path: "crates/trust/x509", kind: null, req: ${JSON.stringify(requirement)} },
        ] },
      { name: "reallyme-trust-core", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [
          { name: "reallyme-ssi-proto", source: null, path: "crates/proto", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-revocation", source: null, path: "crates/revocation", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-trust-x509", source: null, path: "crates/trust/x509", kind: null, req: ${JSON.stringify(requirement)} },
        ] },
      { name: "reallyme-openid-oauth", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [
          { name: "reallyme-trust-core", source: null, path: "crates/trust/core", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-ssi-proto", source: null, path: "crates/proto", kind: null, req: ${JSON.stringify(requirement)} },
        ] },
      { name: "reallyme-disclosure-policy", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [
          { name: "reallyme-credential-claims", source: null, path: "crates/claims", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-ssi-core", source: null, path: "crates/did/core/common", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-ssi-proto", source: null, path: "crates/proto", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-vp-core", source: null, path: "crates/presentation/core", kind: null, req: ${JSON.stringify(requirement)} },
        ] },
      { name: "reallyme-credential", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [
          { name: "reallyme-credential-audit", source: null, path: "crates/audit", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-credential-claims", source: null, path: "crates/claims", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-credential-status", source: null, path: "crates/status", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-ssi-proto", source: null, path: "crates/proto", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-revocation", source: null, path: "crates/revocation", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-trust-x509", source: null, path: "crates/trust/x509", kind: null, req: ${JSON.stringify(requirement)} },
        ] },
      { name: "reallyme-mdoc", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [
          { name: "reallyme-ssi-proto", source: null, path: "crates/proto", kind: null, req: ${JSON.stringify(requirement)} },
          { name: "reallyme-credential-claims", source: null, path: "crates/claims", kind: "dev", req: ${JSON.stringify(requirement)} },
          { name: "reallyme-trust-x509", source: null, path: "crates/trust/x509", kind: "dev", req: ${JSON.stringify(requirement)} },
        ] },
      { name: "reallyme-sd-jwt", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-ssi-proto", source: null, path: "crates/proto", kind: null, req: ${JSON.stringify(requirement)} }] },
      { name: "reallyme-ssi", version: ${JSON.stringify(version)}, publish: [], dependencies: [] },
    ],
  }) };
  if (args[0] === "package") return ok;
  if (args[0] !== "publish") return { ...ok, status: 99 };
  attempts += 1;
  if (scenario === "exhausted" || (scenario === "retry" && attempts === 1)) {
    return { ...ok, status: 101, stderr: "too many requests" };
  }
  if (scenario === "http-429" && attempts === 1) {
    return { ...ok, status: 101, stderr: "HTTP status 429: rate limit exceeded" };
  }
  if (scenario === "index-lag" && attempts === 1) {
    return {
      ...ok,
      status: 101,
      stderr: 'failed to select a version for the requirement \`reallyme-compression-brotli = "=0.1.0"\`',
    };
  }
  if (scenario === "failure") return { ...ok, status: 101, stderr: "package verification failed" };
  return ok;
};
syncBuiltinESMExports();
`);
    const result = spawnSync(process.execPath, ["--import", pathToFileURL(preload).href, script, mode], {
      cwd: directory,
      encoding: "utf8",
      timeout: 10_000,
      env: { ...process.env, RELEASE_VERSION: version },
    });
    assert.equal(result.error, undefined);
    return { ...result, calls: JSON.parse(readFileSync(callsPath, "utf8")) };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("successful publication respects dependency order", () => {
  const result = runFixture();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[1] === "publish").map((call) => call[3]),
    [
      "reallyme-compression-brotli",
      "reallyme-ssi-proto",
      "reallyme-ssi-core",
      "reallyme-did-types",
      "reallyme-vp-core",
      "reallyme-ssi-proto-codec",
      "reallyme-trust-x509",
      "reallyme-credential-status",
      "reallyme-credential-audit",
      "reallyme-credential-claims",
      "reallyme-revocation",
      "reallyme-trust-core",
      "reallyme-openid-oauth",
      "reallyme-disclosure-policy",
      "reallyme-credential",
      "reallyme-mdoc",
      "reallyme-sd-jwt",
    ]);
});

test("rate-limit exhaustion fails without publishing dependent crates", () => {
  const result = runFixture({ scenario: "exhausted" });
  assert.equal(result.status, 101);
  const publishes = result.calls.filter((call) => call[1] === "publish");
  assert.equal(publishes.length, 12);
  assert.ok(publishes.every((call) => call[3] === "reallyme-compression-brotli"));
  assert.equal(result.calls.filter((call) => call[0] === "wait").length, 11);
});

test("transient rate limits retry before publishing dependent crates", () => {
  const result = runFixture({ scenario: "retry" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[0] === "wait"), [["wait", 60000]]);
});

test("HTTP 429 responses retry before publishing dependent crates", () => {
  const result = runFixture({ scenario: "http-429" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[0] === "wait"), [["wait", 60000]]);
});

test("exact-version registry index lag retries before publishing dependent crates", () => {
  const result = runFixture({ scenario: "index-lag" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[0] === "wait"), [["wait", 15000]]);
});

test("non-retryable publication errors fail immediately", () => {
  const result = runFixture({ scenario: "failure" });
  assert.equal(result.status, 101);
  assert.equal(result.calls.filter((call) => call[1] === "publish").length, 1);
  assert.equal(result.calls.filter((call) => call[0] === "wait").length, 0);
});

test("zero-major caret requirements match Cargo compatibility boundaries", () => {
  for (const [requirement, version, accepted] of [
    ["^0.0.1", "0.0.1", true],
    ["^0.0.1", "0.0.2", false],
    ["^0.2.1", "0.2.2", true],
    ["^0.2.2", "0.3.0", false],
    ["^0.2.1junk", "0.2.2", false],
  ]) {
    const result = runFixture({ mode: "order", requirement, version });
    assert.equal(result.status === 0, accepted, `${requirement} / ${version}`);
    assert.ok(result.calls.every((call) => call[1] === "metadata"));
  }
});
