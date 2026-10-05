// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const script = fileURLToPath(new URL("./publish_crates_in_order.mjs", import.meta.url));
const publishedPackages = [
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
  "reallyme-openid4vc-profiles",
  "reallyme-disclosure-policy",
  "reallyme-credential",
  "reallyme-mdoc",
  "reallyme-sd-jwt",
  "reallyme-trust",
];

function runFixture({ mode = "publish", scenario = "success", requirement = "^0.1.0", version = "0.1.0" } = {}) {
  const directory = mkdtempSync(join(tmpdir(), "ssi-publish-test-"));
  try {
    const callsPath = join(directory, "calls.json");
    const ledgerPath = join(directory, "publication-ledger.json");
    const reviewedArchiveDirectory = join(directory, "reviewed-crates");
    if (mode === "publish") {
      mkdirSync(reviewedArchiveDirectory);
      for (const packageName of publishedPackages) {
        writeFileSync(
          join(reviewedArchiveDirectory, `${packageName}-${version}.crate`),
          "reviewed archive",
        );
      }
    }
    const preload = join(directory, "mock.mjs");
    // Intercept every child process: these tests must never invoke Cargo,
    // access a registry, publish a crate, or perform real retry waits.
    writeFileSync(preload, `
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
const calls = [];
const scenario = ${JSON.stringify(scenario)};
let attempts = 0;
let packageAttempts = 0;
const writeArchive = (packageName) => {
  const archive = join(
    ${JSON.stringify(directory)},
    "package",
    packageName + "-" + ${JSON.stringify(version)} + ".crate",
  );
  mkdirSync(dirname(archive), { recursive: true });
  writeFileSync(archive, scenario === "reviewed-mismatch" ? "different archive" : "reviewed archive");
};
Atomics.wait = (_array, _index, _value, delay) => {
  calls.push(["wait", delay]);
  writeFileSync(${JSON.stringify(callsPath)}, JSON.stringify(calls));
  return "timed-out";
};
childProcess.spawnSync = (command, args) => {
  calls.push([command, ...args]);
  writeFileSync(${JSON.stringify(callsPath)}, JSON.stringify(calls));
  const ok = { status: 0, stdout: "", stderr: "" };
  if (command === "curl") {
    const output = args[args.indexOf("--output") + 1];
    writeFileSync(output, "reviewed archive");
    return ok;
  }
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
      { name: "reallyme-openid4vc-profiles", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [] },
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
      { name: "reallyme-trust", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [
          // The facade consumes released trust crates from the registry, so
          // these dependencies do not create workspace publication edges.
          { name: "reallyme-trust-x509", source: "registry+https://github.com/rust-lang/crates.io-index", path: null, kind: null, req: "=0.4.0" },
          { name: "reallyme-trust-core", source: "registry+https://github.com/rust-lang/crates.io-index", path: null, kind: null, req: "=0.4.0" },
          { name: "reallyme-revocation", source: "registry+https://github.com/rust-lang/crates.io-index", path: null, kind: null, req: "=0.4.0" },
          { name: "reallyme-ssi-proto", source: "registry+https://github.com/rust-lang/crates.io-index", path: null, kind: null, req: "=0.4.0" },
        ] },
      { name: "reallyme-ssi", version: ${JSON.stringify(version)}, publish: [], dependencies: [] },
    ],
  }) };
  if (args[0] === "package") {
    packageAttempts += 1;
    if (scenario === "package-index-lag" && packageAttempts === 2) {
      return {
        ...ok,
        status: 101,
        stderr: 'failed to select a version for the requirement \`reallyme-compression-brotli = "=0.1.0"\`',
      };
    }
    writeArchive(args[args.indexOf("-p") + 1]);
    return ok;
  }
  if (args[0] !== "publish") return { ...ok, status: 99 };
  attempts += 1;
  const failAfter = /^fail-after-([0-9]+)$/.exec(scenario);
  if (failAfter !== null && attempts > Number.parseInt(failAfter[1], 10)) {
    return { ...ok, status: 101, stderr: "injected publication interruption" };
  }
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
  if (scenario === "already-exists") {
    return { ...ok, status: 101, stderr: "crate version already exists" };
  }
  if (scenario === "failure") return { ...ok, status: 101, stderr: "package verification failed" };
  writeArchive(args[args.indexOf("-p") + 1]);
  return ok;
};
syncBuiltinESMExports();
`);
    const result = spawnSync(process.execPath, ["--import", pathToFileURL(preload).href, script, mode], {
      cwd: directory,
      encoding: "utf8",
      timeout: 10_000,
      env: {
        ...process.env,
        PUBLICATION_LEDGER_PATH: ledgerPath,
        RELEASE_SHA: "0123456789abcdef0123456789abcdef01234567",
        RELEASE_VERSION: version,
        REVIEWED_CRATE_ARCHIVES_DIRECTORY: reviewedArchiveDirectory,
      },
    });
    assert.equal(result.error, undefined);
    const ledger = mode === "publish" ? JSON.parse(readFileSync(ledgerPath, "utf8")) : null;
    return { ...result, calls: JSON.parse(readFileSync(callsPath, "utf8")), ledger };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("successful publication respects dependency order", () => {
  const result = runFixture();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[1] === "publish").map((call) => call[3]),
    publishedPackages);
  for (const packageName of publishedPackages) {
    const packageIndex = result.calls.findIndex(
      (call) => call[1] === "package" && call[3] === packageName,
    );
    const publishIndex = result.calls.findIndex(
      (call) => call[1] === "publish" && call[3] === packageName,
    );
    assert.ok(packageIndex >= 0 && publishIndex > packageIndex);
  }
  assert.equal(result.ledger.state, "completed");
  assert.equal(result.ledger.source_commit, "0123456789abcdef0123456789abcdef01234567");
  assert.ok(result.ledger.crates.every((entry) => entry.state === "published"));
});

test("resumed publication rebuilds each existing archive before comparing crates.io bytes", () => {
  const result = runFixture({ scenario: "already-exists" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.calls.filter((call) => call[1] === "package").length, publishedPackages.length);
  assert.equal(result.calls.filter((call) => call[0] === "curl").length, publishedPackages.length);
  for (const packageName of publishedPackages) {
    const publishIndex = result.calls.findIndex(
      (call) => call[1] === "publish" && call[3] === packageName,
    );
    const packageIndex = result.calls.findIndex(
      (call) => call[1] === "package" && call[3] === packageName,
    );
    const packageCall = result.calls[packageIndex];
    const nextCurlIndex = result.calls.findIndex(
      (call, index) => index > packageIndex && call[0] === "curl",
    );
    assert.ok(packageIndex >= 0 && publishIndex > packageIndex && nextCurlIndex > publishIndex);
    assert.ok(packageCall.includes("--no-verify"));
    assert.ok(packageCall.includes("--locked"));
  }
  assert.ok(result.ledger.crates.every((entry) => entry.state === "verified_existing"));
});

test("publication stops when rebuilt bytes differ from the reviewed archive", () => {
  const result = runFixture({ scenario: "reviewed-mismatch" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /package bytes differ from reviewed preflight/u);
  assert.equal(result.calls.filter((call) => call[1] === "publish").length, 0);
  assert.equal(result.calls.filter((call) => call[0] === "curl").length, 0);
});

test("rate-limit exhaustion fails without publishing dependent crates", () => {
  const result = runFixture({ scenario: "exhausted" });
  assert.equal(result.status, 101);
  const publishes = result.calls.filter((call) => call[1] === "publish");
  assert.equal(publishes.length, 12);
  assert.ok(publishes.every((call) => call[3] === "reallyme-compression-brotli"));
  assert.equal(result.calls.filter((call) => call[0] === "wait").length, 11);
  assert.equal(result.ledger.state, "in_progress");
  assert.equal(result.ledger.crates[0].state, "attempting");
  assert.ok(result.ledger.crates.slice(1).every((entry) => entry.state === "pending"));
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

test("reviewed archive reproduction retries while a dependency reaches the index", () => {
  const result = runFixture({ scenario: "package-index-lag" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[0] === "wait"), [["wait", 15000]]);
  const packages = result.calls.filter((call) => call[1] === "package");
  assert.equal(packages[1][3], packages[2][3]);
});

test("non-retryable publication errors fail immediately", () => {
  const result = runFixture({ scenario: "failure" });
  assert.equal(result.status, 101);
  assert.equal(result.calls.filter((call) => call[1] === "publish").length, 1);
  assert.equal(result.calls.filter((call) => call[0] === "wait").length, 0);
});

test("publication ledger preserves exact recovery state after every upload boundary", () => {
  const crateCount = runFixture().ledger.crates.length;
  for (let completed = 0; completed < crateCount; completed += 1) {
    const result = runFixture({ scenario: `fail-after-${completed}` });
    assert.equal(result.status, 101);
    assert.equal(result.ledger.state, "in_progress");
    assert.ok(
      result.ledger.crates
        .slice(0, completed)
        .every((entry) => entry.state === "published"),
    );
    assert.equal(result.ledger.crates[completed].state, "attempting");
    assert.ok(
      result.ledger.crates
        .slice(completed + 1)
        .every((entry) => entry.state === "pending"),
    );
  }
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
