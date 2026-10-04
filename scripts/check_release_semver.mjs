// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { execFileSync } from "node:child_process";
import process from "node:process";
import { fileURLToPath } from "node:url";

const VERSION_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u;
const REGISTRY_URL = "https://crates.io/api/v1/crates/";
const REQUEST_TIMEOUT_MS = 15_000;

export class SemverGateError extends Error {
  constructor(code) {
    super(code);
    this.name = "SemverGateError";
    this.code = code;
  }
}

export function parseVersion(value) {
  if (typeof value !== "string") {
    throw new SemverGateError("invalid-version");
  }
  const match = VERSION_PATTERN.exec(value);
  if (match === null) {
    throw new SemverGateError("invalid-version");
  }
  const parsed = {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
  };
  if (Object.values(parsed).some((part) => !Number.isSafeInteger(part))) {
    throw new SemverGateError("invalid-version");
  }
  return parsed;
}

export function compareVersions(left, right) {
  for (const part of ["major", "minor", "patch"]) {
    if (left[part] < right[part]) return -1;
    if (left[part] > right[part]) return 1;
  }
  return 0;
}

export function requiresApiCompatibilityCheck(planned, published) {
  if (compareVersions(planned, published) < 0) {
    throw new SemverGateError("planned-version-precedes-published-version");
  }
  // A 0.x minor bump is a breaking release in Cargo's compatibility model.
  // cargo-semver-checks intentionally executes zero API checks for that bump,
  // so compiling the old crate only adds a failure mode without coverage.
  return !(
    planned.major > published.major ||
    (planned.major === 0 && published.major === 0 && planned.minor > published.minor)
  );
}

export function publishedVersionFromResponse(body) {
  if (
    typeof body !== "object" ||
    body === null ||
    typeof body.crate !== "object" ||
    body.crate === null ||
    typeof body.crate.max_stable_version !== "string"
  ) {
    throw new SemverGateError("invalid-registry-response");
  }
  return parseVersion(body.crate.max_stable_version);
}

async function fetchPublishedVersion(name) {
  let response;
  try {
    response = await fetch(`${REGISTRY_URL}${encodeURIComponent(name)}`, {
      headers: { "User-Agent": "reallyme-ssi-release-semver-check" },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch {
    throw new SemverGateError("registry-request-failed");
  }
  if (response.status === 404) return null;
  if (!response.ok) throw new SemverGateError("registry-request-failed");
  let body;
  try {
    body = await response.json();
  } catch {
    throw new SemverGateError("invalid-registry-response");
  }
  return publishedVersionFromResponse(body);
}

function publicPackages() {
  const metadata = JSON.parse(
    execFileSync("cargo", ["metadata", "--no-deps", "--format-version", "1", "--locked"], {
      encoding: "utf8",
    }),
  );
  if (!Array.isArray(metadata.packages)) {
    throw new SemverGateError("invalid-cargo-metadata");
  }
  return metadata.packages.filter(
    (pkg) => pkg.source === null && (pkg.publish === null || pkg.publish?.length > 0),
  );
}

export async function checkReleaseSemver() {
  const packages = publicPackages();
  if (packages.length === 0) throw new SemverGateError("no-public-packages");
  let checked = 0;
  let breaking = 0;
  let newPackages = 0;
  for (const pkg of packages) {
    if (typeof pkg.name !== "string") throw new SemverGateError("invalid-cargo-metadata");
    const planned = parseVersion(pkg.version);
    const published = await fetchPublishedVersion(pkg.name);
    if (published === null) {
      newPackages += 1;
      continue;
    }
    if (!requiresApiCompatibilityCheck(planned, published)) {
      breaking += 1;
      continue;
    }
    process.stdout.write(`Checking published API compatibility for ${pkg.name}\n`);
    execFileSync("cargo", ["semver-checks", "check-release", "-p", pkg.name], {
      stdio: "inherit",
    });
    checked += 1;
  }
  process.stdout.write(
    `semver gate: ${checked} compatible release checks, ${breaking} breaking release bumps, ${newPackages} first releases\n`,
  );
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    await checkReleaseSemver();
  } catch (error) {
    process.stderr.write(
      `semver gate failed: ${error instanceof SemverGateError ? error.code : "command-failed"}\n`,
    );
    process.exitCode = 1;
  }
}
