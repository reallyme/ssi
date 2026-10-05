// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const MODE_INSPECT = "inspect";
const MODE_ORDER = "order";
const MODE_PUBLISH = "publish";
const MAX_PUBLISH_ATTEMPTS = 12;
const CRATES_IO_DEFAULT_RATE_LIMIT_RETRY_MS = 60000;
const CRATES_IO_INDEX_RETRY_BASE_MS = 15000;
const REQUIRED_PUBLISH_ORDER_EDGES = [
  ["reallyme-ssi-proto", "reallyme-credential-audit"],
  ["reallyme-ssi-proto", "reallyme-credential-status"],
  ["reallyme-ssi-proto", "reallyme-ssi-core"],
  ["reallyme-ssi-proto", "reallyme-vp-core"],
  ["reallyme-ssi-proto", "reallyme-trust-x509"],
  ["reallyme-trust-x509", "reallyme-mdoc"],
  ["reallyme-credential-claims", "reallyme-mdoc"],
  ["reallyme-trust-x509", "reallyme-credential-claims"],
  ["reallyme-credential-status", "reallyme-revocation"],
  ["reallyme-trust-x509", "reallyme-revocation"],
  ["reallyme-revocation", "reallyme-trust-core"],
  ["reallyme-trust-core", "reallyme-trust"],
  ["reallyme-trust-x509", "reallyme-trust"],
  ["reallyme-trust-core", "reallyme-openid-oauth"],
  ["reallyme-credential-claims", "reallyme-disclosure-policy"],
  ["reallyme-credential-audit", "reallyme-credential"],
  ["reallyme-credential-claims", "reallyme-credential"],
  ["reallyme-revocation", "reallyme-credential"],
  ["reallyme-compression-brotli", "reallyme-ssi-proto-codec"],
  ["reallyme-ssi-core", "reallyme-ssi-proto-codec"],
  ["reallyme-did-types", "reallyme-ssi-proto-codec"],
  ["reallyme-vp-core", "reallyme-ssi-proto-codec"],
];
const args = process.argv.slice(2);
const mode = args[0] ?? MODE_INSPECT;
const allowDirty = args.includes("--allow-dirty");
const unknownArgs = args.slice(1).filter((arg) => arg !== "--allow-dirty");
const releaseVersion = process.env.RELEASE_VERSION ?? "";
const publicationLedgerPath = process.env.PUBLICATION_LEDGER_PATH ?? "";
const releaseSha = process.env.RELEASE_SHA ?? "";
const reviewedArchiveDirectoryValue =
  process.env.REVIEWED_CRATE_ARCHIVES_DIRECTORY ?? "";

if (
  (mode !== MODE_INSPECT && mode !== MODE_ORDER && mode !== MODE_PUBLISH) ||
  unknownArgs.length !== 0
) {
  console.error(
    `usage: node scripts/publish_crates_in_order.mjs ${MODE_INSPECT}|${MODE_ORDER}|${MODE_PUBLISH} [--allow-dirty]`,
  );
  process.exit(2);
}

if (allowDirty && mode !== MODE_INSPECT && mode !== MODE_ORDER) {
  console.error("--allow-dirty is only supported for local package inspection and order checks");
  process.exit(2);
}

if (mode === MODE_PUBLISH && releaseVersion.length === 0) {
  console.error("RELEASE_VERSION must be set when publishing crates.");
  process.exit(2);
}

if (mode === MODE_PUBLISH && reviewedArchiveDirectoryValue.length === 0) {
  console.error("REVIEWED_CRATE_ARCHIVES_DIRECTORY must be set when publishing crates.");
  process.exit(2);
}

if (
  mode === MODE_PUBLISH &&
  publicationLedgerPath.length !== 0 &&
  !/^[0-9a-f]{40}$/u.test(releaseSha)
) {
  console.error("RELEASE_SHA must be an exact Git commit when recording a publication ledger.");
  process.exit(2);
}

if (releaseVersion.length !== 0 && !/^[0-9]+[.][0-9]+[.][0-9]+$/u.test(releaseVersion)) {
  console.error("RELEASE_VERSION must be an exact semver release such as 0.1.0.");
  process.exit(2);
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    env: options.env ?? process.env,
    stdio: options.capture ? "pipe" : "inherit",
    maxBuffer: options.maxBuffer ?? 1024 * 1024,
  });
  if (result.error) {
    throw result.error;
  }
  return result;
}

function sleepMs(delayMs) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, delayMs);
}

function retryAfterMs(output) {
  const match = /try again after ([^\n.]+ GMT)/i.exec(output);
  if (!match) {
    return null;
  }

  const retryAt = Date.parse(match[1]);
  if (!Number.isFinite(retryAt)) {
    return null;
  }

  const delayMs = retryAt - Date.now() + 10000;
  return Math.max(delayMs, 10000);
}

const metadataResult = run(
  "cargo",
  ["metadata", "--locked", "--format-version", "1", "--no-deps"],
  {
    capture: true,
  },
);

if (metadataResult.status !== 0) {
  process.stderr.write(metadataResult.stderr);
  process.exit(metadataResult.status ?? 1);
}

const metadata = JSON.parse(metadataResult.stdout);
const packageDirectory = path.join(metadata.target_directory, "package");
const reviewedArchiveDirectory =
  reviewedArchiveDirectoryValue.length === 0
    ? null
    : path.resolve(reviewedArchiveDirectoryValue);

function isPublishablePackage(pkg) {
  return !(Array.isArray(pkg.publish) && pkg.publish.length === 0);
}

const publishable = new Map();
for (const pkg of metadata.packages) {
  if (isPublishablePackage(pkg)) {
    publishable.set(pkg.name, pkg);
  }
}

function dependencyPackageName(dep) {
  return dep.package ?? dep.name;
}

function isWorkspacePathDependency(dep) {
  return (
    dep.source === null &&
    typeof dep.path === "string" &&
    publishable.has(dependencyPackageName(dep))
  );
}

function isPublishOrderingDependency(dep) {
  // crates.io resolves normalized dev-dependencies while validating an upload,
  // so public path-based test dependencies must be available first as well.
  return isWorkspacePathDependency(dep);
}

function parseVersion(version) {
  const parts = version.split(".");
  if (!/^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u.test(version)) {
    return null;
  }

  const parsed = parts.map((part) => Number.parseInt(part, 10));
  if (parsed.some((part) => !Number.isSafeInteger(part) || part < 0)) {
    return null;
  }

  return {
    major: parsed[0],
    minor: parsed[1],
    patch: parsed[2],
  };
}

function isCaretReqSatisfied(req, version) {
  if (!req.startsWith("^")) {
    return req === `=${version}` || req === version;
  }

  const minimum = parseVersion(req.slice(1));
  const actual = parseVersion(version);
  if (minimum === null || actual === null) {
    return false;
  }

  if (actual.major !== minimum.major) {
    return false;
  }

  if (minimum.major === 0 && actual.minor !== minimum.minor) {
    return false;
  }

  // Cargo keeps ^0.0.x within that exact patch release.
  if (minimum.major === 0 && minimum.minor === 0 && actual.patch !== minimum.patch) {
    return false;
  }

  if (actual.minor < minimum.minor) {
    return false;
  }

  if (actual.minor === minimum.minor && actual.patch < minimum.patch) {
    return false;
  }

  return true;
}

function checkPathDependencyVersions() {
  const failures = [];
  for (const pkg of publishable.values()) {
    for (const dep of pkg.dependencies) {
      if (!isPublishOrderingDependency(dep)) {
        continue;
      }

      const target = publishable.get(dependencyPackageName(dep));
      if (!isCaretReqSatisfied(dep.req, target.version)) {
        failures.push(
          `${pkg.name} depends on ${dep.name} with ${dep.req}; local version is ${target.version}`,
        );
      }
    }
  }

  if (failures.length !== 0) {
    console.error("publishable workspace path dependency versions are stale:");
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }
}

function checkReleaseVersion() {
  if (releaseVersion.length === 0) {
    return;
  }

  const failures = [];
  for (const pkg of publishable.values()) {
    if (pkg.version !== releaseVersion) {
      failures.push(`${pkg.name} is ${pkg.version}; expected ${releaseVersion}`);
    }
  }
  if (failures.length !== 0) {
    console.error("publishable crate versions do not match RELEASE_VERSION:");
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }
}

const visiting = new Set();
const visited = new Set();
const ordered = [];

function visit(pkg) {
  if (visited.has(pkg.name)) {
    return;
  }
  if (visiting.has(pkg.name)) {
    console.error(`workspace publish dependency cycle at ${pkg.name}`);
    process.exit(1);
  }

  visiting.add(pkg.name);
  for (const dep of pkg.dependencies) {
    const depName = dependencyPackageName(dep);
    if (isPublishOrderingDependency(dep) && publishable.has(depName)) {
      visit(publishable.get(depName));
    }
  }
  visiting.delete(pkg.name);
  visited.add(pkg.name);
  ordered.push(pkg);
}

for (const pkg of publishable.values()) {
  visit(pkg);
}

console.log(`Publish order (${ordered.length} crates):`);
for (const pkg of ordered) {
  console.log(`- ${pkg.name} ${pkg.version}`);
}

function checkRequiredPublishOrderEdges() {
  const failures = [];
  const orderedPackageNames = new Set(orderedIndexByName.keys());

  for (const [dependencyName, packageName] of REQUIRED_PUBLISH_ORDER_EDGES) {
    const dependencyIndex = orderedIndexByName.get(dependencyName);
    const packageIndex = orderedIndexByName.get(packageName);
    if (dependencyIndex === undefined || packageIndex === undefined) {
      failures.push(`${dependencyName} before ${packageName} cannot be checked; package is missing`);
      continue;
    }

    if (dependencyIndex >= packageIndex) {
      failures.push(`${dependencyName} must publish before ${packageName}`);
    }
  }

  if (failures.length !== 0) {
    console.error(
      `publishable packages discovered: ${[...orderedPackageNames].sort().join(", ")}`,
    );
    console.error("required publish dependency order is not satisfied:");
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }
}

const orderedIndexByName = new Map();
ordered.forEach((pkg, index) => {
  orderedIndexByName.set(pkg.name, index);
});

checkPathDependencyVersions();
checkRequiredPublishOrderEdges();
checkReleaseVersion();

function reviewedArchivePath(pkg) {
  if (reviewedArchiveDirectory === null) {
    return null;
  }
  return path.join(reviewedArchiveDirectory, `${pkg.name}-${pkg.version}.crate`);
}

function validateReviewedArchiveSet() {
  if (mode !== MODE_PUBLISH || reviewedArchiveDirectory === null) {
    return;
  }

  let directoryStatus;
  let entries;
  try {
    directoryStatus = fs.lstatSync(reviewedArchiveDirectory);
    entries = fs.readdirSync(reviewedArchiveDirectory).filter((entry) => entry.endsWith(".crate"));
  } catch {
    console.error("reviewed crate archive directory is unavailable");
    process.exit(1);
  }
  if (directoryStatus.isSymbolicLink() || !directoryStatus.isDirectory()) {
    console.error("reviewed crate archive directory is not a regular directory");
    process.exit(1);
  }

  const expected = ordered.map((pkg) => `${pkg.name}-${pkg.version}.crate`).sort();
  const actual = entries.sort();
  if (
    actual.length !== expected.length ||
    actual.some((entry, index) => entry !== expected[index])
  ) {
    console.error("reviewed crate archive set does not match the publish set");
    process.exit(1);
  }

  for (const archive of actual) {
    let status;
    try {
      status = fs.lstatSync(path.join(reviewedArchiveDirectory, archive));
    } catch {
      console.error("reviewed crate archive set cannot be inspected");
      process.exit(1);
    }
    if (status.isSymbolicLink() || !status.isFile() || status.size === 0) {
      console.error("reviewed crate archive set contains a non-regular file");
      process.exit(1);
    }
  }
}

validateReviewedArchiveSet();

if (mode === MODE_ORDER) {
  process.exit(0);
}

const unpackDirectory = path.join(packageDirectory, "release-preflight");
const inspectionTargetDirectory = path.join(packageDirectory, "release-preflight-target");
const inspectionEnvironment = {
  ...process.env,
  CARGO_TARGET_DIR: inspectionTargetDirectory,
};

if (mode === MODE_INSPECT) {
  // This workspace intentionally contains source-only implementation crates.
  // Package the reviewed set as one workspace operation so Cargo can normalize
  // dependencies whose earlier versions do not exist in the registry yet.
  // Explicit exclusions prevent source-only members from becoming release
  // inputs or blocking package construction.
  const packageArgs = ["package", "--workspace", "--no-verify", "--locked"];
  for (const pkg of metadata.packages) {
    if (!publishable.has(pkg.name)) {
      packageArgs.push("--exclude", pkg.name);
    }
  }
  if (allowDirty) {
    packageArgs.push("--allow-dirty");
  }
  const packageResult = run("cargo", packageArgs);
  if (packageResult.status !== 0) {
    process.exit(packageResult.status ?? 1);
  }

  fs.rmSync(unpackDirectory, { force: true, recursive: true });
  // Rust compile-time environment values such as CARGO_MANIFEST_DIR are not
  // part of Cargo's artifact fingerprint. Reusing this cache could therefore
  // execute a test binary compiled against the workspace instead of the
  // extracted archive, defeating the purpose of the package inspection.
  fs.rmSync(inspectionTargetDirectory, { force: true, recursive: true });
  fs.mkdirSync(unpackDirectory, { recursive: true });
  for (const pkg of ordered) {
    const archive = path.join(packageDirectory, `${pkg.name}-${pkg.version}.crate`);
    const extractResult = run("tar", ["-xzf", archive, "-C", unpackDirectory]);
    if (extractResult.status !== 0) {
      process.exit(extractResult.status ?? 1);
    }
  }
  inspectCombinedArchiveGraph();
}

function inspectCombinedArchiveGraph() {
  const version = publishable.get("reallyme-credential")?.version;
  if (version === undefined) {
    console.error("credential is missing from the public archive set");
    process.exit(1);
  }
  const consumerDirectory = path.join(packageDirectory, "release-graph-consumer");
  fs.rmSync(consumerDirectory, { force: true, recursive: true });
  fs.mkdirSync(path.join(consumerDirectory, "src"), { recursive: true });
  fs.writeFileSync(path.join(consumerDirectory, "src", "main.rs"), "fn main() {}\n");
  fs.writeFileSync(
    path.join(consumerDirectory, "Cargo.toml"),
    `[package]\nname = "ssi-release-graph-check"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nreallyme-trust = "=${version}"\nreallyme-credential = "=${version}"\n`,
  );
  const patchArgs = [];
  for (const pkg of ordered) {
    const archivePath = path.join(unpackDirectory, `${pkg.name}-${pkg.version}`);
    patchArgs.push(
      "--config",
      `patch.crates-io.'${pkg.name}'.path=${JSON.stringify(archivePath)}`,
    );
  }
  const result = run(
    "cargo",
    [
      "metadata",
      "--format-version",
      "1",
      "--manifest-path",
      path.join(consumerDirectory, "Cargo.toml"),
      ...patchArgs,
    ],
    { capture: true, maxBuffer: 32_000_000 },
  );
  if (result.status !== 0) {
    process.stderr.write(result.stderr);
    console.error("combined normalized facade and credential archives cannot resolve");
    process.exit(result.status ?? 1);
  }
  const resolved = JSON.parse(result.stdout);
  const publicNames = new Set(publishable.keys());
  const seen = new Set();
  for (const pkg of resolved.packages) {
    if (!publicNames.has(pkg.name)) continue;
    const expectedPath = path.join(unpackDirectory, `${pkg.name}-${version}`, "Cargo.toml");
    if (
      seen.has(pkg.name) ||
      pkg.version !== version ||
      pkg.source !== null ||
      pkg.manifest_path !== expectedPath
    ) {
      console.error(`${pkg.name} resolves to a duplicate, stale, or unexpected public crate`);
      process.exit(1);
    }
    seen.add(pkg.name);
    for (const dependency of pkg.dependencies) {
      if (!publicNames.has(dependency.name)) continue;
      if (dependency.path != null || !dependency.source?.startsWith("registry+")) {
        console.error(`${pkg.name} archive retains a local public dependency path`);
        process.exit(1);
      }
    }
  }
  for (const name of [
    "reallyme-trust",
    "reallyme-credential",
    "reallyme-trust-core",
    "reallyme-trust-x509",
    "reallyme-revocation",
    "reallyme-credential-status",
    "reallyme-ssi-proto",
  ]) {
    if (!seen.has(name)) {
      console.error(`combined normalized graph omitted ${name}`);
      process.exit(1);
    }
  }
  console.log(`combined normalized facade and credential graph passed at ${version}`);
}

function unresolvedRegistryPackages(output) {
  const missing = [];
  const noMatchPattern = /no matching package named `([^`]+)` found/g;
  for (let match = noMatchPattern.exec(output); match !== null; match = noMatchPattern.exec(output)) {
    missing.push(match[1]);
  }

  const versionSelectPattern = /failed to select a version for the requirement `([^`\s]+) =/g;
  for (
    let match = versionSelectPattern.exec(output);
    match !== null;
    match = versionSelectPattern.exec(output)
  ) {
    missing.push(match[1]);
  }

  return [...new Set(missing)];
}

function isEarlierWorkspaceDependency(pkg, depName) {
  const pkgIndex = orderedIndexByName.get(pkg.name);
  const depIndex = orderedIndexByName.get(depName);
  return depIndex !== undefined && pkgIndex !== undefined && depIndex < pkgIndex;
}

function inspectPackage(pkg) {
  const manifestPath = path.join(unpackDirectory, `${pkg.name}-${pkg.version}`, "Cargo.toml");
  const patchArgs = [];
  for (const dependency of ordered) {
    if (!isEarlierWorkspaceDependency(pkg, dependency.name)) {
      continue;
    }
    const dependencyPath = path.join(unpackDirectory, `${dependency.name}-${dependency.version}`);
    patchArgs.push(
      "--config",
      `patch.crates-io.'${dependency.name}'.path=${JSON.stringify(dependencyPath)}`,
    );
  }

  // Fetch the normalized archive's locked dependency graph explicitly before
  // enforcing an offline build. This proves each packaged crate builds from
  // its published shape, not only from the workspace path dependency graph.
  const fetchArgs = ["fetch", "--manifest-path", manifestPath, ...patchArgs];
  if (patchArgs.length === 0) {
    fetchArgs.push("--locked");
  }
  const fetchResult = run("cargo", fetchArgs);
  if (fetchResult.status !== 0) {
    process.exit(fetchResult.status ?? 1);
  }

  const checkArgs = [
    "check",
    "--manifest-path",
    manifestPath,
    "--all-features",
    "--locked",
    "--offline",
    ...patchArgs,
  ];
  // Every extracted crate is a separate Cargo workspace. Sharing only the
  // target directory preserves those manifest boundaries while allowing Cargo
  // to reuse identical dependency artifacts across the reviewed package set.
  const checkResult = run("cargo", checkArgs, { env: inspectionEnvironment });
  if (checkResult.status !== 0) {
    process.exit(checkResult.status ?? 1);
  }

  // Tests are part of the crate archive and frequently contain compile-time
  // fixtures. Executing them from the extracted archive proves that none of
  // those fixtures accidentally depend on files elsewhere in this checkout.
  const testArgs = [
    "test",
    "--manifest-path",
    manifestPath,
    "--all-features",
    "--locked",
    "--offline",
    ...patchArgs,
  ];
  const testResult = run("cargo", testArgs, { env: inspectionEnvironment });
  if (testResult.status !== 0) {
    process.exit(testResult.status ?? 1);
  }

  const dryRunArgs = ["publish", "-p", pkg.name, "--dry-run", "--locked"];
  if (allowDirty) {
    dryRunArgs.push("--allow-dirty");
  }
  const dryRunResult = run("cargo", dryRunArgs, {
    capture: true,
    env: inspectionEnvironment,
  });
  process.stdout.write(dryRunResult.stdout);
  process.stderr.write(dryRunResult.stderr);
  if (dryRunResult.status === 0) {
    return;
  }

  const combined = `${dryRunResult.stdout}\n${dryRunResult.stderr}`;
  const missing = unresolvedRegistryPackages(combined);
  if (
    missing.length !== 0 &&
    missing.every((depName) => isEarlierWorkspaceDependency(pkg, depName))
  ) {
    console.log(
      `${pkg.name} dry-run reached unpublished ordered workspace dependencies: ${missing.join(", ")}`,
    );
    return;
  }

  process.exit(dryRunResult.status ?? 1);
}

function publishPackage(pkg) {
  // Rebuild and compare before invoking `cargo publish`: detecting a mismatch
  // after Cargo uploads would be an audit signal, not a release control.
  // The release job receives only reviewed archives from preflight, and this
  // check proves the source checkout still reproduces those exact bytes.
  packageForPublishedComparison(pkg);
  const reviewedChecksum = verifyLocalPackageMatchesReviewed(pkg);
  const args = ["publish", "-p", pkg.name, "--locked", "--no-verify"];

  for (let attempt = 1; attempt <= MAX_PUBLISH_ATTEMPTS; attempt += 1) {
    const result = run("cargo", args, { capture: true });
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);

    if (result.status === 0) {
      verifyPublishedPackageMatches(pkg, reviewedChecksum);
      return "published";
    }

    const combined = `${result.stdout}\n${result.stderr}`;
    if (combined.includes("already uploaded") || combined.includes("already exists")) {
      verifyPublishedPackageMatches(pkg, reviewedChecksum);
      console.log(`${pkg.name} ${pkg.version} is already published; continuing.`);
      return "verified_existing";
    }

    const lowerCombined = combined.toLowerCase();
    const rateLimitDelayMs = retryAfterMs(combined);
    if (
      lowerCombined.includes("too many requests") ||
      lowerCombined.includes("rate-limited") ||
      lowerCombined.includes("rate limited") ||
      lowerCombined.includes("rate limit") ||
      /\b429\b/u.test(lowerCombined)
    ) {
      // Exhaustion must fail the release before attempting dependent crates.
      if (attempt === MAX_PUBLISH_ATTEMPTS) {
        console.error(`publication retry limit reached for ${pkg.name}`);
        process.exit(result.status ?? 1);
      }
      const delayMs = rateLimitDelayMs ?? CRATES_IO_DEFAULT_RATE_LIMIT_RETRY_MS;
      console.log(
        `crates.io rate-limited new crate uploads; retrying ${pkg.name} in ${Math.ceil(delayMs / 1000)}s...`,
      );
      sleepMs(delayMs);
      continue;
    }

    const registryIndexIsStale =
      combined.includes("no matching package named") ||
      combined.includes("failed to select a version for the requirement");
    if (!registryIndexIsStale || attempt === MAX_PUBLISH_ATTEMPTS) {
      process.exit(result.status ?? 1);
    }

    const delayMs = attempt * CRATES_IO_INDEX_RETRY_BASE_MS;
    console.log(
      `crates.io index has not observed a freshly published dependency yet; retrying ${pkg.name} in ${delayMs / 1000}s...`,
    );
    sleepMs(delayMs);
  }
}

const publicationLedger = {
  schema: "reallyme.ssi.crates-publication-ledger.v1",
  repository: "reallyme/ssi",
  source_commit: releaseSha,
  release_version: releaseVersion,
  state: "not_started",
  crates: ordered.map((pkg, publish_order) => ({
    name: pkg.name,
    version: pkg.version,
    publish_order,
    state: "pending",
    archive_sha256: null,
  })),
};

function writePublicationLedger() {
  if (mode !== MODE_PUBLISH || publicationLedgerPath.length === 0) {
    return;
  }
  const parent = path.dirname(publicationLedgerPath);
  fs.mkdirSync(parent, { recursive: true });
  const temporaryPath = `${publicationLedgerPath}.tmp`;
  fs.writeFileSync(temporaryPath, `${JSON.stringify(publicationLedger, null, 2)}\n`, {
    mode: 0o600,
  });
  fs.renameSync(temporaryPath, publicationLedgerPath);
}

function archiveSha256(pkg) {
  const archive = path.join(packageDirectory, `${pkg.name}-${pkg.version}.crate`);
  if (!fs.existsSync(archive)) {
    return null;
  }
  return createHash("sha256").update(fs.readFileSync(archive)).digest("hex");
}

function packageForPublishedComparison(pkg) {
  for (let attempt = 1; attempt <= MAX_PUBLISH_ATTEMPTS; attempt += 1) {
    const result = run(
      "cargo",
      ["package", "-p", pkg.name, "--no-verify", "--locked"],
      { capture: true },
    );
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);
    if (result.status === 0) {
      return;
    }

    const combined = `${result.stdout}\n${result.stderr}`;
    const registryIndexIsStale =
      combined.includes("no matching package named") ||
      combined.includes("failed to select a version for the requirement");
    if (!registryIndexIsStale || attempt === MAX_PUBLISH_ATTEMPTS) {
      process.exit(result.status ?? 1);
    }
    const delayMs = attempt * CRATES_IO_INDEX_RETRY_BASE_MS;
    console.log(
      `crates.io index has not observed a dependency needed to reproduce ${pkg.name}; retrying in ${delayMs / 1000}s...`,
    );
    sleepMs(delayMs);
  }
}

if (mode === MODE_PUBLISH) {
  publicationLedger.state = "in_progress";
  writePublicationLedger();
}

function verifyLocalPackageMatchesReviewed(pkg) {
  const localArchive = path.join(packageDirectory, `${pkg.name}-${pkg.version}.crate`);
  if (!fs.existsSync(localArchive)) {
    console.error(`${pkg.name} ${pkg.version} local package archive is missing`);
    process.exit(1);
  }

  const reviewedArchive = reviewedArchivePath(pkg);
  if (reviewedArchive === null || !fs.existsSync(reviewedArchive)) {
    console.error(`${pkg.name} ${pkg.version} reviewed package archive is missing`);
    process.exit(1);
  }

  const localChecksum = createHash("sha256").update(fs.readFileSync(localArchive)).digest("hex");
  const reviewedChecksum = createHash("sha256")
    .update(fs.readFileSync(reviewedArchive))
    .digest("hex");
  // The predecessor job verifies provenance for the immutable artifact. Both
  // the release-time package and the registry response must match those exact
  // reviewed bytes; source equality alone is not sufficient release evidence.
  if (localChecksum !== reviewedChecksum) {
    console.error(`${pkg.name} ${pkg.version} package bytes differ from reviewed preflight`);
    process.exit(1);
  }

  return reviewedChecksum;
}

function verifyPublishedPackageMatches(pkg, reviewedChecksum) {
  const comparisonDirectory = fs.mkdtempSync(path.join(packageDirectory, "published-"));
  const publishedArchive = path.join(comparisonDirectory, `${pkg.name}-${pkg.version}.crate`);
  const packageName = encodeURIComponent(pkg.name);
  const packageVersion = encodeURIComponent(pkg.version);
  const downloadUrl =
    `https://static.crates.io/crates/${packageName}/${packageName}-${packageVersion}.crate`;

  try {
    const downloadResult = run(
      "curl",
      [
        "--fail-with-body",
        "--location",
        "--proto",
        "=https",
        "--tlsv1.2",
        "--retry",
        "5",
        "--retry-all-errors",
        "--output",
        publishedArchive,
        downloadUrl,
      ],
      { capture: true },
    );
    if (downloadResult.status !== 0) {
      process.stdout.write(downloadResult.stdout);
      process.stderr.write(downloadResult.stderr);
      process.exit(downloadResult.status ?? 1);
    }

    const publishedChecksum = createHash("sha256")
      .update(fs.readFileSync(publishedArchive))
      .digest("hex");
    if (reviewedChecksum !== publishedChecksum) {
      console.error(
        `${pkg.name} ${pkg.version} published bytes differ from reviewed preflight`,
      );
      process.exit(1);
    }
  } finally {
    fs.rmSync(comparisonDirectory, { force: true, recursive: true });
  }
}

for (const pkg of ordered) {
  if (mode === MODE_INSPECT) {
    inspectPackage(pkg);
    continue;
  }

  const ledgerEntry = publicationLedger.crates.find((entry) => entry.name === pkg.name);
  if (ledgerEntry !== undefined) {
    ledgerEntry.state = "attempting";
    writePublicationLedger();
  }
  const publishState = publishPackage(pkg);
  if (ledgerEntry !== undefined) {
    ledgerEntry.state = publishState;
    ledgerEntry.archive_sha256 = archiveSha256(pkg);
    writePublicationLedger();
  }
}

if (mode === MODE_PUBLISH) {
  publicationLedger.state = "completed";
  writePublicationLedger();
}
