#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createReleaseReadinessContext } from "./release-readiness/core.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const shared = createReleaseReadinessContext({
  scriptUrl: import.meta.url,
  requireTrackedFiles: true,
});

function assertNoDocumentationSpdxHeaders() {
  const tracked = spawnSync(
    "git",
    ["ls-files", "-z", "--", "*.md", "*.txt"],
    { cwd: root, encoding: "utf8" },
  );
  if (tracked.status !== 0) {
    fail("unable to enumerate tracked documentation");
  }
  for (const path of tracked.stdout.split("\0").filter(Boolean)) {
    const source = readText(path);
    if (
      source.includes("SPDX-FileCopyrightText:") ||
      source.includes("SPDX-License-Identifier:")
    ) {
      fail(`${path} must not carry an SPDX header`);
    }
  }
}

function assertProtoZeroizeCoverage() {
  const result = spawnSync("node", ["scripts/check_proto_zeroize_coverage.mjs"], {
    cwd: root,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    fail(result.stderr.trim() || "protobuf zeroize coverage failed");
  }
}

shared.assertReallyMeVendoredCorePolicy({
  scriptPath: "scripts/check_release_readiness.mjs",
  version: "0.6.2",
});
shared.assertWorkflowActionsPinned();
shared.assertNodeWorkflowJobsPinNode({ nodeVersion: "24" });
shared.assertCargoWorkspacePolicy();
assertProtoZeroizeCoverage();
shared.assertRepositoryShapePolicy({
  archetype: "protocol-engine",
  requiredLanes: ["crates", "contracts", "conformance", "docs", "scripts", ".github"],
  optionalLanes: ["vectors", "fuzz"],
  exceptions: [{ path: "contexts", reason: "organization-specific" }],
  crates: [
    { path: "crates/audit", role: "domain" },
    { path: "crates/claims", role: "domain" },
    { path: "crates/compression/brotli", role: "support" },
    { path: "crates/credential", role: "domain" },
    { path: "crates/credential/vc/api", role: "adapter" },
    { path: "crates/credential/vc/ietf-sd-jwt", role: "adapter" },
    { path: "crates/credential/vc/jwt", role: "adapter" },
    { path: "crates/delivery/contact/api", role: "adapter" },
    { path: "crates/delivery/contact/core", role: "domain" },
    { path: "crates/delivery/contact/validator", role: "adapter" },
    { path: "crates/delivery/core", role: "domain" },
    { path: "crates/delivery/siop/api", role: "adapter" },
    { path: "crates/delivery/siop/core", role: "domain" },
    { path: "crates/delivery/siop/verifier", role: "domain" },
    { path: "crates/delivery/web/core", role: "transport" },
    { path: "crates/delivery/web/validator", role: "adapter" },
    { path: "crates/did/core/api", role: "adapter" },
    { path: "crates/did/core/common", role: "support" },
    { path: "crates/did/core/engine", role: "domain" },
    { path: "crates/did/core/types", role: "domain" },
    { path: "crates/did/methods/cheqd", role: "provider" },
    { path: "crates/did/methods/conformance", role: "test-support" },
    { path: "crates/did/methods/ebsi", role: "provider" },
    { path: "crates/did/methods/ion", role: "provider" },
    { path: "crates/did/methods/jwk", role: "provider" },
    { path: "crates/did/methods/key", role: "provider" },
    { path: "crates/did/methods/me", role: "provider" },
    { path: "crates/did/methods/web", role: "provider" },
    { path: "crates/disclosure-policy", role: "domain" },
    { path: "crates/envelopes/data_integrity", role: "adapter" },
    { path: "crates/envelopes/jwt_vc", role: "adapter" },
    { path: "crates/envelopes/mdoc", role: "adapter" },
    { path: "crates/envelopes/profiles", role: "domain" },
    { path: "crates/envelopes/sd_jwt", role: "adapter" },
    { path: "crates/eudi/etsi-eaa-conformance", role: "domain" },
    { path: "crates/eudi/rp-registration", role: "domain" },
    { path: "crates/keys", role: "provider" },
    { path: "crates/oauth", role: "domain" },
    { path: "crates/presentation/api", role: "adapter" },
    { path: "crates/presentation/core", role: "domain" },
    { path: "crates/presentation/policy", role: "domain" },
    { path: "crates/presentation/sd-jwt", role: "adapter" },
    { path: "crates/presentation/validator", role: "domain" },
    { path: "crates/profiles", role: "domain" },
    { path: "crates/proto", role: "proto" },
    { path: "crates/proto-codec", role: "proto-codec" },
    { path: "crates/revocation", role: "domain" },
    { path: "crates/revocation/crl/core", role: "domain" },
    { path: "crates/revocation/crl/openssl", role: "provider" },
    { path: "crates/revocation/ocsp/core", role: "domain" },
    { path: "crates/revocation/ocsp/dispatch", role: "runtime" },
    { path: "crates/revocation/ocsp/openssl", role: "provider" },
    { path: "crates/single-use", role: "domain" },
    { path: "crates/ssi", role: "adapter" },
    { path: "crates/status", role: "domain" },
    { path: "crates/trust/api", role: "adapter" },
    { path: "crates/trust/core", role: "domain" },
    { path: "crates/trust/jades", role: "domain" },
    { path: "crates/trust/openssl", role: "provider" },
    { path: "crates/trust/tsl-core", role: "domain" },
    { path: "crates/trust/tsl-openssl", role: "provider" },
    { path: "crates/trust/tsl-xmlsec-sys", role: "provider" },
    { path: "crates/trust/tsl-xmlsec", role: "provider" },
    { path: "crates/trust/wasm", role: "adapter" },
    { path: "crates/trust/x509", role: "domain" },
  ],
  subLanes: {},
  forbiddenPaths: [
    "conformance/vectors",
    "crates/proto-audit",
    "crates/proto-common",
    "crates/proto-credential",
    "crates/proto-did",
    "crates/proto-identity-core",
    "crates/proto-presentation",
    "crates/proto-status",
    "crates/proto-trust",
  ],
  requireReleaseReadiness: true,
});
shared.assertRustSourcePolicy({
  roots: ["."],
  generatedPrefixes: ["crates/proto/src/generated/buffa"],
  baselinePath: null,
  productionTargetLines: 500,
  productionHardLines: 500,
  testTargetLines: 800,
  testHardLines: 800,
  moduleHardLines: 100,
  forbidWildcardImports: true,
  forbidInlineTests: true,
  forbidSubstantiveFacades: true,
  forbidPanickingProductionCode: true,
  forbidDynamicErrorSurfaces: true,
});
// This repository currently owns no TypeScript, Swift, or Kotlin source lanes.
// Add the corresponding v0.6 source policy when one of those lanes is introduced.
shared.assertSpdxHeaders({
  exclusions: [
    { path: "scripts/release-readiness/core.mjs", reason: "vendored" },
    { path: "crates/proto/src/generated/buffa", reason: "generated" },
    {
      path: "crates/credential/vc/ietf-sd-jwt/tests/demos.rs",
      reason: "third-party",
    },
    {
      path: "crates/credential/vc/ietf-sd-jwt/tests/utils/fixtures.rs",
      reason: "third-party",
    },
    {
      path: "crates/credential/vc/ietf-sd-jwt/tests/utils/mod.rs",
      reason: "third-party",
    },
    { path: "vectors/ietf-sd-jwt", reason: "third-party" },
  ],
  requireExclusionsMatched: true,
  requireExclusionReasons: true,
  copyright:
    "SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved",
  license: "SPDX-License-Identifier: MIT OR Apache-2.0",
});

const requiredPackageIncludeEntries = [
  '"/src/**/*.rs"',
  '"/Cargo.toml"',
  '"/README.md"',
  '"/LICENSE-MIT"',
  '"/LICENSE-APACHE"',
];

const publicPackageManifests = [
  "crates/audit/Cargo.toml",
  "crates/claims/Cargo.toml",
  "crates/compression/brotli/Cargo.toml",
  "crates/credential/Cargo.toml",
  "crates/did/core/common/Cargo.toml",
  "crates/did/core/types/Cargo.toml",
  "crates/disclosure-policy/Cargo.toml",
  "crates/envelopes/mdoc/Cargo.toml",
  "crates/envelopes/sd_jwt/Cargo.toml",
  "crates/oauth/Cargo.toml",
  "crates/presentation/core/Cargo.toml",
  "crates/profiles/Cargo.toml",
  "crates/proto/Cargo.toml",
  "crates/proto-codec/Cargo.toml",
  "crates/revocation/Cargo.toml",
  "crates/status/Cargo.toml",
  "crates/trust/core/Cargo.toml",
  "crates/trust/x509/Cargo.toml",
];

const requiredInternalManifests = [
  "crates/envelopes/data_integrity/Cargo.toml",
  "crates/envelopes/jwt_vc/Cargo.toml",
  "crates/envelopes/mdoc/Cargo.toml",
  "crates/envelopes/profiles/Cargo.toml",
  "crates/envelopes/sd_jwt/Cargo.toml",
  "crates/did/core/common/Cargo.toml",
  "crates/ssi/Cargo.toml",
  "crates/keys/Cargo.toml",
  "crates/oauth/Cargo.toml",
  "crates/proto/Cargo.toml",
  "crates/proto-codec/Cargo.toml",
  "crates/trust/x509/Cargo.toml",
];

const forbiddenRetiredManifests = [
  "crates/envelopes/cose/Cargo.toml",
  "crates/envelopes/es256-jws-cid-2025/Cargo.toml",
  "crates/envelopes/ietf/Cargo.toml",
  "crates/envelopes/jws-es256/Cargo.toml",
  "crates/envelopes/jwt/Cargo.toml",
  "crates/envelopes/x509/Cargo.toml",
];

const approvedPublicPackages = new Set([
  "reallyme-mdoc",
  "reallyme-sd-jwt",
  "reallyme-trust-core",
  "reallyme-compression-brotli",
  "reallyme-cose",
  "reallyme-credential-audit",
  "reallyme-credential-claims",
  "reallyme-credential-status",
  "reallyme-disclosure-policy",
  "reallyme-credential",
  "reallyme-ssi-core",
  "reallyme-did-types",
  "reallyme-ssi-proto",
  "reallyme-vp-core",
  "reallyme-jose",
  "reallyme-openid-oauth",
  "reallyme-openid4vc-profiles",
  "reallyme-revocation",
  "reallyme-ssi-proto-codec",
  "reallyme-trust-x509",
]);

const requiredWorkspaceLintLines = [
  'unsafe_code = "deny"',
  'missing_docs = "warn"',
  'dbg_macro = "deny"',
  'expect_used = "deny"',
  'large_include_file = "deny"',
  'panic = "deny"',
  'print_stderr = "deny"',
  'print_stdout = "deny"',
  'todo = "deny"',
  'unimplemented = "deny"',
  'unreachable = "deny"',
  'unwrap_used = "deny"',
  'wildcard_imports = "deny"',
];

const requiredCiNeedles = [
  "cargo fmt --check",
  "cargo check --locked --workspace --all-features",
  "cargo clippy --locked --workspace --all-targets --all-features -- -D warnings",
  "node scripts/run_bounded_nextest.mjs native",
  "node scripts/run_bounded_nextest.mjs all-features",
  "cargo check --locked --workspace --no-default-features --features wasm --target wasm32-unknown-unknown",
  "cargo doc --locked --workspace --no-deps --all-features",
  "sh scripts/lint-protos.sh",
  "sh scripts/check-proto-contract.sh",
  "sh scripts/check-protos-fresh.sh",
  "node scripts/check_conformance_coverage.mjs",
  "cargo deny check",
  "scripts/audit_committed_lockfiles.sh",
  "node .release-readiness/scripts/run-consumer-check.mjs",
];

const requiredFuzzTargets = [
  "fuzz_claim_path",
  "fuzz_claim_set",
  "fuzz_mdoc_device_response",
  "fuzz_sd_jwt_processing",
  "fuzz_status_list",
  "fuzz_x509_trust_der",
];

const requiredBoundedNextestNeedles = [
  '"nextest",',
  '"list",',
  '"binaries-only",',
  '"run",',
  '"--test-threads",',
  '"--no-tests",',
  "const MACOS_CONCURRENCY = 1;",
  "const MACOS_BINARIES_PER_BATCH = 16;",
  "const DEFAULT_CONCURRENCY = 4;",
  "const BINARIES_PER_BATCH =",
  "const TEST_THREADS =",
];

const forbiddenRustFeatureNames = [/^swift\s*=/m, /^kotlin\s*=/m];

const requiredCryptoFeatureBundles = [
  [
    "crates/envelopes/sd_jwt/Cargo.toml",
    [
      "native = [\"sd-jwt-crypto\", \"reallyme-crypto/native\", \"reallyme-jose/native\"]",
      "wasm = [\"sd-jwt-crypto\", \"reallyme-crypto/wasm\", \"reallyme-jose/wasm\"]",
      "sd-jwt-crypto = [",
      "\"reallyme-crypto/csprng\"",
      "\"reallyme-crypto/dispatch\"",
      "\"reallyme-crypto/ed25519\"",
      "\"reallyme-crypto/jwk\"",
      "\"reallyme-crypto/sha2\"",
    ],
  ],
  [
    "crates/envelopes/mdoc/Cargo.toml",
    [
      "native = [\"mdoc-crypto\", \"reallyme-cose/native\", \"reallyme-crypto/native\"]",
      "wasm = [\"mdoc-crypto\", \"reallyme-cose/wasm\", \"reallyme-crypto/wasm\"]",
      "mdoc-crypto = [",
      "\"reallyme-crypto/dispatch\"",
      "\"reallyme-crypto/ed25519\"",
      "\"reallyme-crypto/p256\"",
      "\"reallyme-crypto/p384\"",
      "\"reallyme-crypto/p521\"",
      "\"reallyme-crypto/secp256k1\"",
      "\"reallyme-crypto/sha2\"",
    ],
  ],
];

const fail = (message) => {
  console.error(`release readiness check failed: ${message}`);
  process.exit(1);
};

const readText = (path) => readFileSync(resolve(root, path), "utf8");

const headerPolicyExtensions = new Set([
  ".js",
  ".mjs",
  ".proto",
  ".rs",
  ".sh",
  ".toml",
  ".ts",
  ".yaml",
  ".yml",
]);

const byteExactUpstreamVectorPrefixes = [
  "vectors/ietf-sd-jwt/",
  "vectors/sd-jwt-rfc9901/",
];

const findHeaderPolicyFiles = (relativeDir = "") => {
  const absoluteDir = resolve(root, relativeDir);
  const files = [];

  for (const entry of readdirSync(absoluteDir)) {
    if ([".git", ".release-readiness", "target", "node_modules"].includes(entry)) {
      continue;
    }
    const relativeEntry = relativeDir.length === 0 ? entry : `${relativeDir}/${entry}`;
    const absoluteEntry = resolve(root, relativeEntry);
    if (statSync(absoluteEntry).isDirectory()) {
      if (
        byteExactUpstreamVectorPrefixes.some(
          (prefix) => `${relativeEntry}/` === prefix,
        )
      ) {
        // Imported conformance vectors retain their upstream bytes so their
        // recorded digests and cross-repository provenance remain meaningful.
        continue;
      }
      files.push(...findHeaderPolicyFiles(relativeEntry));
      continue;
    }

    const extensionIndex = entry.lastIndexOf(".");
    const extension = extensionIndex === -1 ? "" : entry.slice(extensionIndex);
    if (
      headerPolicyExtensions.has(extension) &&
      !relativeEntry.includes("/src/generated/buffa/")
    ) {
      files.push(relativeEntry);
    }
  }

  return files;
};

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

const findRustSources = (relativeDir) => {
  const absoluteDir = resolve(root, relativeDir);
  if (!existsSync(absoluteDir)) {
    return [];
  }

  const sources = [];
  for (const entry of readdirSync(absoluteDir)) {
    const relativeEntry = `${relativeDir}/${entry}`;
    const absoluteEntry = resolve(root, relativeEntry);
    if (statSync(absoluteEntry).isDirectory()) {
      sources.push(...findRustSources(relativeEntry));
    } else if (entry.endsWith(".rs")) {
      sources.push(relativeEntry);
    }
  }
  return sources;
};

const focusedSourceContinuations = new Map([
  [
    "crates/proto-codec/src/lib.rs",
    findRustSources("crates/proto-codec/src"),
  ],
]);

const rustIncludePattern = /^include!\("([^"]+)"\);$/gm;

const readExpandedRustSource = (path, visited = new Set()) => {
  if (visited.has(path)) {
    fail(`Rust source include cycle contains ${path}`);
  }
  const nextVisited = new Set(visited);
  nextVisited.add(path);
  return readText(path).replace(rustIncludePattern, (_, includedPath) => {
    const resolvedPath = resolve(dirname(resolve(root, path)), includedPath);
    const relativePath = resolvedPath.slice(root.length + 1).replaceAll("\\", "/");
    return readExpandedRustSource(relativePath, nextVisited);
  });
};

const assertContains = (path, needle) => {
  const sourcePaths = [path, ...(focusedSourceContinuations.get(path) ?? [])];
  if (
    !sourcePaths.some((sourcePath) =>
      (sourcePath.endsWith(".rs") ? readExpandedRustSource(sourcePath) : readText(sourcePath)).includes(
        needle,
      ),
    )
  ) {
    fail(`${sourcePaths.join(" or ")} does not contain ${needle}`);
  }
};

const assertNotContains = (path, needle) => {
  const sourcePaths = [path, ...(focusedSourceContinuations.get(path) ?? [])];
  if (
    sourcePaths.some((sourcePath) =>
      (sourcePath.endsWith(".rs") ? readExpandedRustSource(sourcePath) : readText(sourcePath)).includes(
        needle,
      ),
    )
  ) {
    fail(`${sourcePaths.join(" or ")} unexpectedly contains ${needle}`);
  }
};

const assertExists = (path) => {
  if (!existsSync(resolve(root, path))) {
    fail(`${path} is missing`);
  }
};

const assertMissing = (path) => {
  if (existsSync(resolve(root, path))) {
    fail(`${path} is retired and must not be restored`);
  }
};

const parsePackageName = (manifestPath) => {
  const match = readText(manifestPath).match(/^name = "([^"]+)"$/m);
  if (!match) {
    fail(`${manifestPath} is missing a package name`);
  }
  return match[1];
};

const packageRoot = (manifestPath) => dirname(manifestPath);

for (const line of requiredWorkspaceLintLines) {
  assertContains("Cargo.toml", line);
}

assertContains("Cargo.toml", 'rust-version = "1.96"');
assertContains("Cargo.toml", 'panic = "abort"');
assertContains("Cargo.toml", 'license = "MIT OR Apache-2.0"');

assertContains("Cargo.toml", 'publish = false');
assertContains("Cargo.toml", 'repository = "https://github.com/reallyme/ssi"');
assertExists("LICENSE-MIT");
assertExists("LICENSE-APACHE");
assertMissing("LICENSE");
assertMissing("NOTICE");

const apacheOnlySources = new Set([
  "crates/credential/vc/ietf-sd-jwt/tests/demos.rs",
  "crates/credential/vc/ietf-sd-jwt/tests/utils/fixtures.rs",
  "crates/credential/vc/ietf-sd-jwt/tests/utils/mod.rs",
]);
const thirdPartyOnlySource =
  "crates/credential/vc/ietf-sd-jwt/tests/utils/mod.rs";
const vendoredReleaseReadinessCore = "scripts/release-readiness/core.mjs";
assertNoDocumentationSpdxHeaders();
for (const path of findHeaderPolicyFiles()) {
  const source = readText(path);
  const sourceLines = source.split("\n");
  const headerRegion = sourceLines.slice(0, 40).join("\n");
  const expectedCopyright =
    path === vendoredReleaseReadinessCore
      ? "SPDX-FileCopyrightText: 2026 ReallyMe LLC"
      : path === thirdPartyOnlySource
      ? "SPDX-FileCopyrightText: Copyright (c) 2024 DSR Corporation, Denver, Colorado."
      : "SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved";
  const expectedLicense = apacheOnlySources.has(path)
    ? "SPDX-License-Identifier: Apache-2.0"
    : "SPDX-License-Identifier: MIT OR Apache-2.0";

  if (!headerRegion.includes(expectedCopyright)) {
    fail(`${path} is missing the required SPDX copyright header`);
  }
  const expectedCopyrightLine = source.startsWith("<!--") || source.startsWith("#!") ? 1 : 0;
  if (!sourceLines[expectedCopyrightLine]?.includes(expectedCopyright)) {
    fail(`${path} must place its SPDX copyright at the canonical header position`);
  }
  if (!headerRegion.includes(expectedLicense)) {
    fail(`${path} is missing the required SPDX license expression`);
  }
}

assertContains("Cargo.toml", '"crates/ssi"');
assertExists("crates/proto/Cargo.toml");
assertMissing("crates/identity-core");
assertMissing("crates/vp");
assertMissing("crates/proto/identity-codec");
assertMissing("crates/did/core/proto");
assertMissing("crates/presentation/proto");
assertContains("Cargo.toml", '"crates/envelopes/data_integrity"');
assertContains("Cargo.toml", '"crates/envelopes/sd_jwt"');
assertContains("Cargo.toml", '"crates/trust/x509"');

for (const manifestPath of requiredInternalManifests) {
  assertExists(manifestPath);
}

for (const manifestPath of forbiddenRetiredManifests) {
  assertMissing(manifestPath);
}

for (const manifestPath of publicPackageManifests) {
  const manifest = readText(manifestPath);
  const name = parsePackageName(manifestPath);
  const rootPath = packageRoot(manifestPath);

  if (!name.startsWith("reallyme-")) {
    fail(`${manifestPath} package name must be namespaced with reallyme-`);
  }

  if (manifest.includes("publish = true") && !approvedPublicPackages.has(name)) {
    fail(`${name} is public but is not in the approved public package set`);
  }

  if (!manifest.includes("include = [")) {
    fail(`${manifestPath} must define an anchored package include allowlist`);
  }
  for (const expectedEntry of requiredPackageIncludeEntries) {
    if (!manifest.includes(expectedEntry)) {
      fail(`${manifestPath} package include allowlist omits ${expectedEntry}`);
    }
  }

  for (const file of ["README.md", "LICENSE-MIT", "LICENSE-APACHE"]) {
    assertExists(`${rootPath}/${file}`);
  }
  for (const licenseFile of ["LICENSE-MIT", "LICENSE-APACHE"]) {
    if (readText(`${rootPath}/${licenseFile}`) !== readText(licenseFile)) {
      fail(`${rootPath}/${licenseFile} must match the repository license file exactly`);
    }
  }
}

for (const manifestPath of findCargoManifests("crates")) {
  const manifest = readText(manifestPath);
  const name = parsePackageName(manifestPath);

  if (
    !manifest.includes("license.workspace = true") &&
    !manifest.includes('license = "MIT OR Apache-2.0"')
  ) {
    fail(`${manifestPath} must use the repository dual-license expression`);
  }

  if (!manifest.includes("[lints]") || !manifest.includes("workspace = true")) {
    fail(`${manifestPath} must inherit workspace lints`);
  }

  if (manifest.includes("publish = true") && !approvedPublicPackages.has(name)) {
    fail(`${name} is public but is not in the approved public package set`);
  }

  for (const featureName of forbiddenRustFeatureNames) {
    if (featureName.test(manifest)) {
      fail(`${manifestPath} must not expose swift/kotlin Rust cargo features`);
    }
  }
}

for (const [manifestPath, needles] of requiredCryptoFeatureBundles) {
  for (const needle of needles) {
    assertContains(manifestPath, needle);
  }
}

const rootManifest = readText("Cargo.toml");
if (/^\[package\]$/mu.test(rootManifest)) {
  fail("Cargo.toml must remain a virtual workspace manifest");
}
for (const retiredRoot of ["src", "tests", "protos", "bindings", "gen", "packages", "examples"]) {
  assertMissing(retiredRoot);
}
assertExists("crates/ssi/src/lib.rs");
assertContains("crates/ssi/Cargo.toml", 'name = "reallyme-ssi"');
assertContains("crates/did/core/common/Cargo.toml", 'name = "reallyme-ssi-core"');
assertContains(
  "crates/did/core/common/tests/registry_tests.rs",
  "use reallyme_ssi_core::",
);

const ci = readText(".github/workflows/rust-ci.yml");
for (const needle of requiredCiNeedles) {
  if (!ci.includes(needle)) {
    fail(`rust-ci.yml does not contain ${needle}`);
  }
}
const rustCiMarkdownIgnoreCount = ci.match(/- "\*\*\/\*\.md"/gu)?.length ?? 0;
if (rustCiMarkdownIgnoreCount !== 2) {
  fail("rust-ci.yml must ignore Markdown-only pushes and pull requests");
}
const allFeaturesCheckCount =
  ci.match(/cargo check --locked --workspace --all-features/gu)?.length ?? 0;
if (allFeaturesCheckCount !== 1) {
  fail("rust-ci.yml must run the all-features workspace check exactly once");
}

for (const workflow of [
  ".github/workflows/rust-ci.yml",
  ".github/workflows/crates-package-preflight.yml",
]) {
  assertContains(workflow, "path: reallyme/ssi");
  assertNotContains(workflow, "repository: reallyme/zk");
  assertContains(workflow, "working-directory: reallyme/ssi");
  if (readText(workflow).includes("repository: reallyme/crypto")) {
    fail(`${workflow} must use published ReallyMe Crypto crates, not a sibling checkout`);
  }
}
assertContains(".github/workflows/rust-ci.yml", "repository: me-id/protos");
assertContains(".github/workflows/rust-ci.yml", "path: me-id/protos");
assertContains(
  ".github/workflows/rust-ci.yml",
  "sh scripts/install-xmlsec-linux.sh \"${RUNNER_TEMP}/xmlsec\"",
);
assertContains(
  ".github/workflows/rust-ci.yml",
  'echo "PKG_CONFIG_PATH=${RUNNER_TEMP}/xmlsec/lib/pkgconfig" >> "${GITHUB_ENV}"',
);
assertContains(
  ".github/workflows/rust-ci.yml",
  'echo "LD_LIBRARY_PATH=${RUNNER_TEMP}/xmlsec/lib" >> "${GITHUB_ENV}"',
);
assertContains("scripts/install-xmlsec-linux.sh", 'readonly XMLSEC_VERSION="1.3.12"');
assertContains("scripts/install-xmlsec-linux.sh", "--disable-crypto-dl");
assertContains(
  "scripts/install-xmlsec-linux.sh",
  'readonly XMLSEC_ARCHIVE_SHA256="24045199af12d93fe5fdbbbf7e386e823e4842071e9432e2b90ac108b889a923"',
);
assertNotContains(".github/workflows/crates-package-preflight.yml", "repository: me-id/protos");
assertNotContains(".github/workflows/crates-package-preflight.yml", "Install XMLSec");
assertContains(".github/workflows/fuzz.yml", "path: reallyme/ssi");
assertNotContains(".github/workflows/fuzz.yml", "repository: reallyme/zk");
assertContains(".github/workflows/fuzz.yml", "working-directory: reallyme/ssi");
const fuzzCi = readText(".github/workflows/fuzz.yml");
const fuzzMarkdownIgnoreCount = fuzzCi.match(/- "!\*\*\/\*\.md"/gu)?.length ?? 0;
if (fuzzMarkdownIgnoreCount !== 2) {
  fail("fuzz.yml must ignore Markdown-only pushes and pull requests");
}

assertContains(
  ".github/workflows/rust-ci.yml",
  "cargo install protoc-gen-buffa --version 0.9.2 --locked",
);
assertContains(
  ".github/workflows/rust-ci.yml",
  "cargo install protoc-gen-buffa-packaging --version 0.9.2 --locked",
);
assertContains("Cargo.toml", 'buffa = { version = "0.9.2"');
assertContains("Cargo.toml", 'buffa-types = { version = "0.9.2"');
assertContains(".gitignore", "!crates/proto/src/generated/**");
assertContains("buf.gen.yaml", "clean: true");
assertContains("buf.gen.yaml", "strategy: all");
assertContains("buf.gen.yaml", "views=true");
assertContains("buf.gen.yaml", "json=true");
assertContains(
  "crates/proto/proto/identity/presentation/v1/presentation.proto",
  "debug_redact = true",
);
assertContains(
  "crates/proto/tests/presentation_generated_security_tests.rs",
  "sd_jwt_debug_is_redacted",
);
assertContains(
  "crates/proto-codec/src/presentation/own_presentation_proto.rs",
  "impl ZeroizeOnDrop for SensitivePresentationProto",
);
assertContains(
  "crates/presentation/core/src/protect_model.rs",
  "impl_zeroize_on_drop!(",
);
assertMissing("crates/proto-codec/vectors");
assertMissing("protos");

const rustSourcePaths = findRustSources("crates");
const includedRustSourcePaths = new Set();
for (const sourcePath of rustSourcePaths) {
  for (const match of readText(sourcePath).matchAll(rustIncludePattern)) {
    const resolvedPath = resolve(dirname(resolve(root, sourcePath)), match[1]);
    includedRustSourcePaths.add(resolvedPath.slice(root.length + 1).replaceAll("\\", "/"));
  }
}
for (const sourcePath of rustSourcePaths) {
  if (includedRustSourcePaths.has(sourcePath)) {
    continue;
  }
  const source = readExpandedRustSource(sourcePath);
  const manualMarkers = source.matchAll(
    /impl ZeroizeOnDrop for ([A-Za-z0-9_$]+) \{\}/g,
  );
  for (const marker of manualMarkers) {
    const typeName = marker[1];
    if (!source.includes(`impl Drop for ${typeName} {`)) {
      fail(
        `${sourcePath} marks ${typeName} as ZeroizeOnDrop without a destructor that performs cleanup`,
      );
    }
  }
}
assertContains(
  "crates/presentation/core/src/model.rs",
  "Presentation models deliberately do not implement Serde",
);
assertContains(
  "crates/presentation/api/src/commands.rs",
  "pub struct PresentationVerifyRequest",
);
assertContains(
  "crates/proto/proto/identity/credential/v1/subject_bundle.proto",
  "debug_redact = true",
);
assertContains(
  "crates/proto/proto/identity/audit/v1/audit.proto",
  "debug_redact = true",
);
assertContains("buf.gen.yaml", "exclude_package=.reallyme.crypto.v1");
assertContains("scripts/generate-protos.sh", "--include-imports");
assertExists(
  "crates/proto/src/generated/buffa/identity.did.v1.did.rs",
);
assertExists(
  "crates/proto/src/generated/buffa/meid.did.v1.did.rs",
);
assertMissing(
  "crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.rs",
);
assertContains(
  "crates/did/core/api/src/resolve.rs",
  "impl ZeroizeOnDrop for SensitiveDidResolutionResult",
);
assertContains(
  "crates/did/core/api/src/resolve.rs",
  "fn supports_capability",
);
assertContains(
  "crates/did/core/api/src/commands.rs",
  "impl ZeroizeOnDrop for SensitiveDidCreatedDocument",
);
assertContains(
  "crates/did/core/api/src/commands.rs",
  "impl ZeroizeOnDrop for SensitiveDidUpdatedDocument",
);
assertContains(
  "crates/did/core/api/src/commands.rs",
  "impl ZeroizeOnDrop for SensitiveDidDeactivatedDocument",
);
assertContains(
  "crates/did/core/api/src/commands.rs",
  "impl ZeroizeOnDrop for SensitiveDidRotatedDocument",
);
assertContains(
  "crates/did/core/api/src/commands.rs",
  "impl ZeroizeOnDrop for DidRotateRelationshipKeysDocumentRequest",
);
assertContains(
  "crates/did/core/api/src/commands.rs",
  "impl ZeroizeOnDrop for DidReplaceCompromisedKeysRequest",
);
assertContains(
  "crates/did/core/api/src/commands.rs",
  "impl ZeroizeOnDrop for DidRotateAllDocumentKeysRequest",
);
assertContains(
  "crates/did/core/api/src/commands.rs",
  "impl ZeroizeOnDrop for DidSetKeyRelationshipsDocumentRequest",
);
assertContains(
  "crates/did/core/api/src/messaging.rs",
  "impl ZeroizeOnDrop for MessagingPreKeySnapshot",
);
assertContains(
  "crates/did/core/api/src/commands.rs",
  "impl ZeroizeOnDrop for DidDesignateMessagingPreKeysRequest",
);
assertContains(
  "crates/did/core/api/src/commands.rs",
  "impl ZeroizeOnDrop for DidRotateMessagingPreKeysRequest",
);
assertContains(
  "crates/proto/src/zeroize_credential.rs",
  "pub fn zeroize_credential_envelope",
);
assertContains(
  "crates/presentation/api/src/commands.rs",
  "impl ZeroizeOnDrop for PresentationRequestCreateRequest",
);
assertContains(
  "crates/proto/src/zeroize_did.rs",
  "impl Zeroize for pb::DIDDocument",
);
assertContains(
  "crates/proto-codec/src/did/sensitive_document.rs",
  "impl ZeroizeOnDrop for SensitiveDidDocument",
);
assertContains(
  "crates/did/core/engine/src/validate/did_document.rs",
  "impl Drop for FullValidationResult",
);
assertMissing("crates/dispatch");
assertMissing("crates/provider");
assertMissing("crates/proto/proto/reallyme/identity/v1");
assertMissing("crates/proto-codec/src/operation");
assertContains(
  "scripts/check-protos-fresh.sh",
  "generated bindings are ignored and cannot be freshness-checked",
);

assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "node .release-readiness/scripts/run-consumer-check.mjs",
);
assertExists("scripts/check-shared-dependency-boundaries.mjs");
assertContains(
  ".github/workflows/rust-ci.yml",
  "node scripts/check-shared-dependency-boundaries.mjs",
);
assertExists("scripts/run_bounded_nextest.mjs");
for (const needle of requiredBoundedNextestNeedles) {
  assertContains("scripts/run_bounded_nextest.mjs", needle);
}
assertContains(
  ".github/workflows/rust-ci.yml",
  "repository: reallyme/release-readiness",
);
assertContains(
  ".github/workflows/rust-ci.yml",
  "ref: 985cf16f866bcdbd384edd8a9b6f332b38c5eb52",
);
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "ref: 985cf16f866bcdbd384edd8a9b6f332b38c5eb52",
);
assertContains(
  "scripts/run_pinned_release_readiness.mjs",
  'const RELEASE_READINESS_COMMIT = "985cf16f866bcdbd384edd8a9b6f332b38c5eb52";',
);
assertContains(
  "scripts/run_pinned_release_readiness.mjs",
  '"6bf50e9e5e55805191217c39e4291067d227a197ea46ab3d371d308f3f878a20"',
);
assertExists(".github/workflows/crates-package-preflight.yml");
assertExists(".github/workflows/crates-release.yml");
assertExists(".github/workflows/secret-scan.yml");
assertExists(".gitleaksignore");
assertExists("scripts/run_gitleaks.sh");
const releaseWorkflow = ".github/workflows/crates-release.yml";
const packagePreflightWorkflow = ".github/workflows/crates-package-preflight.yml";
const secretScanWorkflow = ".github/workflows/secret-scan.yml";
const releaseVersionMatch = readText("crates/proto/Cargo.toml").match(
  /^version = "([^"]+)"$/m,
);
if (releaseVersionMatch?.[1] === undefined) {
  fail("crates/proto/Cargo.toml has no unambiguous package version");
}
const releaseVersion = releaseVersionMatch[1];

// Keep the operator-facing release flow and its fail-closed authorization
// boundary aligned with reallyme/cose. Repository-specific package gates may
// differ, but the two manual buttons, reviewed attestation, secret, and
// finalization mechanics must not drift.
assertContains(packagePreflightWorkflow, "name: Crates Package Preflight");
assertContains(
  packagePreflightWorkflow,
  "run-name: Crates package preflight ${{ inputs.version }} @ ${{ github.sha }}",
);
assertContains(packagePreflightWorkflow, "workflow_dispatch:");
assertContains(packagePreflightWorkflow, "version:");
assertContains(packagePreflightWorkflow, `default: ${releaseVersion}`);
assertContains(
  packagePreflightWorkflow,
  "group: crates-package-preflight-${{ inputs.version }}-${{ github.sha }}",
);
assertContains(packagePreflightWorkflow, "verify-source-sha:");
assertContains(packagePreflightWorkflow, "crates-package:");
assertContains(packagePreflightWorkflow, "runs-on: ubuntu-24.04");
assertNotContains(packagePreflightWorkflow, "runs-on: ubuntu-latest");
assertContains(packagePreflightWorkflow, "ref: ${{ github.sha }}");
assertContains(packagePreflightWorkflow, "fetch-depth: 0");
assertContains(packagePreflightWorkflow, "persist-credentials: false");
assertContains(packagePreflightWorkflow, "node-version: '24'");
assertContains(packagePreflightWorkflow, "toolchain: 1.98.1");
assertContains(packagePreflightWorkflow, "node scripts/verify_release_source.mjs");
assertContains(packagePreflightWorkflow, "node scripts/write_release_attestation.mjs");
assertContains(packagePreflightWorkflow, "run: scripts/run_gitleaks.sh");
assertContains(packagePreflightWorkflow, "uses: actions/upload-artifact@");
assertContains(
  packagePreflightWorkflow,
  "reallyme-ssi-crates-preflight-${{ inputs.version }}-${{ github.sha }}",
);
for (const duplicatedCiCommand of [
  "cargo fmt --check",
  "scripts/lint-protos.sh",
  "scripts/check-proto-contract.sh",
  "scripts/check-protos-fresh.sh",
  "scripts/check-proto-first-boundaries.mjs",
  "scripts/check-shared-dependency-boundaries.mjs",
  "scripts/check_conformance_coverage.mjs",
  "cargo check --locked --workspace",
  "cargo clippy",
  "scripts/run_bounded_nextest.mjs",
  "cargo doc",
  "cargo deny check",
  "node --test scripts/*.test.mjs",
  "cargo-fuzz",
  "protoc-gen-buffa",
  "wasm-bindgen-cli",
  "wasm-pack",
]) {
  assertNotContains(packagePreflightWorkflow, duplicatedCiCommand);
}

assertContains(releaseWorkflow, "name: Crates.io Release");
assertContains(releaseWorkflow, "run-name: Crates.io release @ ${{ github.sha }}");
assertContains(releaseWorkflow, "workflow_dispatch:");
assertNotContains(releaseWorkflow, "${{ inputs.");
assertContains(releaseWorkflow, "group: crates-release-${{ github.sha }}");
assertContains(
  releaseWorkflow,
  "group: crates-release-${{ needs.verify-preflight.outputs.release_version }}-${{ needs.verify-preflight.outputs.release_sha }}",
);
assertContains(releaseWorkflow, "if: github.ref == 'refs/heads/main'");
assertContains(releaseWorkflow, "actions: read");
assertContains(releaseWorkflow, "runs-on: ubuntu-24.04");
assertNotContains(releaseWorkflow, "runs-on: ubuntu-latest");
assertContains(releaseWorkflow, "environment: crates-io");
assertContains(releaseWorkflow, "verify-preflight:");
assertContains(releaseWorkflow, "ref: ${{ github.sha }}");
assertContains(releaseWorkflow, "persist-credentials: false");
assertContains(releaseWorkflow, "node-version: '24'");
assertContains(releaseWorkflow, "toolchain: 1.98.1");
assertContains(releaseWorkflow, "RELEASE_SOURCE_DERIVE_VERSION: '1'");
assertContains(releaseWorkflow, "RELEASE_ATTESTATION_RESOLVE_ONLY: '1'");
assertContains(releaseWorkflow, "uses: actions/download-artifact@");
assertContains(
  releaseWorkflow,
  "reallyme-ssi-crates-preflight-${{ steps.verify-source.outputs.release_version }}-${{ steps.verify-source.outputs.release_sha }}",
);
assertContains(
  releaseWorkflow,
  "run-id: ${{ steps.resolve-attestation.outputs.preflight_run_id }}",
);
assertContains(
  releaseWorkflow,
  "CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}",
);
assertNotContains(releaseWorkflow, "id-token: write");
assertNotContains(releaseWorkflow, "rust-lang/crates-io-auth-action");
assertNotContains(releaseWorkflow, "steps.crates-io-auth.outputs.token");
assertNotContains(releaseWorkflow, "dry-run:");
assertNotContains(releaseWorkflow, "node scripts/publish_crates_in_order.mjs inspect");
assertNotContains(releaseWorkflow, "cargo nextest run");
assertContains(releaseWorkflow, 'tag="reallyme-ssi-v${RELEASE_VERSION}"');
assertContains(
  releaseWorkflow,
  `if resolved_commit="$(gh api "repos/$GITHUB_REPOSITORY/commits/$tag" --jq '.sha' 2>/dev/null)"; then`,
);
assertNotContains(releaseWorkflow, "git push");
assertContains(releaseWorkflow, 'gh api --method POST "repos/$GITHUB_REPOSITORY/git/refs"');
assertContains(releaseWorkflow, "gh release create");
assertContains(releaseWorkflow, "RELEASE_TAG: ${{ steps.release-tag.outputs.tag }}");
assertNotContains(releaseWorkflow, "--generate-notes");
assertContains(
  packagePreflightWorkflow,
  "node scripts/publish_crates_in_order.mjs inspect",
);
assertContains(
  packagePreflightWorkflow,
  "node scripts/write_release_attestation.mjs",
);
assertContains(
  releaseWorkflow,
  "node scripts/verify_release_attestation.mjs",
);
assertContains(
  releaseWorkflow,
  "node scripts/publish_crates_in_order.mjs publish",
);
assertContains("scripts/publish_crates_in_order.mjs", "Publish order");
assertContains(
  "scripts/publish_crates_in_order.mjs",
  "workspace publish dependency cycle",
);
assertContains("scripts/publish_crates_in_order.mjs", "REQUIRED_PUBLISH_ORDER_EDGES");
assertContains("scripts/publish_crates_in_order.mjs", "checkPathDependencyVersions();");
assertContains("scripts/publish_crates_in_order.mjs", "checkRequiredPublishOrderEdges();");
assertContains("scripts/publish_crates_in_order.mjs", "checkReleaseVersion();");
assertContains("scripts/publish_crates_in_order.mjs", 'const MODE_ORDER = "order";');
assertContains("scripts/publish_crates_in_order.mjs", '"--offline"');
assertContains("scripts/publish_crates_in_order.mjs", "CARGO_TARGET_DIR");
assertContains("scripts/publish_crates_in_order.mjs", "isEarlierWorkspaceDependency");
assertContains(
  "scripts/publish_crates_in_order.mjs",
  "dry-run reached unpublished ordered workspace dependencies",
);
assertContains("scripts/publish_crates_in_order.mjs", "retryAfterMs");
assertContains(
  "scripts/publish_crates_in_order.mjs",
  "verifyPublishedPackageMatches(pkg)",
);
assertContains(
  "scripts/publish_crates_in_order.mjs",
  'const publishedChecksum = createHash("sha256")',
);
assertContains("scripts/verify_release_source.mjs", "main:refs/remotes/origin/main");
assertContains("scripts/verify_release_source.mjs", "manifest-version-mismatch");
assertContains("scripts/verify_release_attestation.mjs", 'value.conclusion !== "success"');
assertContains("scripts/verify_release_attestation.mjs", 'value.event !== "workflow_dispatch"');
assertContains("scripts/verify_release_attestation.mjs", "attestation-input-mismatch");
assertContains("scripts/verify_release_attestation.mjs", "value.run_attempt !== 1");
assertContains("scripts/verify_release_attestation.mjs", "selectLatestPreflightRun");
assertContains("scripts/verify_release_attestation.mjs", "latest-preflight-run-not-successful");
assertContains("scripts/verify_release_attestation.mjs", "preflight-version-mismatch");
assertContains("scripts/verify_release_attestation.mjs", "preflight-run-id-changed");
assertContains("scripts/verify_release_attestation.mjs", 'const RUST_CI_WORKFLOW = "rust-ci.yml"');
assertContains("scripts/verify_release_attestation.mjs", "selectLatestRustCiRun");
assertContains("scripts/verify_release_attestation.mjs", "rust-ci-run-mismatch");
assertContains("scripts/write_release_attestation.mjs", "reallyme.ssi.crates_preflight.v2");
assertContains("scripts/write_release_attestation.mjs", "rust_ci_run_id");
assertContains(secretScanWorkflow, "workflow_dispatch:");
assertContains(secretScanWorkflow, "fetch-depth: 0");
assertContains(secretScanWorkflow, "persist-credentials: false");
assertContains(secretScanWorkflow, "run: scripts/run_gitleaks.sh");
const secretScanMarkdownIgnoreCount = readText(secretScanWorkflow).match(
  /- "\*\*\/\*\.md"/gu,
)?.length ?? 0;
if (secretScanMarkdownIgnoreCount !== 2) {
  fail("secret-scan.yml must ignore Markdown-only pushes and pull requests");
}
assertContains("scripts/run_gitleaks.sh", 'readonly GITLEAKS_VERSION="8.30.1"');
assertContains(
  "scripts/run_gitleaks.sh",
  'readonly GITLEAKS_ARCHIVE_SHA256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"',
);
assertContains("scripts/run_gitleaks.sh", "sha256sum --check --strict");
assertContains("scripts/run_gitleaks.sh", 'git --redact --no-banner --verbose .');
assertMissing(".github/workflows/release-preflight.yml");
assertExists("scripts/inspect_publishable_crates.mjs");
assertContains("scripts/inspect_publishable_crates.mjs", "reallyme-compression-brotli");
assertContains("scripts/inspect_publishable_crates.mjs", "reallyme-ssi-proto");
assertContains("scripts/inspect_publishable_crates.mjs", "reallyme-openid-oauth");
assertContains("scripts/inspect_publishable_crates.mjs", "reallyme-openid4vc-profiles");
assertContains("scripts/inspect_publishable_crates.mjs", "reallyme-disclosure-policy");
assertContains("scripts/inspect_publishable_crates.mjs", "reallyme-credential-status");
assertContains("scripts/inspect_publishable_crates.mjs", "reallyme-trust-x509");
assertContains("scripts/inspect_publishable_crates.mjs", "reallyme-mdoc");
assertContains("scripts/inspect_publishable_crates.mjs", "reallyme-sd-jwt");
assertExists(".github/workflows/fuzz.yml");
assertContains(".github/workflows/fuzz.yml", "cargo +nightly-2026-09-01 fuzz build");
for (const target of requiredFuzzTargets) {
  assertContains("fuzz/Cargo.toml", `name = "${target}"`);
  assertContains("fuzz/README.md", `\`${target}\``);
  assertContains(".github/workflows/fuzz.yml", target);
}
assertContains(".github/workflows/rust-ci.yml", "node scripts/check_conformance_coverage.mjs");
assertExists("scripts/generate_conformance_reports.mjs");
assertExists("conformance/dependencies.lock.json");
assertExists("scripts/generate_conformance_vectors.mjs");
assertExists("conformance/README.md");
assertExists("conformance/upstream/sources.lock");
assertExists("conformance/concepts.json");
assertExists("conformance/requirements/jose.json");
assertExists("conformance/requirements/oauth.json");
assertExists("conformance/requirements/identity-boundaries.json");
assertExists("conformance/requirements/compression.json");
assertExists("conformance/requirements/cose.json");
assertExists("conformance/requirements/credential.json");
assertExists("conformance/requirements/envelope-profiles.json");
assertExists("conformance/requirements/etsi-eaa.json");
assertExists("conformance/requirements/keys.json");
assertExists("conformance/requirements/jwt.json");
assertExists("conformance/requirements/jwt-vc.json");
assertExists("conformance/requirements/sd-jwt.json");
assertExists("conformance/requirements/mdoc.json");
assertExists("conformance/requirements/x509.json");
assertExists("conformance/requirements/status-revocation.json");
assertExists("conformance/requirements/did-data-integrity.json");
assertExists("conformance/requirements/audit-claims.json");
assertExists("conformance/requirements/vp.json");
assertExists("conformance/requirements/resource-limits.json");
assertExists("conformance/upstream/tests.json");
assertMissing("conformance/results");
assertExists("vectors/README.md");
assertExists("vectors/manifest.json");
assertExists("vectors/sd-jwt-compact.json");
assertExists("vectors/sd-jwt-json-serialization.json");
assertExists("vectors/mdoc-issuer-signed.json");
assertExists("vectors/resource-limits.json");
assertExists("docs/ARCHITECTURE.md");
assertContains("scripts/generate_conformance_reports.mjs", "--output-dir");
assertContains("scripts/generate_conformance_reports.mjs", "SSI source repository must be clean");
assertContains("scripts/generate_conformance_reports.mjs", "Cargo.lock does not resolve the pinned published crypto package");
assertContains("scripts/generate_conformance_reports.mjs", "reallyme.ssi.conformance.bundle.v1");
assertContains(
  "conformance/dependencies.lock.json",
  '"version": "0.3.9"',
);
assertContains(".github/workflows/crates-package-preflight.yml", "default: 0.2.0");
assertContains(".github/workflows/crates-package-preflight.yml", "Generate clean SSI conformance evidence");
assertContains(".github/workflows/crates-package-preflight.yml", "reallyme-ssi-conformance-${{ inputs.version }}-${{ github.sha }}");
assertContains(".github/workflows/crates-release.yml", "Download reviewed conformance evidence");
assertContains("docs/ARCHITECTURE.md", "Rust identity crates expose only `native` and `wasm`");
assertContains("docs/ARCHITECTURE.md", "cargo features named `swift` or `kotlin`");
assertContains("docs/ARCHITECTURE.md", "`crates/oauth` owns reusable OAuth substrate");
assertContains("docs/ARCHITECTURE.md", "endpoint orchestration, HTTP");
assertContains("docs/ARCHITECTURE.md", "[`reallyme/jose`](https://github.com/reallyme/jose)");
assertContains("docs/ARCHITECTURE.md", "[`reallyme/cose`](https://github.com/reallyme/cose)");
assertContains("docs/ARCHITECTURE.md", "`reallyme_ssi::credential::api`");
assertContains("docs/ARCHITECTURE.md", "generated-protobuf surfaces under the SSI facade");
assertContains("docs/ARCHITECTURE.md", "issuer-signed mdoc issuance and verification");
assertContains("docs/ARCHITECTURE.md", "SSI has no dependency on `reallyme/zk`");
assertContains("README.md", "Platform packaging is provided by ReallyMe Identity");
assertContains("README.md", "issuer-signed mdoc issuance and verification");
assertContains("README.md", "[`reallyme/jose`](https://github.com/reallyme/jose)");
assertContains("README.md", "[`reallyme/cose`](https://github.com/reallyme/cose)");
assertContains("README.md", "`reallyme_ssi::credential::api`");
assertContains("README.md", "`reallyme_ssi::delivery`");
assertContains("README.md", "`reallyme_ssi::trust`");
assertContains("README.md", "actions/workflows/rust-ci.yml/badge.svg");
assertNotContains("README.md", "[![crates.io");
assertNotContains("README.md", "img.shields.io/badge/crates.io");
assertContains("README.md", "actions/workflows/fuzz.yml/badge.svg");
assertMissing(".github/workflows/taxonomy-coverage.yml");
assertContains("conformance/README.md", "Concept Inventory");
assertContains("conformance/README.md", "every local Cargo manifest");
for (const staleLocalCrate of ["`crates/jose`", "`crates/cose`"]) {
  if (readText("README.md").includes(staleLocalCrate)) {
    fail(`README.md still describes ${staleLocalCrate} as a local crate`);
  }
  if (readText("docs/ARCHITECTURE.md").includes(staleLocalCrate)) {
    fail(`docs/ARCHITECTURE.md still describes ${staleLocalCrate} as a local crate`);
  }
}
assertContains("SECURITY.md", "security@really.me");
assertContains("crates/proto/README.md", "`identity.did.v1.DidDocument.context`");
assertContains("crates/proto/proto/identity/did/v1/did.proto", "Inline JSON-LD object contexts");
assertContains("crates/proto/tests/did_generated_tests.rs", "did_me_domain_verification_accepts_spec_wellknown_json_key");
assertContains("crates/proto/tests/did_generated_tests.rs", 'assert!(!object.contains_key("wellKnown"))');
assertContains("crates/envelopes/mdoc/tests/mdoc_tests.rs", "issues_and_verifies_issuer_signed_mdoc");
assertContains("crates/envelopes/mdoc/src/device_auth.rs", "validate_device_auth");
assertContains("crates/envelopes/mdoc/src/device_auth.rs", "DEVICE_AUTHENTICATION_CONTEXT");
assertContains("scripts/proto-workspace.sh", '"me-id/protos"');
assertContains("scripts/generate-protos.sh", "sync-did-crypto-proto-boundary.mjs");
assertContains(
  "scripts/sync-did-crypto-proto-boundary.mjs",
  "reallyme_crypto_proto::generated::proto::reallyme",
);
assertContains("scripts/proto-workspace.sh", '"me-id/protos"');
assertContains("scripts/check-proto-contract.sh", "reallyme.crypto.v1.CryptoAlgorithmIdentifier");
assertContains("scripts/check-proto-contract.sh", "reallyme.identity.common.v1");
assertContains("scripts/check-proto-contract.sh", "reallyme.identity_core.v1");
assertContains("Cargo.toml", 'reallyme-codec = { version = "=0.2.3"');
assertContains("Cargo.toml", 'reallyme-crypto = { version = "=0.3.9"');
assertContains("Cargo.toml", 'reallyme-crypto-proto = { version = "=0.3.9"');
assertContains("crates/proto/Cargo.toml", "reallyme-crypto-proto/generated");
assertContains("Cargo.toml", 'reallyme-cose = { version = "=0.2.5"');
assertContains("Cargo.toml", 'reallyme-jose = { version = "=0.4.0"');
assertContains("crates/envelopes/mdoc/Cargo.toml", "reallyme-cose = { workspace = true }");
assertContains("crates/envelopes/sd_jwt/Cargo.toml", "reallyme-jose = { workspace = true }");
assertContains("crates/envelopes/jwt_vc/Cargo.toml", "reallyme-jose = { workspace = true }");
assertContains("crates/proto/proto/identity/presentation/v1/presentation.proto", "message VpVerificationReport");
assertContains("crates/proto/proto/identity/presentation/v1/presentation.proto", "enum VpVerificationOutcome");
assertContains("crates/proto/proto/identity/presentation/v1/presentation.proto", "enum VpFailureClass");
assertContains("crates/presentation/api/src/report.rs", "to_proto_summary");
assertContains("crates/presentation/api/src/report.rs", "TryFrom<EnumValue<presentation_pb::VpFailureClass>>");
assertContains("crates/proto/proto/identity/trust/v1/trust.proto", "message TrustDecision");
assertContains("crates/proto/proto/identity/trust/v1/trust.proto", "enum TrustDecisionFailure");
assertContains("crates/proto/proto/identity/trust/v1/trust.proto", "enum AuthorizationPurpose");
assertContains("crates/trust/api/src/dto.rs", "TryFrom<EnumValue<trust_pb::TrustDecisionFailure>>");
assertContains("crates/trust/api/src/dto.rs", "impl From<&TrustDecision> for trust_pb::TrustDecision");
assertContains("scripts/check-protos-fresh.sh", "scripts/generate-protos.sh");
assertContains("scripts/check-protos-fresh.sh", "crates/proto/src/generated/buffa");
assertContains(
  "crates/proto/src/stack_error.rs",
  "identity_core_stack_error_from_enum_value",
);
assertContains(
  "crates/proto/src/stack_error.rs",
  "IDENTITY_STACK_ERROR_DOMAIN_IDENTITY_CORE",
);

console.log("release readiness checks passed");
