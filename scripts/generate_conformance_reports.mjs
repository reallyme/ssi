#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const fail = (reason) => {
  process.stderr.write(`conformance report generation failed: ${reason}\n`);
  process.exit(1);
};

const argumentsList = process.argv.slice(2);
if (argumentsList.length !== 2 || argumentsList[0] !== "--output-dir") {
  fail("expected --output-dir PATH");
}

const reportsDir = resolve(process.cwd(), argumentsList[1]);
const outputRelativeToRoot = relative(root, reportsDir);
if (
  outputRelativeToRoot === "" ||
  (!outputRelativeToRoot.startsWith("..") && outputRelativeToRoot !== "..")
) {
  fail("release evidence must be written outside the SSI source repository");
}
if (existsSync(reportsDir) && readdirSync(reportsDir).length !== 0) {
  fail("output directory must be absent or empty");
}

const readJson = (relativePath) =>
  JSON.parse(readFileSync(resolve(root, relativePath), "utf8"));

const git = (cwd, args) => {
  try {
    return execFileSync("git", args, {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    fail("required repository metadata is unavailable");
  }
};

const ssiCommit = git(root, ["rev-parse", "HEAD"]);
const ssiStatus = git(root, ["status", "--short", "--untracked-files=all"]);
const dependencyLock = readJson("conformance/dependencies.lock.json");
const cryptoDependency = dependencyLock?.dependencies?.["reallyme/crypto"];
if (
  dependencyLock?.schema !== "reallyme.identity.conformance.dependencies.v1" ||
  cryptoDependency?.source !== "crates.io" ||
  cryptoDependency?.package !== "reallyme-crypto" ||
  !/^\d+\.\d+\.\d+$/u.test(cryptoDependency?.version ?? "")
) {
  fail("conformance dependency lock is invalid");
}
if (ssiStatus) {
  fail("SSI source repository must be clean");
}

const metadata = JSON.parse(
  execFileSync("cargo", ["metadata", "--locked", "--format-version", "1", "--quiet"], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    stdio: ["ignore", "pipe", "inherit"],
  }),
);
const workspaceVersions = new Set(
  metadata.packages
    .filter((item) => metadata.workspace_members.includes(item.id))
    .map((item) => item.version),
);
if (workspaceVersions.size !== 1) {
  fail("workspace crates do not share one release version");
}
const [releaseVersion] = workspaceVersions;
const resolvedCrypto = metadata.packages.filter(
  (item) => item.name === cryptoDependency.package,
);
if (
  resolvedCrypto.length !== 1 ||
  resolvedCrypto[0].version !== cryptoDependency.version ||
  !resolvedCrypto[0].source?.startsWith("registry+")
) {
  fail("Cargo.lock does not resolve the pinned published crypto package");
}
const cargoLockSha256 = createHash("sha256")
  .update(readFileSync(resolve(root, "Cargo.lock")))
  .digest("hex");
const generatedAt = new Date().toISOString();
const sources = readJson("conformance/upstream/sources.lock").sources;
const upstream = readJson("conformance/upstream/tests.json").sources;
const conceptInventory = readJson("conformance/concepts.json").concepts;
const vectorManifest = readJson("vectors/manifest.json");
const fuzzTargets = [
  {
    id: "fuzz_claim_path",
    path: "fuzz/fuzz_targets/fuzz_claim_path.rs",
    concepts: ["claims"],
  },
  {
    id: "fuzz_claim_set",
    path: "fuzz/fuzz_targets/fuzz_claim_set.rs",
    concepts: ["claims"],
  },
  {
    id: "fuzz_mdoc_device_response",
    path: "fuzz/fuzz_targets/fuzz_mdoc_device_response.rs",
    concepts: ["mdoc"],
  },
  {
    id: "fuzz_sd_jwt_processing",
    path: "fuzz/fuzz_targets/fuzz_sd_jwt_processing.rs",
    concepts: ["sd-jwt"],
  },
  {
    id: "fuzz_status_list",
    path: "fuzz/fuzz_targets/fuzz_status_list.rs",
    concepts: ["status"],
  },
  {
    id: "fuzz_x509_trust_der",
    path: "fuzz/fuzz_targets/fuzz_x509_trust_der.rs",
    concepts: ["x509"],
  },
].filter((target) => existsSync(resolve(root, target.path)));
const requirementFiles = readdirSync(resolve(root, "conformance/requirements"))
  .filter((file) => file.endsWith(".json"))
  .sort();

const requirementsByFile = new Map();
for (const file of requirementFiles) {
  requirementsByFile.set(file, readJson(`conformance/requirements/${file}`));
}

const reportDefinitions = [
  {
    name: "identity-core",
    files: requirementFiles,
    enabledFormats: [
      "claims",
      "credential",
      "did:me",
      "data-integrity",
      "sd-jwt",
      "jwt-vc",
      "mso_mdoc",
      "cose",
      "jose",
      "jwk",
      "keys",
      "oauth-substrate",
      "x509",
      "status",
      "revocation",
      "audit-evidence",
      "envelope-profiles",
      "vp",
      "brotli-compression",
    ],
  },
  {
    name: "jose",
    files: ["jose.json", "jwk.json", "jwt.json"],
    enabledFormats: ["jws", "jwt", "jwe", "jwk"],
  },
  {
    name: "cose",
    files: ["cose.json"],
    enabledFormats: ["cose-sign1", "cose-key"],
  },
  {
    name: "compression",
    files: ["compression.json"],
    enabledFormats: ["brotli"],
  },
  {
    name: "did-data-integrity",
    files: ["did-data-integrity.json"],
    enabledFormats: ["did-core", "did:me", "data-integrity"],
  },
  {
    name: "keys",
    files: ["keys.json", "jwk.json", "did-data-integrity.json"],
    enabledFormats: ["key-set", "multikey", "verification-method"],
  },
  {
    name: "sd-jwt",
    files: ["sd-jwt.json"],
    enabledFormats: ["sd-jwt", "kb-jwt"],
  },
  {
    name: "jwt-vc",
    files: ["jwt-vc.json", "jwt.json"],
    enabledFormats: ["jwt-vc", "jwt"],
  },
  {
    name: "credential",
    files: ["credential.json"],
    enabledFormats: ["credential-envelope", "claims-commitment", "subject-private-bundle", "credential-proto"],
  },
  {
    name: "mdoc",
    files: ["mdoc.json"],
    enabledFormats: ["mso_mdoc", "device-response"],
  },
  {
    name: "envelope-profiles",
    files: ["envelope-profiles.json"],
    enabledFormats: ["openid4vc-profile", "eudi-pid-profile", "eudi-qeaa-profile", "did:me-profile"],
  },
  {
    name: "etsi-eaa",
    files: ["etsi-eaa.json"],
    enabledFormats: ["etsi-eaa", "sd-jwt-vc", "mso_mdoc", "json-ld-vc", "x509-attribute-certificate"],
  },
  {
    name: "w3c-vc",
    files: ["did-data-integrity.json", "status-revocation.json"],
    enabledFormats: ["data-integrity", "status-list"],
  },
  {
    name: "x509",
    files: ["x509.json"],
    enabledFormats: ["x509", "qcstatements", "tsl-policy"],
  },
  {
    name: "status",
    files: ["status-revocation.json"],
    enabledFormats: ["status-list", "revocation-evidence"],
  },
  {
    name: "attestations",
    files: ["audit-claims.json"],
    enabledFormats: ["qeaa-audit-evidence"],
  },
  {
    name: "vp",
    files: ["vp.json"],
    enabledFormats: ["vp-model", "vp-policy", "vp-proto", "vp-zk-reference"],
  },
  {
    name: "zk-binding",
    files: ["identity-boundaries.json"],
    enabledFormats: ["policy-derivation-planning"],
  },
];

const unique = (values) => [...new Set(values)].sort();

const recordsFor = (files) =>
  files.flatMap((file) => requirementsByFile.get(file) ?? []);

const conceptsFor = (files) => {
  const requirementPaths = new Set(
    files.map((file) => `conformance/requirements/${file}`),
  );
  return conceptInventory
    .filter((concept) =>
      concept.conformance_files.some((file) => requirementPaths.has(file)),
    )
    .map((concept) => ({
      id: concept.id,
      mapping_status: concept.mapping_status,
      publishing_role: concept.publishing.role,
      publishing_package: concept.publishing.package,
      publish_ready: concept.publishing.publish_ready,
      release_blocker: concept.release_blocker,
    }));
};

const fuzzConceptMatches = {
  claims: (definition) =>
    definition.enabledFormats.includes("claims") ||
    definition.files.includes("audit-claims.json"),
  credential: (definition) =>
    definition.enabledFormats.includes("credential") ||
    definition.enabledFormats.includes("credential-envelope") ||
    definition.enabledFormats.includes("credential-proto") ||
    definition.files.includes("credential.json"),
  mdoc: (definition) =>
    definition.enabledFormats.includes("mso_mdoc") ||
    definition.enabledFormats.includes("device-response") ||
    definition.files.includes("mdoc.json"),
  status: (definition) =>
    definition.enabledFormats.includes("status") ||
    definition.enabledFormats.includes("status-list") ||
    definition.enabledFormats.includes("revocation-evidence") ||
    definition.files.includes("status-revocation.json"),
  x509: (definition) =>
    definition.enabledFormats.includes("x509") ||
    definition.enabledFormats.includes("qcstatements") ||
    definition.enabledFormats.includes("tsl-policy") ||
    definition.files.includes("x509.json"),
};

const fuzzTargetApplies = (definition, target) =>
  definition.name === "identity-core" ||
  target.concepts.some((concept) => fuzzConceptMatches[concept]?.(definition));

const fuzzStatusFor = (definition) => {
  const targets = fuzzTargets.filter((target) =>
    fuzzTargetApplies(definition, target),
  );

  return {
    status: targets.length > 0 ? "wired" : "not-wired",
    targets,
  };
};

const buildReport = (definition) => {
  const records = recordsFor(definition.files);
  const applicable = records.filter((record) => record.applicable);
  const exclusions = records
    .filter((record) => !record.applicable)
    .map((record) => ({
      id: record.id,
      feature: record.feature,
      reason: record.exclusion_reason,
    }));

  return {
    schema: "reallyme.identity.conformance.report.v2",
    generated_at: generatedAt,
    release: {
      version: releaseVersion,
    },
    repository: {
      name: "reallyme/ssi",
      commit: ssiCommit,
      dirty: false,
    },
    dependencies: {
      "reallyme/crypto": {
        source: cryptoDependency.source,
        package: cryptoDependency.package,
        version: cryptoDependency.version,
        cargo_lock_sha256: cargoLockSha256,
      },
      "reallyme-jose": {
        source: "crates.io",
        version: "0.4.0",
      },
      "reallyme-cose": {
        source: "crates.io",
        version: "0.2.5",
      },
    },
    specification_sources: sources.map((source) => source.id),
    enabled_formats: definition.enabledFormats,
    enabled_algorithms: unique(
      applicable.flatMap((record) =>
        record.implementation.filter((item) =>
          item.includes("jose") ||
          item.includes("cose") ||
          item.includes("crypto") ||
          item.includes("data_integrity"),
        ),
      ),
    ),
    requirements: {
      files: definition.files,
      applicable: applicable.length,
      exclusions: exclusions.length,
      ids: records.map((record) => record.id),
    },
    concepts: conceptsFor(definition.files),
    positive_tests: unique(applicable.flatMap((record) => record.positive_tests)),
    negative_tests: unique(applicable.flatMap((record) => record.negative_tests)),
    upstream_vectors: upstream,
    conformance_vectors: vectorManifest.suites,
    fuzz_status: fuzzStatusFor(definition),
    mutation_status: "not-wired",
    unsupported_features: exclusions,
    statements: {
      local_format_validation_tests: "mapped",
      normative_requirement_tests: "partially-mapped",
      upstream_vectors: "mapped-where-available",
      eudi_interop_fixtures: "not-certified",
      formal_certification: "not-claimed",
    },
  };
};

mkdirSync(reportsDir, { recursive: true });

const reports = [];
for (const definition of reportDefinitions) {
  const report = buildReport(definition);
  const contents = `${JSON.stringify(report, null, 2)}\n`;
  const filename = `${definition.name}.json`;
  writeFileSync(
    resolve(reportsDir, filename),
    contents,
  );
  reports.push({
    path: filename,
    sha256: createHash("sha256").update(contents).digest("hex"),
  });
}

const bundle = {
  schema: "reallyme.ssi.conformance.bundle.v1",
  classification: "public",
  contains_runtime_data: false,
  generated_at: generatedAt,
  release: {
    version: releaseVersion,
  },
  repository: {
    name: "reallyme/ssi",
    url: "https://github.com/reallyme/ssi",
    commit: ssiCommit,
    dirty: false,
  },
  dependencies: {
    "reallyme/crypto": {
      source: cryptoDependency.source,
      package: cryptoDependency.package,
      version: cryptoDependency.version,
      cargo_lock_sha256: cargoLockSha256,
    },
  },
  reports,
};
writeFileSync(
  resolve(reportsDir, "manifest.json"),
  `${JSON.stringify(bundle, null, 2)}\n`,
);

console.log(`generated ${reports.length} conformance reports and one bundle manifest`);
