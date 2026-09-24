#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const requirementsDir = resolve(root, "conformance/requirements");

const fail = (message) => {
  console.error(`conformance coverage check failed: ${message}`);
  process.exit(1);
};

const readJson = (relativePath) => {
  const absolutePath = resolve(root, relativePath);
  try {
    return JSON.parse(readFileSync(absolutePath, "utf8"));
  } catch {
    fail(`${relativePath} is not valid JSON`);
  }
};

const requireArray = (record, field, path) => {
  const value = record[field];
  if (!Array.isArray(value)) {
    fail(`${path}:${record.id} field ${field} must be an array`);
  }
  return value;
};

if (!existsSync(resolve(root, "conformance/upstream/sources.lock"))) {
  fail("conformance/upstream/sources.lock is missing");
}

const sources = readJson("conformance/upstream/sources.lock");
if (!Array.isArray(sources.sources) || sources.sources.length === 0) {
  fail("conformance/upstream/sources.lock must list normative sources");
}
const sourceIds = new Set();
for (const source of sources.sources) {
  if (typeof source.id !== "string" || source.id.length === 0) {
    fail("conformance/upstream/sources.lock contains a source without an id");
  }
  if (sourceIds.has(source.id)) {
    fail(`source ${source.id} appears more than once`);
  }
  sourceIds.add(source.id);
}

const upstream = readJson("conformance/upstream/tests.json");
if (!Array.isArray(upstream.sources) || upstream.sources.length === 0) {
  fail("conformance/upstream/tests.json must list vector sources");
}
const upstreamTestNames = new Set();
for (const source of upstream.sources) {
  if (source.test_names === undefined) {
    continue;
  }
  if (!Array.isArray(source.test_names)) {
    fail("conformance/upstream/tests.json test_names fields must be arrays");
  }
  for (const testName of source.test_names) {
    if (typeof testName !== "string" || testName.length === 0) {
      fail("conformance/upstream/tests.json contains an invalid external test name");
    }
    upstreamTestNames.add(testName);
  }
}

const collectRustFiles = (relativeDir, files = []) => {
  const absoluteDir = resolve(root, relativeDir);
  if (!existsSync(absoluteDir)) {
    return files;
  }
  for (const entry of readdirSync(absoluteDir)) {
    if ([".git", "target", "node_modules"].includes(entry)) {
      continue;
    }
    const absolutePath = resolve(absoluteDir, entry);
    const stat = statSync(absolutePath);
    if (stat.isDirectory()) {
      collectRustFiles(`${relativeDir}/${entry}`, files);
    } else if (entry.endsWith(".rs")) {
      files.push(absolutePath);
    }
  }
  return files;
};

const findCargoManifests = (relativeDir, manifests = []) => {
  const absoluteDir = resolve(root, relativeDir);
  if (!existsSync(absoluteDir)) {
    return manifests;
  }
  for (const entry of readdirSync(absoluteDir)) {
    if ([".git", "target", "node_modules"].includes(entry)) {
      continue;
    }
    const relativeEntry = `${relativeDir}/${entry}`;
    const absoluteEntry = resolve(root, relativeEntry);
    const stat = statSync(absoluteEntry);
    if (stat.isDirectory()) {
      findCargoManifests(relativeEntry, manifests);
    } else if (entry === "Cargo.toml") {
      manifests.push(relativeEntry);
    }
  }
  return manifests;
};

const rustTestNames = new Set();
const rustFunctionPattern = /\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/g;
for (const file of [
  ...collectRustFiles("crates"),
  ...collectRustFiles("tests"),
]) {
  const source = readFileSync(file, "utf8");
  let match = rustFunctionPattern.exec(source);
  while (match !== null) {
    rustTestNames.add(match[1]);
    match = rustFunctionPattern.exec(source);
  }
}

const vectorManifest = readJson("vectors/manifest.json");
const vectorSuiteIds = new Set();
if (!Array.isArray(vectorManifest.suites)) {
  fail("vectors/manifest.json must list vector suites");
}
for (const suite of vectorManifest.suites) {
  if (typeof suite.id !== "string" || suite.id.length === 0) {
    fail("vectors/manifest.json contains a suite without an id");
  }
  vectorSuiteIds.add(suite.id);
}

const conceptInventory = readJson("conformance/concepts.json");
if (conceptInventory.schema !== "reallyme.identity.conformance.concepts.v1") {
  fail("conformance/concepts.json has an unexpected schema");
}
if (!Array.isArray(conceptInventory.concepts) || conceptInventory.concepts.length === 0) {
  fail("conformance/concepts.json must list identity concepts");
}

const allowedMappingStatuses = new Set([
  "section_by_section",
  "representative",
  "in_progress",
  "external_upstream",
  "not_applicable",
]);
const allowedPublishingRoles = new Set([
  "core_facade_candidate",
  "core_support_candidate",
  "core_support_published",
  "external_dependency",
  "sdk_public",
  "unpublished_internal",
  "not_applicable",
]);
const requirementFiles = new Set(
  readdirSync(requirementsDir)
    .filter((entry) => entry.endsWith(".json"))
    .map((entry) => `conformance/requirements/${entry}`),
);
const coveredManifests = new Map();
const conceptIds = new Set();
for (const concept of conceptInventory.concepts) {
  if (typeof concept.id !== "string" || concept.id.length === 0) {
    fail("conformance/concepts.json contains a concept without an id");
  }
  if (conceptIds.has(concept.id)) {
    fail(`concept ${concept.id} appears more than once`);
  }
  conceptIds.add(concept.id);

  for (const field of ["title", "owner"]) {
    if (typeof concept[field] !== "string" || concept[field].length === 0) {
      fail(`conformance/concepts.json:${concept.id} field ${field} is required`);
    }
  }

  for (const field of ["local_crates", "external_crates", "public_api", "conformance_files", "next_actions"]) {
    if (!Array.isArray(concept[field])) {
      fail(`conformance/concepts.json:${concept.id} field ${field} must be an array`);
    }
  }
  if (concept.local_crates.length === 0 && concept.external_crates.length === 0) {
    fail(`conformance/concepts.json:${concept.id} must name a local or external crate`);
  }
  if (concept.public_api.length === 0) {
    fail(`conformance/concepts.json:${concept.id} must name a public API surface`);
  }
  if (!allowedMappingStatuses.has(concept.mapping_status)) {
    fail(`conformance/concepts.json:${concept.id} has unsupported mapping_status ${concept.mapping_status}`);
  }
  if (concept.mapping_status !== "section_by_section" && concept.next_actions.length === 0) {
    fail(`conformance/concepts.json:${concept.id} must list next_actions until section-by-section coverage is complete`);
  }
  if (typeof concept.release_blocker !== "boolean") {
    fail(`conformance/concepts.json:${concept.id} field release_blocker must be boolean`);
  }
  if (typeof concept.publishing !== "object" || concept.publishing === null) {
    fail(`conformance/concepts.json:${concept.id} field publishing is required`);
  }
  if (!allowedPublishingRoles.has(concept.publishing.role)) {
    fail(`conformance/concepts.json:${concept.id} has unsupported publishing role ${concept.publishing.role}`);
  }
  if (typeof concept.publishing.package !== "string" || concept.publishing.package.length === 0) {
    fail(`conformance/concepts.json:${concept.id} publishing.package is required`);
  }
  if (typeof concept.publishing.publish_ready !== "boolean") {
    fail(`conformance/concepts.json:${concept.id} publishing.publish_ready must be boolean`);
  }
  if (typeof concept.publishing.notes !== "string" || concept.publishing.notes.length === 0) {
    fail(`conformance/concepts.json:${concept.id} publishing.notes is required`);
  }
  if (!concept.publishing.publish_ready && concept.next_actions.length === 0) {
    fail(`conformance/concepts.json:${concept.id} must list next_actions when publish_ready is false`);
  }

  for (const localCrate of concept.local_crates) {
    if (typeof localCrate !== "string" || localCrate.length === 0) {
      fail(`conformance/concepts.json:${concept.id} contains an invalid local_crates entry`);
    }
    if (!existsSync(resolve(root, localCrate))) {
      fail(`conformance/concepts.json:${concept.id} local crate ${localCrate} does not exist`);
    }
    coveredManifests.set(localCrate, concept.id);
  }
  for (const externalCrate of concept.external_crates) {
    if (typeof externalCrate !== "string" || externalCrate.length === 0) {
      fail(`conformance/concepts.json:${concept.id} contains an invalid external_crates entry`);
    }
  }
  for (const conformanceFile of concept.conformance_files) {
    if (!requirementFiles.has(conformanceFile)) {
      fail(`conformance/concepts.json:${concept.id} references unknown conformance file ${conformanceFile}`);
    }
  }
}

for (const manifest of findCargoManifests("crates")) {
  if (!coveredManifests.has(manifest)) {
    fail(`${manifest} is not assigned to a concept in conformance/concepts.json`);
  }
}

const assertKnownTest = (relativePath, record, testName) => {
  if (!rustTestNames.has(testName) && !vectorSuiteIds.has(testName) && !upstreamTestNames.has(testName)) {
    fail(`${relativePath}:${record.id} references unknown test or vector suite ${testName}`);
  }
};

const ids = new Set();
for (const file of readdirSync(requirementsDir).filter((entry) => entry.endsWith(".json"))) {
  const relativePath = `conformance/requirements/${file}`;
  const records = readJson(relativePath);
  if (!Array.isArray(records) || records.length === 0) {
    fail(`${relativePath} must contain requirement records`);
  }

  for (const record of records) {
    if (typeof record.id !== "string" || record.id.length === 0) {
      fail(`${relativePath} contains a requirement without an id`);
    }
    if (ids.has(record.id)) {
      fail(`${record.id} appears more than once`);
    }
    ids.add(record.id);

    for (const field of ["source", "section", "keyword", "feature"]) {
      if (typeof record[field] !== "string" || record[field].length === 0) {
        fail(`${relativePath}:${record.id} field ${field} is required`);
      }
    }
    if (!sourceIds.has(record.source)) {
      fail(`${relativePath}:${record.id} source ${record.source} is not pinned in conformance/upstream/sources.lock`);
    }
    if (typeof record.applicable !== "boolean") {
      fail(`${relativePath}:${record.id} field applicable must be boolean`);
    }

    const implementation = requireArray(record, "implementation", relativePath);
    const positiveTests = requireArray(record, "positive_tests", relativePath);
    const negativeTests = requireArray(record, "negative_tests", relativePath);
    for (const testName of [...positiveTests, ...negativeTests]) {
      assertKnownTest(relativePath, record, testName);
    }

    if (record.applicable) {
      if (implementation.length === 0) {
        fail(`${relativePath}:${record.id} applicable requirement has no implementation`);
      }
      if (positiveTests.length === 0 && negativeTests.length === 0) {
        fail(`${relativePath}:${record.id} applicable requirement has no tests`);
      }
      if (record.exclusion_reason !== null) {
        fail(`${relativePath}:${record.id} applicable requirement must not have an exclusion reason`);
      }
    } else if (typeof record.exclusion_reason !== "string" || record.exclusion_reason.length === 0) {
      fail(`${relativePath}:${record.id} inapplicable requirement must explain the exclusion`);
    }
  }
}

console.log(
  `conformance coverage checks passed for ${ids.size} requirements across ${conceptIds.size} concepts`,
);
