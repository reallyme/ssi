#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const fail = (message) => {
  process.stderr.write(`upstream conformance execution failed: ${message}\n`);
  process.exit(1);
};

const readJson = (path) => JSON.parse(readFileSync(resolve(root, path), "utf8"));

const git = (cwd, args) => {
  try {
    return execFileSync("git", args, {
      cwd,
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    fail(`Git metadata is unavailable for ${cwd}`);
  }
};

const sourceRoots = new Map();
let outputPath = null;
let verifyOnly = false;
for (let index = 2; index < process.argv.length; index += 1) {
  const argument = process.argv[index];
  if (argument === "--source") {
    const value = process.argv[index + 1];
    index += 1;
    const separator = value?.indexOf("=") ?? -1;
    if (separator <= 0 || separator === value.length - 1) {
      fail("--source requires PACKAGE=PATH");
    }
    sourceRoots.set(value.slice(0, separator), resolve(value.slice(separator + 1)));
  } else if (argument === "--output") {
    const value = process.argv[index + 1];
    index += 1;
    if (value === undefined || value.length === 0) {
      fail("--output requires a path");
    }
    outputPath = resolve(value);
  } else if (argument === "--verify-only") {
    verifyOnly = true;
  } else {
    fail(`unsupported argument ${argument}`);
  }
}

if (sourceRoots.size === 0) {
  fail("at least one --source PACKAGE=PATH is required");
}
if (!verifyOnly && outputPath === null) {
  fail("--output is required when executing upstream tests");
}
if (outputPath !== null) {
  const outputRelativeToRoot = relative(root, outputPath);
  if (outputRelativeToRoot === "" || (!outputRelativeToRoot.startsWith("..") && outputRelativeToRoot !== "..")) {
    fail("upstream execution results must be written outside the source repository");
  }
}

const manifest = readJson("conformance/upstream/tests.json");
if (manifest.schema !== "reallyme.identity.conformance.upstream.v2") {
  fail("upstream evidence manifest has an unexpected schema");
}

const requirementsByTest = new Map();
for (const file of readdirSync(resolve(root, "conformance/requirements"))) {
  if (!file.endsWith(".json")) {
    continue;
  }
  for (const requirement of readJson(`conformance/requirements/${file}`)) {
    for (const [field, polarity] of [
      ["positive_tests", "positive"],
      ["negative_tests", "negative"],
    ]) {
      for (const testName of requirement[field] ?? []) {
        const references = requirementsByTest.get(testName) ?? [];
        references.push({ requirement: requirement.id, polarity });
        requirementsByTest.set(testName, references);
      }
    }
  }
}

const externalSources = manifest.sources.filter(
  (source) => typeof source.path === "string" && source.path.startsWith("crates.io:"),
);
const executions = new Map();
for (const source of externalSources) {
  const execution = source.execution;
  const current = executions.get(execution.id);
  if (current === undefined) {
    executions.set(execution.id, { execution, sources: [source] });
  } else {
    current.sources.push(source);
  }
}

const testFunctionPattern = /#\[[^\]]*(?:test|wasm_bindgen_test)[^\]]*\][\s\S]*?\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/gu;
const results = [];

for (const { execution, sources } of executions.values()) {
  const sourceRoot = sourceRoots.get(execution.package);
  if (sourceRoot === undefined) {
    fail(`no source checkout was supplied for ${execution.package}`);
  }
  const commitType = git(sourceRoot, ["cat-file", "-t", execution.source_commit]);
  if (commitType !== "commit") {
    fail(`${execution.package} source commit is unavailable`);
  }

  const testPrefix = `${execution.crate_path}/tests/`;
  const files = git(sourceRoot, ["ls-tree", "-r", "--name-only", execution.source_commit, testPrefix])
    .split("\n")
    .filter((path) => path.endsWith(".rs"));
  const topLevelTestSources = new Map();
  for (const path of files) {
    const relativeTestPath = path.slice(testPrefix.length);
    if (!relativeTestPath.includes("/")) {
      topLevelTestSources.set(
        relativeTestPath.slice(0, -3),
        git(sourceRoot, ["show", `${execution.source_commit}:${path}`]),
      );
    }
  }
  const discovered = new Map();
  for (const path of files) {
    const relativeTestPath = path.slice(testPrefix.length);
    const firstComponent = relativeTestPath.split("/", 1)[0];
    let testBinary;
    if (firstComponent.endsWith(".rs")) {
      testBinary = firstComponent.slice(0, -3);
    } else if (topLevelTestSources.has(firstComponent)) {
      testBinary = firstComponent;
    } else {
      const owners = [...topLevelTestSources.entries()]
        .filter(([, sourceText]) =>
          sourceText.includes(`#[path = "${relativeTestPath}"]`) ||
          sourceText.includes(`"${firstComponent}/`) ||
          new RegExp(`\\bmod\\s+${firstComponent}\\s*;`, "u").test(sourceText),
        )
        .map(([name]) => name);
      if (owners.length !== 1) {
        fail(`cannot determine the test binary that owns ${path}`);
      }
      [testBinary] = owners;
    }
    const sourceText = git(sourceRoot, ["show", `${execution.source_commit}:${path}`]);
    let match = testFunctionPattern.exec(sourceText);
    while (match !== null) {
      const locations = discovered.get(match[1]) ?? [];
      locations.push({ path, test_binary: testBinary });
      discovered.set(match[1], locations);
      match = testFunctionPattern.exec(sourceText);
    }
  }

  const mappedTests = [];
  for (const source of sources) {
    for (const testName of source.test_names ?? []) {
      const locations = discovered.get(testName) ?? [];
      const accepted = locations.filter((location) =>
        execution.test_binaries.includes(location.test_binary),
      );
      if (accepted.length !== 1) {
        fail(
          `${execution.id} test ${testName} must resolve once in an approved test binary`,
        );
      }
      const requirementReferences = requirementsByTest.get(testName) ?? [];
      if (requirementReferences.length === 0) {
        fail(`${execution.id} test ${testName} is not mapped to a requirement polarity`);
      }
      mappedTests.push({
        name: testName,
        source: accepted[0].path,
        test_binary: accepted[0].test_binary,
        requirements: requirementReferences,
      });
    }
  }

  if (!verifyOnly) {
    const head = git(sourceRoot, ["rev-parse", "HEAD"]);
    const status = git(sourceRoot, ["status", "--short", "--untracked-files=all"]);
    if (head !== execution.source_commit || status.length !== 0) {
      fail(`${execution.package} checkout must be clean at the pinned source commit`);
    }
    const completed = spawnSync(execution.command[0], execution.command.slice(1), {
      cwd: sourceRoot,
      encoding: "utf8",
      stdio: "inherit",
    });
    if (completed.error !== undefined || completed.status !== 0) {
      fail(`${execution.id} test command did not pass`);
    }
  }

  results.push({
    id: execution.id,
    repository: execution.repository,
    source_commit: execution.source_commit,
    package: execution.package,
    version: execution.version,
    cargo_checksum: execution.cargo_checksum,
    command: execution.command,
    status: verifyOnly ? "source-verified" : "passed",
    mapped_tests: mappedTests,
  });
}

if (outputPath !== null) {
  const repositoryCommit = git(root, ["rev-parse", "HEAD"]);
  const repositoryStatus = git(root, ["status", "--short", "--untracked-files=all"]);
  if (repositoryStatus.length !== 0) {
    fail("SSI source repository must be clean before recording execution evidence");
  }
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(
    outputPath,
    `${JSON.stringify(
      {
        schema: "reallyme.identity.conformance.upstream-results.v1",
        repository: { name: "reallyme/ssi", commit: repositoryCommit },
        results,
      },
      null,
      2,
    )}\n`,
  );
}

process.stdout.write(
  `${verifyOnly ? "verified" : "executed"} ${results.length} pinned upstream conformance test sets\n`,
);
