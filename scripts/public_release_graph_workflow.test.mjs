// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workflow = readFileSync(resolve(root, ".github/workflows/rust-ci.yml"), "utf8");

const job = (name, nextName) => {
  const start = workflow.indexOf(`  ${name}:\n`);
  assert.notEqual(start, -1, `${name} job must exist`);
  const end = workflow.indexOf(`  ${nextName}:\n`, start + 1);
  assert.notEqual(end, -1, `${nextName} job must follow ${name}`);
  return workflow.slice(start, end);
};

test("public dependency graph checks precede expensive Rust validation", () => {
  const checks = job("rust-checks", "workspace-tests");
  const workspace = job("workspace-tests", "package-archives");
  const archives = job("package-archives", "rust");
  for (const [source, firstExpensiveStep] of [
    [checks, "- name: Install nextest"],
    [workspace, "- name: Install nextest"],
    [archives, "- name: Inspect and test normalized crate archives"],
  ]) {
    const guard = source.indexOf("node scripts/check_public_release_graph.mjs");
    const expensive = source.indexOf(firstExpensiveStep);
    assert.ok(guard >= 0 && expensive >= 0 && guard < expensive);
  }
});

test("package preflight inspects the same public release graph", () => {
  const inspector = readFileSync(resolve(root, "scripts/inspect_publishable_crates.mjs"), "utf8");
  assert.match(inspector, /scripts\/check_public_release_graph\.mjs/u);
  const publisher = readFileSync(resolve(root, "scripts/publish_crates_in_order.mjs"), "utf8");
  const graphCheck = publisher.indexOf("  inspectCombinedArchiveGraph();");
  const packageBuild = publisher.indexOf("    inspectPackage(pkg);");
  assert.ok(graphCheck >= 0 && packageBuild >= 0 && graphCheck < packageBuild);
});
