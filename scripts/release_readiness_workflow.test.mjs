// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";

const coreUrl =
  process.env.RELEASE_READINESS_CORE_URL ??
  new URL("../.release-readiness/core.mjs", import.meta.url).href;

const validWorkflow = `name: Gate fixture

on:
  workflow_dispatch:

jobs:
  gate:
    runs-on: ubuntu-24.04
    steps:
      - name: Required check
        working-directory: repository
        run: node scripts/check.mjs
  final:
    needs: gate
    runs-on: ubuntu-24.04
    steps:
      - name: Finalize
        run: node scripts/finalize.mjs
`;

const policy = {
  path: ".github/workflows/gate.yml",
  jobs: {
    gate: { needs: [] },
    final: { needs: ["gate"] },
  },
  runSteps: [
    {
      job: "gate",
      name: "Required check",
      run: "node scripts/check.mjs",
      workingDirectory: "repository",
    },
  ],
};

function runFixture(workflow, selectedPolicy = policy) {
  const root = mkdtempSync(join(tmpdir(), "ssi-workflow-policy-"));
  mkdirSync(join(root, ".github", "workflows"), { recursive: true });
  mkdirSync(join(root, "scripts"), { recursive: true });
  writeFileSync(join(root, ".github", "workflows", "gate.yml"), workflow);

  const scriptUrl = pathToFileURL(join(root, "scripts", "runner.mjs")).href;
  const source = `
    import { createReleaseReadinessContext } from ${JSON.stringify(coreUrl)};
    const context = createReleaseReadinessContext({
      scriptUrl: ${JSON.stringify(scriptUrl)},
      repoRoot: "..",
      failurePrefix: "workflow fixture failed",
    });
    context.assertWorkflowPolicy(${JSON.stringify(selectedPolicy)});
  `;
  return spawnSync(process.execPath, ["--input-type=module", "--eval", source], {
    cwd: root,
    encoding: "utf8",
  });
}

test("workflow policy accepts an active control in the required job and directory", () => {
  const result = runFixture(validWorkflow);
  assert.equal(result.status, 0, result.stderr);
});

test("workflow required text rejects a value that appears only in a comment", () => {
  const result = runFixture(`${validWorkflow}\n# required-active-marker\n`, {
    path: ".github/workflows/gate.yml",
    required: ["required-active-marker"],
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /workflow fixture failed/u);
});

for (const [name, mutate] of [
  [
    "comment-only command",
    (workflow) => workflow.replace(
      "        run: node scripts/check.mjs",
      "        # run: node scripts/check.mjs",
    ),
  ],
  [
    "folded command substitution",
    (workflow) => workflow.replace(
      "        run: node scripts/check.mjs",
      "        run: >-\n          node scripts/other.mjs",
    ),
  ],
  [
    "statically disabled step",
    (workflow) => workflow.replace(
      "        working-directory: repository",
      "        if: false\n        working-directory: repository",
    ),
  ],
  [
    "wrong working directory",
    (workflow) => workflow.replace(
      "        working-directory: repository",
      "        working-directory: elsewhere",
    ),
  ],
  [
    "unreachable dependency",
    (workflow) => workflow.replace("    needs: gate", "    needs: missing-gate"),
  ],
  [
    "statically disabled job",
    (workflow) => workflow.replace(
      "  gate:\n    runs-on:",
      "  gate:\n    if: ${{ false }}\n    runs-on:",
    ),
  ],
  [
    "wrong job",
    (workflow) => workflow
      .replace(
        "      - name: Required check\n        working-directory: repository\n        run: node scripts/check.mjs\n",
        "",
      )
      .replace(
        "      - name: Finalize",
        "      - name: Required check\n        working-directory: repository\n        run: node scripts/check.mjs\n      - name: Finalize",
      ),
  ],
]) {
  test(`workflow policy rejects ${name}`, () => {
    const result = runFixture(mutate(validWorkflow));
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /workflow fixture failed/u);
  });
}
