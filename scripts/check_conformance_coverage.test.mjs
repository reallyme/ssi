// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function checkInventory(updateInventory) {
  const fixtureRoot = mkdtempSync(join(tmpdir(), "ssi-conformance-"));
  try {
    mkdirSync(join(fixtureRoot, "scripts"));
    mkdirSync(join(fixtureRoot, "conformance"));
    copyFileSync(
      join(root, "scripts/check_conformance_coverage.mjs"),
      join(fixtureRoot, "scripts/check_conformance_coverage.mjs"),
    );

    // Keep real implementation and test evidence intact while isolating the
    // inventory under test. Validation must still resolve the full workspace.
    for (const path of ["Cargo.lock", "crates", "vectors", "fuzz"]) {
      symlinkSync(join(root, path), join(fixtureRoot, path));
    }
    for (const entry of readdirSync(join(root, "scripts"))) {
      if (entry !== "check_conformance_coverage.mjs") {
        symlinkSync(join(root, "scripts", entry), join(fixtureRoot, "scripts", entry));
      }
    }
    for (const entry of readdirSync(join(root, "conformance"))) {
      if (entry !== "concepts.json") {
        symlinkSync(
          join(root, "conformance", entry),
          join(fixtureRoot, "conformance", entry),
        );
      }
    }

    const inventory = JSON.parse(readFileSync(join(root, "conformance/concepts.json"), "utf8"));
    updateInventory(inventory);
    writeFileSync(join(fixtureRoot, "conformance/concepts.json"), JSON.stringify(inventory));
    return spawnSync(process.execPath, ["scripts/check_conformance_coverage.mjs"], {
      cwd: fixtureRoot,
      encoding: "utf8",
      timeout: 30_000,
      maxBuffer: 1024 * 1024,
    });
  } finally {
    rmSync(fixtureRoot, { recursive: true, force: true });
  }
}

test("the v1 inventory resolves implementation and test evidence", () => {
  const result = checkInventory((inventory) => {
    assert.equal(inventory.schema, "reallyme.identity.conformance.concepts.v1");
    for (const concept of inventory.concepts) {
      assert.ok(Array.isArray(concept.coverage_notes));
    }
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
});

test("unsupported inventory schemas fail closed", () => {
  const result = checkInventory((inventory) => {
    inventory.schema = "invalid";
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /has an unexpected schema/u);
});

test("external coverage requires an explicit current evidence boundary", () => {
  const result = checkInventory((inventory) => {
    for (const concept of inventory.concepts) {
      concept.coverage_notes = [];
    }
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /must describe its current coverage boundary/u);
});

test("publication gaps still require an explanation", () => {
  const result = checkInventory((inventory) => {
    inventory.concepts[0].publishing.publish_ready = false;
    inventory.concepts[0].coverage_notes = [];
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /must describe publication gaps/u);
});

test("in-progress coverage requires notes and retains the release blocker", () => {
  const accepted = checkInventory((inventory) => {
    inventory.concepts[0].mapping_status = "in_progress";
    inventory.concepts[0].coverage_notes = ["Required section-level evidence is missing."];
    inventory.concepts[0].release_blocker = true;
  });
  assert.equal(accepted.status, 0, accepted.stderr);

  const missingNotes = checkInventory((inventory) => {
    inventory.concepts[0].mapping_status = "in_progress";
    inventory.concepts[0].coverage_notes = [];
    inventory.concepts[0].release_blocker = true;
  });
  assert.equal(missingNotes.status, 1);
  assert.match(missingNotes.stderr, /must describe its current coverage boundary/u);
});

test("malformed and nested coverage notes are rejected", () => {
  for (const value of [null, {}, "text", [null], [1], [{}], [["nested"]], [""], [" \n "]]) {
    const result = checkInventory((inventory) => {
      inventory.concepts[0].coverage_notes = value;
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /coverage_notes (?:must be an array|must contain nonempty text)/u);
  }
});

test("release blocker values must remain explicit booleans", () => {
  const result = checkInventory((inventory) => {
    inventory.concepts[0].release_blocker = "false";
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /field release_blocker must be boolean/u);
});
