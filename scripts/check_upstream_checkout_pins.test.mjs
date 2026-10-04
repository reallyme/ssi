// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { upstreamCheckoutPinFailures } from "./check_upstream_checkout_pins.mjs";

const manifest = JSON.parse(
  readFileSync(new URL("../conformance/upstream/tests.json", import.meta.url), "utf8"),
);
const workflow = readFileSync(new URL("../.github/workflows/rust-ci.yml", import.meta.url), "utf8");

test("CI shallow checkouts match the external conformance source commits", () => {
  assert.deepEqual(upstreamCheckoutPinFailures(manifest, workflow), []);
});

test("a stale COSE checkout ref is rejected", () => {
  const commit = manifest.sources.find((source) => source.execution?.package === "reallyme-cose")
    ?.execution.source_commit;
  assert.equal(typeof commit, "string");
  const stale = workflow.replace(`ref: ${commit}`, `ref: ${"0".repeat(40)}`);
  assert.deepEqual(upstreamCheckoutPinFailures(manifest, stale), [
    "reallyme-cose CI checkout does not match its source commit",
  ]);
});

test("missing or inconsistent source pins are rejected", () => {
  const missingStep = workflow.replace(
    "Checkout pinned JOSE conformance source",
    "Checkout unpinned JOSE conformance source",
  );
  assert.deepEqual(upstreamCheckoutPinFailures(manifest, missingStep), [
    "reallyme-jose CI checkout does not match its source commit",
  ]);

  const inconsistent = structuredClone(manifest);
  const secondJoseSource = inconsistent.sources.filter(
    (source) => source.execution?.package === "reallyme-jose",
  )[1];
  assert.ok(secondJoseSource);
  secondJoseSource.execution.source_commit = "0".repeat(40);
  assert.deepEqual(upstreamCheckoutPinFailures(inconsistent, workflow), [
    "reallyme-jose has no unique source commit",
  ]);
});

test("source repository substitution is rejected", () => {
  const substituted = structuredClone(manifest);
  const coseSource = substituted.sources.find(
    (source) => source.execution?.package === "reallyme-cose",
  );
  assert.ok(coseSource);
  coseSource.execution.repository = "https://github.com/example/cose";
  assert.deepEqual(upstreamCheckoutPinFailures(substituted, workflow), [
    "reallyme-cose source repository does not match its CI checkout",
  ]);
});
