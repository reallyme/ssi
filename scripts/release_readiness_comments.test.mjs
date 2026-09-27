// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import { scrubCommentsForAssertion } from "./release-readiness/core.mjs";

test("readiness assertions ignore shell controls preserved only in comments", () => {
  const source = `
    gh attestation verify evidence.json # --deny-self-hosted-runners
    # cargo publish --no-verify
    cargo check # cargo +1.96.0 check
  `;
  const searchable = scrubCommentsForAssertion("release.sh", source);
  assert.doesNotMatch(searchable, /--deny-self-hosted-runners/u);
  assert.doesNotMatch(searchable, /--no-verify/u);
  assert.doesNotMatch(searchable, /\+1\.96\.0/u);
});

test("readiness assertions preserve comment markers inside quoted values", () => {
  const source = `run: cargo check --config 'net.git-fetch-with-cli=#required' # retired`;
  const searchable = scrubCommentsForAssertion("workflow.yml", source);
  assert.match(searchable, /net\.git-fetch-with-cli=#required/u);
  assert.doesNotMatch(searchable, /retired/u);
});
